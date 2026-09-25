# SentinelGraph — Graph-Augmented Retrieval for Cyber Threat Intelligence

BCSE302P Database Systems Lab · Fall 2025–26 · Kshitij Rahul Manikshete (24BCI0080) · Yashasvi Dagar (24BCI0112)

A hybrid NoSQL system: **Neo4j** answers *how entities connect* (multi-hop traversal, shortest path, centrality), **MongoDB** answers *what the evidence says* (narrative reports, embeddings, aggregations, audit logs). The two are joined by a single key — `mitreId` / `cveId` — present and indexed in both stores.

```
                    ┌──────────────────────────────────────────┐
                    │            REST API (Node/Express)        │
                    │  Auth · CRUD · Q&A · Analytics · Viz data │
                    └───────────────┬──────────────────────────┘
                                    │
              ┌─────────────────────┴──────────────────────┐
              │                                            │
     ┌────────▼─────────┐                       ┌──────────▼──────────┐
     │      Neo4j       │                       │      MongoDB        │
     │ "HOW things      │   joined by           │ "WHAT the evidence  │
     │  connect"        │  mitreId / cveId      │  says"              │
     │                  │◄─────────────────────►│                     │
     │ ThreatActor      │                       │ entities            │
     │ Campaign         │                       │ reports             │
     │ Malware          │                       │ chunks + embeddings │
     │ Technique/Tactic │                       │ vulnerabilities     │
     │ Mitigation       │                       │ users               │
     │ Vulnerability    │                       │ queryLogs           │
     │ Software, Sector │                       │                     │
     └──────────────────┘                       └─────────────────────┘
```

## Quick start

Prereqs: Node 20+. Databases can run **either** natively (recommended for dev machines —
cooler, no VM) **or** in Docker (recommended for lab/demo machines):

**Option A — native databases (macOS, Homebrew):**
```bash
brew tap mongodb/brew
brew install mongodb-community neo4j
# Neo4j: set the password before first start
/opt/homebrew/opt/neo4j/bin/neo4j-admin dbms set-initial-password sentinelgraph
brew services start neo4j mongodb/brew/mongodb-community
```

**Option B — Docker (any machine):**
```bash
docker compose up -d            # neo4j (7474/7687) + mongodb (27017), memory-capped
```
> Never run both at once — they share ports 27017/7687/7474.

Then, on any machine (one-time setup, all idempotent):

```bash
git clone <repo-url> sentinelgraph && cd sentinelgraph

cp .env.example .env            # adjust passwords/secret if you like
npm install
npm run ensure-indexes          # 9 unique constraints, range + fulltext indexes, Mongo indexes

npm run ingest:attack           # MITRE ATT&CK STIX 2.1 → both stores (idempotent)
npm run ingest:nvd              # NVD CRITICAL/HIGH CVEs + CPE-based Software/AFFECTS (idempotent)
npm run ingest:cisa             # CISA KEV → knownExploited flags
npm run seed:software           # curated Software/Sector nodes + TARGETS links
npm run seed:users              # admin + analyst accounts (bcrypt cost 12)
npm run seed:reports            # curated advisories + entity profiles + NVD advisories → chunks+embeddings

npm start                       # API + dashboard on http://localhost:3000
npm run demo                    # the end-to-end Review 2 demo runner
npm test                        # jest + supertest (DBs must be running)
```

Stop the databases at the end of the day:
`brew services stop neo4j mongodb/brew/mongodb-community` (native) or `docker compose down` (Docker).

Login: `admin@sentinelgraph.local` / `Admin@123` (admin), `analyst@vitstudent.ac.in` / `Analyst@123`.

> Ingest scripts are **idempotent** — re-running them adds nothing (MERGE/upserts everywhere).
> MongoDB is the system of record: docs are written first, then graph nodes/edges
> (no cross-DB transactions; a failed run is fixed by re-running).

## Architecture & data model

| Store | Labels / Collections | Key property | Volume (loaded) |
|---|---|---|---|
| Neo4j | ThreatActor, Campaign, Malware, Technique, Tactic, Mitigation, Vulnerability, Software, Sector | mitreId / cveId / cpeName / sectorName | ~25,000 nodes, ~64,000 relationships |
| Neo4j rels | ATTRIBUTED_TO, DEPLOYS, USES_TECHNIQUE, PERFORMS, BELONGS_TO, MITIGATED_BY, EXPLOITS, AFFECTS, TARGETS, SUBTECHNIQUE_OF | — | all 10 types present |
| MongoDB | entities, reports, chunks, vulnerabilities, users, queryLogs | mitreId unique, cveId unique, email unique | ~5,800+ docs |

Domain chain: `Software ← AFFECTS ← Vulnerability ← EXPLOITS ← Malware → USES_TECHNIQUE → Technique ← PERFORMS ← ThreatActor ← ATTRIBUTED_TO ← Campaign ← DEPLOYS ← Malware`.

Indexes (NFR3): Mongo — unique `entities.mitreId`, text `name/aliases`, multikey `chunks.entityIds`, unique `vulnerabilities.cveId`, compound `{cvss.baseScore, publishedDate}`, unique `users.email`, compound `{userId, askedAt}`; Neo4j — 9 uniqueness constraints, range `vulnerability.cvssScore`, full-text over entity names/aliases. Vector search runs service-side (cosine over the `entityIds`-filtered candidate set — community MongoDB has no Atlas Vector Search; a vector index attempt is logged and skipped).

Embeddings: `@huggingface/transformers` all-MiniLM-L6-v2 (384-d) with an offline hashing fallback (768-d). Set `EMBEDDING_MODE=hash|transformers` in `.env`; dimension consistency is handled per engine.

## API surface

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` · `/register` · `GET /api/auth/me` | public / admin | JWT auth (bcrypt, 8 h expiry) |
| POST/GET/PATCH/DELETE | `/api/graph/:label/:key` (+ `/:key/neighbors`, `/search?q=`) | writes: admin | graph CRUD, DETACH delete, full-text search |
| POST/GET/PUT/DELETE | `/api/entities` (…`/:mitreId`) | writes: admin | entity docs, mirrored into Neo4j |
| POST/GET/PUT/DELETE | `/api/reports` (…`/:id`) | writes: admin | report CRUD; POST/PUT trigger chunk+embed pipeline |
| GET / POST/PUT/DELETE | `/api/vulnerabilities` | writes: admin | CVE records, severity/date/KEV filters |
| GET / PATCH | `/api/users` · `/api/users/:id/role` | admin | user admin |
| POST | `/api/qa/ask` | any | resolve → Cypher traversal (depth) → vector retrieval → cited template answer; logs to queryLogs (FR13) |
| GET | `/api/algorithms/shortest-path` · `technique-criticality` · `similar-actors` | any | FR9/FR10 |
| GET | `/api/analytics/*` (5 pipelines) | any | severity-by-month, most-cited sources, per-user volume, chunks-per-entity, severity×KEV cross-tab |
| GET | `/health` | public | DB health |

Errors: `{ error: { code, message } }` — 400 bad payload, 401 missing/expired token, 403 wrong role, 404 not found, 409 duplicate key.

## Project layout

```
src/
├── server.js                 # express app + static dashboard
├── config/                   # mongo + neo4j singletons
├── middleware/auth.js        # JWT sign/verify, requireAuth/requireRole
├── routes/                   # auth graph entities reports vulnerabilities users qa algorithms analytics
├── services/
│   ├── ingest/               # attack-stix.js · nvd.js · cisa-kev.js
│   ├── chunker.js embeddings.js entityResolver.js retrieval.js answerBuilder.js reportIngest.js
└── scripts/                  # ensureIndexes seed* ingest* demoQueries
tests/                        # jest + supertest integration suites
public/                       # dashboard (vanilla HTML/JS, force-graph viz)
docs/demo-notes.md            # exact Review 2 demo script
```

## Review 2 scorecard

- **DB implementation:** both DBs in Docker; 9 labels / 10 rel types / 6 collections; 25,096 nodes, 63,534 rels, ~5,800+ docs (rubric floor: 100 nodes / 6 types).
- **CRUD:** graph + document round-trips through one REST API; role-restricted writes; 409 on duplicate keys; DETACH deletes; mirrored writes between stores.
- **Advanced NoSQL:** entity-filtered vector retrieval, configurable-depth Cypher traversal, shortest path, degree-centrality, Jaccard similarity, 5 aggregation pipelines, 8+ indexes incl. text/compound/multikey/unique, idempotent ingestion (proved by re-run diffs).
- **Deliverables:** repo, `npm run demo`, `docs/demo-notes.md`, README.