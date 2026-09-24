# SentinelGraph — Team Rundown (Review 2)

> Handoff doc for the team. Covers: what's built, what's left, the Review 2 demo plan,
> and what Review 3 still needs. Repo root: `sentinelgraph/` (fresh git repo, 7 commits).
> Team: Kshitij Rahul Manikshete (24BCI0080) · Yashasvi Dagar (24BCI0112) · BCSE302P

---

## 1 · One-paragraph status

SentinelGraph is **built and Review-2 ready**: a hybrid NoSQL system where **Neo4j** answers
*how threat entities connect* and **MongoDB** answers *what the evidence says*, joined by a
single `mitreId`/`cveId` key. Both databases run in local Docker with real public data
(MITRE ATT&CK STIX, NVD CVEs, CISA KEV, curated advisories). The REST API covers auth,
full CRUD, a cited Q&A pipeline, graph algorithms and 5 aggregation pipelines, with a
vanilla-JS dashboard. 24 jest/supertest integration tests pass, and `npm run demo` drives
the complete Review 2 walkthrough end-to-end.

---

## 2 · What is DONE (all verified)

### Data (loaded, idempotent — re-running adds nothing)
| Store | Contents | Volume |
|---|---|---|
| Neo4j | 9 labels (ThreatActor, Campaign, Malware, Technique, Tactic, Mitigation, Vulnerability, Software, Sector) | 25,096 nodes |
| Neo4j | 10 relationship types (ATTRIBUTED_TO, DEPLOYS, USES_TECHNIQUE, PERFORMS, BELONGS_TO, MITIGATED_BY, EXPLOITS, AFFECTS, TARGETS, SUBTECHNIQUE_OF) | 63,534 relationships |
| MongoDB | entities · reports · chunks · vulnerabilities · users · queryLogs | ~12,000+ docs (entities 1,835 · vulns 4,007 · reports 3,833 · chunks 3,856) |

Sources: MITRE ATT&CK Enterprise STIX 2.1 (1835 entities), NVD API (4,007 CRITICAL/HIGH
CVEs incl. Log4Shell/EternalBlue/MOVEit/PAN-OS/ProxyLogon), CISA KEV (183 exploited flags),
20+ sectors, 19,000+ CPE-based software nodes, ~200 curated software products, 16 hand-written
advisories + auto-generated entity profiles + NVD advisories (3,833 reports → chunked → embedded).

### Schema & indexes
- 9 Neo4j uniqueness constraints (mitreId/cveId/cpeName/sectorName) + range index on
  `Vulnerability.cvssScore` + full-text index over entity names/aliases.
- Mongo unique (`entities.mitreId`, `vulnerabilities.cveId`, `users.email`), text
  (`entities.name/aliases`), compound (`cvss.baseScore×publishedDate`, `userId×askedAt`),
  multikey (`chunks.entityIds`), `reports.publishedDate`.

### API (Express, port 3000)
- Auth: JWT + bcrypt(cost 12), roles analyst/admin, 8h expiry.
- Full CRUD: `/api/graph/:label/:key` (DETACH deletes, mirrors to Mongo), `/api/entities`,
  `/api/reports` (POST/PUT auto chunk+embed), `/api/vulnerabilities` (severity/date/KEV
  filters), `/api/users` (admin-only). Consistent errors: 400/401/403/404/**409 on duplicates**.
- Q&A `/api/qa/ask`: resolve entities → configurable depth Cypher traversal → entityIds-
  filtered vector retrieval → **template answer with citations** (title+URL+date), logged
  to `queryLogs` with per-stage latency (FR13).
- Algorithms: `/api/algorithms/shortest-path` (log4j → APT29: 4 hops,
  Software→CVE-2021-44228→Cobalt Strike→PowerShell→APT29), `technique-criticality`
  (degree centrality; #1 Ingress Tool Transfer), `similar-actors` (Jaccard; APT29↔APT28 0.22).
- 5 aggregations: severity-by-month, most-cited sources, per-user query volume, chunks-per-
  entity, severity×KEV cross-tab — all ≤ 10 ms.

### Performance (steady-state, recorded in `docs/demo-notes.md`)
- 2-hop traversal: **79 ms** (NFR1 < 500 ms ✓) · vector top-10: **7–9 ms** (NFR2 < 300 ms ✓) ·
  full Q&A ask: ~80–110 ms total.

### Dashboard (Phase 6, functional but needs human click-through)
- Login (JWT), role pill, Graph tab (force-directed canvas, search, label filter, click node →
  expand neighbours), Ask tab (answer + citations + similarity %, latency readout), Reports
  tab (4 charts from the aggregations). Static, no build step.

### Tests
`npm test` → **24/24 pass** (auth, graph CRUD, document CRUD, advanced/NoSQL). Requires DBs running.

---

## 3 · What is LEFT for Review 2

**Only one thing: a manual dashboard walkthrough.** All APIs behind it are verified, but
no browser was available in the build session, so someone needs to click through:
1. Login as **analyst** and as **admin** → role pill updates.
2. Graph tab: search `APT29` → subgraph renders; click a node → neighbours expand; label filter.
3. Ask tab: run the flagship question (below) → answer + citations + latency render.
4. Reports tab: 4 charts render.
5. Check no console errors; roughly responsive.

That's it — everything else for Review 2 is done and recorded.

---

## 4 · Review 2 demo plan (10 min, `docs/demo-notes.md` has the full script)

1. **Setup proof**: `docker compose ps` (both healthy) + `curl :3000/health` + re-run
   `npm run ensure-indexes` (no-op).
2. **Volumes**: Neo4j browser counts (25,096 nodes / 63,534 rels) and MongoDB counts
   (entities 1,835 · vulns 4,007 · reports 3,833 · chunks 3,856) — 20× the rubric floor.
3. **Idempotency**: re-run `npm run ingest:attack` → identical counts (MERGE/upserts).
4. **CRUD + roles**: live POST→GET→PATCH→DELETE on a Technique via the API; show analyst
   write → **403**; duplicate insert → **409**; wrong password → **401**.
5. **Q&A flagship** (dashboard Ask or `curl`): *"Which adversary groups exploit Log4j, and how?"*
   → resolves `CVE-2021-44228` + apache/log4j → traverses → evidence chunks → answer citing
   *Mitigating Log4Shell…* (CISA/NIST) + *MIDNIGHT BLIZZARD guidance* (Microsoft) + *NVD Advisory*.
6. **Algorithms**: shortest path log4j→APT29 (4 hops), technique criticality, similar actors.
7. **Aggregations**: 5 pipelines, each < 1 s (usually < 10 ms).
8. **Export logs**: `queryLogs` shows every question + latencies (FR13).

Log in as `analyst@vitstudent.ac.in` / `Analyst@123` (or `admin@sentinelgraph.local` / `Admin@123`).

---

## 5 · What is LEFT for Review 3 (deferred, do NOT do before Review 2)

From the rubric (3 marks UI/UX + analytics + docs; viva):

| Item | Detail |
|---|---|
| LLM-powered answers | Replace template `answerBuilder` with a hosted model API (chunks + graph path as context) |
| UI polish + responsiveness audit | Current dashboard is functional but minimal; needs desktop/tablet pass, better styling |
| Attack-path visualization | Highlight the shortest-path chain on the graph view (directional arrows) |
| Reconciliation job + report | Detect identifiers present in one store but missing in the other |
| Final report | Project report document |
| User manual | How-to for analysts/admins |
| Presentation slides + demonstration video (optional) | For the viva |
| Saved queries for users | `savedQueries` field exists in schema; not implemented yet |

---

## 6 · How to run everything

```bash
cd sentinelgraph
docker compose up -d          # neo4j (7474/7687) + mongodb (27017) — memory-capped
npm run ensure-indexes        # (already done; no-op on re-run)
npm run ingest:attack         # STIX (cached bundle in data/, 51 MB)   [idempotent]
npm run ingest:nvd            # NVD CVEs (cached in data/nvd-cves.json) [idempotent]
npm run ingest:cisa           # CISA KEV flags                          [idempotent]
npm run seed:software         # software/sectors + TARGETS              [idempotent]
npm run seed:users            # admin + analyst accounts
npm run seed:reports          # advisories + profiles + NVD → chunks    [idempotent]
npm start                     # API + dashboard → http://localhost:3000
npm run demo                  # full automated Review 2 demo run
npm test                      # 24 integration tests (DBs must be running)
```

Neo4j browser: http://localhost:7474 (neo4j / sentinelgraph). Mongo shell: `docker exec -it sentinelgraph-mongodb mongosh sentinelgraph`.

---

## 7 · Infrastructure & gotchas (read before touching anything)

- **Docker Desktop GUI may not open** (current machine quirk — the daemon/VM still runs
  fine in the background; CLI `docker ps` / `docker compose` work). Use the CLI, not the GUI.
- **Memory**: containers are capped (neo4j 2 GB — heap 512 MB/page cache 256 MB;
  mongo 1.5 GB — WiredTiger 0.75 GB). Keep the caps — the machine froze once when Docker
  was unbounded. Don't run ingestion and the demo at the same time as other heavy apps.
- **Mongo-first, then Neo4j** for every dual write; re-running ingestion fixes any failed run.
- **Community MongoDB has no Atlas Vector Search**: retrieval = service-layer cosine over the
  `entityIds`-indexed candidate set (plan's Option B). Embeddings: all-MiniLM-L6-v2 384-d via
  transformers with offline hash fallback (`EMBEDDING_MODE` in `.env`).
- **2026 data quirks handled**: ATT&CK STIX keeps `external_id` in `external_references`
  (plus 224 legacy T-prefixed course-of-action objects + revoked objects — filtered);
  NVD API nests metrics under `metrics`, removed date filters, orders oldest-first —
  flagship CVEs are fetched explicitly by id.
- **Never commit `.env`** (gitignored). `data/` bundle caches are also gitignored.
- Errors are `{error:{code,message}}`; read more in `README.md` (API table) and
  `AGENT_PLAN.md` (checkpoints & global rules).

---

## 8 · File map (quick orientation)

```
sentinelgraph/
├── docker-compose.yml · Dockerfile · .env.example · package.json
├── README.md                     # setup + architecture + API table
├── docs/demo-notes.md            # the exact Review 2 demo script + recorded numbers
├── AGENT_PLAN.md                 # (upstream plan; checkpoints 0–6, all verified)
├── src/
│   ├── server.js                 # Express + static dashboard + /health
│   ├── config/  middleware/  routes/      (auth, graph, entities, reports,
│   │                                       vulnerabilities, users, qa, algorithms, analytics)
│   ├── services/ ingest/ (attack-stix, nvd, cisa-kev) · chunker · embeddings ·
│   │                entityResolver · retrieval · answerBuilder · reportIngest
│   └── scripts/  ensureIndexes · ingest* · seed* · demoQueries
├── tests/                        # auth, graph-crud, document-crud, advanced (24 tests)
└── public/                       # dashboard (index.html, app.js, style.css)
```