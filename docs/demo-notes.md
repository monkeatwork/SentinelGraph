# SentinelGraph — Demo Notes (Review 2 + Review 3)

The exact demonstration scripts. Every query below is reproducible against the loaded
dataset. Review 2 latencies are from the 25-Sep run; refresh with `npm run demo`.
The Review 3 dashboard walkthrough is in the [Review 3 section](#review-3--dashboard-walkthrough-5-min).

## 0 · Setup proof (2 min)

```bash
brew services list                # native neo4j + mongodb running (or: docker compose ps)
npm run ensure-indexes            # re-run is a no-op (idempotent)
curl localhost:3000/health        # → {"mongo":"up","neo4j":"up",…}
```

## 1 · Volume claims (rubric: 50+ records; we load 20× that)

| Store | Claim | Evidence |
|---|---|---|
| Neo4j nodes | 25,096 (≥2,200 promised) | `MATCH (n) RETURN labels(n)[0], count(*)` |
| Neo4j relationships | 63,534 (≥8,000 promised) | `MATCH ()-[r]->() RETURN type(r), count(*)` |
| Mongo docs | ~5,800+ (entities 1,835 · vulns 4,007 · reports+chunks ~4,000) | `db.entities.countDocuments({})` … |

10 relationship types all > 0 (ATTRIBUTED_TO, DEPLOYS, USES_TECHNIQUE, PERFORMS, BELONGS_TO,
MITIGATED_BY, EXPLOITS, AFFECTS, TARGETS, SUBTECHNIQUE_OF).

## 2 · Idempotency (NFR5) — 1 min

```bash
npm run ingest:attack && npm run ingest:attack
# second run: 0 new nodes/docs — counts identical (MERGE/upserts everywhere)
```

Show in Neo4j browser:
```cypher
MATCH (a:ThreatActor {name:'APT29'})-[:PERFORMS]->(t) RETURN count(t)   -- 66
```

## 3 · CRUD + roles (FR4/FR12) — 2 min

```bash
node -e "
const base='http://localhost:3000'; const H={'Content-Type':'application/json'};
(async()=>{
  const t=async(p,o={})=>{const r=await fetch(base+p,{...o,headers:H});return r.json()};
  const {token}=await t('/api/auth/login',{method:'POST',body:JSON.stringify({email:'admin@sentinelgraph.local',password:'Admin@123'})});
  const A={...H,Authorization:'Bearer '+token};
  await fetch(base+'/api/graph/Technique',{method:'POST',headers:A,body:JSON.stringify({mitreId:'T8DEMO',name:'Demo'})});
  await fetch(base+'/api/graph/Technique/T8DEMO',{method:'PATCH',headers:A,body:JSON.stringify({name:'Demo v2'})});
  console.log(await fetch(base+'/api/graph/Technique/T8DEMO',{headers:A}).then(r=>r.json()));
  await fetch(base+'/api/graph/Technique/T8DEMO',{method:'DELETE',headers:A});
  // analyst write → 403, duplicate key → 409
})()"
```

Neo4j browser equivalents (node CRUD + constraint):
```cypher
CREATE (n:Technique {mitreId:'T8X', name:'X'})
MATCH (n:Technique {mitreId:'T8X'}) SET n.name='Y'
MATCH (n:Technique {mitreId:'T8X'}) DETACH DELETE n
CREATE (n:ThreatActor {mitreId:'G0016'}) -- fails: ConstraintValidationFailed (APT29 exists)
// careful: constraints are per label, so CREATE (n:Technique {mitreId:'G0016'}) SUCCEEDS
// and leaves a stray node; `npm run reconcile` reports it as "mitreId on more than one label"
```

## 4 · Q&A flagship question (FR5–FR8, NFR1/2/6) — 2 min

Dashboard → **Ask**: `Which adversary groups exploit Log4j, and how?` (depth 2)

Pipeline: resolve (`CVE-2021-44228` by regex, `apache/log4j` software by name) →
Cypher 2-hop expansion → vector retrieval over `chunks` filtered to traversed
`entityIds` → template answer citing source reports.

Expected evidence citations: *Mitigating Log4Shell and Other Log4j Related Vulnerabilities*
(CISA/NIST), *MIDNIGHT BLIZZARD: Guidance for Responders…* (Microsoft), *Cobalt Strike Profile*
(MITRE). Each evidence chunk carries similarity score + report title + URL + date (NFR6).

Recorded latencies (hash engine): graph ≈ 20–60 ms, vector ≈ 10–40 ms, total < 300 ms.
(NFR1 < 500 ms ✓, NFR2 < 300 ms ✓.)

## 5 · Graph algorithms (FR9/FR10) — 2 min

```bash
curl 'localhost:3000/api/algorithms/shortest-path?from=log4j&to=APT29' -H "Authorization: Bearer $TOKEN"
# → Software log4j ←AFFECTS← CVE-2021-44228 ←EXPLOITS← Cobalt Strike →USES_TECHNIQUE→ … ←PERFORMS← APT29 (4 hops)
curl 'localhost:3000/api/algorithms/technique-criticality' -H "Authorization: Bearer $TOKEN"
# → Ingress Tool Transfer (T1105) top, then System Information Discovery (degree centrality)
curl 'localhost:3000/api/algorithms/similar-actors?actor=APT29' -H "Authorization: Bearer $TOKEN"
# → Jaccard-similar groups (shared PERFORMS techniques)
```

Neo4j browser equivalents:
```cypher
MATCH p = shortestPath((s:Software {cpeName:'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*'})-[:AFFECTS|EXPLOITS|USES_TECHNIQUE|PERFORMS*]-(a:ThreatActor {mitreId:'G0016'}))
RETURN [n IN nodes(p) | labels(n)[0]+':'+n.name]
```

## 6 · Aggregations (5 pipelines, <1 s each) — 1 min

| Endpoint | Pipeline |
|---|---|
| `/api/analytics/cve-severity-by-month` | `$match → $group {year,month,severity} → $sort` |
| `/api/analytics/most-cited-sources` | `$unwind citedReportIds → $lookup reports → $group source` |
| `/api/analytics/user-query-volume` | `$group userId → $avg latencyMs.graph → $lookup users` |
| `/api/analytics/chunks-per-entity` | `$unwind entityIds → $group → $lookup entities` |
| `/api/analytics/severity-exploited-crosstab` | `$group severity × knownExploited` |

Mongo shell equivalents:
```js
db.vulnerabilities.aggregate([{$group:{_id:{sev:'$cvss.severity',kev:'$knownExploited'},count:{$sum:1}}}])
```

## 7 · Indexes & performance (NFR3)

```cypher
SHOW INDEXES        -- 9 constraints + range (cvssScore) + fulltext (entity names)
db.entities.getIndexes()
```

`EXPLAIN` on the 2-hop traversal shows index-backed lookup on `mitreId`; the vector
retrieval's candidate scan is bounded by the multikey `chunks.entityIds` index.

---

### Recorded numbers (run `npm run demo` to refresh)

| Metric | Value |
|---|---|
| Graph nodes / rels | 25,096 / 63,534 |
| Mongo docs | entities 1,835 · vulnerabilities 4,007 · reports 3,833 · chunks 3,856 |
| Q&A resolve / graph / vector / total | 50 ms / 45 ms / 9 ms / ~80–106 ms |
| 2-hop traversal | graph 79 ms (NFR1 < 500 ms ✓) |
| Vector top-10 | 7–9 ms steady-state (NFR2 < 300 ms ✓) |
| Aggregations | all 2–10 ms (well < 1 s) |
| Shortest path log4j→APT29 | 4 hops (AFFECTS→EXPLOITS→USES_TECHNIQUE→PERFORMS), 2–6 ms |
| Technique criticality #1 | Ingress Tool Transfer (T1105, 491) |
| Most similar to APT29 | APT28 (J=0.22) |

---

## Review 3 — dashboard walkthrough (5 min)

Scripted walkthrough, verified with zero console errors at desktop (1366 px), tablet
(820 px) and phone (390 px) widths, light and dark themes (13 Oct 2026).
Start: `brew services start neo4j mongodb/brew/mongodb-community && npm start`, open
http://localhost:3000.

| # | Page | Action | What to point out |
|---|---|---|---|
| 1 | Login | Click the **analyst** demo chip → Sign in | JWT login; bcrypt-only passwords; analyst has no Admin tab |
| 2 | Graph | Attack path bar: `log4j` → `APT29` → **Show attack path** | Neo4j `shortestPath`: 4 hops, arrows show real direction (CVE –AFFECTS→ log4j, Cobalt Strike –EXPLOITS→ CVE, Cobalt Strike –USES_TECHNIQUE→ PowerShell, APT29 –PERFORMS→ PowerShell); faded neighbours are context |
| 3 | Graph | **Clear path**, search `APT29`, click a technique node | Click-to-expand (1-hop Cypher), drag to pan, +/− to zoom, label filter |
| 4 | Ask | Flagship question, **Template**, depth 2 → Ask | Resolve → traversal → entity-filtered vector search → cited answer; latency breakdown (~100–150 ms) |
| 5 | Ask | Switch to **LLM answer (gemini)** → Ask | Same evidence, Gemini writes it with `[n]` citations + Sources list; badge shows model; graph paths given to the LLM listed; falls back to template if the LLM is down |
| 6 | Ask | **☆ Save**, then click the saved chip | Saved queries live inside the user's Mongo document (`$push` with cap + duplicate guard) |
| 7 | Ask | `What techniques does APT29 use and how can they be mitigated?` (LLM) | Actor resolved by name; mitigations come from `MITIGATED_BY` graph edges |
| 8 | Insights | Read the three cards | Degree centrality (top: Ingress Tool Transfer 491); Jaccard similar actors (APT28 22%); mitigation coverage for APT29 (Privileged Account Management 18/66) |
| 9 | Insights | Click **APT28** | Recommendation opens straight into the graph |
| 10 | Reports | Scroll the four cards | 4 Mongo aggregation pipelines named on each card with latency; KEV matrix (183 known-exploited, 4.6%) |
| 11 | Login | Log out, sign in as **admin** | Admin tab appears (role-based UI) |
| 12 | Admin | Create `G9DEMO` ThreatActor → Edit name → **Graph** → Delete (click twice) | Mongo-first write mirrored to Neo4j; duplicate create shows 409; DETACH DELETE |
| 13 | Admin | **Run consistency check** | Same check as `npm run reconcile`: every mitreId/cveId in both stores, 0 drift |
| 14 | Any | Toggle 🌙 / ☀️, narrow the window | Light/dark themes; layout adapts down to phone width |

### Review 3 commands

```bash
npm test             # 59 integration tests (LLM calls mocked, no key needed)
npm run demo         # Review 2 end-to-end regression, unchanged
npm run reconcile    # cross-store drift report (add --json for the full lists)
```

### Review 3 recorded numbers

| Metric | Value |
|---|---|
| Q&A template mode total | ~100–150 ms |
| Q&A LLM mode total | ~1.5–2.5 s (Gemini flash-lite; ~2.2k input + ~250 output tokens per question) |
| Attack path log4j → APT29 | 4 hops, 3–7 ms |
| Mitigation priorities (APT29) | ~25–60 ms |
| Reconcile (both key spaces) | ~85–100 ms, 0 drift |

