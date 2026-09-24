# SentinelGraph — Review 2 Demo Notes

The exact 10-minute demonstration script. Every query below is reproducible against the
loaded dataset. Recorded latencies from the 25-Sep demo run — refresh with `npm run demo`.

## 0 · Setup proof (2 min)

```bash
docker compose ps                 # both DBs healthy, memory-capped (2g / 1.5g)
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
CREATE (n:Technique {mitreId:'G0016'})   -- fails: constraint (duplicate mitreId)
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
# → Phishing / Command and Scripting Interpreter top (degree centrality)
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