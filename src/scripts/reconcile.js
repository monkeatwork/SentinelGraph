/**
 * Review 3 — cross-store reconciliation report.
 * Lists every join key present in one store but missing in the other, in both directions:
 *   Mongo `entities.mitreId`       <-> Neo4j entity-label nodes (mitreId)
 *   Mongo `vulnerabilities.cveId`  <-> Neo4j :Vulnerability nodes (cveId)
 * Also flags entities whose Mongo `entityType` disagrees with their graph label, and
 * mitreIds that exist on more than one graph label (per-label constraints allow this).
 * Read-only: safe to re-run at any time. `--json` prints the full report as JSON.
 */
require('dotenv').config();

const mongo = require('../config/mongo');
const neo4j = require('../config/neo4j');
const { ENTITY_LABELS } = require('../services/graphMeta');

function diff(a, b) {
  return [...a].filter((k) => !b.has(k)).sort();
}

async function graphKeys(cypher, params = {}) {
  const session = neo4j.getDriver().session();
  try {
    const res = await session.run(cypher, params);
    return res.records.map((r) => ({ key: r.get('key'), label: r.get('label') }));
  } finally {
    await session.close();
  }
}

async function reconcile() {
  const db = await mongo.getDb();
  const labels = [...ENTITY_LABELS];

  // --- entities (mitreId) ---
  const mongoEntities = await db
    .collection('entities')
    .find({}, { projection: { _id: 0, mitreId: 1, entityType: 1 } })
    .toArray();
  const graphEntities = await graphKeys(
    `MATCH (n) WHERE any(l IN labels(n) WHERE l IN $labels) AND n.mitreId IS NOT NULL
     RETURN n.mitreId AS key, [l IN labels(n) WHERE l IN $labels][0] AS label`,
    { labels }
  );

  const mongoTypeById = new Map(mongoEntities.map((e) => [e.mitreId, e.entityType]));
  const graphLabelsById = new Map();
  for (const e of graphEntities) {
    if (!graphLabelsById.has(e.key)) graphLabelsById.set(e.key, []);
    graphLabelsById.get(e.key).push(e.label);
  }
  const mongoIds = new Set(mongoTypeById.keys());
  const graphIds = new Set(graphLabelsById.keys());

  const multiLabel = [...graphLabelsById]
    .filter(([, ls]) => ls.length > 1)
    .map(([id, ls]) => ({ mitreId: id, labels: ls.sort(), mongo: mongoTypeById.get(id) || null }))
    .sort((a, b) => a.mitreId.localeCompare(b.mitreId));

  const labelMismatch = [...mongoIds]
    .filter((id) => graphIds.has(id) && !graphLabelsById.get(id).includes(mongoTypeById.get(id)))
    .sort()
    .map((id) => ({ mitreId: id, mongo: mongoTypeById.get(id), graph: graphLabelsById.get(id).join('/') }));

  // --- vulnerabilities (cveId) ---
  const mongoCves = await db.collection('vulnerabilities').distinct('cveId');
  const graphCves = await graphKeys('MATCH (v:Vulnerability) RETURN v.cveId AS key, "Vulnerability" AS label');
  const mongoCveSet = new Set(mongoCves);
  const graphCveSet = new Set(graphCves.map((v) => v.key));

  return {
    checkedAt: new Date().toISOString(),
    entities: {
      mongoCount: mongoIds.size,
      graphCount: graphIds.size,
      missingInGraph: diff(mongoIds, graphIds),
      missingInMongo: diff(graphIds, mongoIds),
      labelMismatch,
      multiLabel,
    },
    vulnerabilities: {
      mongoCount: mongoCveSet.size,
      graphCount: graphCveSet.size,
      missingInGraph: diff(mongoCveSet, graphCveSet),
      missingInMongo: diff(graphCveSet, mongoCveSet),
    },
  };
}

function driftCount(report) {
  const e = report.entities, v = report.vulnerabilities;
  return e.missingInGraph.length + e.missingInMongo.length + e.labelMismatch.length + e.multiLabel.length +
    v.missingInGraph.length + v.missingInMongo.length;
}

function printList(title, items, fmt = (x) => x) {
  console.log(`  ${title}: ${items.length}`);
  for (const x of items.slice(0, 25)) console.log(`    - ${fmt(x)}`);
  if (items.length > 25) console.log(`    ... and ${items.length - 25} more (use --json for the full list)`);
}

function printReport(r) {
  console.log(`Reconciliation report (${r.checkedAt})\n`);
  console.log(`Entities (mitreId): Mongo ${r.entities.mongoCount} / Neo4j ${r.entities.graphCount}`);
  printList('in Mongo, missing in Neo4j', r.entities.missingInGraph);
  printList('in Neo4j, missing in Mongo', r.entities.missingInMongo);
  printList('entityType vs label mismatch', r.entities.labelMismatch,
    (m) => `${m.mitreId}: Mongo ${m.mongo}, Neo4j ${m.graph}`);
  printList('mitreId on more than one label', r.entities.multiLabel,
    (m) => `${m.mitreId}: Neo4j ${m.labels.join(' + ')} (Mongo says ${m.mongo || 'nothing'})`);
  console.log(`\nVulnerabilities (cveId): Mongo ${r.vulnerabilities.mongoCount} / Neo4j ${r.vulnerabilities.graphCount}`);
  printList('in Mongo, missing in Neo4j', r.vulnerabilities.missingInGraph);
  printList('in Neo4j, missing in Mongo', r.vulnerabilities.missingInMongo);
  const n = driftCount(r);
  console.log(n === 0 ? '\nNo drift: both stores agree on every join key.' : `\nTotal drift: ${n} key(s). Ingest-made drift is repaired by re-running ingest; anything else needs a look.`);
}

module.exports = { reconcile, driftCount };

if (require.main === module) {
  reconcile()
    .then((r) => {
      if (process.argv.includes('--json')) console.log(JSON.stringify(r, null, 2));
      else printReport(r);
    })
    .then(() => Promise.all([mongo.close(), neo4j.close()]))
    .then(() => process.exit(0))
    .catch((e) => {
      console.error('reconcile failed:', e);
      process.exit(1);
    });
}
