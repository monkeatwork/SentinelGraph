/**
 * Phase 1 — Schema, constraints & indexes.
 * Idempotent: safe to re-run any number of times.
 */
require('dotenv').config();
const { getDb, close: closeMongo } = require('../config/mongo');
const { getDriver, close: closeNeo4j } = require('../config/neo4j');

const EMBEDDING_DIM = parseInt(process.env.EMBEDDING_DIM || '384', 10);

async function ensureMongoIndexes() {
  const db = await getDb();
  const created = [];

  // entities: unique on mitreId
  created.push(await db.collection('entities').createIndex({ mitreId: 1 }, { unique: true, name: 'unique_mitreId' }));
  // entities: text index on name + aliases
  created.push(await db.collection('entities').createIndex(
    { name: 'text', aliases: 'text' },
    { name: 'text_name_aliases' }
  ));

  // chunks: multikey on entityIds
  created.push(await db.collection('chunks').createIndex({ entityIds: 1 }, { name: 'multikey_entityIds' }));
  created.push(await db.collection('chunks').createIndex({ reportId: 1 }, { name: 'reportId' }));

  // chunks: Atlas-style vector index — community MongoDB cannot host it; attempt + graceful fallback
  try {
    created.push(await db.collection('chunks').createIndex(
      { embedding: 'vector' },
      {
        name: 'vector_embedding',
        vectorSearchOptions: {
          dimensions: EMBEDDING_DIM,
          similarity: 'cosine',
        },
      }
    ));
    console.log(`  [chunks] vector_embedding created (${EMBEDDING_DIM}d cosine)`);
  } catch (e) {
    console.log(`  [chunks] vector index skipped on community MongoDB (${e.message}). Service-layer cosine fallback is active.`);
  }

  // vulnerabilities
  created.push(await db.collection('vulnerabilities').createIndex({ cveId: 1 }, { unique: true, name: 'unique_cveId' }));
  created.push(await db.collection('vulnerabilities').createIndex(
    { 'cvss.baseScore': -1, publishedDate: -1 },
    { name: 'compound_cvss_published' }
  ));

  // users
  created.push(await db.collection('users').createIndex({ email: 1 }, { unique: true, name: 'unique_email' }));

  // queryLogs
  created.push(await db.collection('queryLogs').createIndex({ userId: 1, askedAt: -1 }, { name: 'compound_user_askedAt' }));

  // reports
  created.push(await db.collection('reports').createIndex({ publishedDate: 1 }, { name: 'publishedDate' }));

  return created;
}

const NEO4J_CONSTRAINTS = [
  "CREATE CONSTRAINT IF NOT EXISTS FOR (n:ThreatActor) REQUIRE n.mitreId IS UNIQUE",
  "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Campaign) REQUIRE n.mitreId IS UNIQUE",
  "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Malware) REQUIRE n.mitreId IS UNIQUE",
  "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Technique) REQUIRE n.mitreId IS UNIQUE",
  "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Tactic) REQUIRE n.mitreId IS UNIQUE",
  "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.mitreId IS UNIQUE",
  "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.cveId IS UNIQUE",
  "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Software) REQUIRE n.cpeName IS UNIQUE",
  "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Sector) REQUIRE n.sectorName IS UNIQUE",
];

async function ensureNeo4jIndexes() {
  const driver = getDriver();
  const session = driver.session();
  try {
    for (const c of NEO4J_CONSTRAINTS) {
      await session.run(c);
    }
    await session.run(
      "CREATE RANGE INDEX vulnerability_cvss IF NOT EXISTS FOR (n:Vulnerability) ON (n.cvssScore)"
    );
    await session.run(
      "CREATE FULLTEXT INDEX entity_name_ft IF NOT EXISTS FOR (n:ThreatActor|Campaign|Malware|Technique|Tactic|Mitigation) ON EACH [n.name, n.aliases]"
    );
    console.log('  [neo4j] 9 uniqueness constraints + range + fulltext indexes ensured');
  } finally {
    await session.close();
  }
}

async function main() {
  console.log('ensureIndexes — MongoDB:');
  const mIdx = await ensureMongoIndexes();
  mIdx.forEach((n) => console.log(`  created index: ${n}`));

  console.log('ensureIndexes — Neo4j:');
  await ensureNeo4jIndexes();

  // ---- verification: report what exists now ----
  const db = await getDb();
  console.log('\nVerification — Mongo indexes:');
  for (const col of ['entities', 'chunks', 'vulnerabilities', 'users', 'queryLogs', 'reports']) {
    const idx = await db.collection(col).indexes();
    console.log(`  ${col}: ${idx.map((i) => i.name).join(', ')}`);
  }

  console.log('\nVerification — Neo4j constraints/indexes:');
  const driver = getDriver();
  const s = driver.session();
  try {
    const cRes = await s.run('SHOW CONSTRAINTS YIELD name, labelsOrTypes, properties RETURN name');
    console.log(`  constraints (${cRes.records.length}): ${cRes.records.map((r) => r.get('name')).join(', ')}`);
    const iRes = await s.run('SHOW INDEXES YIELD name, type RETURN name, type');
    iRes.records.forEach((r) => console.log(`  index: ${r.get('name')} (${r.get('type')})`));
  } finally {
    await s.close();
  }

  await closeMongo();
  await closeNeo4j();
}

main().catch((e) => {
  console.error('ensureIndexes failed:', e);
  process.exit(1);
});