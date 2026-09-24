/**
 * Phase 3 — CISA Known Exploited Vulnerabilities catalog.
 * Sets knownExploited=true on matching cveIds in Mongo + Neo4j. Idempotent.
 */
const { getDb } = require('../../config/mongo');
const { getDriver } = require('../../config/neo4j');

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

async function ingestCisaKev() {
  const res = await fetch(KEV_URL, { headers: { 'User-Agent': 'SentinelGraph/0.1' } });
  if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
  const json = await res.json();
  const ids = (json.vulnerabilities || []).map((v) => v.cveID);
  console.log(`  KEV catalog: ${ids.length} exploited CVEs`);

  const db = await getDb();
  const upserted = await db.collection('vulnerabilities').updateMany(
    { cveId: { $in: ids } },
    { $set: { knownExploited: true } }
  );
  console.log(`  [mongo] marked knownExploited: matched=${upserted.matchedCount} modified=${upserted.modifiedCount}`);

  const driver = getDriver();
  const session = driver.session();
  try {
    for (let i = 0; i < ids.length; i += 500) {
      const chunk = ids.slice(i, i + 500);
      const r = await session.run(
        `
        UNWIND $ids AS id
        MATCH (v:Vulnerability {cveId: id})
        SET v.knownExploited = true
        RETURN count(*) AS c
        `,
        { ids: chunk }
      );
      console.log(`  [neo4j] flagged batch ${i / 500 + 1}: ${r.records[0].get('c').toNumber()}`);
    }
  } finally {
    await session.close();
  }
}

module.exports = { ingestCisaKev };

if (require.main === module) {
  ingestCisaKev()
    .then(() => process.exit(0))
    .catch((e) => {
      console.error('ingestCisaKev failed:', e);
      process.exit(1);
    });
}