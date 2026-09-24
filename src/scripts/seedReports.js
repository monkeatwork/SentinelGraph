/**
 * Phase 5 — seed reports, then chunk + embed them.
 *
 * 1. Curated advisories/writeups (src/data/curatedReports.js)
 * 2. Auto-generated entity "profile" reports from the STIX entities (verified content,
 *    MITRE-attribution, 1-hop neighbour mentions → strong entityIds overlap for retrieval)
 * 3. NVD "advisory" reports from the highest-severity vulnerability records (KEV-first)
 *
 * Idempotent: upserts keyed on (title, source); re-running only re-chunks.
 */
const { getDb } = require('../config/mongo');
const { getDriver } = require('../config/neo4j');
const { processReport } = require('../services/reportIngest');
const { CURATED_REPORTS } = require('../data/curatedReports');

const BATCH = 100;

async function upsertReport(db, { title, source, url, publishedDate, rawText, entityMentions }) {
  const existing = await db.collection('reports').findOne({ title, source });
  if (existing) return { _id: existing._id, isNew: false };
  const { insertedId } = await db.collection('reports').insertOne({
    title,
    source,
    url: url || null,
    publishedDate: publishedDate ? new Date(publishedDate) : new Date(),
    rawText,
    entityMentions: entityMentions || [],
    ingestStatus: 'pending',
    chunkCount: 0,
    createdAt: new Date(),
  });
  return { _id: insertedId, isNew: true };
}

async function neighborMentions(driver, rows) {
  const session = driver.session();
  const map = new Map();
  try {
    for (let i = 0; i < rows.length; i += BATCH) {
      const chunk = rows.slice(i, i + BATCH);
      const r = await session.run(
        `
        UNWIND $rows AS row
        MATCH (n {mitreId: row.mitreId})
        OPTIONAL MATCH (n)-[*1..1]-(m)
        WITH row.mitreId AS src, collect(DISTINCT coalesce(m.mitreId, m.cveId, m.cpeName, m.sectorName)) AS nb
        RETURN src, [x IN nb WHERE x IS NOT NULL AND x <> src] AS neighbors
        `,
        { rows: chunk }
      );
      for (const rec of r.records) {
        map.set(rec.get('src'), (rec.get('neighbors') || []).slice(0, 12));
      }
    }
  } finally {
    await session.close();
  }
  return map;
}

async function seedReports() {
  const db = await getDb();
  const driver = getDriver();
  let created = 0;
  let processed = 0;

  // ---- 1) curated reports -------------------------------------------------
  console.log('[1/3] curated advisories…');
  for (const rep of CURATED_REPORTS) {
    const { _id, isNew } = await upsertReport(db, rep);
    if (isNew) created++;
    const n = await processReport(_id);
    processed += n;
  }
  console.log(`  curated: ${CURATED_REPORTS.length} reports, ${processed} chunks`);

  // ---- 2) entity profile reports ------------------------------------------
  console.log('[2/3] entity profile reports…');
  const entities = await db.collection('entities').find({}).toArray();
  console.log(`  entities in Mongo: ${entities.length}`);
  const neighbors = await neighborMentions(driver, entities.map((e) => ({ mitreId: e.mitreId })));
  let profileChunks = 0;
  let profileCreated = 0;
  for (const e of entities) {
    const nb = neighbors.get(e.mitreId) || [];
    const linked = await db.collection('entities')
      .find({ mitreId: { $in: nb.slice(0, 8) } })
      .project({ name: 1, entityType: 1, _id: 0 })
      .toArray();
    const nameList = linked.map((l) => `${l.name || l.mitreId} (${l.entityType})`).join(', ') || 'none in this snapshot';
    const rawText = [
      `${e.name} (${e.mitreId}) is a ${e.entityType} tracked in the MITRE ATT&CK knowledge base.`,
      e.description ? e.description : '',
      `Within the SentinelGraph dataset this entity is directly connected to: ${nameList}.`,
      `External references: ${(e.externalRefs || []).slice(0, 5).map((r) => r.sourceName).join(', ') || 'MITRE ATT&CK'}.`,
    ].filter(Boolean).join(' ');
    const { _id, isNew } = await upsertReport(db, {
      title: `${e.entityType} Profile: ${e.name}`,
      source: 'MITRE ATT&CK (auto-profile)',
      url: `https://attack.mitre.org/`,
      publishedDate: '2024-01-01',
      rawText,
      entityMentions: [e.mitreId, ...nb], // both keys exist in the graph/mongo
    });
    if (isNew) profileCreated++;
    const n = await processReport(_id);
    profileChunks += n;
  }
  console.log(`  profiles: ${profileCreated} new of ${entities.length}, ${profileChunks} chunks`);

  // ---- 3) NVD advisory reports (KEV first, then critical) ------------------
  console.log('[3/3] NVD advisory reports…');
  const vulns = await db.collection('vulnerabilities')
    .find({})
    .sort({ knownExploited: -1, 'cvss.baseScore': -1 })
    .limit(2000)
    .toArray();
  let vulnChunks = 0;
  let vulnCreated = 0;
  for (const v of vulns) {
    const products = (v.affectedProducts || []).slice(0, 5)
      .map((p) => `${p.vendor || '?'}/${p.product || '?'} ${p.versionRange || ''}`)
      .join(', ');
    const rawText = [
      `National Vulnerability Database entry for ${v.cveId}.`,
      v.description || '(description not available)',
      v.knownExploited
        ? `This vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog, indicating confirmed exploitation in the wild; organisations should treat it as an active threat.`
        : `This vulnerability is not currently listed in the CISA Known Exploited Vulnerabilities catalog.`,
      `CVSS base score ${v.cvss && v.cvss.baseScore != null ? v.cvss.baseScore : 'n/a'} (${v.cvss && v.cvss.severity || 'UNKNOWN'}). Published ${v.publishedDate ? new Date(v.publishedDate).toISOString().slice(0, 10) : 'n/a'}.`,
      products ? `Affected products in this dataset: ${products}.` : '',
    ].filter(Boolean).join(' ');
    const { _id, isNew } = await upsertReport(db, {
      title: `NVD Advisory: ${v.cveId}`,
      source: 'NVD',
      url: `https://nvd.nist.gov/vuln/detail/${v.cveId}`,
      publishedDate: v.publishedDate || '2024-01-01',
      rawText,
      entityMentions: [v.cveId],
    });
    if (isNew) vulnCreated++;
    const n = await processReport(_id);
    vulnChunks += n;
  }
  console.log(`  nvd: ${vulnCreated} new of ${vulns.length}, ${vulnChunks} chunks`);

  // ---- totals ---------------------------------------------------------------
  const totals = {
    reports: await db.collection('reports').countDocuments({}),
    chunks: await db.collection('chunks').countDocuments({}),
    embedded: await db.collection('reports').countDocuments({ ingestStatus: 'embedded' }),
  };
  console.log('\n=== seedReports totals ===');
  console.log(JSON.stringify(totals, null, 2));
  return totals;
}

module.exports = { seedReports };

if (require.main === module) {
  seedReports()
    .then(() => process.exit(0))
    .catch((e) => {
      console.error('seedReports failed:', e);
      process.exit(1);
    });
}