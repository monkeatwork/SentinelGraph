/**
 * Phase 2 — MITRE ATT&CK Enterprise STIX 2.1 ingestion → MongoDB (entities) + Neo4j (graph).
 *
 * Rules (AGENT_PLAN global rules):
 *  - Mongo FIRST, then Neo4j (no cross-DB transactions).
 *  - MERGE / upserts only → idempotent.
 *  - One join key: mitreId present + indexed in both stores.
 *  - No long text in the graph (narratives live in Mongo only).
 */
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');
const { pipeline } = require('stream/promises');

const { getDb } = require('../../config/mongo');
const { getDriver } = require('../../config/neo4j');
const { ACTOR_SECTORS } = require('../../data/actorSectors');
const { EXPLOITS_CURATED } = require('../../data/curatedRelations');

const BATCH = 400;

// STIX object type → graph label + Mongo entityType
const TYPE_TO_LABEL = {
  'intrusion-set': 'ThreatActor',
  campaign: 'Campaign',
  malware: 'Malware',
  tool: 'Malware',
  'attack-pattern': 'Technique',
  'x-mitre-tactic': 'Tactic',
  'course-of-action': 'Mitigation',
};

const CVE_RE = /CVE-\d{4}-\d{4,7}/g;

/**
 * ATT&CK current data keeps the attack id (G0016, T1059, S0154, TA0001, M1036…)
 * inside external_references with source_name 'mitre-attack'.
 */
function getMitreId(obj) {
  if (obj.external_id) return obj.external_id;
  const ref = (obj.external_references || []).find((r) => r.source_name === 'mitre-attack' && r.external_id);
  return ref ? ref.external_id : null;
}

function getAliases(obj) {
  if (obj.aliases) return obj.aliases;
  if (obj.x_mitre_aliases) return obj.x_mitre_aliases;
  return [];
}

function downloadBundle(destPath) {
  return new Promise(async (resolve, reject) => {
    const url = 'https://github.com/mitre-attack/attack-stix-data/raw/master/enterprise-attack/enterprise-attack.json';
    console.log(`  downloading STIX bundle (~200 MB) from ${url}`);
    try {
      const res = await fetch(url, {
        headers: { 'User-Agent': 'SentinelGraph' },
        redirect: 'follow',
      });
      if (!res.ok) return reject(new Error(`download failed: HTTP ${res.status}`));
      await pipeline(Readable.fromWeb(res.body), fs.createWriteStream(destPath));
      resolve();
    } catch (e) {
      reject(e);
    }
  });
}

async function loadBundle() {
  const bundlePath = process.env.STIX_BUNDLE_PATH || './data/enterprise-attack.json';
  if (!fs.existsSync(bundlePath)) {
    fs.mkdirSync(path.dirname(bundlePath), { recursive: true });
    await downloadBundle(bundlePath);
  }
  const raw = fs.readFileSync(bundlePath, 'utf8');
  console.log(`  bundle loaded: ${(raw.length / 1024 / 1024).toFixed(1)} MB`);
  return JSON.parse(raw);
}

/** Convert a STIX object into a Mongo `entities` document (or null). */
function toEntityDoc(obj) {
  const label = TYPE_TO_LABEL[obj.type];
  if (!label) return null;
  const mitreId = getMitreId(obj);
  if (!mitreId) return null;
  const externalRefs = (obj.external_references || [])
    .filter((r) => r.url || r.source_name)
    .map((r) => ({ sourceName: r.source_name || 'MITRE ATT&CK', url: r.url }));
  return {
    mitreId,
    entityType: label,
    name: obj.name || mitreId,
    aliases: getAliases(obj),
    description: obj.description || '',
    externalRefs,
    neo4jSynced: true,
    updatedAt: new Date(),
  };
}

/** Map a STIX object to its Neo4j node property row. */
function toNodeRow(obj) {
  const label = TYPE_TO_LABEL[obj.type];
  if (!label) return null;
  const mitreId = getMitreId(obj);
  if (!mitreId) return null;
  const row = { label, mitreId, name: obj.name || mitreId };
  row.aliases = getAliases(obj);
  const platforms = obj.x_mitre_platforms || [];
  switch (label) {
    case 'ThreatActor':
      row.firstSeen = obj.first_seen || null;
      row.country = obj.x_mitre_country || null;
      break;
    case 'Campaign':
      row.startDate = obj.first_seen || null;
      row.endDate = obj.last_seen || null;
      break;
    case 'Malware':
      row.type = obj.is_family ? 'family' : null;
      row.platforms = platforms;
      break;
    case 'Technique':
      row.isSubTechnique = Boolean(obj.x_mitre_is_subtechnique);
      row.platforms = platforms;
      break;
    case 'Tactic':
      row.shortName = obj.x_mitre_shortname || null;
      row.order = obj.x_mitre_order || null;
      break;
    case 'Mitigation':
      break;
    default:
      break;
  }
  return row;
}

async function ingestMongo(objects) {
  const db = await getDb();
  const ops = [];
  for (const obj of objects) {
    const doc = toEntityDoc(obj);
    if (!doc) continue;
    ops.push({
      updateOne: {
        filter: { mitreId: doc.mitreId },
        update: { $set: doc, $setOnInsert: { createdAt: new Date() } },
        upsert: true,
      },
    });
  }
  for (let i = 0; i < ops.length; i += BATCH) {
    const chunk = ops.slice(i, i + BATCH);
    const res = await db.collection('entities').bulkWrite(chunk, { ordered: false });
    console.log(`  [mongo entities] batch ${i / BATCH + 1}/${Math.ceil(ops.length / BATCH)} upserted=${res.upsertedCount} modified=${res.modifiedCount}`);
  }
  return ops.length;
}

/** Re-run-safe node upsert: MERGE keyed on mitreId, batched with UNWIND. */
async function ingestNeo4jNodes(rows, label) {
  const driver = getDriver();
  const session = driver.session();
  try {
    for (let i = 0; i < rows.length; i += BATCH) {
      const chunk = rows.slice(i, i + BATCH);
      const res = await session.run(
        `
        UNWIND $rows AS row
        MERGE (n:${label} {mitreId: row.mitreId})
        SET n += row
        RETURN count(*) AS c
        `,
        { rows: chunk }
      );
      console.log(`  [neo4j ${label}] batch ${i / BATCH + 1}/${Math.ceil(rows.length / BATCH)} (${res.records[0].get('c').toNumber()})`);
    }
  } finally {
    await session.close();
  }
}

/**
 * Derive EXPLOITS rows (malware/tool external CVE refs + curated anchors).
 * Separate so the NVD phase can re-link them once Vulnerability nodes exist.
 */
function deriveExploits(bundle) {
  const seen = new Set();
  const out = [];
  for (const obj of bundle.objects) {
    if ((obj.type !== 'malware' && obj.type !== 'tool')) continue;
    const malId = getMitreId(obj);
    if (!malId) continue;
    const cves = new Set();
    for (const ref of obj.external_references || []) {
      const hay = [ref.url, ref.description, ref.source_name].filter(Boolean).join(' ');
      for (const m of hay.matchAll(CVE_RE)) cves.add(m[0].toUpperCase());
    }
    for (const cve of cves) {
      const k = `${malId}|${cve}`;
      if (!seen.has(k)) {
        seen.add(k);
        out.push({ type: 'EXPLOITS', from: malId, to: cve });
      }
    }
  }
  for (const e of EXPLOITS_CURATED) {
    const k = `${e.malwareId}|${e.cveId}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push({ type: 'EXPLOITS', from: e.malwareId, to: e.cveId });
    }
  }
  return out;
}

/** Re-run after NVD ingestion so EXPLOITS edges land on real Vulnerability nodes. */
async function linkExploits() {
  const bundle = await loadBundle();
  const rows = deriveExploits(bundle);
  const driver = getDriver();
  const session = driver.session();
  try {
    for (let i = 0; i < rows.length; i += BATCH) {
      const chunk = rows.slice(i, i + BATCH);
      await session.run(
        `
        UNWIND $rows AS row
        MATCH (a:Malware {mitreId: row.from})
        MATCH (b:Vulnerability {cveId: row.to})
        MERGE (a)-[r:EXPLOITS]->(b)
        RETURN count(*) AS c
        `,
        { rows: chunk }
      );
    }
    const res = await session.run('MATCH ()-[r:EXPLOITS]->() RETURN count(r) AS c');
    console.log(`  [neo4j] EXPLOITS edges after NVD link: ${res.records[0].get('c').toNumber()}`);
  } finally {
    await session.close();
  }
}

/**
 * Derive relationship rows (from + to mitreIds) from STIX objects.
 */
function deriveRelationships(bundle, objectsById, rowsByLabel) {
  const out = [];
  // 1) STIX relationship objects
  for (const obj of bundle.objects) {
    if (obj.type !== 'relationship') continue;
    const src = objectsById.get(obj.source_ref);
    const dst = objectsById.get(obj.target_ref);
    if (!src || !dst) continue;
    const sl = TYPE_TO_LABEL[src.type];
    const tl = TYPE_TO_LABEL[dst.type];
    if (!sl || !tl) continue;
    const sKey = getMitreId(src);
    const tKey = getMitreId(dst);
    if (!sKey || !tKey) continue;
    const rt = obj.relationship_type;
    if (rt === 'subtechnique-of' && sl === 'Technique' && tl === 'Technique') {
      out.push({ type: 'SUBTECHNIQUE_OF', from: sKey, to: tKey });
    } else if (rt === 'attributed-to' && sl === 'Campaign' && tl === 'ThreatActor') {
      out.push({ type: 'ATTRIBUTED_TO', from: sKey, to: tKey });
    } else if (rt === 'uses' && sl === 'Campaign' && tl === 'Malware') {
      out.push({ type: 'DEPLOYS', from: sKey, to: tKey });
    } else if (rt === 'uses' && sl === 'Malware' && tl === 'Technique') {
      out.push({ type: 'USES_TECHNIQUE', from: sKey, to: tKey });
    } else if (rt === 'uses' && sl === 'ThreatActor' && tl === 'Technique') {
      out.push({ type: 'PERFORMS', from: sKey, to: tKey });
    } else if (rt === 'mitigates' && sl === 'Mitigation' && tl === 'Technique') {
      out.push({ type: 'MITIGATED_BY', from: tKey, to: sKey }); // (Technique)-[:MITIGATED_BY]->(Mitigation)
    }
    // 'uses' from intrusion-set→malware, 'detects', 'revoked-by' fall outside the 10 relationship types.
  }

  // 2) BELONGS_TO derived from kill_chain_phases → tactic short name
  const shortNameToTactic = new Map(); // x_mitre_shortname -> tactic mitreId
  for (const row of rowsByLabel.Tactic || []) {
    if (row.shortName) shortNameToTactic.set(row.shortName, row.mitreId);
  }
  for (const obj of bundle.objects) {
    if (obj.type !== 'attack-pattern') continue;
    const techId = getMitreId(obj);
    if (!techId) continue;
    for (const kcp of obj.kill_chain_phases || []) {
      const tacticId = shortNameToTactic.get(kcp.phase_name);
      if (tacticId && kcp.kill_chain_name === 'mitre-attack') {
        out.push({ type: 'BELONGS_TO', from: techId, to: tacticId });
      }
    }
  }

  // 3) EXPLOITS (may be re-linked by the NVD phase when Vulnerability nodes exist)
  out.push(...deriveExploits(bundle));

  return out;
}

async function ingestNeo4jRelationships(relRows) {
  const driver = getDriver();
  const session = driver.session();
  // Label-constrained endpoint MATCHes so the uniqueness indexes are used.
  const ENDPOINT_LABELS = {
    ATTRIBUTED_TO: ['Campaign', 'ThreatActor'],
    DEPLOYS: ['Campaign', 'Malware'],
    USES_TECHNIQUE: ['Malware', 'Technique'],
    PERFORMS: ['ThreatActor', 'Technique'],
    BELONGS_TO: ['Technique', 'Tactic'],
    MITIGATED_BY: ['Technique', 'Mitigation'],
    SUBTECHNIQUE_OF: ['Technique', 'Technique'],
    EXPLOITS: ['Malware', 'Vulnerability'],
    TARGETS: ['ThreatActor', 'Sector'],
  };
  try {
    for (let i = 0; i < relRows.length; i += BATCH) {
      const chunk = relRows.slice(i, i + BATCH);
      const byType = new Map();
      for (const r of chunk) {
        if (!byType.has(r.type)) byType.set(r.type, []);
        byType.get(r.type).push(r);
      }
      for (const [type, rows] of byType) {
        if (!rows.length) continue;
        const [la, lb] = ENDPOINT_LABELS[type] || ['', ''];
        const tpl = la && lb
          ? `MATCH (a:${la} {mitreId: row.from})\n MATCH (b:${lb} {mitreId: row.to})`
          : `MATCH (a {mitreId: row.from})\n MATCH (b {mitreId: row.to})`;
        await session.run(
          `UNWIND $rows AS row\n${tpl}\nMERGE (a)-[r:${type}]->(b)\nRETURN count(*) AS c`,
          { rows }
        );
      }
      console.log(`  [neo4j rels] batch ${i / BATCH + 1}/${Math.ceil(relRows.length / BATCH)}`);
    }
  } finally {
    await session.close();
  }
}

/** Link ThreatActor → Sector per curated map (sectors must exist: run after seedSoftware). */
async function linkTargets() {
  const driver = getDriver();
  const session = driver.session();
  try {
    for (const [mitreId, sectors] of Object.entries(ACTOR_SECTORS)) {
      await session.run(
        `
        MATCH (a:ThreatActor {mitreId: $mitreId})
        UNWIND $sectors AS s
        MATCH (sec:Sector {sectorName: s})
        MERGE (a)-[r:TARGETS]->(sec)
        SET r.incidentCount = 1
        `,
        { mitreId, sectors }
      );
    }
    const res = await session.run('MATCH ()-[r:TARGETS]->() RETURN count(r) AS c');
    console.log(`  [neo4j] TARGETS edges: ${res.records[0].get('c').toNumber()}`);
  } finally {
    await session.close();
  }
}

async function ingestAttack() {
  let bundle = await loadBundle();
  const objects = bundle.objects || [];
  console.log(`  STIX objects in bundle: ${objects.length}`);

  const objectsById = new Map();
  for (const o of objects) if (o.id) objectsById.set(o.id, o);

  // --- Mongo first ---
  console.log('\n[MongoDB entities]');
  const nDocs = await ingestMongo(objects);
  console.log(`  total entity documents upserted: ${nDocs}`);

  // --- Neo4j nodes ---
  console.log('\n[Neo4j nodes]');
  const rowsByLabel = { ThreatActor: [], Campaign: [], Malware: [], Technique: [], Tactic: [], Mitigation: [] };
  let totalRows = 0;
  for (const obj of objects) {
    const row = toNodeRow(obj);
    if (!row) continue;
    rowsByLabel[row.label].push(row);
    totalRows++;
  }
  const labelsOrder = Object.keys(rowsByLabel);
  for (const label of labelsOrder) {
    const rows = rowsByLabel[label];
    if (!rows.length) continue;
    console.log(`  ${label}: ${rows.length} rows`);
    await ingestNeo4jNodes(rows, label);
  }
  console.log(`  total node rows: ${totalRows}`);

  // --- Relationships ---
  console.log('\n[Neo4j relationships]');
  const relRows = deriveRelationships(bundle, objectsById, rowsByLabel);
  console.log(`  derived relationship rows: ${relRows.length}`);
  for (const [type, n] of [...new Set(relRows.map((r) => r.type))].map((t) => [t, relRows.filter((r) => r.type === t).length])) {
    console.log(`    ${type}: ${n}`);
  }

  // Release the raw STIX object graph — it is the single biggest heap consumer.
  bundle.objects = null;
  bundle = null;
  objectsById.clear();
  rowsByLabel.Tactic.length = 0;
  await ingestNeo4jRelationships(relRows);
  await linkTargets();

  // --- Counts summary ---
  const session = getDriver().session();
  try {
    const nodes = await session.run('MATCH (n) RETURN labels(n)[0] AS l, count(*) AS c ORDER BY l');
    console.log('\nNode counts by label:');
    for (const r of nodes.records) console.log(`  ${r.get('l')}: ${r.get('c').toNumber()}`);
    const rels = await session.run('MATCH ()-[r]->() RETURN type(r) AS t, count(*) AS c ORDER BY t');
    console.log('\nRelationship counts by type:');
    for (const r of rels.records) console.log(`  ${r.get('t')}: ${r.get('c').toNumber()}`);
  } finally {
    await session.close();
  }
  return { nodeRows: totalRows, relRows: relRows.length };
}

module.exports = { ingestAttack, linkTargets, linkExploits, deriveExploits };

if (require.main === module) {
  (async () => {
    await ingestAttack();
    process.exit(0);
  })().catch((e) => {
    console.error('ingestAttack failed:', e);
    process.exit(1);
  });
}