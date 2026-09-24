/**
 * Phase 3 — NVD CVE ingestion → MongoDB (vulnerabilities) + Neo4j (Vulnerability nodes,
 * Software nodes from CPE match data, AFFECTS edges). Idempotent (MERGE/upserts).
 */
const fs = require('fs');
const path = require('path');

const { getDb } = require('../../config/mongo');
const { getDriver } = require('../../config/neo4j');
const { AFFECTS_CURATED } = require('../../data/curatedRelations');

const BATCH = 400;
const CACHE_PATH = path.join(__dirname, '../../../data/nvd-cves.json');

function parseCpe(criteria) {
  const parts = criteria.split(':');
  // cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw...
  return {
    cpeName: criteria,
    vendor: parts[3] || null,
    product: parts[4] || null,
    version: parts[5] || '*',
  };
}

function mapCve(cve) {
  const id = cve.id;
  const desc = (cve.descriptions || []).find((d) => d.lang === 'en') || {};
  const m31 = (cve.cvssMetricV31 || [])[0];
  const m30 = (cve.cvssMetricV30 || [])[0];
  const metric = m31 || m30;
  const affected = new Map(); // cpeName -> {cpeName, vendor, product, versionStart, versionEnd}
  for (const cfg of cve.configurations || []) {
    for (const node of cfg.nodes || []) {
      for (const m of node.cpeMatch || []) {
        if (!m.vulnerable) continue;
        const c = parseCpe(m.criteria);
        if (!affected.has(m.criteria)) {
          const vStart = m.versionStartIncluding || m.versionStartExcluding;
          const vEnd = m.versionEndIncluding || m.versionEndExcluding;
          affected.set(m.criteria, {
            cpeName: m.criteria,
            vendor: c.vendor,
            product: c.product,
            version: c.version,
            versionStart: vStart || null,
            versionEnd: vEnd || null,
            versionRange: vStart || vEnd ? `${vStart || '*'}-${vEnd || '*'}` : c.version || '*',
          });
        }
      }
    }
  }
  return {
    cveId: id,
    description: desc.value || '',
    cvss: {
      baseScore: metric ? metric.cvssData.baseScore : null,
      severity: metric ? (metric.cvssData.baseSeverity || 'UNKNOWN') : 'UNKNOWN',
      vector: metric ? metric.cvssData.vectorString : null,
    },
    publishedDate: cve.published ? new Date(cve.published) : null,
    lastModified: cve.lastModified ? new Date(cve.lastModified) : null,
    affectedProducts: [...affected.values()],
    knownExploited: false,
    source: 'NVD',
  };
}

async function fetchNvd() {
  if (fs.existsSync(CACHE_PATH)) {
    console.log(`  using cached NVD payload from ${CACHE_PATH}`);
    return JSON.parse(fs.readFileSync(CACHE_PATH, 'utf8'));
  }
  const severities = ['CRITICAL', 'HIGH'];
  const all = [];
  let delay = 0;
  for (const sev of severities) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=${sev}&resultsPerPage=2000`;
    console.log(`  fetching NVD ${sev}…`);
    const res = await fetch(url, { headers: { 'User-Agent': 'SentinelGraph/0.1 (db-project)' } });
    if (!res.ok) throw new Error(`NVD HTTP ${res.status} for ${sev}`);
    const json = await res.json();
    const vulns = json.vulnerabilities || [];
    console.log(`  NVD ${sev}: ${vulns.length} records (totalResults=${json.totalResults})`);
    all.push(...vulns.map((v) => v.cve));
    delay += 6000; // stay comfortably inside the anonymous rate limit
    if (delay) await new Promise((r) => setTimeout(r, 6000));
  }
  fs.mkdirSync(path.dirname(CACHE_PATH), { recursive: true });
  fs.writeFileSync(CACHE_PATH, JSON.stringify(all));
  return all;
}

async function ingestNvd() {
  const cves = await fetchNvd();
  const db = await getDb();
  const docs = cves.map(mapCve);
  console.log(`  mapped ${docs.length} vulnerability docs`);

  // --- Mongo first ---
  const ops = docs.map((d) => ({
    updateOne: {
      filter: { cveId: d.cveId },
      update: { $set: d, $setOnInsert: { createdAt: new Date() } },
      upsert: true,
    },
  }));
  for (let i = 0; i < ops.length; i += BATCH) {
    const res = await db.collection('vulnerabilities').bulkWrite(ops.slice(i, i + BATCH), { ordered: false });
    console.log(`  [mongo vulnerabilities] batch ${i / BATCH + 1} upserted=${res.upsertedCount} modified=${res.modifiedCount}`);
  }

  // --- Neo4j: Vulnerability nodes ---
  const driver = getDriver();
  const session = driver.session();
  try {
    const vRows = docs.map((d) => ({
      cveId: d.cveId,
      cvssScore: d.cvss.baseScore,
      severity: d.cvss.severity,
      publishedDate: d.publishedDate ? d.publishedDate.toISOString() : null,
      knownExploited: d.knownExploited,
    }));
    for (let i = 0; i < vRows.length; i += BATCH) {
      const chunk = vRows.slice(i, i + BATCH);
      await session.run(
        `
        UNWIND $rows AS row
        MERGE (v:Vulnerability {cveId: row.cveId})
        SET v.cvssScore = row.cvssScore, v.severity = row.severity,
            v.publishedDate = row.publishedDate, v.knownExploited = row.knownExploited
        RETURN count(*) AS c
        `,
        { rows: chunk }
      );
      console.log(`  [neo4j Vulnerability] batch ${i / BATCH + 1}/${Math.ceil(vRows.length / BATCH)}`);
    }

    // --- Neo4j: Software nodes + AFFECTS edges from CPE match data ---
    const swRows = new Map(); // cpeName -> row
    const affRows = []; // {from: cveId, to: cpeName, versionRange}
    for (const d of docs) {
      for (const p of d.affectedProducts) {
        if (!swRows.has(p.cpeName)) {
          swRows.set(p.cpeName, { cpeName: p.cpeName, vendor: p.vendor, product: p.product, version: p.version });
        }
        affRows.push({ from: d.cveId, to: p.cpeName, versionRange: p.versionRange });
      }
    }
    // curated flagship AFFECTS edge (Log4j)
    for (const a of AFFECTS_CURATED) {
      swRows.set(a.cpeName, parseCpe(a.cpeName));
      affRows.push({ from: a.cveId, to: a.cpeName, versionRange: a.versionRange });
    }
    const swArray = [...swRows.values()];
    console.log(`  software nodes from CPE data: ${swArray.length}; AFFECTS edges: ${affRows.length}`);

    for (let i = 0; i < swArray.length; i += BATCH) {
      const chunk = swArray.slice(i, i + BATCH);
      await session.run(
        `
        UNWIND $rows AS row
        MERGE (s:Software {cpeName: row.cpeName})
        SET s.vendor = row.vendor, s.product = row.product, s.version = row.version
        RETURN count(*) AS c
        `,
        { rows: chunk }
      );
    }
    for (let i = 0; i < affRows.length; i += BATCH) {
      const chunk = affRows.slice(i, i + BATCH);
      await session.run(
        `
        UNWIND $rows AS row
        MATCH (v:Vulnerability {cveId: row.from})
        MATCH (s:Software {cpeName: row.to})
        MERGE (v)-[r:AFFECTS]->(s)
        SET r.versionRange = row.versionRange
        RETURN count(*) AS c
        `,
        { rows: chunk }
      );
      console.log(`  [neo4j AFFECTS] batch ${i / BATCH + 1}/${Math.ceil(affRows.length / BATCH)}`);
    }

    // --- Neo4j: EXPLOITS edges (malware → vulnerability) now that vuln nodes exist ---
    const { linkExploits } = require('./attack-stix');
    await linkExploits();
  } finally {
    await session.close();
  }

  // --- Counts ---
  const s2 = getDriver().session();
  try {
    const v = await db.collection('vulnerabilities').countDocuments({});
    const n = await s2.run('MATCH (n:Vulnerability) RETURN count(n) AS c');
    const sw = await s2.run('MATCH (n:Software) RETURN count(n) AS c');
    const af = await s2.run('MATCH ()-[r:AFFECTS]->() RETURN count(r) AS c');
    console.log(`\n  Mongo vulnerabilities: ${v}`);
    console.log(`  Neo4j Vulnerability nodes: ${n.records[0].get('c').toNumber()}`);
    console.log(`  Neo4j Software nodes: ${sw.records[0].get('c').toNumber()}`);
    console.log(`  Neo4j AFFECTS edges: ${af.records[0].get('c').toNumber()}`);
  } finally {
    await s2.close();
  }
}

module.exports = { ingestNvd, mapCve };

if (require.main === module) {
  ingestNvd()
    .then(() => process.exit(0))
    .catch((e) => {
      console.error('ingestNvd failed:', e);
      process.exit(1);
    });
}