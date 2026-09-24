/**
 * Phase 5a — entity resolver (FR5): extract the entities mentioned in a question.
 *
 * Strategies, in order:
 *  1. CVE regex — "Log4j"/"Log4Shell" questions carry CVE-2021-44228 explicitly.
 *  2. Neo4j full-text index over entity names + aliases (ThreatActor|Campaign|Malware|Technique|Tactic|Mitigation).
 *  3. Neo4j Software product/vendor name containment (for "Log4j", "Exchange", …).
 *  4. Mongo $text over entities as a tie-breaker for names.
 */
const { getDriver } = require('../config/neo4j');
const { getDb } = require('../config/mongo');

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

async function resolveEntities(question) {
  const resolved = {
    cves: [],
    mitreIds: [],
    cpeNames: [],
    names: [],
  };
  const seen = new Set();

  // 1) explicit CVEs
  for (const m of question.matchAll(CVE_RE)) {
    const cve = m[0].toUpperCase();
    if (!seen.has(cve)) {
      seen.add(cve);
      resolved.cves.push(cve);
    }
  }

  const driver = getDriver();
  const session = driver.session();
  try {
    // 2) full-text entity names/aliases
    const ft = await session.run(
      `CALL db.index.fulltext.queryNodes('entity_name_ft', $q) YIELD node, score
       RETURN node.mitreId AS id, labels(node)[0] AS label, node.name AS name, score
       ORDER BY score DESC LIMIT 6`,
      { q: question }
    );
    for (const r of ft.records) {
      const id = r.get('id');
      if (!id || seen.has(id)) continue;
      seen.add(id);
      resolved.mitreIds.push(id);
      resolved.names.push({ id, label: r.get('label'), name: r.get('name'), score: r.get('score') });
    }

    // 3) Software product containment (e.g. "Log4j")
    const terms = question.toLowerCase().match(/[a-z0-9][a-z0-9 _.-]{2,}/g) || [];
    for (const term of terms.slice(0, 4)) {
      const sw = await session.run(
        `MATCH (s:Software)
         WHERE toLower(s.product) CONTAINS $term OR toLower(s.vendor) CONTAINS $term
         RETURN s.cpeName AS cpe, s.vendor AS vendor, s.product AS product
         LIMIT 4`,
        { term }
      );
      for (const r of sw.records) {
        const cpe = r.get('cpe');
        if (!cpe || seen.has(cpe)) continue;
        seen.add(cpe);
        resolved.cpeNames.push(cpe);
        resolved.names.push({ id: cpe, label: 'Software', name: `${r.get('vendor') || '?'}/${r.get('product')}` });
      }
    }
  } finally {
    await session.close();
  }

  // 4) Mongo $text tie-breaker
  if (!resolved.mitreIds.length && !resolved.cves.length) {
    const db = await getDb();
    try {
      const docs = await db
        .collection('entities')
        .find({ $text: { $search: question } })
        .limit(3)
        .toArray();
      for (const d of docs) {
        if (seen.has(d.mitreId)) continue;
        seen.add(d.mitreId);
        resolved.mitreIds.push(d.mitreId);
        resolved.names.push({ id: d.mitreId, label: d.entityType, name: d.name });
      }
    } catch (e) {
      /* text index not ready yet */
    }
  }

  return resolved;
}

module.exports = { resolveEntities };