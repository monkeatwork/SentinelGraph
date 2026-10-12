/**
 * Phase 5a — entity resolver (FR5): extract the entities mentioned in a question.
 *
 * Strategy order:
 *  1. CVE regex — "Log4j"/"Log4Shell" questions carry CVE-2021-44228 explicitly.
 *  1b. Whole-word ATT&CK name/alias match ("APT29", "Cobalt Strike") — Review 3.
 *  2. Software product/vendor name containment (for "Log4j", "Exchange", …);
 *     then pull the CVEs AFFECTing each resolved product (1 hop) into the set.
 *  3. Neo4j full-text over entity names/aliases — restricted to names that share
 *     a content token with the question (keeps "Exploit Protection" out of a
 *     question about Log4j).
 *  4. Mongo $text tie-breaker.
 */
const { getDriver } = require('../config/neo4j');
const { getDb } = require('../config/mongo');

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

const STOP = new Set([
  'which', 'what', 'how', 'when', 'where', 'why', 'who', 'does', 'do', 'are', 'is', 'the', 'a', 'an',
  'and', 'or', 'of', 'with', 'by', 'for', 'against', 'that', 'this', 'these', 'those', 'from', 'into',
  'adversary', 'adversaries', 'group', 'groups', 'actor', 'actors', 'attack', 'attacks', 'attackers',
  'exploit', 'exploits', 'exploitation', 'exploited', 'use', 'uses', 'used', 'using', 'via',
  'my', 'organisation', 'organization', 'runs', 'run', 'positioned', 'reach', 'me', 'they', 'them',
  'can', 'could', 'should', 'would', 'will', 'may', 'might', 'has', 'have', 'had', 'was', 'were', 'been',
  'our', 'your', 'their', 'its', 'there', 'about', 'any', 'all', 'most', 'more', 'also', 'not',
  // domain words that name the question's intent, not a product
  'threat', 'threats', 'detect', 'detection', 'look', 'looks', 'like', 'abuse', 'technique', 'techniques',
  'mitigate', 'mitigated', 'mitigation', 'mitigations', 'malware', 'campaign', 'campaigns', 'vulnerability',
  'vulnerabilities', 'software', 'tool', 'tools', 'target', 'targets', 'targeted', 'sector', 'sectors',
]);

// Labels whose names are distinctive enough to match in free text, most specific first.
const NAME_LABELS = ['ThreatActor', 'Campaign', 'Malware', 'Technique'];
const MIN_NAME_LEN = 4; // skips tool names like "at" / "net" that collide with English words
const NAME_CACHE_MS = 5 * 60 * 1000;
let nameCache = null;

/** In-memory (name|alias → entity) list from Mongo `entities`, refreshed every few minutes. */
async function entityNames() {
  if (nameCache && Date.now() - nameCache.at < NAME_CACHE_MS) return nameCache.rows;
  const db = await getDb();
  const docs = await db
    .collection('entities')
    .find({ entityType: { $in: NAME_LABELS } }, { projection: { _id: 0, mitreId: 1, entityType: 1, name: 1, aliases: 1 } })
    .toArray();
  const rows = [];
  for (const d of docs) {
    for (const n of new Set([d.name, ...(d.aliases || [])])) {
      if (typeof n === 'string' && n.length >= MIN_NAME_LEN) rows.push({ phrase: n.toLowerCase(), id: d.mitreId, label: d.entityType, name: d.name });
    }
  }
  rows.sort((a, b) => NAME_LABELS.indexOf(a.label) - NAME_LABELS.indexOf(b.label) || b.phrase.length - a.phrase.length);
  nameCache = { at: Date.now(), rows };
  return rows;
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function contentWords(question) {
  return question.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 3 && !STOP.has(w));
}

async function resolveEntities(question) {
  const resolved = {
    cves: [],
    mitreIds: [],
    cpeNames: [],
    names: [],
  };
  const seen = new Set();
  const words = contentWords(question);

  // 1) explicit CVEs
  for (const m of question.matchAll(CVE_RE)) {
    const cve = m[0].toUpperCase();
    if (!seen.has(cve)) {
      seen.add(cve);
      resolved.cves.push(cve);
    }
  }

  // 1b) whole-word ATT&CK names/aliases in the question
  const lowerQ = question.toLowerCase();
  const namedWords = new Set();
  for (const row of await entityNames()) {
    if (resolved.mitreIds.length >= 4) break;
    if (seen.has(row.id)) continue;
    if (!new RegExp(`(^|[^a-z0-9])${escapeRe(row.phrase)}($|[^a-z0-9])`).test(lowerQ)) continue;
    seen.add(row.id);
    resolved.mitreIds.push(row.id);
    resolved.names.push({ id: row.id, label: row.label, name: row.name });
    for (const w of row.phrase.split(/[^a-z0-9]+/)) namedWords.add(w);
  }

  const driver = getDriver();
  const session = driver.session();
  try {
    // 2) Software product containment (e.g. "Log4j") — most specific terms first;
    //    words already explained by a named entity are not re-used as product terms
    const terms = [...new Set(words)]
      .filter((w) => w.length >= 4 && !/^\d+$/.test(w) && !namedWords.has(w))
      .sort((a, b) => b.length - a.length)
      .slice(0, 5);
    // with several terms, rank all candidates together so products matching more terms win
    // ("microsoft exchange" → microsoft/exchange_server, not a third-party Exchange add-on)
    const termHits = (r) => {
      const text = `${r.get('vendor') || ''} ${r.get('product') || ''}`.toLowerCase();
      return terms.filter((t) => text.includes(t)).length;
    };
    const startsWithTerm = (r) => terms.some((t) => (r.get('product') || '').toLowerCase().startsWith(t));
    let candidates = [];
    for (const term of terms) {
      const sw = await session.run(
        `MATCH (s:Software)
         WHERE toLower(s.product) CONTAINS $term OR toLower(s.vendor) CONTAINS $term
         RETURN s.cpeName AS cpe, s.vendor AS vendor, s.product AS product
         ORDER BY ${terms.length > 1 ? 'toLower(s.product) STARTS WITH $term DESC, ' : ''}toLower(s.product) CONTAINS $term DESC
         LIMIT ${terms.length > 1 ? 50 : 3}`,
        { term }
      );
      candidates.push(...sw.records);
    }
    if (terms.length > 1) {
      const byCpe = new Map();
      candidates.forEach((r, i) => { if (!byCpe.has(r.get('cpe'))) byCpe.set(r.get('cpe'), { r, i }); });
      candidates = [...byCpe.values()]
        .map((x) => ({ ...x, hits: termHits(x.r), starts: startsWithTerm(x.r) }))
        .sort((a, b) => b.hits - a.hits || b.starts - a.starts || a.i - b.i)
        .slice(0, 3)
        .map((x) => x.r);
    }
    const resolvedCpes = new Set();
    for (const r of candidates) {
      const cpe = r.get('cpe');
      if (!cpe || seen.has(cpe)) continue;
      seen.add(cpe);
      resolvedCpes.add(cpe);
      resolved.cpeNames.push(cpe);
      resolved.names.push({ id: cpe, label: 'Software', name: `${r.get('vendor') || '?'}/${r.get('product')}` });
    }

    // 2b) CVEs affecting the resolved software (1 hop: (v)-[:AFFECTS]->(s))
    for (const cpe of resolvedCpes) {
      const v = await session.run(
        `MATCH (v:Vulnerability)-[:AFFECTS]->(:Software {cpeName: $cpe})
         RETURN v.cveId AS cveId ORDER BY v.cvssScore DESC LIMIT 5`,
        { cpe }
      );
      for (const rec of v.records) {
        const cve = rec.get('cveId');
        if (!cve || seen.has(cve)) continue;
        seen.add(cve);
        resolved.cves.push(cve);
        resolved.names.push({ id: cve, label: 'Vulnerability', name: cve });
      }
    }

    // 3) full-text entity names/aliases — must share a content token with the question
    if (resolved.cves.length + resolved.cpeNames.length < 3) {
      const ft = await session.run(
        `CALL db.index.fulltext.queryNodes('entity_name_ft', $q) YIELD node, score
         RETURN node.mitreId AS id, labels(node)[0] AS label, node.name AS name, score
         ORDER BY score DESC LIMIT 12`,
        { q: question }
      );
      const lowerWords = new Set(words);
      for (const r of ft.records) {
        const id = r.get('id');
        if (!id || seen.has(id)) continue;
        const name = r.get('name') || '';
        const nameWords = name.toLowerCase().split(/[^a-z0-9]+/);
        if (!nameWords.some((w) => lowerWords.has(w))) continue; // token overlap required
        seen.add(id);
        resolved.mitreIds.push(id);
        resolved.names.push({ id, label: r.get('label'), name: r.get('name'), score: r.get('score') });
        if (resolved.mitreIds.length >= 3) break;
      }
    }
  } finally {
    await session.close();
  }

  // 4) Mongo $text tie-breaker
  if (!resolved.mitreIds.length && !resolved.cves.length && !resolved.cpeNames.length) {
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