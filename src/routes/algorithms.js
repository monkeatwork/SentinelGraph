/**
 * Phase 5b — graph algorithms (FR9, FR10).
 *   shortest-path  : Software → … → ThreatActor
 *   criticality    : technique importance by degree (malware usage + actor usage)
 *   similarity     : Jaccard over shared techniques (no GDS plugin needed)
 *   mitigations    : Review 3 — mitigations ranked by technique coverage (defence recommendation)
 */
const express = require('express');

const { getDriver } = require('../config/neo4j');
const { requireAuth } = require('../middleware/auth');
const { httpError } = require('../services/graphMeta');

const router = express.Router();

async function findSoftwareNode(session, from) {
  const r = await session.run(
    `
    MATCH (s:Software)
    WHERE s.cpeName = $from OR toLower(s.product) = toLower($from) OR toLower(s.vendor) = toLower($from)
    RETURN s.cpeName AS cpe, s.vendor AS vendor, s.product AS product
    ORDER BY size(s.cpeName) ASC LIMIT 1`,
    { from }
  );
  return r.records[0] ? { cpe: r.records[0].get('cpe'), vendor: r.records[0].get('vendor'), product: r.records[0].get('product') } : null;
}

async function findActorNode(session, to) {
  const r = await session.run(
    `
    MATCH (a:ThreatActor)
    WHERE a.mitreId = $to OR toLower(a.name) = toLower($to)
    RETURN a.mitreId AS id, a.name AS name LIMIT 1`,
    { to }
  );
  return r.records[0] ? { id: r.records[0].get('id'), name: r.records[0].get('name') } : null;
}

function pathRows(records) {
  const rec = records[0];
  if (!rec) return null;
  const path = rec.get('path');
  return (path || []).map((n) => ({
    label: (n.labels && n.labels[0]) || null,
    key: n.properties.mitreId || n.properties.cveId || n.properties.cpeName || n.properties.sectorName,
    name: n.properties.name || n.properties.product || n.properties.sectorName || n.properties.mitreId || n.properties.cveId || null,
  }));
}

/** Relationship type + direction per hop: forward means path[i] -[type]-> path[i+1]. */
function pathRels(records) {
  const rec = records[0];
  if (!rec) return null;
  const ids = rec.get('ids');
  return rec.get('rels').map((r, i) => ({ type: r.type, forward: r.start === ids[i] }));
}

/** GET /api/algorithms/shortest-path?from=apache/log4j&to=APT29 */
router.get('/shortest-path', requireAuth, async (req, res, next) => {
  let session;
  try {
    const { from, to } = req.query;
    if (!from || !to) throw httpError(400, 'BAD_REQUEST', 'from (software) and to (actor) are required');
    const driver = getDriver();
    session = driver.session();

    const sw = await findSoftwareNode(session, from);
    const actor = await findActorNode(session, to);
    if (!sw) throw httpError(404, 'NOT_FOUND', `No Software node matches '${from}'`);
    if (!actor) throw httpError(404, 'NOT_FOUND', `No ThreatActor matches '${to}'`);

    const CHAIN_TYPES = 'AFFECTS|EXPLOITS|USES_TECHNIQUE|DEPLOYS|ATTRIBUTED_TO|PERFORMS|TARGETS|BELONGS_TO|SUBTECHNIQUE_OF|MITIGATED_BY';

    const t0 = Date.now();
    let result = await session.run(
      `
      MATCH p = shortestPath((s:Software {cpeName: $cpe})-[:${CHAIN_TYPES}*]-(a:ThreatActor {mitreId: $id}))
      RETURN [n IN nodes(p) | n] AS path, [n IN nodes(p) | elementId(n)] AS ids,
             [r IN relationships(p) | {type: type(r), start: elementId(startNode(r))}] AS rels LIMIT 1`,
      { cpe: sw.cpe, id: actor.id }
    );
    // fallback: any relationship types (unconstrained chain)
    if (!result.records.length) {
      result = await session.run(
        `
        MATCH p = shortestPath((s:Software {cpeName: $cpe})-[*]-(a:ThreatActor {mitreId: $id}))
        RETURN [n IN nodes(p) | n] AS path, [n IN nodes(p) | elementId(n)] AS ids,
               [r IN relationships(p) | {type: type(r), start: elementId(startNode(r))}] AS rels LIMIT 1`,
        { cpe: sw.cpe, id: actor.id }
      );
    }
    const latencyMs = Date.now() - t0;
    const path = pathRows(result.records);

    res.json({
      from: sw,
      to: actor,
      found: Boolean(path),
      hops: path ? path.length - 1 : null,
      path,
      rels: pathRels(result.records),
      constrained: true,
      latencyMs,
    });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** GET /api/algorithms/technique-criticality — degree-based importance ranking */
router.get('/technique-criticality', requireAuth, async (req, res, next) => {
  let session;
  try {
    const driver = getDriver();
    session = driver.session();
    const t0 = Date.now();
    const r = await session.run(
      `
      MATCH (t:Technique)<-[:USES_TECHNIQUE]-(m:Malware)
      WITH t, count(DISTINCT m) AS malwareCount
      OPTIONAL MATCH (t)<-[:PERFORMS]-(a:ThreatActor)
      WITH t, malwareCount, count(DISTINCT a) AS actorCount
      RETURN t.mitreId AS mitreId, t.name AS name, malwareCount, actorCount,
             (malwareCount + actorCount) AS criticality
      ORDER BY criticality DESC LIMIT 20`
    );
    res.json({
      algorithm: 'degree-centrality (Malware USES_TECHNIQUE + ThreatActor PERFORMS)',
      latencyMs: Date.now() - t0,
      techniques: r.records.map((rec) => ({
        mitreId: rec.get('mitreId'),
        name: rec.get('name'),
        malwareCount: rec.get('malwareCount').toNumber(),
        actorCount: rec.get('actorCount').toNumber(),
        criticality: rec.get('criticality').toNumber(),
      })),
    });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** GET /api/algorithms/similar-actors?actor=APT29 — Jaccard over shared techniques */
router.get('/similar-actors', requireAuth, async (req, res, next) => {
  let session;
  try {
    const { actor } = req.query;
    if (!actor) throw httpError(400, 'BAD_REQUEST', 'actor is required');
    const driver = getDriver();
    session = driver.session();
    const t0 = Date.now();
    const r = await session.run(
      `
      MATCH (a:ThreatActor)-[:PERFORMS]->(t:Technique)
      WHERE toLower(a.name) = toLower($actor) OR a.mitreId = $actor
      WITH a, collect(DISTINCT t.mitreId) AS aTech
      MATCH (b:ThreatActor)-[:PERFORMS]->(t2:Technique)
      WHERE b <> a
      WITH a, b, aTech, collect(DISTINCT t2.mitreId) AS bTech
      WITH a, b, aTech, bTech,
           [x IN aTech WHERE x IN bTech] AS inter
      WITH a, b, size(inter) AS shared, size(bTech) AS bCount, size(aTech) AS aCount,
           toFloat(size(inter)) / toFloat(size(aTech) + size(bTech) - size(inter)) AS jaccard
      WHERE jaccard > 0
      RETURN b.mitreId AS mitreId, b.name AS name, jaccard, shared, bCount, aCount, a.mitreId AS actorId, a.name AS actorName
      ORDER BY jaccard DESC LIMIT 10`,
      { actor }
    );
    const first = r.records[0];
    res.json({
      actor,
      actorId: first ? first.get('actorId') : null,
      actorName: first ? first.get('actorName') : null,
      actorTechniques: first ? first.get('aCount').toNumber() : 0,
      algorithm: 'Jaccard similarity on shared PERFORMS techniques',
      latencyMs: Date.now() - t0,
      similar: r.records.map((rec) => ({
        mitreId: rec.get('mitreId'),
        name: rec.get('name'),
        jaccard: rec.get('jaccard'),
        sharedTechniques: rec.get('shared').toNumber(),
        techniqueCount: rec.get('bCount').toNumber(),
      })),
    });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/**
 * GET /api/algorithms/mitigation-priorities?actor=APT29 — defence recommendation.
 * Ranks mitigations by how many relevant techniques they cover: the actor's PERFORMS
 * techniques when an actor is given, otherwise the 50 most-used techniques, weighted by usage.
 */
router.get('/mitigation-priorities', requireAuth, async (req, res, next) => {
  let session;
  try {
    const { actor } = req.query;
    const driver = getDriver();
    session = driver.session();
    const t0 = Date.now();
    let actorInfo = null;
    let r;
    if (actor) {
      const found = await findActorNode(session, actor);
      if (!found) throw httpError(404, 'NOT_FOUND', `No ThreatActor matches '${actor}'`);
      actorInfo = found;
      r = await session.run(
        `
        MATCH (a:ThreatActor {mitreId: $id})-[:PERFORMS]->(t:Technique)
        WITH collect(DISTINCT t) AS techs
        UNWIND techs AS t
        MATCH (t)-[:MITIGATED_BY]->(m:Mitigation)
        WITH m, size(techs) AS total, collect(DISTINCT t.name) AS covered
        RETURN m.mitreId AS mitreId, m.name AS name, size(covered) AS coverage, size(covered) AS score,
               total, covered[0..5] AS examples
        ORDER BY score DESC, name LIMIT 10`,
        { id: found.id }
      );
    } else {
      r = await session.run(
        `
        MATCH (t:Technique)<-[u:USES_TECHNIQUE|PERFORMS]-()
        WITH t, count(u) AS usage ORDER BY usage DESC LIMIT 50
        WITH collect({t: t, usage: usage}) AS top
        UNWIND top AS row
        WITH row.t AS t, row.usage AS usage, size(top) AS total
        MATCH (t)-[:MITIGATED_BY]->(m:Mitigation)
        WITH m, total, collect(DISTINCT t.name) AS covered, sum(usage) AS score
        RETURN m.mitreId AS mitreId, m.name AS name, size(covered) AS coverage, score, total, covered[0..5] AS examples
        ORDER BY score DESC, name LIMIT 10`
      );
    }
    const num = (v) => (v && typeof v.toNumber === 'function' ? v.toNumber() : v);
    res.json({
      actor: actorInfo,
      algorithm: actor
        ? 'Mitigation coverage over the actor\'s PERFORMS techniques'
        : 'Mitigation coverage over the 50 most-used techniques, weighted by usage',
      latencyMs: Date.now() - t0,
      mitigations: r.records.map((rec) => ({
        mitreId: rec.get('mitreId'),
        name: rec.get('name'),
        coverage: num(rec.get('coverage')),
        score: num(rec.get('score')),
        total: num(rec.get('total')),
        examples: rec.get('examples'),
      })),
    });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

module.exports = router;