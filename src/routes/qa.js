/**
 * Phase 5a — POST /api/qa/ask (FR5–FR8, FR13):
 *   resolve → Cypher traversal (depth) → vector retrieval (entityIds-filtered) → cited answer.
 * Review 3: `mode: "llm"` synthesises the answer with an LLM over the same evidence plus typed
 * attack paths; any LLM failure falls back to the template answer. Default mode is "template".
 */
const express = require('express');
const { ObjectId } = require('mongodb');
const { int: neo4jInt } = require('neo4j-driver');

const { getDb } = require('../config/mongo');
const { getDriver } = require('../config/neo4j');
const { requireAuth } = require('../middleware/auth');
const { httpError } = require('../services/graphMeta');
const { resolveEntities } = require('../services/entityResolver');
const { vectorSearch } = require('../services/retrieval');
const { buildTemplateAnswer, buildLlmAnswer } = require('../services/answerBuilder');
const llm = require('../services/llm');

const MODES = ['template', 'llm'];

const router = express.Router();

/** Expand resolved entities through the graph to `depth` hops. */
async function traverse(resolved, depth) {
  const driver = getDriver();
  const session = driver.session();
  try {
    const keys = [
      ...resolved.mitreIds.map((id) => ({ kind: 'mitreId', v: id })),
      ...resolved.cves.map((id) => ({ kind: 'cveId', v: id })),
      ...resolved.cpeNames.map((id) => ({ kind: 'cpeName', v: id })),
    ];
    if (!keys.length) return [];
    const rows = [];
    for (const { kind, v } of keys) {
      const r = await session.run(
        `
        MATCH (n {${kind}: $v})
        OPTIONAL MATCH (n)-[*1..${depth}]-(m)
        WHERE m IS NOT NULL
        RETURN DISTINCT labels(m)[0] AS label, coalesce(m.mitreId, m.cveId, m.cpeName, m.sectorName) AS key, m.name AS name
        LIMIT 100`,
        { v }
      );
      for (const rec of r.records) rows.push({
        label: rec.get('label'),
        key: rec.get('key'),
        name: rec.get('name') ||
          (rec.get('label') === 'Software' ? rec.get('key') : null) ||
          (rec.get('label') === 'Vulnerability' ? rec.get('key') : null),
      });
    }
    // de-dupe
    const seen = new Set();
    const out = [];
    for (const row of rows) {
      if (!row.key) continue;
      const k = `${row.label}|${row.key}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(row);
    }
    return out;
  } finally {
    await session.close();
  }
}

const keyOfNode = 'coalesce(x.mitreId, x.cveId, x.cpeName, x.sectorName)';

/** Typed shortest paths from resolved entities to ThreatActor nodes (LLM grounding facts). */
async function attackPaths(resolved, { maxKeys = 4, limit = 8 } = {}) {
  const keys = [
    ...resolved.cves.map((v) => ['cveId', v]),
    ...resolved.mitreIds.map((v) => ['mitreId', v]),
    ...resolved.cpeNames.map((v) => ['cpeName', v]),
  ].slice(0, maxKeys);
  if (!keys.length) return [];
  const session = getDriver().session();
  try {
    const out = [];
    const seenActors = new Set();
    for (const [kind, v] of keys) {
      const r = await session.run(
        `MATCH (n {${kind}: $v}) MATCH (a:ThreatActor) WHERE a <> n
         MATCH p = shortestPath((n)-[*..4]-(a))
         WITH p ORDER BY length(p) LIMIT $limit
         RETURN [x IN nodes(p) | {label: labels(x)[0], key: ${keyOfNode}, name: coalesce(x.name, ${keyOfNode})}] AS nodes,
                [r IN relationships(p) | {type: type(r), from: coalesce(startNode(r).mitreId, startNode(r).cveId, startNode(r).cpeName, startNode(r).sectorName)}] AS rels`,
        { v, limit: neo4jInt(limit) }
      );
      for (const rec of r.records) {
        const nodes = rec.get('nodes');
        const actor = nodes[nodes.length - 1].key;
        if (seenActors.has(actor)) continue;
        seenActors.add(actor);
        out.push({ nodes, rels: rec.get('rels') });
      }
      if (out.length >= limit) break;
    }
    return out.slice(0, limit);
  } finally {
    await session.close();
  }
}

/** Mitigations (MITIGATED_BY) for techniques on the attack paths or named in the question. */
async function pathMitigations(paths, resolved, limit = 10) {
  const techIds = new Set(resolved.mitreIds.filter((id) => /^T\d/.test(id)));
  for (const p of paths) for (const n of p.nodes) if (n.label === 'Technique') techIds.add(n.key);
  if (!techIds.size) return [];
  const session = getDriver().session();
  try {
    const r = await session.run(
      `MATCH (t:Technique)-[:MITIGATED_BY]->(m:Mitigation) WHERE t.mitreId IN $ids
       RETURN t.name AS technique, collect(DISTINCT m.name)[0..3] AS mitigations
       ORDER BY technique LIMIT $limit`,
      { ids: [...techIds], limit: neo4jInt(limit) }
    );
    return r.records.map((rec) => ({ technique: rec.get('technique'), mitigations: rec.get('mitigations') }));
  } finally {
    await session.close();
  }
}

/** GET /api/qa/modes — which answer modes this server can serve (dashboard toggle). */
router.get('/modes', requireAuth, (req, res) => {
  const c = llm.llmConfig();
  res.json({
    default: 'template',
    modes: MODES,
    llm: {
      available: llm.isConfigured(),
      provider: c.provider,
      models: c.models,
      fallback: c.fallback,
      targets: c.targets.length, // key x model combinations tried in order
    },
  });
});

router.post('/ask', requireAuth, async (req, res, next) => {
  const t0 = Date.now();
  try {
    const { question, depth } = req.body || {};
    const mode = (req.body && req.body.mode) || 'template';
    if (!question || typeof question !== 'string' || !question.trim()) {
      throw httpError(400, 'BAD_REQUEST', 'question is required');
    }
    if (!MODES.includes(mode)) throw httpError(400, 'BAD_REQUEST', `mode must be one of: ${MODES.join(', ')}`);
    const maxDepth = Math.min(Number(depth) || 2, 5);

    // 1) resolve
    const resolved = await resolveEntities(question.trim());
    const tResolve = Date.now();

    // 2) graph traversal
    const traversed = await traverse(resolved, maxDepth);
    const tTraverse = Date.now();

    // 3) vector retrieval filtered by traversed entities
    const filterIds = [
      ...resolved.cves,
      ...resolved.mitreIds,
      ...new Set(traversed.map((t) => t.key)),
    ];
    const hits = await vectorSearch({ entityIds: filterIds, query: question, topK: 10 });
    const tVector = Date.now();

    // 4) evidence + citations
    const db = await getDb();
    const reportIds = [...new Set(hits.map((h) => h.chunk.reportId.toString()))];
    const reports = await db.collection('reports')
      .find({ _id: { $in: reportIds.map((id) => ObjectId.createFromHexString(id)) } })
      .toArray();
    const reportsById = new Map(reports.map((r) => [r._id.toString(), r]));

    const evidence = hits.map(({ chunk, score }) => ({
      chunkId: chunk._id,
      text: chunk.text,
      reportId: chunk.reportId,
      score,
      report: reportsById.get(chunk.reportId.toString()) || null,
    }));

    let citedReportIds = [...new Set(evidence.map((e) => e.reportId))];
    const templateInput = { question, resolved, traversed, chunks: hits, reportsById };
    let answer;
    let answerMode = 'template';
    let llmInfo = null;
    let paths = [];
    if (mode === 'llm') {
      try {
        paths = await attackPaths(resolved);
        const mitigations = await pathMitigations(paths, resolved);
        const out = await buildLlmAnswer({ ...templateInput, attackPaths: paths, mitigations });
        answer = out.text;
        answerMode = 'llm';
        citedReportIds = out.citedReportIds.map((id) => ObjectId.createFromHexString(id));
        llmInfo = { provider: out.provider, model: out.model, via: out.via, attempts: out.attempts, usage: out.usage };
      } catch (e) {
        llmInfo = { fallbackReason: e.message };
      }
    }
    if (!answer) answer = buildTemplateAnswer(templateInput);
    const tSynth = Date.now();

    const latencyMs = {
      resolve: tResolve - t0,
      graph: tTraverse - tResolve,
      vector: tVector - tTraverse,
      synthesis: tSynth - tVector,
      total: tSynth - t0,
    };

    // 5) audit log (FR13, append-only)
    await db.collection('queryLogs').insertOne({
      userId: ObjectId.createFromHexString(req.user.sub),
      question: question.trim(),
      answerText: answer,
      answerMode,
      resolvedEntities: [...resolved.cves, ...resolved.mitreIds, ...resolved.cpeNames],
      traversalDepth: maxDepth,
      retrievedChunkIds: evidence.map((e) => e.chunkId),
      citedReportIds,
      latencyMs,
      askedAt: new Date(),
    });

    res.json({
      question: question.trim(),
      answer,
      requestedMode: mode,
      answerMode,
      llm: llmInfo,
      attackPaths: paths,
      resolved: {
        cves: resolved.cves,
        mitreIds: resolved.mitreIds,
        cpeNames: resolved.cpeNames,
        names: resolved.names,
      },
      traversedEntities: traversed.slice(0, 40),
      evidence,
      citations: evidence.filter((e) => e.report),
      latencyMs,
    });
  } catch (e) {
    next(e);
  }
});

module.exports = router;