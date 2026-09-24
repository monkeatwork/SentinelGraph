/**
 * Phase 5a — POST /api/qa/ask (FR5–FR8, FR13):
 *   resolve → Cypher traversal (depth) → vector retrieval (entityIds-filtered) → cited template answer.
 */
const express = require('express');
const { ObjectId } = require('mongodb');

const { getDb } = require('../config/mongo');
const { getDriver } = require('../config/neo4j');
const { requireAuth } = require('../middleware/auth');
const { httpError } = require('../services/graphMeta');
const { resolveEntities } = require('../services/entityResolver');
const { vectorSearch } = require('../services/retrieval');
const { buildAnswer } = require('../services/answerBuilder');

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

router.post('/ask', requireAuth, async (req, res, next) => {
  const t0 = Date.now();
  try {
    const { question, depth } = req.body || {};
    if (!question || typeof question !== 'string' || !question.trim()) {
      throw httpError(400, 'BAD_REQUEST', 'question is required');
    }
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

    const citedReportIds = [...new Set(evidence.map((e) => e.reportId))];
    const answer = buildAnswer({ question, resolved, traversed, chunks: hits, reportsById });
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