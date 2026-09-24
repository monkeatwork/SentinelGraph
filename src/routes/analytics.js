/**
 * Phase 5c — MongoDB aggregation pipelines (5 of them, per plan §5c + Review 2 rubric).
 */
const express = require('express');

const { getDb } = require('../config/mongo');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

/** 1) CVE severity distribution grouped by month ($match → $group → $sort) */
router.get('/cve-severity-by-month', requireAuth, async (req, res, next) => {
  try {
    const db = await getDb();
    const t0 = Date.now();
    const rows = await db.collection('vulnerabilities').aggregate([
      { $match: { publishedDate: { $ne: null }, 'cvss.severity': { $nin: [null, 'UNKNOWN'] } } },
      {
        $group: {
          _id: {
            year: { $year: '$publishedDate' },
            month: { $month: '$publishedDate' },
            severity: '$cvss.severity',
          },
          count: { $sum: 1 },
        },
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.severity': 1 } },
      { $limit: 500 },
    ]).toArray();
    res.json({
      pipeline: '$match → $group → $sort on vulnerabilities.publishedDate × cvss.severity',
      latencyMs: Date.now() - t0,
      rows,
    });
  } catch (e) {
    next(e);
  }
});

/** 2) Most-cited sources ($unwind citedReportIds → $lookup reports → $group) */
router.get('/most-cited-sources', requireAuth, async (req, res, next) => {
  try {
    const db = await getDb();
    const t0 = Date.now();
    const rows = await db.collection('queryLogs').aggregate([
      { $match: { citedReportIds: { $exists: true, $ne: [] } } },
      { $unwind: '$citedReportIds' },
      { $lookup: { from: 'reports', localField: 'citedReportIds', foreignField: '_id', as: 'report' } },
      { $unwind: '$report' },
      {
        $group: {
          _id: '$report.source',
          citations: { $sum: 1 },
          reports: { $addToSet: '$report.title' },
        },
      },
      { $sort: { citations: -1 } },
      { $limit: 10 },
    ]).toArray();
    res.json({
      pipeline: 'queryLogs $unwind → $lookup reports → $group by source',
      latencyMs: Date.now() - t0,
      rows,
    });
  } catch (e) {
    next(e);
  }
});

/** 3) Per-user query volume + avg latency ($group on userId, $avg latency) */
router.get('/user-query-volume', requireAuth, async (req, res, next) => {
  try {
    const db = await getDb();
    const t0 = Date.now();
    const rows = await db.collection('queryLogs').aggregate([
      {
        $group: {
          _id: '$userId',
          queries: { $sum: 1 },
          avgGraphLatency: { $avg: '$latencyMs.graph' },
          avgVectorLatency: { $avg: '$latencyMs.vector' },
          avgSynthesisLatency: { $avg: '$latencyMs.synthesis' },
          avgTotal: { $avg: '$latencyMs.total' },
        },
      },
      { $lookup: { from: 'users', localField: '_id', foreignField: '_id', as: 'user' } },
      { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } },
      { $project: { user: { email: '$user.email', role: '$user.role' }, queries: 1, avgGraphLatency: 1, avgVectorLatency: 1, avgSynthesisLatency: 1, avgTotal: 1 } },
      { $sort: { queries: -1 } },
    ]).toArray();
    res.json({
      pipeline: 'queryLogs $group by userId → $avg latencyMs.graph/vector → $lookup users',
      latencyMs: Date.now() - t0,
      rows,
    });
  } catch (e) {
    next(e);
  }
});

/** 4) Chunks-per-entity with report join ($unwind entityIds → $group → $lookup) */
router.get('/chunks-per-entity', requireAuth, async (req, res, next) => {
  try {
    const db = await getDb();
    const t0 = Date.now();
    const rows = await db.collection('chunks').aggregate([
      { $unwind: '$entityIds' },
      { $group: { _id: '$entityIds', chunkCount: { $sum: 1 } } },
      { $sort: { chunkCount: -1 } },
      { $limit: 20 },
      { $lookup: { from: 'entities', localField: '_id', foreignField: 'mitreId', as: 'entity' } },
      { $unwind: { path: '$entity', preserveNullAndEmptyArrays: true } },
      { $project: { entityId: '$_id', chunkCount: 1, entityName: '$entity.name', entityType: '$entity.entityType' } },
    ]).toArray();
    res.json({
      pipeline: 'chunks $unwind entityIds → $group → $lookup entities',
      latencyMs: Date.now() - t0,
      rows,
    });
  } catch (e) {
    next(e);
  }
});

/** 5) Vulnerability severity × knownExploited cross-tab */
router.get('/severity-exploited-crosstab', requireAuth, async (req, res, next) => {
  try {
    const db = await getDb();
    const t0 = Date.now();
    const rows = await db.collection('vulnerabilities').aggregate([
      { $match: { 'cvss.severity': { $nin: [null, 'UNKNOWN'] } } },
      {
        $group: {
          _id: { severity: '$cvss.severity', knownExploited: '$knownExploited' },
          count: { $sum: 1 },
          avgScore: { $avg: '$cvss.baseScore' },
        },
      },
      { $sort: { '_id.severity': 1, '_id.knownExploited': 1 } },
    ]).toArray();
    res.json({
      pipeline: 'vulnerabilities $group by cvss.severity × knownExploited',
      latencyMs: Date.now() - t0,
      rows,
    });
  } catch (e) {
    next(e);
  }
});

module.exports = router;