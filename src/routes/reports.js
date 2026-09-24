const express = require('express');
const { ObjectId } = require('mongodb');

const { getDb } = require('../config/mongo');
const { requireAuth, requireRole } = require('../middleware/auth');
const { httpError } = require('../services/graphMeta');
const { processReport } = require('../services/reportIngest');

const router = express.Router();

/** POST /api/reports — admin only; triggers chunking + embedding pipeline */
router.post('/', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { title, source, url, publishedDate, rawText, entityMentions } = req.body || {};
    if (!title || !rawText) throw httpError(400, 'BAD_REQUEST', 'title and rawText are required');

    const db = await getDb();
    const doc = {
      title,
      source: source || 'Unknown',
      url: url || null,
      publishedDate: publishedDate ? new Date(publishedDate) : new Date(),
      rawText,
      entityMentions: entityMentions || [],
      ingestStatus: 'pending',
      chunkCount: 0,
      createdAt: new Date(),
    };
    const { insertedId } = await db.collection('reports').insertOne(doc);

    // Fire the chunk + embed pipeline (Phase 5a)
    const chunks = await processReport(insertedId).catch(async (e) => {
      await db.collection('reports').updateOne({ _id: insertedId }, { $set: { ingestStatus: 'failed' } });
      throw e;
    });

    const report = await db.collection('reports').findOne({ _id: insertedId });
    res.status(201).json({ report, chunksGenerated: chunks });
  } catch (e) {
    next(e);
  }
});

/** GET /api/reports — list with filters (source, q, limit) */
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { source, q, limit = 50 } = req.query;
    const db = await getDb();
    const filter = {};
    if (source) filter.source = source;
    if (q) filter.$or = [{ title: { $regex: String(q), $options: 'i' } }, { source: { $regex: String(q), $options: 'i' } }];
    const docs = await db.collection('reports')
      .find(filter)
      .project({ rawText: 0 })
      .sort({ publishedDate: -1 })
      .limit(Number(limit) || 50)
      .toArray();
    res.json({ count: docs.length, reports: docs });
  } catch (e) {
    next(e);
  }
});

/** GET /api/reports/:id — full report + its chunks */
router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const db = await getDb();
    let _id;
    try {
      _id = ObjectId.createFromHexString(req.params.id);
    } catch (e) {
      throw httpError(400, 'BAD_REQUEST', 'Invalid report id');
    }
    const report = await db.collection('reports').findOne({ _id });
    if (!report) throw httpError(404, 'NOT_FOUND', 'Report not found');
    const chunks = await db.collection('chunks').find({ reportId: _id }).project({ embedding: 0 }).sort({ chunkIndex: 1 }).toArray();
    res.json({ report, chunks });
  } catch (e) {
    next(e);
  }
});

/** PUT /api/reports/:id — admin only; update + re-run chunk/embed pipeline */
router.put('/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const db = await getDb();
    let _id;
    try {
      _id = ObjectId.createFromHexString(req.params.id);
    } catch (e) {
      throw httpError(400, 'BAD_REQUEST', 'Invalid report id');
    }
    const existing = await db.collection('reports').findOne({ _id });
    if (!existing) throw httpError(404, 'NOT_FOUND', 'Report not found');

    const { title, source, url, publishedDate, rawText, entityMentions } = req.body || {};
    const $set = { updatedAt: new Date() };
    if (title !== undefined) $set.title = title;
    if (source !== undefined) $set.source = source;
    if (url !== undefined) $set.url = url;
    if (publishedDate !== undefined) $set.publishedDate = new Date(publishedDate);
    if (rawText !== undefined) $set.rawText = rawText;
    if (entityMentions !== undefined) $set.entityMentions = entityMentions;
    if (rawText !== undefined || entityMentions !== undefined) $set.ingestStatus = 'pending';

    await db.collection('reports').updateOne({ _id }, { $set });
    let chunks = existing.chunkCount || 0;
    if (rawText !== undefined || entityMentions !== undefined) {
      chunks = await processReport(_id);
    }
    const report = await db.collection('reports').findOne({ _id });
    res.json({ report, chunksGenerated: chunks });
  } catch (e) {
    next(e);
  }
});

/** DELETE /api/reports/:id — admin only; delete report + its chunks */
router.delete('/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const db = await getDb();
    let _id;
    try {
      _id = ObjectId.createFromHexString(req.params.id);
    } catch (e) {
      throw httpError(400, 'BAD_REQUEST', 'Invalid report id');
    }
    const report = await db.collection('reports').findOne({ _id });
    if (!report) throw httpError(404, 'NOT_FOUND', 'Report not found');
    await db.collection('chunks').deleteMany({ reportId: _id });
    await db.collection('reports').deleteOne({ _id });
    res.json({ ok: true, deleted: _id.toString() });
  } catch (e) {
    next(e);
  }
});

module.exports = router;