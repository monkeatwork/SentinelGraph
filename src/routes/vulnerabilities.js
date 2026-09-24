const express = require('express');

const { getDb } = require('../config/mongo');
const { getDriver } = require('../config/neo4j');
const { requireAuth, requireRole } = require('../middleware/auth');
const { httpError } = require('../services/graphMeta');

const router = express.Router();

/** GET /api/vulnerabilities — filter by severity, date range, knownExploited */
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { severity, from, to, knownExploited, limit = 50 } = req.query;
    const db = await getDb();
    const filter = {};
    if (severity) filter['cvss.severity'] = String(severity).toUpperCase();
    if (from || to) {
      filter.publishedDate = {};
      if (from) filter.publishedDate.$gte = new Date(from);
      if (to) filter.publishedDate.$lte = new Date(to);
    }
    if (knownExploited !== undefined) filter.knownExploited = knownExploited === 'true';

    const docs = await db.collection('vulnerabilities')
      .find(filter)
      .sort({ 'cvss.baseScore': -1, publishedDate: -1 })
      .limit(Number(limit) || 50)
      .toArray();
    res.json({ count: docs.length, vulnerabilities: docs });
  } catch (e) {
    next(e);
  }
});

/** POST /api/vulnerabilities — admin only; insert doc + Vulnerability node */
router.post('/', requireAuth, requireRole('admin'), async (req, res, next) => {
  let session;
  try {
    const { cveId, description, cvss, publishedDate } = req.body || {};
    if (!cveId) throw httpError(400, 'BAD_REQUEST', 'cveId is required');
    const db = await getDb();
    const doc = {
      cveId,
      description: description || '',
      cvss: cvss || { baseScore: null, severity: 'UNKNOWN', vector: null },
      publishedDate: publishedDate ? new Date(publishedDate) : null,
      affectedProducts: [],
      knownExploited: false,
      source: 'API',
      createdAt: new Date(),
    };
    try {
      await db.collection('vulnerabilities').insertOne(doc);
    } catch (e) {
      if (e.code === 11000) throw httpError(409, 'DUPLICATE_KEY', `cveId '${cveId}' already exists`);
      throw e;
    }
    const driver = getDriver();
    session = driver.session();
    await session.run(
      `MERGE (v:Vulnerability {cveId: $cveId})
       SET v.cvssScore = $score, v.severity = $severity, v.publishedDate = $publishedDate, v.knownExploited = false`,
      {
        cveId,
        score: doc.cvss.baseScore,
        severity: doc.cvss.severity,
        publishedDate: doc.publishedDate ? doc.publishedDate.toISOString() : null,
      }
    );
    res.status(201).json({ vulnerability: doc });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** PUT /api/vulnerabilities/:cveId — admin only */
router.put('/:cveId', requireAuth, requireRole('admin'), async (req, res, next) => {
  let session;
  try {
    const { cveId } = req.params;
    const db = await getDb();
    const existing = await db.collection('vulnerabilities').findOne({ cveId });
    if (!existing) throw httpError(404, 'NOT_FOUND', `No vulnerability '${cveId}'`);

    const { description, cvss, publishedDate, knownExploited } = req.body || {};
    const $set = { updatedAt: new Date() };
    if (description !== undefined) $set.description = description;
    if (cvss !== undefined) $set.cvss = cvss;
    if (publishedDate !== undefined) $set.publishedDate = new Date(publishedDate);
    if (knownExploited !== undefined) $set.knownExploited = Boolean(knownExploited);

    await db.collection('vulnerabilities').updateOne({ cveId }, { $set });

    const driver = getDriver();
    session = driver.session();
    const props = {};
    if (cvss !== undefined) { props.cvssScore = cvss.baseScore; props.severity = cvss.severity; }
    if (knownExploited !== undefined) props.knownExploited = Boolean(knownExploited);
    if (Object.keys(props).length) {
      await session.run(`MATCH (v:Vulnerability {cveId: $cveId}) SET v += $props`, { cveId, props });
    }
    const updated = await db.collection('vulnerabilities').findOne({ cveId });
    res.json({ vulnerability: updated });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** DELETE /api/vulnerabilities/:cveId — admin only; DETACH DELETE + doc delete */
router.delete('/:cveId', requireAuth, requireRole('admin'), async (req, res, next) => {
  let session;
  try {
    const { cveId } = req.params;
    const db = await getDb();
    const existing = await db.collection('vulnerabilities').findOne({ cveId });
    if (!existing) throw httpError(404, 'NOT_FOUND', `No vulnerability '${cveId}'`);
    await db.collection('vulnerabilities').deleteOne({ cveId });
    const driver = getDriver();
    session = driver.session();
    await session.run(`MATCH (v:Vulnerability {cveId: $cveId}) DETACH DELETE v`, { cveId });
    res.json({ ok: true, deleted: cveId });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

module.exports = router;