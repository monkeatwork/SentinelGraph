const express = require('express');
const { ObjectId } = require('mongodb');

const { getDb } = require('../config/mongo');
const { requireAuth, requireRole } = require('../middleware/auth');
const { httpError } = require('../services/graphMeta');

const router = express.Router();

/** GET /api/users — admin only; list users */
router.get('/', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const db = await getDb();
    const users = await db.collection('users')
      .find({})
      .project({ passwordHash: 0 })
      .toArray();
    res.json({ count: users.length, users });
  } catch (e) {
    next(e);
  }
});

/** PATCH /api/users/:id/role — admin only; change a user's role */
router.patch('/:id/role', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { id } = req.params;
    const { role } = req.body || {};
    if (!['admin', 'analyst'].includes(role)) throw httpError(400, 'BAD_REQUEST', 'role must be admin or analyst');
    const db = await getDb();
    let _id;
    try {
      _id = ObjectId.createFromHexString(id);
    } catch (e) {
      throw httpError(400, 'BAD_REQUEST', 'Invalid user id');
    }
    const user = await db.collection('users').findOne({ _id });
    if (!user) throw httpError(404, 'NOT_FOUND', 'User not found');
    await db.collection('users').updateOne({ _id }, { $set: { role, updatedAt: new Date() } });
    res.json({ user: { id: _id, email: user.email, role, name: user.name } });
  } catch (e) {
    next(e);
  }
});

/* ---------- saved queries (Review 3): embedded in the user's own document ---------- */

const MAX_SAVED = 25;
const SAVED_MODES = ['template', 'llm'];
const questionKey = (q) => q.trim().toLowerCase().replace(/\s+/g, ' ');
const meId = (req) => ObjectId.createFromHexString(req.user.sub);
const publicSaved = ({ questionKey: _k, ...q }) => q; // internal dedupe key stays server-side

/** GET /api/users/me/saved-queries — newest first */
router.get('/me/saved-queries', requireAuth, async (req, res, next) => {
  try {
    const db = await getDb();
    const user = await db.collection('users').findOne({ _id: meId(req) }, { projection: { savedQueries: 1 } });
    if (!user) throw httpError(404, 'NOT_FOUND', 'User not found');
    const saved = (user.savedQueries || []).map(publicSaved).sort((a, b) => b.createdAt - a.createdAt);
    res.json({ count: saved.length, max: MAX_SAVED, savedQueries: saved });
  } catch (e) {
    next(e);
  }
});

/** POST /api/users/me/saved-queries — { question, depth?, mode?, name? } */
router.post('/me/saved-queries', requireAuth, async (req, res, next) => {
  try {
    const { question, depth, mode, name } = req.body || {};
    if (!question || typeof question !== 'string' || !question.trim()) throw httpError(400, 'BAD_REQUEST', 'question is required');
    if (question.length > 500) throw httpError(400, 'BAD_REQUEST', 'question must be at most 500 characters');
    const d = depth === undefined ? 2 : Number(depth);
    if (!Number.isInteger(d) || d < 1 || d > 5) throw httpError(400, 'BAD_REQUEST', 'depth must be an integer from 1 to 5');
    const m = mode || 'template';
    if (!SAVED_MODES.includes(m)) throw httpError(400, 'BAD_REQUEST', `mode must be one of: ${SAVED_MODES.join(', ')}`);
    if (name !== undefined && (typeof name !== 'string' || name.length > 80)) throw httpError(400, 'BAD_REQUEST', 'name must be a string of at most 80 characters');

    const entry = {
      _id: new ObjectId(),
      name: (name && name.trim()) || question.trim().slice(0, 60),
      question: question.trim(),
      questionKey: questionKey(question),
      depth: d,
      mode: m,
      createdAt: new Date(),
    };
    const db = await getDb();
    const _id = meId(req);
    // one atomic update enforces both the cap and "no duplicate question/depth/mode"
    const r = await db.collection('users').updateOne(
      {
        _id,
        [`savedQueries.${MAX_SAVED - 1}`]: { $exists: false },
        savedQueries: { $not: { $elemMatch: { questionKey: entry.questionKey, depth: d, mode: m } } },
      },
      { $push: { savedQueries: entry } }
    );
    if (!r.matchedCount) {
      const user = await db.collection('users').findOne({ _id }, { projection: { savedQueries: 1 } });
      if (!user) throw httpError(404, 'NOT_FOUND', 'User not found');
      if ((user.savedQueries || []).length >= MAX_SAVED) throw httpError(400, 'LIMIT_REACHED', `You can save up to ${MAX_SAVED} queries; delete one first`);
      throw httpError(409, 'DUPLICATE_KEY', 'This question is already saved with the same depth and mode');
    }
    res.status(201).json({ savedQuery: publicSaved(entry) });
  } catch (e) {
    next(e);
  }
});

/** DELETE /api/users/me/saved-queries/:id */
router.delete('/me/saved-queries/:id', requireAuth, async (req, res, next) => {
  try {
    let qid;
    try {
      qid = ObjectId.createFromHexString(req.params.id);
    } catch (e) {
      throw httpError(400, 'BAD_REQUEST', 'Invalid saved query id');
    }
    const db = await getDb();
    const r = await db.collection('users').updateOne(
      { _id: meId(req), 'savedQueries._id': qid },
      { $pull: { savedQueries: { _id: qid } } }
    );
    if (!r.matchedCount) throw httpError(404, 'NOT_FOUND', 'Saved query not found');
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

module.exports = router;