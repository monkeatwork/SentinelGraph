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

module.exports = router;