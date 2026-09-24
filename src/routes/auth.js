const express = require('express');
const bcrypt = require('bcrypt');

const { getDb } = require('../config/mongo');
const { signToken, requireAuth, requireRole } = require('../middleware/auth');
const { httpError } = require('../services/graphMeta');

const router = express.Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** POST /api/auth/register — admin only (FR12) */
router.post('/register', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { email, password, name, role } = req.body || {};
    if (!email || !EMAIL_RE.test(email)) throw httpError(400, 'BAD_REQUEST', 'A valid email is required');
    if (!password || password.length < 8) throw httpError(400, 'BAD_REQUEST', 'Password must be at least 8 characters');
    const db = await getDb();
    const existing = await db.collection('users').findOne({ email: email.toLowerCase() });
    if (existing) throw httpError(409, 'DUPLICATE_KEY', 'Email already registered');
    const passwordHash = await bcrypt.hash(password, 12);
    const user = {
      email: email.toLowerCase(),
      passwordHash,
      role: role === 'admin' ? 'admin' : 'analyst',
      name: name || email.split('@')[0],
      savedQueries: [],
      createdAt: new Date(),
    };
    const { insertedId } = await db.collection('users').insertOne(user);
    res.status(201).json({ user: { id: insertedId, email: user.email, role: user.role, name: user.name } });
  } catch (e) {
    next(e);
  }
});

/** POST /api/auth/login */
router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) throw httpError(400, 'BAD_REQUEST', 'email and password are required');
    const db = await getDb();
    const user = await db.collection('users').findOne({ email: email.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      throw httpError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
    }
    const token = signToken(user);
    res.json({
      token,
      user: { id: user._id, email: user.email, role: user.role, name: user.name },
    });
  } catch (e) {
    next(e);
  }
});

/** GET /api/auth/me */
router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const db = await getDb();
    const user = await db.collection('users').findOne({ _id: require('mongodb').ObjectId.createFromHexString(req.user.sub) });
    if (!user) throw httpError(404, 'NOT_FOUND', 'User not found');
    res.json({ user: { id: user._id, email: user.email, role: user.role, name: user.name } });
  } catch (e) {
    next(e);
  }
});

module.exports = router;