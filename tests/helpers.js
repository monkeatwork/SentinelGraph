/** Shared helpers for integration tests. */
const bcrypt = require('bcrypt');
const { getDb } = require('../src/config/mongo');

/** Upsert test users directly (independent of seeding), return via login. */
async function ensureTestUsers() {
  const db = await getDb();
  for (const u of [
    { email: 'testadmin@sg.test', role: 'admin', password: 'AdminPass123' },
    { email: 'testanalyst@sg.test', role: 'analyst', password: 'AnalystPass123' },
  ]) {
    const passwordHash = await bcrypt.hash(u.password, 12);
    await db.collection('users').updateOne(
      { email: u.email },
      { $set: { passwordHash, role: u.role, name: u.email }, $setOnInsert: { createdAt: new Date(), savedQueries: [] } },
      { upsert: true }
    );
  }
}

async function login(app, email, password) {
  const res = await app.post('/api/auth/login').send({ email, password });
  if (res.status !== 200) throw new Error(`login failed ${res.status}: ${JSON.stringify(res.body)}`);
  return res.body.token;
}

module.exports = { ensureTestUsers, login };