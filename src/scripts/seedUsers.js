/**
 * Phase 3 — Seed users: admin@sentinelgraph.local (admin) + analyst@vitstudent.ac.in (analyst).
 * bcrypt cost 12 (NFR4). Idempotent (upsert).
 */
require('dotenv').config();
const bcrypt = require('bcrypt');

const { getDb, close } = require('../config/mongo');

const USERS = [
  { email: 'admin@sentinelgraph.local', password: process.env.ADMIN_PASSWORD || 'Admin@123', role: 'admin', name: 'Admin' },
  { email: 'analyst@vitstudent.ac.in', password: process.env.ANALYST_PASSWORD || 'Analyst@123', role: 'analyst', name: 'Analyst' },
];

async function seedUsers() {
  const db = await getDb();
  for (const u of USERS) {
    const hash = await bcrypt.hash(u.password, 12);
    await db.collection('users').updateOne(
      { email: u.email },
      {
        $set: { email: u.email, passwordHash: hash, role: u.role, name: u.name },
        $setOnInsert: { savedQueries: [], createdAt: new Date() },
      },
      { upsert: true }
    );
    console.log(`  user ${u.email} (${u.role}) upserted; hash prefix: ${hash.slice(0, 7)}`);
  }
  const counts = await db.collection('users').aggregate([{ $group: { _id: '$role', n: { $sum: 1 } } }]).toArray();
  console.log('user roles:', JSON.stringify(counts));
}

module.exports = { seedUsers };

if (require.main === module) {
  seedUsers()
    .then(() => close())
    .then(() => process.exit(0))
    .catch((e) => {
      console.error('seedUsers failed:', e);
      process.exit(1);
    });
}