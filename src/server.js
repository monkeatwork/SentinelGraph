require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');

const mongo = require('./config/mongo');
const neo4j = require('./config/neo4j');

const app = express();
app.use(cors());
app.use(express.json({ limit: '25mb' }));

// Dashboard (Phase 6) — plain HTML/JS served from ./public
app.use(express.static(path.join(__dirname, '..', 'public')));

// --- Health ---------------------------------------------------------------
app.get('/health', async (req, res) => {
  const status = { mongo: 'down', neo4j: 'down', timestamp: new Date().toISOString() };
  try {
    await mongo.ping();
    status.mongo = 'up';
  } catch (e) {
    status.mongoError = e.message;
  }
  try {
    await neo4j.ping();
    status.neo4j = 'up';
  } catch (e) {
    status.neo4jError = e.message;
  }
  const ok = status.mongo === 'up' && status.neo4j === 'up';
  res.status(ok ? 200 : 503).json(status);
});

// API routes are mounted in src/routes/index.js (added in later phases)
try {
  const mountRoutes = require('./routes');
  mountRoutes(app);
} catch (e) {
  if (e.code !== 'MODULE_NOT_FOUND') throw e;
}

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`✅ SentinelGraph API listening on http://localhost:${PORT}`));
}

module.exports = app;