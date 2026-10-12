/**
 * Mounts every API router + the shared error handler.
 */
const auth = require('./auth');
const graph = require('./graph');
const entities = require('./entities');
const reports = require('./reports');
const vulnerabilities = require('./vulnerabilities');
const users = require('./users');
const qa = require('./qa');
const algorithms = require('./algorithms');
const analytics = require('./analytics');
const admin = require('./admin');

function mountRoutes(app) {
  app.use('/api/auth', auth);
  app.use('/api/graph', graph);
  app.use('/api/entities', entities);
  app.use('/api/reports', reports);
  app.use('/api/vulnerabilities', vulnerabilities);
  app.use('/api/users', users);
  app.use('/api/qa', qa);
  app.use('/api/algorithms', algorithms);
  app.use('/api/analytics', analytics);
  app.use('/api/admin', admin);

  // consistent error format: { error: { code, message } }
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err.status || 500;
    const code = err.code || 'INTERNAL_ERROR';
    if (status >= 500) console.error('[api error]', err);
    res.status(status).json({ error: { code, message: err.message || 'Internal error' } });
  });
}

module.exports = mountRoutes;