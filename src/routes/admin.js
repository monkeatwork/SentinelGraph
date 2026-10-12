/**
 * Review 3 — admin-only operational endpoints for the dashboard.
 */
const express = require('express');

const { requireAuth, requireRole } = require('../middleware/auth');
const { reconcile, driftCount } = require('../scripts/reconcile');

const router = express.Router();

/** GET /api/admin/reconcile — cross-store join-key drift (same report as `npm run reconcile`) */
router.get('/reconcile', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const t0 = Date.now();
    const report = await reconcile();
    res.json({ drift: driftCount(report), latencyMs: Date.now() - t0, report });
  } catch (e) {
    next(e);
  }
});

module.exports = router;
