/**
 * Phase 5 — Q&A pipeline, graph algorithms and aggregation pipelines.
 * Requires seeded data (npm run seed:reports) and running DBs.
 */
const request = require('supertest');

const app = require('../src/server');
const { ensureTestUsers, login } = require('./helpers');

let adminToken;

beforeAll(async () => {
  await ensureTestUsers();
  adminToken = await login(request(app), 'testadmin@sg.test', 'AdminPass123');
});

describe('Advanced NoSQL features (Phase 5)', () => {
  test('Q&A resolves Log4j → CVE-2021-44228 and returns cited evidence (FR5–FR8, NFR6)', async () => {
    const res = await request(app)
      .post('/api/qa/ask')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ question: 'Which adversary groups exploit Log4j, and how?', depth: 2 });
    expect(res.status).toBe(200);
    expect(res.body.resolved.cves).toContain('CVE-2021-44228');
    expect(res.body.resolved.cpeNames.length).toBeGreaterThan(0);
    expect(res.body.answer).toContain('CVE-2021-44228');
    expect(res.body.evidence.length).toBeGreaterThan(0);
    const cited = res.body.evidence.filter((e) => e.report);
    expect(cited.length).toBeGreaterThan(0);
    expect(cited[0].report.url).toBeTruthy(); // traceability (NFR6)
    expect(res.body.latencyMs.total).toBeLessThan(5000);
  });

  test('Q&A logs the query (FR13)', async () => {
    const { getDb } = require('../src/config/mongo');
    const db = await getDb();
    const log = await db.collection('queryLogs').findOne({ question: /Log4j/ }, { sort: { askedAt: -1 } });
    expect(log).toBeTruthy();
    expect(log.resolvedEntities).toContain('CVE-2021-44228');
    expect(log.latencyMs).toHaveProperty('graph');
    expect(log.latencyMs).toHaveProperty('vector');
  });

  test('shortest attack path Software(log4j) → ThreatActor(APT29) (FR9)', async () => {
    const res = await request(app)
      .get('/api/algorithms/shortest-path?from=log4j&to=APT29')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.found).toBe(true);
    expect(res.body.path.length).toBeGreaterThan(1);
    const labels = res.body.path.map((n) => n.label);
    expect(labels[0]).toBe('Software');
    expect(labels[labels.length - 1]).toBe('ThreatActor');
  });

  test('technique criticality returns ranked techniques (FR10)', async () => {
    const res = await request(app)
      .get('/api/algorithms/technique-criticality')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.techniques.length).toBeGreaterThan(5);
    expect(res.body.techniques[0].mitreId).toMatch(/^T\d+/);
    expect(res.body.techniques[0].criticality).toBeGreaterThan(0);
  });

  test('similar actors returns a ranked list for APT29 (FR10)', async () => {
    const res = await request(app)
      .get('/api/algorithms/similar-actors?actor=APT29')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.similar.length).toBeGreaterThan(0);
    expect(res.body.similar[0].jaccard).toBeGreaterThan(0);
    expect(res.body.similar[0].jaccard).toBeLessThanOrEqual(1);
  });

  test('all 5 aggregations return in < 1 s each', async () => {
    const eps = [
      'cve-severity-by-month',
      'most-cited-sources',
      'user-query-volume',
      'chunks-per-entity',
      'severity-exploited-crosstab',
    ];
    for (const ep of eps) {
      const t0 = Date.now();
      const res = await request(app).get(`/api/analytics/${ep}`).set('Authorization', `Bearer ${adminToken}`);
      const ms = Date.now() - t0;
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.rows)).toBe(true);
      expect(ms).toBeLessThan(1000);
    }
  });

  test('variable-depth traversal endpoint respects depth (FR6)', async () => {
    const d1 = await request(app)
      .post('/api/qa/ask')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ question: 'Which adversary groups exploit Log4j, and how?', depth: 1 });
    const d3 = await request(app)
      .post('/api/qa/ask')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ question: 'Which adversary groups exploit Log4j, and how?', depth: 3 });
    expect(d1.status).toBe(200);
    expect(d3.status).toBe(200);
    expect(d3.body.traversedEntities.length).toBeGreaterThanOrEqual(d1.body.traversedEntities.length);
  });
});