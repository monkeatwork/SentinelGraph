/** Review 3 — admin endpoints and entity-route hardening used by the Admin page. */
const request = require('supertest');

const app = require('../src/server');
const { getDb } = require('../src/config/mongo');
const { getDriver } = require('../src/config/neo4j');
const { ensureTestUsers, login } = require('./helpers');

let admin;
let analyst;
const ID = 'G9TESTADM';

const cleanup = async () => {
  await (await getDb()).collection('entities').deleteMany({ mitreId: ID });
  const s = getDriver().session();
  try { await s.run('MATCH (n {mitreId: $id}) DETACH DELETE n', { id: ID }); } finally { await s.close(); }
};

beforeAll(async () => {
  await ensureTestUsers();
  admin = await login(request(app), 'testadmin@sg.test', 'AdminPass123');
  analyst = await login(request(app), 'testanalyst@sg.test', 'AnalystPass123');
  await cleanup();
});
afterAll(cleanup);

const as = (token) => (req) => req.set('Authorization', `Bearer ${token}`);

describe('Admin APIs (Review 3)', () => {
  test('reconcile endpoint is admin-only and reports both key spaces', async () => {
    expect((await as(analyst)(request(app).get('/api/admin/reconcile'))).status).toBe(403);
    const res = await as(admin)(request(app).get('/api/admin/reconcile'));
    expect(res.status).toBe(200);
    expect(typeof res.body.drift).toBe('number');
    expect(res.body.report.entities.mongoCount).toBeGreaterThan(0);
    expect(res.body.report.vulnerabilities.graphCount).toBeGreaterThan(0);
  });

  test('entities can only be created with mitreId-keyed labels', async () => {
    const res = await as(admin)(request(app).post('/api/entities')).send({ mitreId: ID, entityType: 'Software', name: 'x' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/entityType must be one of/);
  });

  test('changing entityType on update is rejected so the stores cannot drift', async () => {
    expect((await as(admin)(request(app).post('/api/entities')).send({ mitreId: ID, entityType: 'ThreatActor', name: 'Adm Test' })).status).toBe(201);
    const bad = await as(admin)(request(app).put(`/api/entities/${ID}`)).send({ entityType: 'Malware' });
    expect(bad.status).toBe(400);
    const same = await as(admin)(request(app).put(`/api/entities/${ID}`)).send({ entityType: 'ThreatActor', name: 'Adm Test 2' });
    expect(same.status).toBe(200);
    expect(same.body.entity.name).toBe('Adm Test 2');
    const node = await as(admin)(request(app).get(`/api/graph/ThreatActor/${ID}`));
    expect(node.body.node.name).toBe('Adm Test 2');
  });
});
