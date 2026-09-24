const request = require('supertest');

const app = require('../src/server');
const { ensureTestUsers, login } = require('./helpers');
const { getDb } = require('../src/config/mongo');
const { getDriver } = require('../src/config/neo4j');
const { ObjectId } = require('mongodb');

let adminToken;
let analystToken;

beforeAll(async () => {
  await ensureTestUsers();
  adminToken = await login(request(app), 'testadmin@sg.test', 'AdminPass123');
  analystToken = await login(request(app), 'testanalyst@sg.test', 'AnalystPass123');
});

describe('Document CRUD (entities, reports, vulnerabilities, users)', () => {
  afterAll(async () => {
    const db = await getDb();
    await db.collection('entities').deleteMany({ mitreId: 'G9TESTENT' });
    await db.collection('vulnerabilities').deleteMany({ cveId: 'CVE-2099-TEST01' });
    const s = getDriver().session();
    await s.run(`MATCH (n:ThreatActor {mitreId: 'G9TESTENT'}) DETACH DELETE n`);
    await s.run(`MATCH (n:Vulnerability {cveId: 'CVE-2099-TEST01'}) DETACH DELETE n`);
    await s.close();
    getDriver().close();
  });

  test('entities POST/GET/PUT/DELETE round-trip; duplicate → 409', async () => {
    const c = await request(app)
      .post('/api/entities')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ mitreId: 'G9TESTENT', entityType: 'ThreatActor', name: 'Test Group 9', description: 'integration test' });
    expect(c.status).toBe(201);

    const dup = await request(app)
      .post('/api/entities')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ mitreId: 'G9TESTENT', entityType: 'ThreatActor', name: 'dupe' });
    expect(dup.status).toBe(409);

    const g = await request(app).get('/api/entities/G9TESTENT').set('Authorization', `Bearer ${adminToken}`);
    expect(g.status).toBe(200);
    expect(g.body.entity.entityType).toBe('ThreatActor');

    const u = await request(app)
      .put('/api/entities/G9TESTENT')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'Test Group 9 v2' });
    expect(u.status).toBe(200);
    expect(u.body.entity.name).toBe('Test Group 9 v2');

    const d = await request(app).delete('/api/entities/G9TESTENT').set('Authorization', `Bearer ${adminToken}`);
    expect(d.status).toBe(200);
    const gone = await request(app).get('/api/entities/G9TESTENT').set('Authorization', `Bearer ${adminToken}`);
    expect(gone.status).toBe(404);
  });

  test('analyst cannot write documents (403)', async () => {
    const r = await request(app)
      .post('/api/entities')
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ mitreId: 'G9TESTNA', entityType: 'ThreatActor', name: 'nope' });
    expect(r.status).toBe(403);
  });

  test('report POST triggers chunking pipeline; PUT/DELETE work', async () => {
    const text = 'APT29 (Cozy Bear) conducted spearphishing campaigns. '.repeat(300);
    const c = await request(app)
      .post('/api/reports')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        title: 'Integration Test Report',
        source: 'SG Tests',
        url: 'https://example.invalid/report',
        rawText: text,
        entityMentions: ['G0016'],
      });
    expect(c.status).toBe(201);
    expect(c.body.chunksGenerated).toBeGreaterThan(0);
    const reportId = c.body.report._id;
    const rid = ObjectId.createFromHexString(reportId);

    const db = await getDb();
    const chunks = await db.collection('chunks').countDocuments({ reportId: rid });
    expect(chunks).toBe(c.body.chunksGenerated);
    const chunk = await db.collection('chunks').findOne({ reportId: rid });
    expect(chunk.entityIds).toContain('G0016');
    expect(chunk.embedding.length).toBeGreaterThan(0);
    expect(chunk.embedding.reduce((a, b) => a + b * b, 0)).toBeCloseTo(1, 1); // normalised

    const g = await request(app).get(`/api/reports/${reportId}`).set('Authorization', `Bearer ${adminToken}`);
    expect(g.status).toBe(200);
    expect(g.body.chunks.length).toBe(chunks);

    const u = await request(app)
      .put(`/api/reports/${reportId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ title: 'Integration Test Report v2' });
    expect(u.status).toBe(200);
    expect(u.body.report.title).toBe('Integration Test Report v2');

    const d = await request(app).delete(`/api/reports/${reportId}`).set('Authorization', `Bearer ${adminToken}`);
    expect(d.status).toBe(200);
    expect(await db.collection('chunks').countDocuments({ reportId: rid })).toBe(0);
  });

  test('vulnerabilities GET filter + admin POST/PUT/DELETE', async () => {
    const c = await request(app)
      .post('/api/vulnerabilities')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ cveId: 'CVE-2099-TEST01', description: 'test vuln', cvss: { baseScore: 9.9, severity: 'CRITICAL', vector: 'X' } });
    expect(c.status).toBe(201);

    const dup = await request(app)
      .post('/api/vulnerabilities')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ cveId: 'CVE-2099-TEST01' });
    expect(dup.status).toBe(409);

    const list = await request(app)
      .get('/api/vulnerabilities?severity=CRITICAL&limit=5000')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(list.status).toBe(200);
    expect(list.body.vulnerabilities.map((v) => v.cveId)).toContain('CVE-2099-TEST01');

    const u = await request(app)
      .put('/api/vulnerabilities/CVE-2099-TEST01')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ description: 'updated' });
    expect(u.status).toBe(200);
    expect(u.body.vulnerability.description).toBe('updated');

    const d = await request(app).delete('/api/vulnerabilities/CVE-2099-TEST01').set('Authorization', `Bearer ${adminToken}`);
    expect(d.status).toBe(200);
  });

  test('users list + role change are admin-only', async () => {
    const forbidden = await request(app).get('/api/users').set('Authorization', `Bearer ${analystToken}`);
    expect(forbidden.status).toBe(403);

    const list = await request(app).get('/api/users').set('Authorization', `Bearer ${adminToken}`);
    expect(list.status).toBe(200);
    const analyst = list.body.users.find((u) => u.email === 'testanalyst@sg.test');
    expect(analyst).toBeTruthy();

    const roleChange = await request(app)
      .patch(`/api/users/${analyst._id}/role`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ role: 'admin' });
    expect(roleChange.status).toBe(200);
    expect(roleChange.body.user.role).toBe('admin');

    await request(app)
      .patch(`/api/users/${analyst._id}/role`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ role: 'analyst' });
  });
});