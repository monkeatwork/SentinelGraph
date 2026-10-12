const request = require('supertest');

const app = require('../src/server');
const { ensureTestUsers, login } = require('./helpers');
const { getDriver } = require('../src/config/neo4j');
const { getDb } = require('../src/config/mongo');

let adminToken;
let analystToken;

beforeAll(async () => {
  await ensureTestUsers();
  adminToken = await login(request(app), 'testadmin@sg.test', 'AdminPass123');
  analystToken = await login(request(app), 'testanalyst@sg.test', 'AnalystPass123');
});

const clean = async (label, keyProp, key) => {
  const s = getDriver().session();
  try {
    await s.run(`MATCH (n:${label} {${keyProp}: $key}) DETACH DELETE n`, { key });
  } finally {
    await s.close();
  }
  // POST /api/graph mirrors entity labels into Mongo, so clean that side too
  if (keyProp === 'mitreId') await (await getDb()).collection('entities').deleteOne({ mitreId: key });
};

describe('Graph CRUD + role restrictions', () => {
  const MID = 'T9TESTCRUD';

  afterAll(async () => {
    await clean('Technique', 'mitreId', MID);
    await clean('Technique', 'mitreId', 'T9TESTSUBTECH');
    await clean('Malware', 'mitreId', 'S9TESTMAL');
    getDriver().close();
  });

  test('admin: create → read → update → delete round-trip', async () => {
    // create
    const c = await request(app)
      .post('/api/graph/Technique')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ mitreId: MID, name: 'Test Technique 9', platforms: ['Windows'] });
    expect(c.status).toBe(201);

    // read
    const r = await request(app).get(`/api/graph/Technique/${MID}`).set('Authorization', `Bearer ${adminToken}`);
    expect(r.status).toBe(200);
    expect(r.body.node.name).toBe('Test Technique 9');

    // update
    const u = await request(app)
      .patch(`/api/graph/Technique/${MID}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'Test Technique 9 (renamed)' });
    expect(u.status).toBe(200);
    expect(u.body.node.name).toBe('Test Technique 9 (renamed)');

    // delete
    const d = await request(app).delete(`/api/graph/Technique/${MID}`).set('Authorization', `Bearer ${adminToken}`);
    expect(d.status).toBe(200);

    // gone
    const g = await request(app).get(`/api/graph/Technique/${MID}`).set('Authorization', `Bearer ${adminToken}`);
    expect(g.status).toBe(404);
  });

  test('graph write mirrors into Mongo entities; delete mirrors back', async () => {
    await request(app)
      .post('/api/graph/Malware')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ mitreId: 'S9TESTMAL', name: 'Test Malware 9' });
    const e = await request(app).get('/api/entities/S9TESTMAL').set('Authorization', `Bearer ${adminToken}`);
    expect(e.status).toBe(200);
    expect(e.body.entity.entityType).toBe('Malware');

    await request(app).delete('/api/graph/Malware/S9TESTMAL').set('Authorization', `Bearer ${adminToken}`);
    const g = await request(app).get('/api/entities/S9TESTMAL').set('Authorization', `Bearer ${adminToken}`);
    expect(g.status).toBe(404);
  });

  test('DELETE detaches relationships (node + rel removed, neighbour survives)', async () => {
    // create parent + child through the API, link them directly
    await request(app)
      .post('/api/graph/Technique')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ mitreId: 'T9TESTCRUD', name: 'Parent Test' });
    await request(app)
      .post('/api/graph/Technique')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ mitreId: 'T9TESTSUBTECH', name: 'Subtest' });
    const s = getDriver().session();
    try {
      await s.run(
        `MATCH (a:Technique {mitreId: 'T9TESTSUBTECH'}), (b:Technique {mitreId: 'T9TESTCRUD'})
         MERGE (a)-[r:SUBTECHNIQUE_OF]->(b)`
      );
      const before = await s.run(
        `MATCH (:Technique {mitreId: 'T9TESTSUBTECH'})-[:SUBTECHNIQUE_OF]->(b) RETURN b.mitreId AS m`
      );
      expect(before.records.length).toBe(1);

      await request(app).delete('/api/graph/Technique/T9TESTSUBTECH').set('Authorization', `Bearer ${adminToken}`);

      const after = await s.run(`MATCH (b:Technique {mitreId: 'T9TESTCRUD'}) RETURN count(b) AS c`);
      expect(after.records[0].get('c').toNumber()).toBe(1); // neighbour intact
      const rel = await s.run(
        `MATCH (:Technique {mitreId: 'T9TESTSUBTECH'})-[:SUBTECHNIQUE_OF]->(:Technique) RETURN count(*) AS c`
      );
      expect(rel.records[0].get('c').toNumber()).toBe(0); // relationship detached
    } finally {
      await s.close();
    }
  });

  test('analyst gets 403 on graph writes; admin succeeds (FR12)', async () => {
    const post = await request(app)
      .post('/api/graph/Technique')
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ mitreId: 'T9TESTANALYST', name: 'x' });
    expect(post.status).toBe(403);

    const del = await request(app)
      .delete('/api/graph/Technique/anything')
      .set('Authorization', `Bearer ${analystToken}`);
    expect(del.status).toBe(403);

    // admin can create another label fine
    const ok = await request(app)
      .post('/api/graph/Technique')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ mitreId: 'T9TESTANALYST', name: 'x' });
    expect(ok.status).toBe(201);
    await clean('Technique', 'mitreId', 'T9TESTANALYST');
  });

  test('duplicate key insert → 409 (not a crash)', async () => {
    await request(app)
      .post('/api/graph/Technique')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ mitreId: 'T9TESTDUP', name: 'one' });
    const dup = await request(app)
      .post('/api/graph/Technique')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ mitreId: 'T9TESTDUP', name: 'two' });
    expect(dup.status).toBe(409);
    expect(dup.body.error.code).toBe('DUPLICATE_KEY');
    await clean('Technique', 'mitreId', 'T9TESTDUP');
  });

  test('full-text search endpoint returns results', async () => {
    const r = await request(app).get('/api/graph/search?q=APT29').set('Authorization', `Bearer ${adminToken}`);
    expect(r.status).toBe(200);
    const ids = r.body.results.neo4j.map((x) => x.mitreId);
    expect(ids).toContain('G0016');
  });
});