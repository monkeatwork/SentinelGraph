/** Review 3 — saved queries embedded in the user document. */
const request = require('supertest');

const app = require('../src/server');
const { getDb } = require('../src/config/mongo');
const { ensureTestUsers, login } = require('./helpers');

const Q = 'Which adversary groups exploit Log4j, and how?';
const BASE = '/api/users/me/saved-queries';
let analyst;
let admin;

const clearSaved = async () => {
  const db = await getDb();
  await db.collection('users').updateMany({ email: { $in: ['testanalyst@sg.test', 'testadmin@sg.test'] } }, { $set: { savedQueries: [] } });
};

beforeAll(async () => {
  await ensureTestUsers();
  analyst = await login(request(app), 'testanalyst@sg.test', 'AnalystPass123');
  admin = await login(request(app), 'testadmin@sg.test', 'AdminPass123');
});
beforeEach(clearSaved);
afterAll(clearSaved);

const as = (token) => ({
  get: () => request(app).get(BASE).set('Authorization', `Bearer ${token}`),
  post: (body) => request(app).post(BASE).set('Authorization', `Bearer ${token}`).send(body),
  del: (id) => request(app).delete(`${BASE}/${id}`).set('Authorization', `Bearer ${token}`),
});

describe('Saved queries', () => {
  test('analyst saves the flagship question, lists it, and re-runs it', async () => {
    const c = await as(analyst).post({ question: Q, depth: 2, mode: 'llm' });
    expect(c.status).toBe(201);
    expect(c.body.savedQuery).toMatchObject({ question: Q, depth: 2, mode: 'llm', name: Q.slice(0, 60) });
    expect(c.body.savedQuery).not.toHaveProperty('questionKey');

    const l = await as(analyst).get();
    expect(l.status).toBe(200);
    expect(l.body.count).toBe(1);
    const saved = l.body.savedQueries[0];

    // re-run = ask with the saved parameters (template so no LLM is needed in tests)
    const run = await request(app).post('/api/qa/ask').set('Authorization', `Bearer ${analyst}`)
      .send({ question: saved.question, depth: saved.depth });
    expect(run.status).toBe(200);
    expect(run.body.resolved.cves).toContain('CVE-2021-44228');
  });

  test('same question/depth/mode is a 409, a different depth is allowed', async () => {
    expect((await as(analyst).post({ question: Q })).status).toBe(201);
    const dup = await as(analyst).post({ question: `  ${Q.toUpperCase()}  ` });
    expect(dup.status).toBe(409);
    expect(dup.body.error.code).toBe('DUPLICATE_KEY');
    expect((await as(analyst).post({ question: Q, depth: 3 })).status).toBe(201);
  });

  test('saved queries are per user', async () => {
    await as(analyst).post({ question: Q });
    const other = await as(admin).get();
    expect(other.body.count).toBe(0);
  });

  test('delete removes only the caller\'s query; unknown id is 404', async () => {
    const c = await as(analyst).post({ question: Q });
    const id = c.body.savedQuery._id;
    expect((await as(admin).del(id)).status).toBe(404); // not admin's to delete
    expect((await as(analyst).del(id)).status).toBe(200);
    expect((await as(analyst).get()).body.count).toBe(0);
    expect((await as(analyst).del(id)).status).toBe(404);
    expect((await as(analyst).del('not-an-id')).status).toBe(400);
  });

  test('validation and the 25-query cap', async () => {
    expect((await as(analyst).post({})).status).toBe(400);
    expect((await as(analyst).post({ question: Q, depth: 9 })).status).toBe(400);
    expect((await as(analyst).post({ question: Q, mode: 'magic' })).status).toBe(400);
    for (let i = 0; i < 25; i++) expect((await as(analyst).post({ question: `question ${i}` })).status).toBe(201);
    const over = await as(analyst).post({ question: 'one too many' });
    expect(over.status).toBe(400);
    expect(over.body.error.code).toBe('LIMIT_REACHED');
  });

  test('requires a token', async () => {
    expect((await request(app).get(BASE)).status).toBe(401);
  });
});
