/** Review 3 — attack-path directions, actor recommendations and mitigation priorities. */
const request = require('supertest');

const app = require('../src/server');
const { ensureTestUsers, login } = require('./helpers');

let token;
beforeAll(async () => {
  await ensureTestUsers();
  token = await login(request(app), 'testanalyst@sg.test', 'AnalystPass123');
});
const get = (url) => request(app).get(url).set('Authorization', `Bearer ${token}`);

describe('Insights and attack-path APIs (Review 3)', () => {
  test('shortest path returns typed, directed hops for log4j → APT29', async () => {
    const res = await get('/api/algorithms/shortest-path?from=log4j&to=APT29');
    expect(res.status).toBe(200);
    expect(res.body.rels).toHaveLength(res.body.hops);
    expect(res.body.rels[0]).toEqual({ type: 'AFFECTS', forward: false }); // CVE -AFFECTS-> Software
    expect(res.body.path[res.body.path.length - 1].name).toBe('APT29');
    const last = res.body.rels[res.body.rels.length - 1];
    expect(last).toEqual({ type: 'PERFORMS', forward: false }); // APT29 -PERFORMS-> technique
  });

  test('similar actors accepts a MITRE id and reports shared techniques', async () => {
    const res = await get('/api/algorithms/similar-actors?actor=G0016');
    expect(res.status).toBe(200);
    expect(res.body.actorName).toBe('APT29');
    expect(res.body.similar.length).toBeGreaterThan(0);
    const top = res.body.similar[0];
    expect(top.sharedTechniques).toBeGreaterThan(0);
    expect(top.sharedTechniques).toBeLessThanOrEqual(Math.min(top.techniqueCount, res.body.actorTechniques));
    // ranked by Jaccard
    const scores = res.body.similar.map((s) => s.jaccard);
    expect([...scores].sort((a, b) => b - a)).toEqual(scores);
  });

  test('mitigation priorities for an actor cover its techniques, ranked', async () => {
    const res = await get('/api/algorithms/mitigation-priorities?actor=APT29');
    expect(res.status).toBe(200);
    expect(res.body.actor.name).toBe('APT29');
    expect(res.body.mitigations.length).toBeGreaterThan(0);
    for (const m of res.body.mitigations) {
      expect(m.mitreId).toMatch(/^M\d{4}$/);
      expect(m.coverage).toBeLessThanOrEqual(m.total);
    }
    const scores = res.body.mitigations.map((m) => m.score);
    expect([...scores].sort((a, b) => b - a)).toEqual(scores);
  });

  test('mitigation priorities without an actor use the most-used techniques', async () => {
    const res = await get('/api/algorithms/mitigation-priorities');
    expect(res.status).toBe(200);
    expect(res.body.actor).toBeNull();
    expect(res.body.mitigations[0].total).toBe(50);
  });

  test('unknown actor is a 404', async () => {
    const res = await get('/api/algorithms/mitigation-priorities?actor=NoSuchGroup');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });
});
