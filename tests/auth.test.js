const request = require('supertest');
const jwt = require('jsonwebtoken');

const app = require('../src/server');
const { ensureTestUsers, login } = require('./helpers');
const { JWT_SECRET } = require('../src/middleware/auth');
const { getDb } = require('../src/config/mongo');

let adminToken;
let analystToken;

const FRESH_EMAIL = `fresh-${Date.now()}@sg.test`;

beforeAll(async () => {
  await ensureTestUsers();
  adminToken = await login(request(app), 'testadmin@sg.test', 'AdminPass123');
  analystToken = await login(request(app), 'testanalyst@sg.test', 'AnalystPass123');
});

afterAll(async () => {
  const db = await getDb();
  await db.collection('users').deleteMany({ email: FRESH_EMAIL });
});

describe('API auth', () => {
  test('login returns a JWT with role claims', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'testadmin@sg.test', password: 'AdminPass123' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
    const payload = jwt.verify(res.body.token, JWT_SECRET);
    expect(payload.role).toBe('admin');
    expect(payload.role).toBe('admin');
  });

  test('login rejects a wrong password', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'testadmin@sg.test', password: 'nope' });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  test('no token → 401', async () => {
    const res = await request(app).get('/api/users');
    expect(res.status).toBe(401);
  });

  test('expired token → 401', async () => {
    const expired = jwt.sign({ sub: 'x', role: 'admin' }, JWT_SECRET, { expiresIn: -60 });
    const res = await request(app).get('/api/users').set('Authorization', `Bearer ${expired}`);
    expect(res.status).toBe(401);
    expect(res.body.error.message).toBe('Token expired');
  });

  test('register is admin-only (analyst → 403)', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ email: 'analyst-created@sg.test', password: 'Password123' });
    expect(res.status).toBe(403);
  });

  test('register creates a user; duplicate email → 409', async () => {
    const res1 = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: FRESH_EMAIL, password: 'Password123', role: 'analyst' });
    expect(res1.status).toBe(201);

    const res2 = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: FRESH_EMAIL, password: 'Password123' });
    expect(res2.status).toBe(409);
    expect(res2.body.error.code).toBe('DUPLICATE_KEY');
  });
});