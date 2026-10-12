/**
 * Review 3 — LLM answer mode on POST /api/qa/ask.
 * The LLM client is mocked: these tests never call a real provider and need no API key.
 */
jest.mock('../src/services/llm', () => {
  const actual = jest.requireActual('../src/services/llm');
  return {
    ...actual,
    generate: jest.fn(),
    isConfigured: jest.fn(() => true),
  };
});

const request = require('supertest');

const app = require('../src/server');
const llm = require('../src/services/llm');
const { buildLlmPrompt } = require('../src/services/answerBuilder');
const { ensureTestUsers, login } = require('./helpers');

const QUESTION = 'Which adversary groups exploit Log4j, and how?';
let token;

beforeAll(async () => {
  await ensureTestUsers();
  token = await login(request(app), 'testanalyst@sg.test', 'AnalystPass123');
});

beforeEach(() => llm.generate.mockReset());

const ask = (body) => request(app).post('/api/qa/ask').set('Authorization', `Bearer ${token}`).send(body);

describe('Q&A answer modes (Review 3)', () => {
  test('default request stays in template mode and never calls the LLM', async () => {
    const res = await ask({ question: QUESTION, depth: 2 });
    expect(res.status).toBe(200);
    expect(res.body.answerMode).toBe('template');
    expect(res.body.answer).toContain('template-mode answer');
    expect(llm.generate).not.toHaveBeenCalled();
  });

  test('mode=llm returns a grounded answer citing a stored report', async () => {
    llm.generate.mockResolvedValue({
      text: 'Log4Shell (CVE-2021-44228) is exploited via JNDI lookups [1]. Patch Log4j [1][2].',
      provider: 'gemini',
      model: 'mock-model',
    });
    const res = await ask({ question: QUESTION, depth: 2, mode: 'llm' });
    expect(res.status).toBe(200);
    expect(res.body.answerMode).toBe('llm');
    expect(res.body.llm).toMatchObject({ provider: 'gemini', model: 'mock-model' });
    expect(res.body.answer).toContain('Sources:');
    expect(res.body.answer).toMatch(/\[1\] .+/);
    expect(res.body.attackPaths.length).toBeGreaterThan(0);

    // the prompt carried the question, typed graph paths and numbered evidence
    const { prompt } = llm.generate.mock.calls[0][0];
    expect(prompt).toContain(QUESTION);
    expect(prompt).toMatch(/-(EXPLOITS|AFFECTS|USES_TECHNIQUE|PERFORMS)->|<-(EXPLOITS|AFFECTS|USES_TECHNIQUE|PERFORMS)-/);
    expect(prompt).toContain('[1] "');

    // the audit log records the mode and only the cited reports
    const { getDb } = require('../src/config/mongo');
    const log = await (await getDb()).collection('queryLogs').findOne({ question: QUESTION }, { sort: { askedAt: -1 } });
    expect(log.answerMode).toBe('llm');
    expect(log.citedReportIds.length).toBeGreaterThan(0);
  });

  test('LLM failure (e.g. rate limit) falls back to the template answer', async () => {
    llm.generate.mockRejectedValue(new llm.LlmError('gemini: quota exceeded', { status: 429, retryable: true }));
    const res = await ask({ question: QUESTION, depth: 2, mode: 'llm' });
    expect(res.status).toBe(200);
    expect(res.body.answerMode).toBe('template');
    expect(res.body.llm.fallbackReason).toContain('quota');
    expect(res.body.answer).toContain('CVE-2021-44228');
  });

  test('an LLM answer that cites no provided source is rejected', async () => {
    llm.generate.mockResolvedValue({ text: 'Lots of groups, trust me. [99]', provider: 'gemini', model: 'mock-model' });
    const res = await ask({ question: QUESTION, depth: 2, mode: 'llm' });
    expect(res.body.answerMode).toBe('template');
    expect(res.body.llm.fallbackReason).toMatch(/cited none/);
  });

  test('unknown mode is a 400', async () => {
    const res = await ask({ question: QUESTION, mode: 'magic' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('BAD_REQUEST');
  });

  test('GET /api/qa/modes reports template default and LLM availability', async () => {
    const res = await request(app).get('/api/qa/modes').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.default).toBe('template');
    expect(res.body.modes).toEqual(['template', 'llm']);
    expect(res.body.llm.available).toBe(true);
  });

  test('prompt builder only numbers report-backed chunks', () => {
    const rep = { _id: 'r1', title: 'Real report', source: 'CISA', publishedDate: '2021-12-28', url: 'https://x' };
    const { sources, prompt } = buildLlmPrompt({
      question: 'q',
      resolved: { names: [], cves: [], mitreIds: [] },
      chunks: [
        { chunk: { reportId: 'missing', text: 'orphan' }, score: 0.9 },
        { chunk: { reportId: 'r1', text: 'grounded text' }, score: 0.8 },
      ],
      reportsById: new Map([['r1', rep]]),
    });
    expect(sources).toHaveLength(1);
    expect(prompt).toContain('[1] "Real report"');
    expect(prompt).not.toContain('orphan');
  });
});
