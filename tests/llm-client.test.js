/**
 * Review 3 — LLM client fallback order (keys → models → fallback provider) and cooldowns.
 * fetch is mocked: no network, no real keys.
 */
const ENV_KEYS = ['LLM_PROVIDER', 'LLM_API_KEY', 'LLM_MODEL', 'LLM_FALLBACK_PROVIDER', 'LLM_FALLBACK_API_KEY', 'LLM_FALLBACK_MODEL', 'LLM_FALLBACK_BASE_URL'];
const saved = {};
const realFetch = global.fetch;

const llm = require('../src/services/llm');

const geminiOk = (text, model = 'gm') => ({
  ok: true, status: 200,
  json: async () => ({ candidates: [{ content: { parts: [{ text }] } }], modelVersion: model, usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5 } }),
});
const openAiOk = (text, model = 'llama') => ({
  ok: true, status: 200,
  json: async () => ({ choices: [{ message: { content: text } }], model, usage: { prompt_tokens: 10, completion_tokens: 5 } }),
});
const fail = (status, message = 'nope') => ({ ok: false, status, json: async () => ({ error: { message } }) });

function setEnv(vars) {
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, vars);
}

beforeAll(() => { for (const k of ENV_KEYS) saved[k] = process.env[k]; });
afterAll(() => {
  for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  global.fetch = realFetch;
});
beforeEach(() => { llm.resetCooldowns(); global.fetch = jest.fn(); });

const keyOf = (call) => call[1].headers['x-goog-api-key'] || call[1].headers.Authorization;
const modelOf = (call) => (call[0].match(/models\/([^:]+):/) || [])[1] || JSON.parse(call[1].body).model;

describe('LLM client fallback chain', () => {
  test('targets are ordered key x model, then the fallback provider', () => {
    setEnv({ LLM_API_KEY: 'k1,k2', LLM_MODEL: 'm1,m2', LLM_FALLBACK_PROVIDER: 'groq', LLM_FALLBACK_API_KEY: 'g1', LLM_FALLBACK_MODEL: 'llama' });
    const t = llm.llmConfig().targets.map((x) => `${x.provider}:${x.apiKey}:${x.model}`);
    expect(t).toEqual(['gemini:k1:m1', 'gemini:k1:m2', 'gemini:k2:m1', 'gemini:k2:m2', 'groq:g1:llama']);
  });

  test('a rate-limited first key falls through to the second key', async () => {
    setEnv({ LLM_API_KEY: 'k1,k2', LLM_MODEL: 'm1' });
    global.fetch.mockResolvedValueOnce(fail(429, 'quota')).mockResolvedValueOnce(geminiOk('answer [1]'));
    const out = await llm.generate({ system: 's', prompt: 'p' });
    expect(out.text).toBe('answer [1]');
    expect(out.via).toBe('primary key 2');
    expect(global.fetch.mock.calls.map(keyOf)).toEqual(['k1', 'k2']);
  });

  test('all Gemini targets failing hands over to the OpenAI-compatible fallback', async () => {
    setEnv({ LLM_API_KEY: 'k1', LLM_MODEL: 'm1,m2', LLM_FALLBACK_PROVIDER: 'groq', LLM_FALLBACK_API_KEY: 'g1', LLM_FALLBACK_MODEL: 'llama' });
    global.fetch
      .mockResolvedValueOnce(fail(503, 'overloaded'))
      .mockResolvedValueOnce(fail(429, 'quota'))
      .mockResolvedValueOnce(openAiOk('fallback answer'));
    const out = await llm.generate({ system: 's', prompt: 'p' });
    expect(out).toMatchObject({ provider: 'groq', via: 'fallback', attempts: 3, text: 'fallback answer' });
    const last = global.fetch.mock.calls[2];
    expect(last[0]).toBe('https://api.groq.com/openai/v1/chat/completions');
    expect(keyOf(last)).toBe('Bearer g1');
  });

  test('a 429 puts that key/model on cooldown for the next request', async () => {
    setEnv({ LLM_API_KEY: 'k1,k2', LLM_MODEL: 'm1' });
    global.fetch.mockResolvedValueOnce(fail(429)).mockResolvedValueOnce(geminiOk('a [1]'));
    await llm.generate({ system: 's', prompt: 'p' });
    global.fetch.mockClear();
    global.fetch.mockResolvedValueOnce(geminiOk('b [1]'));
    await llm.generate({ system: 's', prompt: 'p' });
    expect(global.fetch.mock.calls.map(keyOf)).toEqual(['k2']); // k1 skipped while cooling down
  });

  test('a non-retryable error (400) stops the chain', async () => {
    setEnv({ LLM_API_KEY: 'k1,k2', LLM_MODEL: 'm1' });
    global.fetch.mockResolvedValueOnce(fail(400, 'bad request'));
    await expect(llm.generate({ system: 's', prompt: 'p' })).rejects.toThrow('bad request');
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('error messages name targets but never contain API keys', async () => {
    setEnv({ LLM_API_KEY: 'secretkey123', LLM_MODEL: 'm1,m2' });
    global.fetch.mockResolvedValue(fail(503, 'overloaded'));
    const err = await llm.generate({ system: 's', prompt: 'p' }).catch((e) => e);
    expect(err.message).toContain('all LLM targets failed');
    expect(err.message).not.toContain('secretkey123');
    expect(global.fetch.mock.calls.map(modelOf)).toEqual(['m1', 'm2']);
  });

  test('not configured without any key', () => {
    setEnv({});
    expect(llm.isConfigured()).toBe(false);
  });
});
