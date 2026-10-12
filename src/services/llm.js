/**
 * Review 3 — thin LLM client used by the Q&A "llm" answer mode.
 * Provider switch keeps the rest of the pipeline provider-agnostic; every provider is called
 * over plain REST with built-in fetch (no SDK dependency).
 *
 * Fallback order (first success wins):
 *   1. primary provider: each key in LLM_API_KEY (comma-separated) x each model in LLM_MODEL
 *   2. optional fallback provider: LLM_FALLBACK_API_KEY x LLM_FALLBACK_MODEL
 * Overload / rate-limit / auth failures move on to the next target; a target that was just
 * rate limited is skipped for a cooldown so later questions do not wait on it again.
 */
require('dotenv').config();

const DEFAULT_MODELS = {
  gemini: 'gemini-flash-lite-latest,gemini-flash-latest',
};

// OpenAI-compatible chat-completions providers (free tiers available on both)
const OPENAI_COMPATIBLE_BASE = {
  groq: 'https://api.groq.com/openai/v1',
  openrouter: 'https://openrouter.ai/api/v1',
};

const RATE_LIMIT_COOLDOWN_MS = Number(process.env.LLM_COOLDOWN_MS) || 60 * 1000;

const list = (v) => String(v || '').split(',').map((x) => x.trim()).filter(Boolean);

const isKnownProvider = (p) => p === 'gemini' || p in OPENAI_COMPATIBLE_BASE || p === 'openai-compatible';

function providerTargets(provider, keys, models, baseUrl, tier) {
  if (!isKnownProvider(provider) || !keys.length || !models.length) return [];
  if (provider === 'openai-compatible' && !baseUrl) return [];
  const out = [];
  keys.forEach((apiKey, k) => {
    for (const model of models) out.push({ provider, apiKey, model, baseUrl, label: `${tier}${keys.length > 1 ? ` key ${k + 1}` : ''}` });
  });
  return out;
}

function llmConfig() {
  const provider = (process.env.LLM_PROVIDER || 'gemini').toLowerCase();
  const models = list(process.env.LLM_MODEL || DEFAULT_MODELS[provider]);
  const fbProvider = (process.env.LLM_FALLBACK_PROVIDER || '').toLowerCase();
  const fbModels = list(process.env.LLM_FALLBACK_MODEL || DEFAULT_MODELS[fbProvider]);
  const targets = [
    ...providerTargets(provider, list(process.env.LLM_API_KEY), models, process.env.LLM_BASE_URL, 'primary'),
    ...providerTargets(fbProvider, list(process.env.LLM_FALLBACK_API_KEY), fbModels, process.env.LLM_FALLBACK_BASE_URL, 'fallback'),
  ];
  return {
    provider,
    models,
    fallback: fbProvider ? { provider: fbProvider, models: fbModels } : null,
    targets,
    timeoutMs: Number(process.env.LLM_TIMEOUT_MS) || 12000,
  };
}

function isConfigured() {
  return llmConfig().targets.length > 0;
}

class LlmError extends Error {
  constructor(message, { status, retryable } = {}) {
    super(message);
    this.status = status;
    this.retryable = Boolean(retryable);
  }
}

// 401/403 = bad or revoked key: worth trying the next key, not worth failing the request
const RETRYABLE_STATUS = new Set([401, 403, 408, 429, 500, 502, 503, 504]);

async function postJson(url, headers, body, { model, timeoutMs }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = json.error;
      const msg = (err && (err.message || (typeof err === 'string' ? err : null))) || `HTTP ${res.status}`;
      throw new LlmError(`${model}: ${msg}`, { status: res.status, retryable: RETRYABLE_STATUS.has(res.status) });
    }
    return json;
  } catch (e) {
    if (e.name === 'AbortError') throw new LlmError(`${model}: timed out after ${timeoutMs} ms`, { retryable: true });
    if (e instanceof LlmError) throw e;
    throw new LlmError(`${model}: ${e.message}`, { retryable: true });
  } finally {
    clearTimeout(timer);
  }
}

async function geminiGenerate({ system, prompt, model, apiKey, timeoutMs }) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  const json = await postJson(url, { 'x-goog-api-key': apiKey }, {
    systemInstruction: { parts: [{ text: system }] },
    contents: [{ role: 'user', parts: [{ text: prompt }] }],
    generationConfig: { temperature: 0.2, maxOutputTokens: 1024 },
  }, { model, timeoutMs });
  const cand = json.candidates && json.candidates[0];
  const text = cand && cand.content && (cand.content.parts || []).map((p) => p.text || '').join('').trim();
  if (!text) throw new LlmError(`${model}: empty response (${(cand && cand.finishReason) || 'no candidate'})`, { retryable: true });
  const u = json.usageMetadata || {};
  return { text, model: json.modelVersion || model, usage: { input: u.promptTokenCount || 0, output: u.candidatesTokenCount || 0 } };
}

async function openAiCompatibleGenerate({ system, prompt, model, apiKey, timeoutMs, provider, baseUrl }) {
  const base = (baseUrl || OPENAI_COMPATIBLE_BASE[provider]).replace(/\/+$/, '');
  const json = await postJson(`${base}/chat/completions`, { Authorization: `Bearer ${apiKey}` }, {
    model,
    temperature: 0.2,
    max_tokens: 1024,
    messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }],
  }, { model, timeoutMs });
  const text = json.choices && json.choices[0] && json.choices[0].message && (json.choices[0].message.content || '').trim();
  if (!text) throw new LlmError(`${model}: empty response`, { retryable: true });
  const u = json.usage || {};
  return { text, model: json.model || model, usage: { input: u.prompt_tokens || 0, output: u.completion_tokens || 0 } };
}

const callFor = (provider) => (provider === 'gemini' ? geminiGenerate : openAiCompatibleGenerate);

// target id → time it was rate limited; module-level so it spans requests
const cooldown = new Map();
const targetId = (t) => `${t.provider}|${t.model}|${t.apiKey.slice(-6)}`;

/** Generate text, walking keys → models → fallback provider on retryable failures. */
async function generate({ system, prompt }) {
  const c = llmConfig();
  if (!c.targets.length) throw new LlmError('LLM is not configured (set LLM_API_KEY in .env)');
  const now = Date.now();
  const ready = c.targets.filter((t) => !(now - (cooldown.get(targetId(t)) || 0) < RATE_LIMIT_COOLDOWN_MS));
  const order = ready.length ? ready : c.targets; // everything cooling down: try anyway
  const errors = [];
  for (const t of order) {
    try {
      const out = await callFor(t.provider)({ system, prompt, ...t, timeoutMs: c.timeoutMs });
      return { ...out, provider: t.provider, via: t.label, attempts: errors.length + 1 };
    } catch (e) {
      if (e.status === 429) cooldown.set(targetId(t), Date.now());
      errors.push(`${t.label}: ${e.message}`);
      if (!e.retryable) break;
    }
  }
  const err = new LlmError(errors.length > 1 ? `all LLM targets failed — ${errors.join(' | ')}` : errors[0] || 'LLM failed');
  throw err;
}

function resetCooldowns() {
  cooldown.clear();
}

module.exports = { generate, isConfigured, llmConfig, LlmError, resetCooldowns };
