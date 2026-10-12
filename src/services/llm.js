/**
 * Review 3 — thin LLM client used by the Q&A "llm" answer mode.
 * Provider switch keeps the rest of the pipeline provider-agnostic. Gemini is called over
 * its REST API with built-in fetch (no SDK dependency).
 * LLM_MODEL may be a comma-separated fallback chain: on an overload/rate-limit response
 * the next model is tried before giving up.
 */
require('dotenv').config();

const DEFAULT_MODELS = {
  gemini: 'gemini-flash-lite-latest,gemini-flash-latest',
};

function llmConfig() {
  const provider = (process.env.LLM_PROVIDER || 'gemini').toLowerCase();
  const models = (process.env.LLM_MODEL || DEFAULT_MODELS[provider] || '')
    .split(',')
    .map((m) => m.trim())
    .filter(Boolean);
  return {
    provider,
    models,
    apiKey: process.env.LLM_API_KEY || '',
    timeoutMs: Number(process.env.LLM_TIMEOUT_MS) || 12000,
  };
}

function isConfigured() {
  const c = llmConfig();
  return Boolean(c.apiKey && c.models.length && c.provider in DEFAULT_MODELS);
}

class LlmError extends Error {
  constructor(message, { status, retryable } = {}) {
    super(message);
    this.status = status;
    this.retryable = Boolean(retryable);
  }
}

async function geminiGenerate({ system, prompt, model, apiKey, timeoutMs }) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: system }] },
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 1024 },
      }),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = (json.error && json.error.message) || `HTTP ${res.status}`;
      throw new LlmError(`${model}: ${msg}`, { status: res.status, retryable: [429, 500, 503].includes(res.status) });
    }
    const cand = json.candidates && json.candidates[0];
    const text = cand && cand.content && (cand.content.parts || []).map((p) => p.text || '').join('').trim();
    if (!text) throw new LlmError(`${model}: empty response (${(cand && cand.finishReason) || 'no candidate'})`, { retryable: true });
    return { text, model: json.modelVersion || model };
  } catch (e) {
    if (e.name === 'AbortError') throw new LlmError(`${model}: timed out after ${timeoutMs} ms`, { retryable: true });
    if (e instanceof LlmError) throw e;
    throw new LlmError(`${model}: ${e.message}`, { retryable: true });
  } finally {
    clearTimeout(timer);
  }
}

const PROVIDERS = { gemini: geminiGenerate };

/** Generate text; walks the model fallback chain on retryable failures. */
async function generate({ system, prompt }) {
  const c = llmConfig();
  if (!isConfigured()) throw new LlmError('LLM is not configured (set LLM_API_KEY in .env)');
  const call = PROVIDERS[c.provider];
  let lastErr;
  for (const model of c.models) {
    try {
      const out = await call({ system, prompt, model, apiKey: c.apiKey, timeoutMs: c.timeoutMs });
      return { ...out, provider: c.provider };
    } catch (e) {
      lastErr = e;
      if (!e.retryable) break;
    }
  }
  throw lastErr;
}

module.exports = { generate, isConfigured, llmConfig, LlmError };
