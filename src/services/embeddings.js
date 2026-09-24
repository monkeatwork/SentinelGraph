/**
 * Phase 5a — 768/384-dim dense embedding computation.
 *
 * Two pluggable engines (swappable via EMBEDDING_MODE):
 *  - transformers: all-MiniLM-L6-v2 via @huggingface/transformers (384-d, real semantics;
 *    downloads ~90 MB ONNX model on first use). Falls back to `hash` if unavailable.
 *  - hash: offline hashing-trick bag-of-words vectors (768-d, L2-normalised).
 *
 * Dimension consistency matters more than the number (plan §5a.2) — one dim is
 * declared per engine and used everywhere (chunks, retrieval, vector index attempt).
 */
const HASH_DIM = parseInt(process.env.EMBEDDING_DIM || '768', 10);
const TF_DIM = 384;

let pipelinePromise = null;
let mode = process.env.EMBEDDING_MODE || 'hash'; // default offline; switch to transformers in .env

/** Lazily load the transformers pipeline (with in-process model download). */
function getPipeline() {
  if (!pipelinePromise) {
    pipelinePromise = (async () => {
      try {
        const { pipeline } = await import('@huggingface/transformers');
        return await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2');
      } catch (e) {
        console.warn(`[embeddings] transformers unavailable (${e.message}); using hash engine`);
        mode = 'hash';
        return null;
      }
    })();
  }
  return pipelinePromise;
}

// --- hash engine -----------------------------------------------------------

function hashCode(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

function hashEmbedding(text) {
  const vec = new Array(HASH_DIM).fill(0);
  const tokens = text.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 2);
  for (const t of tokens) {
    vec[hashCode(t) % HASH_DIM] += 1;
  }
  return normalize(vec);
}

function normalize(vec) {
  let norm = 0;
  for (const v of vec) norm += v * v;
  norm = Math.sqrt(norm) || 1;
  return vec.map((v) => v / norm);
}

// --- transformers engine ----------------------------------------------------

async function tfEmbed(texts) {
  const pipe = await getPipeline();
  if (!pipe) return texts.map(hashEmbedding);
  const out = await pipe(texts, { pooling: 'mean', normalize: true });
  // { data: Float32Array, dims: [n, 384] }
  const dims = out.dims[out.dims.length - 1];
  const rows = [];
  for (let i = 0; i < texts.length; i++) {
    const start = i * dims;
    rows.push(Array.from(out.data.subarray(start, start + dims)));
  }
  return rows;
}

/** Embed an array of texts → Array<Array<number>>. */
async function embedTexts(texts) {
  if (mode === 'transformers') {
    try {
      return await tfEmbed(texts);
    } catch (e) {
      console.warn(`[embeddings] transformers failed (${e.message}); falling back to hash`);
      mode = 'hash';
    }
  }
  return texts.map(hashEmbedding);
}

function getDim() {
  return mode === 'transformers' ? TF_DIM : HASH_DIM;
}

// --- similarity --------------------------------------------------------------

function cosine(a, b) {
  let dot = 0;
  let na = 0;
  let nb = 0;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (!na || !nb) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

module.exports = { embedTexts, cosine, getDim };