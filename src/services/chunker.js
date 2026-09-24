/**
 * Phase 5a — overlapping text chunker.
 * ~500-token chunks with ~50-token overlap (plan §5a.1).
 */
const TARGET_TOKENS = 500;
const OVERLAP_TOKENS = 50;

/** Crude tokeniser: ~4 chars ≈ 1 token; words are the natural unit here. */
function tokenize(text) {
  return text.split(/\s+/).filter(Boolean);
}

/**
 * Split `text` into overlapping chunks.
 * @returns {string[]}
 */
function chunkText(text, { targetTokens = TARGET_TOKENS, overlapTokens = OVERLAP_TOKENS } = {}) {
  const words = tokenize(text);
  if (!words.length) return [];
  if (words.length <= targetTokens) return [words.join(' ')];
  const step = Math.max(1, targetTokens - overlapTokens);
  const chunks = [];
  for (let i = 0; i < words.length; i += step) {
    const slice = words.slice(i, i + targetTokens);
    if (slice.length < Math.min(50, targetTokens) && chunks.length) continue; // drop trailing slivers
    chunks.push(slice.join(' '));
  }
  return chunks;
}

module.exports = { chunkText, tokenize };