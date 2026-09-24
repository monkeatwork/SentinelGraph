/**
 * Phase 5a — vector retrieval over `chunks`.
 *
 * Community MongoDB has no Atlas Vector Search, so retrieval runs a
 * brute-force cosine over the entityIds-filtered candidate set (plan §5a Option B).
 * The multikey index on chunk.entityIds keeps the candidate set small
 * (NFR2: top-10 in <300 ms on a few hundred candidates).
 */
const { getDb } = require('../config/mongo');
const { embedTexts, cosine } = require('./embeddings');

/**
 * @param {object} opts
 * @param {string[]} opts.entityIds   mitreIds/cveIds/cpeNames the chunks must touch
 * @param {string} opts.query         natural-language query text
 * @param {number} opts.topK
 * @returns {Promise<Array<{chunk, score}>>} highest-score first
 */
async function vectorSearch({ entityIds = [], query, topK = 10 }) {
  const db = await getDb();
  const filter =
    entityIds && entityIds.length
      ? { entityIds: { $in: entityIds } }
      : {};

  const [qvec, candidates] = await Promise.all([
    embedTexts([query]),
    db.collection('chunks').find(filter).limit(2000).toArray(),
  ]);

  const q = qvec[0];
  const scored = [];
  for (const c of candidates) {
    if (!c.embedding || !c.embedding.length) continue;
    const s = cosine(q, c.embedding);
    scored.push({ chunk: c, score: s });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, topK);
}

module.exports = { vectorSearch };