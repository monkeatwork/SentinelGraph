/**
 * Report → chunks → embeddings pipeline (FR3, Phase 5a).
 * Idempotent: re-processing a report replaces its chunks.
 */
const { getDb } = require('../config/mongo');
const { chunkText } = require('./chunker');
const { embedTexts } = require('./embeddings');

async function processReport(reportId) {
  const db = await getDb();
  const report = await db.collection('reports').findOne({ _id: reportId });
  if (!report) throw new Error(`report not found: ${reportId}`);

  const texts = chunkText(report.rawText || '');
  if (!texts.length) {
    await db.collection('reports').updateOne(
      { _id: reportId },
      { $set: { ingestStatus: 'failed', chunkCount: 0, chunkedAt: new Date() } }
    );
    return 0;
  }

  // Embed in batches to bound memory
  const embeddings = [];
  const B = 32;
  for (let i = 0; i < texts.length; i += B) {
    const batch = texts.slice(i, i + B);
    const vecs = await embedTexts(batch);
    embeddings.push(...vecs);
  }

  // Replace existing chunks (idempotent)
  await db.collection('chunks').deleteMany({ reportId });

  const entityIds = report.entityMentions || [];
  const docs = texts.map((text, i) => ({
    reportId,
    chunkIndex: i,
    text,
    embedding: embeddings[i] || [],
    entityIds,
    tokenCount: text.split(/\s+/).length,
    createdAt: new Date(),
  }));
  await db.collection('chunks').insertMany(docs, { ordered: false });

  await db.collection('reports').updateOne(
    { _id: reportId },
    { $set: { ingestStatus: 'embedded', chunkCount: docs.length, chunkedAt: new Date() } }
  );
  return docs.length;
}

module.exports = { processReport };