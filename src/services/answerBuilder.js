/**
 * Phase 5a — template answer builder (FR8, NFR6).
 * Assembles a readable cited answer from graph traversal + evidence chunks.
 * No LLM in Review 2 (deferred to Review 3).
 */
function buildAnswer({ question, resolved, traversed, chunks, reportsById }) {
  const lines = [];

  const subject = resolved.names.map((n) => n.name).slice(0, 5).join(', ') || 'these entities';
  lines.push(`Regarding "${question}" — the system resolved: ${subject}.`);

  if (traversed && traversed.length) {
    const hops = traversed
      .slice(0, 8)
      .map((n) => `${n.label} "${n.name}" (${n.key})`)
      .join(' → ');
    lines.push(`Graph traversal (depth ${traversed.length ? '2' : '1'}) found the chain: ${hops}.`);
  }

  if (!chunks.length) {
    lines.push('No supporting evidence chunks were retrieved for the resolved entities.');
    return lines.join('\n');
  }

  const cited = new Map();
  const evidence = chunks.slice(0, 3).map(({ chunk, score }) => {
    const rep = reportsById.get(chunk.reportId.toString());
    if (rep) {
      cited.set(rep._id.toString(), rep);
      const date = rep.publishedDate ? new Date(rep.publishedDate).toISOString().slice(0, 10) : 'n.d.';
      return `• ${chunk.text.slice(0, 320)}${chunk.text.length > 320 ? '…' : ''}\n  — ${rep.source} "${rep.title}" (${date}) ${rep.url || ''}  [similarity ${(score * 100).toFixed(1)}%]`;
    }
    return `• ${chunk.text.slice(0, 320)}…`;
  });

  lines.push('\nEvidence:');
  lines.push(...evidence);

  if (cited.size) {
    lines.push('\nCited sources:');
    for (const rep of cited.values()) {
      const date = rep.publishedDate ? new Date(rep.publishedDate).toISOString().slice(0, 10) : 'n.d.';
      lines.push(`  [${rep._id}] ${rep.title} — ${rep.source} (${date}) ${rep.url || ''}`);
    }
  }

  lines.push('\nNote: template-mode answer (Review 2). LLM synthesis arrives in Review 3; every claim above is traceable to a stored report.');
  return lines.join('\n');
}

module.exports = { buildAnswer };