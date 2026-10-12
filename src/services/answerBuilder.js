/**
 * Phase 5a — template answer builder (FR8, NFR6).
 * Assembles a readable cited answer from graph traversal + evidence chunks.
 * Review 3 adds an LLM-synthesised mode (buildLlmAnswer) over the same inputs;
 * the template stays the default and the fallback.
 */
const { generate, LlmError } = require('./llm');

function buildTemplateAnswer({ question, resolved, traversed, chunks, reportsById }) {
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

const fmtDate = (d) => (d ? new Date(d).toISOString().slice(0, 10) : 'n.d.');

const REL_MEANING = [
  'AFFECTS: vulnerability affects software',
  'EXPLOITS: malware/tool exploits vulnerability',
  'USES_TECHNIQUE: malware/tool uses ATT&CK technique',
  'PERFORMS: threat actor performs technique',
  'DEPLOYS: campaign deploys malware',
  'ATTRIBUTED_TO: campaign attributed to threat actor',
  'TARGETS: threat actor targets sector',
  'MITIGATED_BY: technique mitigated by mitigation',
  'BELONGS_TO: technique belongs to tactic',
  'SUBTECHNIQUE_OF: sub-technique of technique',
];

const SYSTEM_PROMPT = [
  'You are SentinelGraph, a cyber threat intelligence assistant.',
  'Answer ONLY from the graph paths and numbered evidence sources you are given. Never use outside knowledge.',
  'Cite evidence with its number in square brackets, e.g. [1] or [2][3], right after each claim it supports.',
  'Graph paths are structural links, not proof of attribution: when you name an actor that is only',
  'linked through a shared technique, say it is "linked through" that technique, not confirmed.',
  'Graph facts (paths, mitigations) need no citation number; mention they come from the graph.',
  'Only mention graph paths or graph mitigations if they are actually listed below.',
  'If the material does not answer the question, say what is missing. Plain text only, no markdown,',
  'no headings, at most 220 words: a direct answer first, then the attack route(s), then any mitigation in the sources.',
].join(' ');

function pathLine(p) {
  let line = `${p.nodes[0].name} (${p.nodes[0].label})`;
  p.rels.forEach((r, i) => {
    const a = p.nodes[i], b = p.nodes[i + 1];
    const forward = r.from === a.key;
    line += forward ? ` -${r.type}-> ` : ` <-${r.type}- `;
    line += `${b.name} (${b.label})`;
  });
  return line;
}

/** Build the grounded prompt; exported for tests. */
function buildLlmPrompt({ question, resolved, attackPaths = [], mitigations = [], traversed = [], chunks, reportsById, maxSources = 6 }) {
  const sources = [];
  for (const { chunk, score } of chunks) {
    if (sources.length >= maxSources) break;
    const rep = reportsById.get(chunk.reportId.toString());
    if (!rep) continue; // only report-backed evidence is citable (NFR6)
    sources.push({ n: sources.length + 1, chunk, score, report: rep });
  }

  const parts = [`Question: ${question}`];
  const names = (resolved.names || []).map((x) => x.name);
  parts.push(`Resolved entities: ${[...new Set([...names, ...resolved.cves, ...resolved.mitreIds])].slice(0, 12).join(', ') || 'none'}`);
  parts.push(`Relationship meanings: ${REL_MEANING.join('; ')}.`);
  if (attackPaths.length) {
    parts.push('Graph paths from the resolved entities to threat actors:\n' + attackPaths.map((p) => `- ${pathLine(p)}`).join('\n'));
  } else if (traversed.length) {
    parts.push('Nearby graph entities: ' + traversed.slice(0, 20).map((t) => `${t.name || t.key} (${t.label})`).join(', '));
  }
  if (mitigations.length) {
    parts.push('Graph mitigations (MITIGATED_BY) for techniques above:\n' +
      mitigations.map((m) => `- ${m.technique}: ${m.mitigations.join(', ')}`).join('\n'));
  }
  parts.push(
    'Evidence sources:\n' +
      (sources.length
        ? sources.map((s) => `[${s.n}] "${s.report.title}" (${s.report.source}, ${fmtDate(s.report.publishedDate)}): ${s.chunk.text.slice(0, 900)}`).join('\n\n')
        : '(none retrieved)')
  );
  return { system: SYSTEM_PROMPT, prompt: parts.join('\n\n'), sources };
}

/**
 * LLM-synthesised answer over the same inputs as the template.
 * Rejects (LlmError) when the model cites none of the provided sources, so callers fall back.
 */
async function buildLlmAnswer(input) {
  const { system, prompt, sources } = buildLlmPrompt(input);
  if (!sources.length) throw new LlmError('no report-backed evidence to ground an LLM answer');

  const out = await generate({ system, prompt });
  const body = out.text.replace(/\*\*(.+?)\*\*/g, '$1').replace(/^#+\s*/gm, '').trim();

  const used = new Set();
  for (const m of body.matchAll(/\[(\d+(?:\s*,\s*\d+)*)\]/g)) {
    for (const n of m[1].split(',')) {
      const k = Number(n.trim());
      if (k >= 1 && k <= sources.length) used.add(k);
    }
  }
  if (!used.size) throw new LlmError('LLM answer cited none of the provided sources');

  const cited = sources.filter((s) => used.has(s.n));
  const lines = cited.map((s) => `[${s.n}] ${s.report.title} — ${s.report.source} (${fmtDate(s.report.publishedDate)}) ${s.report.url || ''}`.trim());
  return {
    text: `${body}\n\nSources:\n${lines.join('\n')}`,
    citedReportIds: [...new Set(cited.map((s) => s.report._id.toString()))],
    provider: out.provider,
    model: out.model,
    usage: out.usage,
    via: out.via,
    attempts: out.attempts,
  };
}

module.exports = {
  buildTemplateAnswer,
  buildAnswer: buildTemplateAnswer, // Review 2 name, kept for compatibility
  buildLlmPrompt,
  buildLlmAnswer,
};