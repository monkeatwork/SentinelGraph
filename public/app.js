/* SentinelGraph dashboard — plain JS, no build step, no external libs. */
'use strict';

const $ = (sel) => document.querySelector(sel);
const state = {
  token: localStorage.getItem('sg_token') || null,
  user: JSON.parse(localStorage.getItem('sg_user') || 'null'),
  graph: { nodes: new Map(), edges: new Map(), sim: null },
};

// ---------- API client ----------
async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  let res;
  try {
    res = await fetch(path, { ...opts, headers });
  } catch (e) {
    throw new Error(`Cannot reach the server (${e.message}). Is 'npm start' still running?`);
  }
  // Don't wipe the session on the login endpoint itself — a wrong password is
  // not an expired session.
  if (res.status === 401 && !path.startsWith('/api/auth/')) {
    logout();
    throw new Error('Session expired — log in again');
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((body.error && body.error.message) || `HTTP ${res.status}`);
  return body;
}

// ---------- auth ----------
function showApp() {
  $('#login-view').hidden = true;
  $('#app-view').hidden = false;
  const role = state.user ? state.user.role : 'analyst';
  $('#user-role').textContent = `${role} · ${state.user.email}`;
  // admin-only controls: none currently hidden (CRUD happens via API), pill shows role
}

function logout() {
  state.token = null; state.user = null;
  localStorage.removeItem('sg_token'); localStorage.removeItem('sg_user');
  $('#app-view').hidden = true;
  $('#login-view').hidden = false;
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.querySelector('#login-form button[type="submit"]');
  const errBox = $('#login-error');
  const email = $('#login-email').value.trim();
  const password = $('#login-password').value;
  if (!email || !password) {
    errBox.textContent = 'Enter both email and password.';
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  errBox.textContent = '';
  try {
    const body = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    state.token = body.token; state.user = body.user;
    localStorage.setItem('sg_token', body.token);
    localStorage.setItem('sg_user', JSON.stringify(body.user));
    errBox.textContent = '';
    showApp();
  } catch (err) {
    errBox.textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
});
window.__sg_login_ready = true;

$('#logout').addEventListener('click', logout);

// ---------- tabs ----------
document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab, .tab-panel').forEach((el) => el.classList.remove('active'));
    btn.classList.add('active');
    const tab = btn.dataset.tab;
    const prev = ['graph', 'ask', 'reports'].find((t) => t !== tab);
    $(`#tab-${tab}`).classList.add('active');
    void prev;
    if (tab === 'graph' && state.graph.nodes.size) layoutGraph();
    if (tab === 'reports') loadReports();
  });
});

// ---------- graph view (force-directed canvas) ----------
const COLORS = {
  ThreatActor: '#f47067', Campaign: '#ffa657', Malware: '#e3b341', Technique: '#58a6ff',
  Tactic: '#bc8cff', Mitigation: '#3fb950', Vulnerability: '#d2a8ff', Software: '#39c5cf', Sector: '#8b949e',
};
let mouse = null;

function nodeKey(n) { return `${n.label}|${n.key}`; }

function addNode(label, key, name, props) {
  const k = nodeKey({ label, key });
  if (!state.graph.nodes.has(k)) {
    state.graph.nodes.set(k, {
      label, key, name: name || key, props: props || {},
      x: Math.random() * 700 + 50, y: Math.random() * 400 + 50, vx: 0, vy: 0,
    });
  }
  return state.graph.nodes.get(k);
}

function addEdge(a, b, rel, dir) {
  const k = [nodeKey(a), nodeKey(b)].sort().join('<>');
  if (!state.graph.edges.has(k)) state.graph.edges.set(k, { a: nodeKey(a), b: nodeKey(b), rel, dir });
}

async function expandNode(label, key) {
  try {
    const body = await api(`/api/graph/${encodeURIComponent(label)}/${encodeURIComponent(key)}/neighbors`);
    const me = addNode(label, key, body.node.name, body.node.props);
    state.graph.nodes.set(nodeKey(me), me);
    for (const nb of body.neighbors) {
      const n = addNode(nb.label, nb.key, nb.name);
      state.graph.nodes.set(nodeKey(n), n);
      addEdge(me, n, nb.rel, nb.direction);
    }
    layoutGraph();
  } catch (err) { $('#graph-status').textContent = err.message; }
}

function layoutGraph() {
  const canvas = $('#graph-canvas');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = canvas.clientWidth * dpr;
  canvas.height = canvas.clientHeight * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  const W = canvas.clientWidth, H = canvas.clientHeight;

  const nodes = [...state.graph.nodes.values()];
  const edges = [...state.graph.edges.values()];
  const labelFilter = $('#graph-label-filter').value;
  const visible = new Set(
    nodes.filter((n) => !labelFilter || n.label === labelFilter).map(nodeKey)
  );
  const visibleNodes = nodes.filter((n) => visible.has(nodeKey(n)));
  const visibleEdges = edges.filter((e) => visible.has(e.a) && visible.has(e.b));

  // simple force simulation (few dozen nodes → fast)
  const k = 0.06, rep = 9000, c = 0.85;
  for (let i = 0; i < 80; i++) {
    for (const n of visibleNodes) {
      n.vx = 0; n.vy = 0;
      for (const m of visibleNodes) {
        if (n === m) continue;
        let dx = n.x - m.x, dy = n.y - m.y;
        let d2 = dx * dx + dy * dy || 1;
        const f = rep / d2;
        n.vx += (dx / Math.sqrt(d2)) * f;
        n.vy += (dy / Math.sqrt(d2)) * f;
        // spring to centre
        n.vx -= (n.x - W / 2) * k;
        n.vy -= (n.y - H / 2) * k;
      }
      for (const e of visibleEdges) {
        if (e.a === nodeKey(n)) { const m = state.graph.nodes.get(e.b); if (m && visible.has(nodeKey(m))) { n.vx += (m.x - n.x) * 0.12; n.vy += (m.y - n.y) * 0.12; } }
        if (e.b === nodeKey(n)) { const m = state.graph.nodes.get(e.a); if (m && visible.has(nodeKey(m))) { n.vx += (m.x - n.x) * 0.12; n.vy += (m.y - n.y) * 0.12; } }
      }
      n.vx *= c; n.vy *= c;
      n.x += n.vx; n.y += n.vy;
      n.x = Math.min(W - 20, Math.max(20, n.x));
      n.y = Math.min(H - 20, Math.max(20, n.y));
    }
  }

  ctx.clearRect(0, 0, W, H);
  ctx.strokeStyle = '#30363d'; ctx.lineWidth = 1;
  for (const e of visibleEdges) {
    const a = state.graph.nodes.get(e.a), b = state.graph.nodes.get(e.b);
    if (!a || !b) continue;
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
  }
  let r = 1;
  for (const n of visibleNodes) {
    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = COLORS[n.label] || '#fff';
    ctx.fill();
    r += 0.12;
  }
  // labels for the larger subset
  let shown = 0;
  for (const n of visibleNodes) {
    if (shown > 24) break;
    shown++;
    ctx.font = '11px -apple-system, sans-serif';
    const w = ctx.measureText(n.name).width;
    ctx.fillStyle = 'rgba(13,17,23,0.75)';
    ctx.fillRect(n.x - w / 2 - 4, n.y - 24, w + 8, 16);
    ctx.fillStyle = '#e6edf3';
    ctx.fillText(n.name, n.x - w / 2, n.y - 12);
  }
  if (mouse) {
    ctx.beginPath(); ctx.arc(mouse.x, mouse.y, 5, 0, Math.PI * 2); ctx.fillStyle = '#fff'; ctx.fill();
  }
}

canvasEvents();
function canvasEvents() {
  const canvas = $('#graph-canvas');
  canvas.addEventListener('click', (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left, y = e.clientY - rect.top;
    let best = null, bd = 12;
    for (const n of state.graph.nodes.values()) {
      const d = Math.hypot(n.x - x, n.y - y);
      if (d < bd) { bd = d; best = n; }
    }
    if (best) {
      expandNode(best.label, best.key);
      $('#node-detail').hidden = false;
      $('#node-detail').textContent = `${best.label}  ${best.name}  (${best.key})\n${JSON.stringify(best.props || {}, null, 2)}`;
    }
  });
  $('#graph-label-filter').addEventListener('change', layoutGraph);
  $('#graph-reset').addEventListener('click', () => { state.graph = { nodes: new Map(), edges: new Map() }; layoutGraph(); });
}

$('#graph-search-btn').addEventListener('click', async () => {
  const q = $('#graph-search').value.trim();
  if (!q) return;
  try {
    const body = await api(`/api/graph/search?q=${encodeURIComponent(q)}`);
    const picks = [...body.results.neo4j, ...body.results.mongo.map((m) => ({ mitreId: m.mitreId, label: m.entityType, name: m.name }))];
    if (!picks.length) { $('#graph-status').textContent = 'No matches'; return; }
    const p = picks[0];
    state.graph = { nodes: new Map(), edges: new Map() };
    const me = addNode(p.label || 'ThreatActor', p.mitreId, p.name);
    state.graph.nodes.set(nodeKey(me), me);
    await expandNode(me.label, me.key);
    $('#graph-status').textContent = `Showing ${state.graph.nodes.size} nodes / ${state.graph.edges.size} edges`;
  } catch (err) { $('#graph-status').textContent = err.message; }
});

// ---------- Q&A ----------
$('#ask-btn').addEventListener('click', async () => {
  const question = $('#ask-input').value.trim();
  if (!question) return;
  const result = $('#ask-result');
  result.textContent = 'Thinking…';
  try {
    const body = await api('/api/qa/ask', {
      method: 'POST',
      body: JSON.stringify({ question, depth: Number($('#ask-depth').value) || 2 }),
    });
    const { answer, resolved, evidence, latencyMs } = body;
    let html = `<div class="resolved-pills">` +
      resolved.names.map((n) => `<span class="pill-entity">${n.label} ${n.name} (${n.id})</span>`).join('') +
      `</div>`;
    html += `<p style="white-space:pre-wrap">${escapeHtml(answer)}</p>`;
    if (evidence && evidence.length) {
      html += `<div class="evidence"><h4>Evidence chunks (${evidence.length})</h4>`;
      for (const ev of evidence.slice(0, 5)) {
        const rep = ev.report;
        html += `<div class="cite">${escapeHtml(ev.text.slice(0, 260))}…<br/>` +
          (rep ? `<a href="${escapeAttr(rep.url)}" target="_blank" rel="noopener">${escapeHtml(rep.title)}</a> · ${escapeHtml(rep.source)} · ${rep.publishedDate ? new Date(rep.publishedDate).toISOString().slice(0, 10) : ''} · similarity ${(ev.score * 100).toFixed(1)}%` : '') +
          `</div>`;
      }
      html += `</div>`;
    }
    result.innerHTML = html;
    $('#ask-latency').textContent =
      `resolve ${latencyMs.resolve}ms · graph ${latencyMs.graph}ms · vector ${latencyMs.vector}ms · synthesis ${latencyMs.synthesis}ms · total ${latencyMs.total}ms`;
  } catch (err) {
    result.textContent = `Error: ${err.message}`;
  }
});

function escapeHtml(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function escapeAttr(s) { return String(s || '').replace(/"/g, '&quot;'); }

// ---------- Reports / analytics ----------
function drawBars(canvas, items, { label = (r) => r._id, value = (r) => r.count, color = '#58a6ff', rotate = false }) {
  const dpr = window.devicePixelRatio || 1;
  canvas.width = canvas.clientWidth * dpr;
  canvas.height = canvas.clientHeight * dpr;
  const ctx = canvas.getContext('2d');
  const W = canvas.clientWidth, H = canvas.clientHeight;
  ctx.scale(dpr, dpr); ctx.clearRect(0, 0, W, H);
  const max = Math.max(1, ...items.map(value));
  const pad = 46, bars = items.slice(0, 14);
  const bw = (W - pad * 1.6) / Math.max(1, bars.length);
  bars.forEach((it, i) => {
    const h = (value(it) / max) * (H - 40);
    ctx.fillStyle = '#21262d';
    ctx.fillRect(pad + i * bw + bw * 0.15, H - 28 - h, bw * 0.7, h);
    ctx.fillStyle = color;
    ctx.fillRect(pad + i * bw + bw * 0.15, H - 28 - h + 2, bw * 0.7, Math.max(2, h - 2));
    ctx.fillStyle = '#8b949e'; ctx.font = '9px sans-serif';
    ctx.save();
    if (rotate) { ctx.translate(pad + i * bw + bw / 2, H - 14); ctx.rotate(-Math.PI / 4); }
    ctx.fillText(String(label(it)).slice(0, 14), rotate ? 0 : pad + i * bw + 2, rotate ? 0 : H - 16);
    ctx.restore();
  });
}

async function loadReports() {
  try {
    const months = await api('/api/analytics/cve-severity-by-month');
    const byMonth = new Map();
    for (const r of months.rows) {
      const k = `${r._id.year}-${String(r._id.month).padStart(2, '0')}`;
      if (!byMonth.has(k)) byMonth.set(k, {});
      byMonth.get(k)[r._id.severity] = (byMonth.get(k)[r._id.severity] || 0) + r.count;
    }
    const entries = [...byMonth.entries()].slice(-12);
    const totals = entries.map(([m, s]) => ({ _id: m, count: Object.values(s).reduce((a, b) => a + b, 0), ...s }));
    drawBars($('#chart-sev-month'), totals, { label: (r) => r._id, value: (r) => r.count });

    const sources = await api('/api/analytics/most-cited-sources');
    drawBars($('#chart-sources'), sources.rows, { label: (r) => String(r._id).slice(0, 20), value: (r) => r.citations, color: '#e3b341' });

    const cross = await api('/api/analytics/severity-exploited-crosstab');
    drawBars($('#chart-crosstab'), cross.rows.map((r) => ({ _id: `${r._id.severity}:${r._id.knownExploited ? 'KEV' : 'no'}:${r.count}`, count: r.count })), { color: '#d2a8ff', rotate: true });

    const cpe = await api('/api/analytics/chunks-per-entity');
    $('#chunks-entity-list').innerHTML = cpe.rows.slice(0, 12)
      .map((r) => `<div>${escapeHtml(r.entityName || r.entityId)} — ${r.chunkCount} chunks <span class="hint">${escapeHtml(r._id)}</span></div>`)
      .join('');
  } catch (err) { /* charts may be empty early on */ }
}

// ---------- boot ----------
if (state.token && state.user) showApp();