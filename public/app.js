/* SentinelGraph dashboard — hash-routed pages, light/dark themes, no libs. */
'use strict';

const $ = (sel) => document.querySelector(sel);
const state = {
  token: localStorage.getItem('sg_token') || null,
  user: JSON.parse(localStorage.getItem('sg_user') || 'null'),
  graph: { nodes: new Map(), edges: new Map() },
};

/* ============================ API client ============================ */
async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  let res;
  try {
    res = await fetch(path, { ...opts, headers });
  } catch (e) {
    throw new Error(`Cannot reach the server (${e.message}). Is 'npm start' still running?`);
  }
  // A failed login is not an expired session — don't wipe it.
  if (res.status === 401 && !path.startsWith('/api/auth/')) {
    logout();
    throw new Error('Session expired — log in again');
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((body.error && body.error.message) || `HTTP ${res.status}`);
  return body;
}

/* ============================ Theme ============================ */
function applyTheme(t) {
  document.body.dataset.theme = t;
  localStorage.setItem('sg_theme', t);
  const btn = $('#theme-toggle');
  if (btn) btn.textContent = t === 'light' ? '🌙' : '☀️';
  if (t === 'light') $('#theme-toggle').title = 'Switch to dark mode';
  else $('#theme-toggle').title = 'Switch to light mode';
}
function initTheme() {
  const saved = localStorage.getItem('sg_theme');
  applyTheme(saved === 'dark' ? 'dark' : 'light'); // light is primary
}

/* ============================ Router ============================ */
const PAGES = ['login', 'graph', 'ask', 'reports'];

function currentRoute() {
  const r = (location.hash.replace(/^#\/?/, '') || 'graph').toLowerCase();
  return PAGES.includes(r) ? r : 'graph';
}

function navigate(route) {
  if (route === 'login') {
    if (location.hash !== '#/login') location.hash = '#/login';
    else renderRoute();
  } else {
    if (location.hash !== `#/${route}`) location.hash = `#/${route}`;
    else renderRoute();
  }
}

function renderRoute() {
  const route = currentRoute();
  const authed = Boolean(state.token && state.user);

  if (!authed && route !== 'login') {
    location.replace('#/login');
    return;
  }
  if (authed && route === 'login') {
    location.replace('#/graph');
    return;
  }

  const showLogin = route === 'login';
  $('#page-login').hidden = !showLogin;
  $('#page-app').hidden = showLogin;

  document.querySelectorAll('.nav-link').forEach((a) => {
    a.classList.toggle('active', a.dataset.nav === route);
  });

  if (!showLogin) {
    PAGES.filter((p) => p !== 'login').forEach((p) => {
      $(`#page-${p}`).classList.toggle('hidden', p !== route);
    });
    window.scrollTo(0, 0);

    // re-fit content that depends on visible dimensions
    requestAnimationFrame(() => {
      if (route === 'graph') layoutGraph();
      if (route === 'reports') loadReports();
    });
  }
}

window.addEventListener('hashchange', renderRoute);

/* ============================ Auth ============================ */
function showUser() {
  const u = state.user;
  $('#user-role').textContent = u ? `${u.role} · ${u.email}` : '';
}

function logout() {
  state.token = null;
  state.user = null;
  localStorage.removeItem('sg_token');
  localStorage.removeItem('sg_user');
  navigate('login');
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#login-form button[type="submit"]');
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
    state.token = body.token;
    state.user = body.user;
    localStorage.setItem('sg_token', body.token);
    localStorage.setItem('sg_user', JSON.stringify(body.user));
    showUser();
    navigate('graph');
  } catch (err) {
    errBox.textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
});

$('#logout').addEventListener('click', logout);

// demo credential chips fill the form
document.querySelectorAll('.chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    $('#login-email').value = chip.dataset.email;
    $('#login-password').value = chip.dataset.pass;
    $('#login-error').textContent = '';
  });
});

/* ============================ Graph page ============================ */
const COLORS = {
  ThreatActor: '#f47067', Campaign: '#ffa657', Malware: '#e3b341', Technique: '#58a6ff',
  Tactic: '#bc8cff', Mitigation: '#3fb950', Vulnerability: '#d2a8ff', Software: '#39c5cf', Sector: '#8b949e',
};

function nodeKey(n) { return `${n.label}|${n.key}`; }

function addNode(label, key, name, props) {
  const k = nodeKey({ label, key });
  if (!state.graph.nodes.has(k)) {
    state.graph.nodes.set(k, {
      label, key, name: name || key, props: props || {},
      x: Math.random() * 600 + 60, y: Math.random() * 300 + 50, vx: 0, vy: 0,
    });
  }
  return state.graph.nodes.get(k);
}

function addEdge(a, b, rel, dir) {
  const k = [nodeKey(a), nodeKey(b)].sort().join('<>');
  if (!state.graph.edges.has(k)) state.graph.edges.set(k, { a: nodeKey(a), b: nodeKey(b), rel, dir });
}

function updateGraphEmpty() {
  $('#graph-empty').classList.toggle('hidden', state.graph.nodes.size > 0);
  $('#graph-count-hint').textContent = state.graph.nodes.size
    ? `${state.graph.nodes.size} nodes · ${state.graph.edges.size} edges`
    : '';
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
    updateGraphEmpty();
    layoutGraph();
    $('#graph-status').textContent = '';
  } catch (err) {
    $('#graph-status').textContent = err.message;
  }
}

function layoutGraph() {
  const canvas = $('#graph-canvas');
  const wrap = $('#graph-canvas-wrap');
  if (!canvas || !wrap || wrap.clientWidth === 0) return;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = wrap.clientWidth * dpr;
  canvas.height = wrap.clientHeight * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  const W = wrap.clientWidth, H = wrap.clientHeight;

  const nodes = [...state.graph.nodes.values()];
  const edges = [...state.graph.edges.values()];
  const labelFilter = $('#graph-label-filter').value;
  const visible = new Set(nodes.filter((n) => !labelFilter || n.label === labelFilter).map(nodeKey));
  const visibleNodes = nodes.filter((n) => visible.has(nodeKey(n)));
  const visibleEdges = edges.filter((e) => visible.has(e.a) && visible.has(e.b));

  // simple force simulation
  const k = 0.06, rep = 9000, c = 0.85;
  for (let i = 0; i < 80; i++) {
    for (const n of visibleNodes) {
      n.vx = 0; n.vy = 0;
      for (const m of visibleNodes) {
        if (n === m) continue;
        const dx = n.x - m.x, dy = n.y - m.y;
        const d2 = dx * dx + dy * dy || 1;
        const f = rep / d2;
        n.vx += (dx / Math.sqrt(d2)) * f;
        n.vy += (dy / Math.sqrt(d2)) * f;
        n.vx -= (n.x - W / 2) * k;
        n.vy -= (n.y - H / 2) * k;
      }
      for (const e of visibleEdges) {
        if (e.a === nodeKey(n)) {
          const m = state.graph.nodes.get(e.b);
          if (m && visible.has(nodeKey(m))) { n.vx += (m.x - n.x) * 0.12; n.vy += (m.y - n.y) * 0.12; }
        }
        if (e.b === nodeKey(n)) {
          const m = state.graph.nodes.get(e.a);
          if (m && visible.has(nodeKey(m))) { n.vx += (m.x - n.x) * 0.12; n.vy += (m.y - n.y) * 0.12; }
        }
      }
      n.vx *= c; n.vy *= c;
      n.x += n.vx; n.y += n.vy;
      n.x = Math.min(W - 20, Math.max(20, n.x));
      n.y = Math.min(H - 20, Math.max(20, n.y));
    }
  }

  ctx.clearRect(0, 0, W, H);
  ctx.strokeStyle = '#94a3b8';
  ctx.globalAlpha = 0.45;
  ctx.lineWidth = 1;
  for (const e of visibleEdges) {
    const a = state.graph.nodes.get(e.a), b = state.graph.nodes.get(e.b);
    if (!a || !b) continue;
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
  }
  ctx.globalAlpha = 1;
  let r = 1;
  for (const n of visibleNodes) {
    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = COLORS[n.label] || '#fff';
    ctx.fill();
    r += 0.12;
  }
  let shown = 0;
  for (const n of visibleNodes) {
    if (shown > 24) break;
    shown++;
    ctx.font = '11px -apple-system, sans-serif';
    const w = ctx.measureText(n.name).width;
    const isLight = document.body.dataset.theme === 'light';
    ctx.fillStyle = isLight ? 'rgba(255,255,255,0.92)' : 'rgba(13,17,23,0.78)';
    ctx.fillRect(n.x - w / 2 - 4, n.y - 24, w + 8, 16);
    ctx.fillStyle = isLight ? '#0f172a' : '#e6edf3';
    ctx.fillText(n.name, n.x - w / 2, n.y - 12);
  }
}

// canvas interactions
$('#graph-canvas').addEventListener('click', (e) => {
  if (!state.graph.nodes.size) return;
  const wrap = $('#graph-canvas-wrap');
  const rect = wrap.getBoundingClientRect();
  const x = e.clientX - rect.left, y = e.clientY - rect.top;
  let best = null, bd = 12;
  for (const n of state.graph.nodes.values()) {
    const d = Math.hypot(n.x - x, n.y - y);
    if (d < bd) { bd = d; best = n; }
  }
  if (best) {
    expandNode(best.label, best.key);
    const detail = $('#node-detail');
    detail.hidden = false;
    detail.textContent = `${best.label}  ${best.name}  (${best.key})\n${JSON.stringify(best.props || {}, null, 2)}`;
    detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
});

$('#graph-label-filter').addEventListener('change', layoutGraph);
$('#graph-reset').addEventListener('click', () => {
  state.graph = { nodes: new Map(), edges: new Map() };
  $('#node-detail').hidden = true;
  updateGraphEmpty();
  layoutGraph();
});

$('#graph-search-btn').addEventListener('click', async () => {
  const q = $('#graph-search').value.trim();
  if (!q) return;
  try {
    const body = await api(`/api/graph/search?q=${encodeURIComponent(q)}`);
    const picks = [
      ...body.results.neo4j,
      ...body.results.mongo.map((m) => ({ mitreId: m.mitreId, label: m.entityType, name: m.name })),
    ];
    if (!picks.length) { $('#graph-status').textContent = 'No matches'; return; }
    const p = picks[0];
    state.graph = { nodes: new Map(), edges: new Map() };
    $('#node-detail').hidden = true;
    const me = addNode(p.label || 'ThreatActor', p.mitreId, p.name);
    state.graph.nodes.set(nodeKey(me), me);
    updateGraphEmpty();
    await expandNode(me.label, me.key);
    $('#graph-status').textContent = `Showing “${p.name}” and its neighbourhood`;
  } catch (err) {
    $('#graph-status').textContent = err.message;
  }
});
$('#graph-search').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#graph-search-btn').click(); });

/* ============================ Ask page ============================ */
$('#ask-btn').addEventListener('click', askQuestion);
$('#ask-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) askQuestion();
});

async function askQuestion() {
  const question = $('#ask-input').value.trim();
  if (!question) return;
  const result = $('#ask-result');
  const empty = $('#ask-empty');
  empty.classList.add('hidden');
  result.innerHTML = '<p class="hint">Thinking…</p>';
  try {
    const body = await api('/api/qa/ask', {
      method: 'POST',
      body: JSON.stringify({ question, depth: Number($('#ask-depth').value) || 2 }),
    });
    const { answer, resolved, evidence, latencyMs } = body;

    let html = '<div class="resolved-pills">';
    if (resolved.names.length) {
      html += resolved.names.map((n) => `<span class="pill-entity">${escapeHtml(n.label)} · ${escapeHtml(n.name)}</span>`).join('');
    } else {
      html += '<span class="pill-entity">no entities resolved</span>';
    }
    html += '</div>';

    html += `<div class="ask-answer">${escapeHtml(answer)}</div>`;

    if (evidence && evidence.length) {
      html += '<div class="evidence"><h4>Evidence chunks</h4>';
      for (const ev of evidence.slice(0, 5)) {
        const rep = ev.report;
        html += `<div class="cite">${escapeHtml(ev.text.slice(0, 300))}${ev.text.length > 300 ? '…' : ''}`;
        if (rep) {
          const date = rep.publishedDate ? new Date(rep.publishedDate).toISOString().slice(0, 10) : '';
          html += `<div class="meta">📄 <a href="${escapeAttr(rep.url)}" target="_blank" rel="noopener">${escapeHtml(rep.title)}</a>` +
            ` · ${escapeHtml(rep.source)} · ${date} · similarity ${(ev.score * 100).toFixed(1)}%</div>`;
        }
        html += '</div>';
      }
      html += '</div>';
    }

    result.innerHTML = html;
    $('#ask-latency').textContent =
      `resolve ${latencyMs.resolve} ms · graph ${latencyMs.graph} ms · vector ${latencyMs.vector} ms · synthesis ${latencyMs.synthesis} ms · total ${latencyMs.total} ms`;
  } catch (err) {
    result.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

function escapeHtml(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function escapeAttr(s) { return escapeHtml(s); }

/* ============================ Reports page ============================ */
function drawBars(canvas, items, { label = (r) => r._id, value = (r) => r.count, color = '#4f46e5', rotate = false }) {
  if (!canvas || !canvas.parentElement || canvas.parentElement.clientWidth === 0) return;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = canvas.parentElement.clientWidth * dpr;
  canvas.height = (canvas.parentElement.clientHeight || 180) * dpr;
  const ctx = canvas.getContext('2d');
  const W = canvas.width / dpr, H = canvas.height / dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);
  if (!items.length) {
    ctx.fillStyle = 'var(--muted)';
    ctx.font = '12px -apple-system, sans-serif';
    ctx.fillText('No data yet — ask a question first.', 12, 24);
    return;
  }
  const max = Math.max(1, ...items.map(value));
  const padL = 40, padB = 34;
  const bars = items.slice(0, 14);
  const bw = (W - padL - 8) / Math.max(1, bars.length);
  const isLight = document.body.dataset.theme === 'light';
  bars.forEach((it, i) => {
    const h = (value(it) / max) * (H - padB - 20);
    ctx.fillStyle = isLight ? '#e2e8f0' : '#21262d';
    ctx.fillRect(padL + i * bw + bw * 0.14, H - padB - h, bw * 0.72, h);
    ctx.fillStyle = color;
    ctx.fillRect(padL + i * bw + bw * 0.14, H - padB - h + 2, bw * 0.72, Math.max(2, h - 2));
    ctx.fillStyle = isLight ? '#64748b' : '#8b949e';
    ctx.font = '9px -apple-system, sans-serif';
    ctx.save();
    if (rotate) {
      ctx.translate(padL + i * bw + bw / 2, H - 8);
      ctx.rotate(-Math.PI / 3.2);
    }
    ctx.fillText(String(label(it)).slice(0, 14), rotate ? 0 : padL + i * bw + 1, rotate ? 0 : H - 14);
    ctx.restore();
  });
  // value labels on top
  ctx.fillStyle = isLight ? '#475569' : '#8b949e';
  bars.forEach((it, i) => {
    const h = (value(it) / max) * (H - padB - 20);
    ctx.fillText(String(value(it)), padL + i * bw + bw * 0.14, H - padB - h - 4);
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
    const totals = entries.map(([m, s]) => ({ _id: m, count: Object.values(s).reduce((a, b) => a + b, 0) }));
    drawBars($('#chart-sev-month'), totals, { label: (r) => r._id, value: (r) => r.count });

    const sources = await api('/api/analytics/most-cited-sources');
    drawBars($('#chart-sources'), sources.rows, {
      label: (r) => String(r._id).slice(0, 18), value: (r) => r.citations, color: '#e3b341',
    });

    const cross = await api('/api/analytics/severity-exploited-crosstab');
    drawBars($('#chart-crosstab'), cross.rows.map((r) => ({
      _id: `${r._id.severity}:${r._id.knownExploited ? 'KEV' : 'no'}:${r.count}`,
      count: r.count,
    })), { color: '#d2a8ff', rotate: true });

    const cpe = await api('/api/analytics/chunks-per-entity');
    $('#chunks-entity-list').innerHTML = cpe.rows.slice(0, 12)
      .map((r) => `<div><span title="${escapeAttr(r._id)}">${escapeHtml(r.entityName || r.entityId || r._id)}</span><span class="n">${r.chunkCount} chunks</span></div>`)
      .join('');
  } catch (err) {
    $('.charts-grid') && ($('.charts-grid').dataset.error = err.message);
  }
}

/* ============================ Boot ============================ */
$('#theme-toggle').addEventListener('click', () => {
  applyTheme(document.body.dataset.theme === 'light' ? 'dark' : 'light');
});

initTheme();

if (state.token && state.user) {
  showUser();
  navigate('graph');
} else {
  navigate('login');
}
window.__sg_login_ready = true;