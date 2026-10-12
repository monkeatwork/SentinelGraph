/* SentinelGraph dashboard — hash-routed pages, light/dark themes, no libs. */
'use strict';

const $ = (sel) => document.querySelector(sel);
const state = {
  token: localStorage.getItem('sg_token') || null,
  user: JSON.parse(localStorage.getItem('sg_user') || 'null'),
  graph: { nodes: new Map(), edges: new Map(), view: { scale: 1, tx: 0, ty: 0 } },
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
  if (btn) {
    btn.textContent = t === 'light' ? '🌙' : '☀️';
    btn.title = t === 'light' ? 'Switch to dark mode' : 'Switch to light mode';
  }
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
  if (location.hash !== `#/${route}`) location.hash = `#/${route}`;
  else renderRoute();
}

function renderRoute() {
  const route = currentRoute();
  const authed = Boolean(state.token && state.user);

  if (!authed && route !== 'login') { location.replace('#/login'); return; }
  if (authed && route === 'login') { location.replace('#/graph'); return; }

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
    requestAnimationFrame(() => {
      if (route === 'graph') layoutGraph();
      if (route === 'reports') loadReports();
      if (route === 'ask') loadAskModes();
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
  if (!email || !password) { errBox.textContent = 'Enter both email and password.'; return; }
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  errBox.textContent = '';
  try {
    const body = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
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

function addNode(label, key, name, props, near) {
  const k = nodeKey({ label, key });
  if (!state.graph.nodes.has(k)) {
    state.graph.nodes.set(k, {
      label, key, name: name || key, props: props || {},
      // seed next to the parent node so expansions are stable, not chaotic
      x: near ? near.x + (Math.random() - 0.5) * 100 : Math.random() * 600 - 300,
      y: near ? near.y + (Math.random() - 0.5) * 100 : Math.random() * 400 - 200,
      vx: 0, vy: 0,
    });
  }
  return state.graph.nodes.get(k);
}

function addEdge(a, b, rel, dir) {
  const k = [nodeKey(a), nodeKey(b)].sort().join('<>');
  if (!state.graph.edges.has(k)) state.graph.edges.set(k, { a: nodeKey(a), b: nodeKey(b), rel, dir });
}

function degreeOf(node) {
  let d = 0;
  for (const e of state.graph.edges.values()) {
    if (e.a === nodeKey(node) || e.b === nodeKey(node)) d++;
  }
  return d;
}

function updateGraphEmpty() {
  const has = state.graph.nodes.size > 0;
  $('#graph-empty').classList.toggle('hidden', has);
  $('#graph-count-hint').textContent = has
    ? `${state.graph.nodes.size} nodes · ${state.graph.edges.size} edges — click a node to expand it, drag to pan, scroll to zoom`
    : '';
}

async function expandNode(label, key) {
  try {
    const body = await api(`/api/graph/${encodeURIComponent(label)}/${encodeURIComponent(key)}/neighbors`);
    const me = addNode(label, key, body.node.name, body.node.props);
    state.graph.nodes.set(nodeKey(me), me);
    for (const nb of body.neighbors) {
      const n = addNode(nb.label, nb.key, nb.name, null, me); // spawn near parent
      state.graph.nodes.set(nodeKey(n), n);
      addEdge(me, n, nb.rel, nb.direction);
    }
    updateGraphEmpty();
    simulate();      // physics once — the graph then stays still
    layoutGraph();   // render
    $('#graph-status').textContent = '';
  } catch (err) {
    $('#graph-status').textContent = err.message;
    console.error('[expandNode]', err);
  }
}

/* ---- viewport: pan (drag on empty space) + zoom (wheel), click a node ---- */
function w2s(node, scale, tx, ty) { return { x: node.x * scale + tx, y: node.y * scale + ty }; }
function s2w(x, y, scale, tx, ty) { return { x: (x - tx) / scale, y: (y - ty) / scale }; }

function fitView(scale, tx, ty) {
  const wrap = $('#graph-canvas-wrap');
  if (!wrap || !state.graph.nodes.size) return { scale, tx, ty };
  const W = wrap.clientWidth, H = wrap.clientHeight;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of state.graph.nodes.values()) {
    minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x);
    minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y);
  }
  const pad = 60;
  const s = Math.min((W - pad) / Math.max(1, maxX - minX), (H - pad) / Math.max(1, maxY - minY), 1.4);
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
  return { scale: Math.max(0.15, s), tx: W / 2 - cx * s, ty: H / 2 - cy * s };
}

let hoverNode = null;
let dragState = null;
let clickMoved = false;

function nodeAt(wx, wy) {
  const { scale, tx, ty } = state.graph.view;
  let best = null, bd = 22 / scale;
  for (const n of state.graph.nodes.values()) {
    if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) continue;
    const d = Math.hypot(n.x - wx, n.y - wy);
    const r = Math.max(7, 5 + Math.min(9, Math.sqrt(degreeOf(n)) * 2));
    if (d < bd + r) { bd = d; best = n; }
  }
  return best;
}

function visibleSets() {
  const nodes = [...state.graph.nodes.values()];
  const edges = [...state.graph.edges.values()];
  const labelFilter = $('#graph-label-filter').value;
  const visible = new Set(nodes.filter((n) => !labelFilter || n.label === labelFilter).map(nodeKey));
  return {
    nodes,
    edges,
    visible,
    visibleNodes: nodes.filter((n) => visible.has(nodeKey(n))),
    visibleEdges: edges.filter((e) => visible.has(e.a) && visible.has(e.b)),
  };
}

/**
 * Run the force simulation ONCE (only when data changes: search/expand/filter).
 * Never re-run on mouse move — that was the "graph keeps rotating/swirling" bug.
 */
function simulate() {
  if (dragState) return;
  const { visibleNodes, visibleEdges, visible } = visibleSets();
  if (!visibleNodes.length) return;
  const k = 0.05, rep = 11000, c = 0.85;
  const MAX_SPEED = 60; // velocities can never explode to Infinity/NaN
  for (let i = 0; i < 120; i++) {
    for (const n of visibleNodes) {
      n.vx = 0; n.vy = 0;
      for (const m of visibleNodes) {
        if (n === m) continue;
        const dx = n.x - m.x, dy = n.y - m.y;
        const d2 = dx * dx + dy * dy || 1;
        const f = rep / d2;
        n.vx += (dx / Math.sqrt(d2)) * f;
        n.vy += (dy / Math.sqrt(d2)) * f;
      }
      n.vx -= n.x * k;
      n.vy -= n.y * k;
      for (const e of visibleEdges) {
        if (e.a === nodeKey(n)) { const m = state.graph.nodes.get(e.b); if (m && visible.has(nodeKey(m))) { n.vx += (m.x - n.x) * 0.14; n.vy += (m.y - n.y) * 0.14; } }
        if (e.b === nodeKey(n)) { const m = state.graph.nodes.get(e.a); if (m && visible.has(nodeKey(m))) { n.vx += (m.x - n.x) * 0.14; n.vy += (m.y - n.y) * 0.14; } }
      }
      n.vx *= c; n.vy *= c;
      const sp = Math.hypot(n.vx, n.vy);
      if (sp > MAX_SPEED) { n.vx *= MAX_SPEED / sp; n.vy *= MAX_SPEED / sp; }
      if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) { n.x = 0; n.y = 0; n.vx = 0; n.vy = 0; }
      n.x += n.vx; n.y += n.vy;
    }
  }
}

/** Pure render — no physics. Called on mouse move, hover, pan, zoom, resize. */
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
  const { scale, tx, ty } = state.graph.view;

  // diagnostics for on-screen verification
  const dbg = $('#graph-debug');
  if (dbg) {
    dbg.textContent = `canvas ${W}×${H} · nodes ${state.graph.nodes.size} · view s=${scale.toFixed(2)} t=(${tx.toFixed(0)},${ty.toFixed(0)})`;
  }

  const { visibleNodes, visibleEdges, visible } = visibleSets();

  ctx.clearRect(0, 0, W, H);
  const isLight = document.body.dataset.theme === 'light';
  ctx.strokeStyle = isLight ? '#94a3b8' : '#404650';
  ctx.globalAlpha = 0.5;
  ctx.lineWidth = 1;
  for (const e of visibleEdges) {
    const a = state.graph.nodes.get(e.a), b = state.graph.nodes.get(e.b);
    if (!a || !b) continue;
    const pa = w2s(a, scale, tx, ty), pb = w2s(b, scale, tx, ty);
    ctx.beginPath(); ctx.moveTo(pa.x, pa.y); ctx.lineTo(pb.x, pb.y); ctx.stroke();
  }
  ctx.globalAlpha = 1;

  const ordered = [...visibleNodes].sort((a, b) => degreeOf(b) - degreeOf(a));
  for (const n of ordered) {
    const p = w2s(n, scale, tx, ty);
    if (!Number.isFinite(p.x) || !Number.isFinite(p.y)) continue; // never draw NaN
    if (p.x < -40 || p.x > W + 40 || p.y < -40 || p.y > H + 40) continue;
    const r = Math.max(7, 5 + Math.min(9, Math.sqrt(degreeOf(n)) * 2));
    // halo
    ctx.beginPath();
    ctx.arc(p.x, p.y, r + 4, 0, Math.PI * 2);
    ctx.fillStyle = isLight ? 'rgba(255,255,255,0.85)' : 'rgba(13,17,23,0.8)';
    ctx.fill();
    // body
    ctx.beginPath();
    ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
    ctx.fillStyle = COLORS[n.label] || '#888';
    ctx.fill();
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = isLight ? '#ffffff' : '#0d1117';
    ctx.stroke();
    if (hoverNode && nodeKey(hoverNode) === nodeKey(n)) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, r + 6, 0, Math.PI * 2);
      ctx.strokeStyle = isLight ? '#4f46e5' : '#58a6ff';
      ctx.lineWidth = 2.5;
      ctx.stroke();
    }
  }

  // labels for the most-connected nodes
  ctx.font = '11px -apple-system, sans-serif';
  for (const n of ordered.slice(0, 26)) {
    const p = w2s(n, scale, tx, ty);
    if (p.x < -60 || p.x > W + 60 || p.y < -20 || p.y > H + 20) continue;
    const r = Math.max(7, 5 + Math.min(9, Math.sqrt(degreeOf(n)) * 2));
    const w = ctx.measureText(n.name).width;
    const labelBg = isLight ? 'rgba(255,255,255,0.92)' : 'rgba(13,17,23,0.85)';
    ctx.fillStyle = labelBg;
    ctx.fillRect(p.x - w / 2 - 4, p.y - 24, w + 8, 16);
    ctx.fillStyle = isLight ? '#0f172a' : '#e6edf3';
    ctx.fillText(n.name, p.x - w / 2, p.y - 12);
  }
}

/* ---- canvas events: hover, drag-pan, wheel-zoom, click-expand ---- */
const canvas = $('#graph-canvas');
const wrap = $('#graph-canvas-wrap');

canvas.addEventListener('mousemove', (e) => {
  const rect = wrap.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  const wpt = s2w(mx, my, state.graph.view.scale, state.graph.view.tx, state.graph.view.ty);
  const hit = nodeAt(wpt.x, wpt.y);
  hoverNode = hit;
  canvas.style.cursor = hit ? 'pointer' : dragState ? 'grabbing' : 'grab';
  if (dragState) {
    clickMoved = true;
    state.graph.view.tx = dragState.tx + (mx - dragState.x);
    state.graph.view.ty = dragState.ty + (my - dragState.y);
    layoutGraph();
  } else {
    layoutGraph();
  }
});

canvas.addEventListener('mouseleave', () => { hoverNode = null; layoutGraph(); });

canvas.addEventListener('mousedown', (e) => {
  const rect = wrap.getBoundingClientRect();
  dragState = { x: e.clientX - rect.left, y: e.clientY - rect.top, tx: state.graph.view.tx, ty: state.graph.view.ty };
  clickMoved = false;
});

canvas.addEventListener('mouseup', (e) => {
  dragState = null;
  if (clickMoved) return;
  const rect = wrap.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  const wpt = s2w(mx, my, state.graph.view.scale, state.graph.view.tx, state.graph.view.ty);
  const hit = nodeAt(wpt.x, wpt.y);
  if (hit) {
    expandNode(hit.label, hit.key);
    const detail = $('#node-detail');
    detail.hidden = false;
    detail.textContent = `${hit.label}  ${hit.name}  (${hit.key}) — degree ${degreeOf(hit)}\n${JSON.stringify(hit.props || {}, null, 2)}`;
  }
});

canvas.addEventListener('wheel', (e) => {
  e.preventDefault();
  const rect = wrap.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  const { scale, tx, ty } = state.graph.view;
  const factor = e.deltaY < 0 ? 1.12 : 0.89;
  const ns = Math.min(6, Math.max(0.12, scale * factor));
  // zoom towards cursor
  state.graph.view.tx = mx - ((mx - tx) / scale) * ns;
  state.graph.view.ty = my - ((my - ty) / scale) * ns;
  state.graph.view.scale = ns;
  layoutGraph();
}, { passive: false });

$('#graph-label-filter').addEventListener('change', layoutGraph);
$('#graph-reset').addEventListener('click', () => {
  state.graph = { nodes: new Map(), edges: new Map(), view: { scale: 1, tx: 0, ty: 0 } };
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
    if (!picks.length) { $('#graph-status').textContent = `No matches for “${q}”`; return; }
    const p = picks[0];
    state.graph = { nodes: new Map(), edges: new Map(), view: { scale: 1, tx: 0, ty: 0 } };
    $('#node-detail').hidden = true;
    const me = addNode(p.label || 'ThreatActor', p.mitreId, p.name);
    state.graph.nodes.set(nodeKey(me), me);
    updateGraphEmpty();
    await expandNode(me.label, me.key);   // pulls the whole 1-hop neighbourhood
    fitAfterLayout();
    $('#graph-status').textContent = '';
  } catch (err) {
    $('#graph-status').textContent = err.message;
    console.error('[search]', err);
  }
});

function fitAfterLayout() {
  state.graph.view = fitView(state.graph.view.scale, state.graph.view.tx, state.graph.view.ty);
  layoutGraph();
}
$('#graph-search').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#graph-search-btn').click(); });

window.addEventListener('resize', layoutGraph);

/* ============================ Ask page ============================ */
$('#ask-btn').addEventListener('click', askQuestion);
$('#ask-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) askQuestion();
});

let askModesLoaded = false;
async function loadAskModes() {
  if (askModesLoaded) return;
  try {
    const m = await api('/api/qa/modes');
    const opt = $('#ask-mode option[value="llm"]');
    opt.disabled = !m.llm.available;
    opt.textContent = m.llm.available ? `LLM answer (${m.llm.provider})` : 'LLM answer (not configured)';
    askModesLoaded = true;
  } catch (e) { /* toggle keeps defaults; template mode always works */ }
}

const linkify = (escaped) => escaped.replace(/https?:\/\/[^\s<]+/g, (u) => `<a href="${u}" target="_blank" rel="noopener">${u}</a>`);

function pathHtml(p) {
  let html = `<span class="path-node">${escapeHtml(p.nodes[0].name)}</span>`;
  p.rels.forEach((r, i) => {
    const forward = r.from === p.nodes[i].key;
    html += `<span class="path-rel">${forward ? '' : '←'}${escapeHtml(r.type)}${forward ? '→' : ''}</span>`;
    html += `<span class="path-node">${escapeHtml(p.nodes[i + 1].name)}</span>`;
  });
  return `<div class="path-row">${html}</div>`;
}

async function askQuestion() {
  const question = $('#ask-input').value.trim();
  if (!question) return;
  const out = $('#ask-output');
  const btn = $('#ask-btn');
  const mode = $('#ask-mode').value;
  $('#ask-empty').classList.add('hidden');
  btn.disabled = true;
  btn.textContent = 'Asking…';
  $('#ask-latency').textContent = '';
  out.innerHTML = `<p class="hint">${mode === 'llm' ? 'Retrieving evidence and asking the LLM…' : 'Retrieving evidence…'}</p>`;
  try {
    const body = await api('/api/qa/ask', {
      method: 'POST',
      body: JSON.stringify({ question, depth: Number($('#ask-depth').value) || 2, mode }),
    });
    const { answer, resolved, evidence, latencyMs, answerMode, llm, attackPaths } = body;

    let badge;
    if (answerMode === 'llm') {
      const via = llm.via && llm.via !== 'primary' ? ` · ${escapeHtml(llm.via)}` : '';
      const tokens = llm.usage ? `${llm.usage.input} in / ${llm.usage.output} out tokens` : '';
      badge = `<span class="mode-badge mode-llm" title="${escapeAttr(tokens)}">LLM · ${escapeHtml(llm.model)}${via}</span>`;
    }
    else if (llm && llm.fallbackReason) badge = `<span class="mode-badge mode-fallback" title="${escapeAttr(llm.fallbackReason)}">Template · LLM unavailable, fell back</span>`;
    else badge = '<span class="mode-badge">Template</span>';

    let html = `<div class="answer-head">${badge}<div class="resolved-pills">`;
    if (resolved.names.length) {
      const pills = [...new Set(resolved.names.map((n) => `${n.label} · ${n.name}`))]; // CPE versions share a name
      html += pills.map((p) => `<span class="pill-entity">${escapeHtml(p)}</span>`).join('');
    } else {
      html += '<span class="pill-entity">no entities resolved</span>';
    }
    html += '</div></div>';
    html += `<div class="ask-answer">${linkify(escapeHtml(answer))}</div>`;

    if (attackPaths && attackPaths.length) {
      html += '<div class="evidence"><h4>Graph paths given to the LLM</h4>';
      html += attackPaths.map(pathHtml).join('');
      html += '</div>';
    }

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
    out.innerHTML = html;
    $('#ask-latency').textContent =
      `resolve ${latencyMs.resolve} ms · graph ${latencyMs.graph} ms · vector ${latencyMs.vector} ms · synthesis ${latencyMs.synthesis} ms · total ${latencyMs.total} ms`;
  } catch (err) {
    out.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Ask';
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
    console.error('[reports]', err);
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