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
const PAGES = ['login', 'graph', 'ask', 'insights', 'reports', 'admin'];
const isAdmin = () => Boolean(state.user && state.user.role === 'admin');

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
  if (route === 'admin' && !isAdmin()) { location.replace('#/graph'); return; }

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
      if (route === 'ask') { loadAskModes(); loadSavedQueries(); }
      if (route === 'insights') loadInsights();
      if (route === 'admin') loadAdmin();
    });
  }
}

window.addEventListener('hashchange', renderRoute);

/* ============================ Auth ============================ */
function showUser() {
  const u = state.user;
  $('#user-role').textContent = u ? `${u.role} · ${u.email}` : '';
  document.querySelectorAll('.admin-only').forEach((el) => el.classList.toggle('hidden', !isAdmin()));
}

function logout() {
  adminLoaded = false;
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
  $('#zoom-controls').classList.toggle('hidden', !has);
  $('#graph-count-hint').textContent = has
    ? `${state.graph.nodes.size} nodes · ${state.graph.edges.size} edges — click a node to expand it, drag to pan, scroll or use +/− to zoom`
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
      if (n.pinned) { n.vx = 0; n.vy = 0; continue; } // attack-path nodes stay in their row
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
  const path = state.graph.path;
  const onPath = path ? new Set(path.keys) : null;
  const accent = isLight ? '#4f46e5' : '#58a6ff';
  ctx.strokeStyle = isLight ? '#94a3b8' : '#404650';
  ctx.globalAlpha = path ? 0.18 : 0.5;
  ctx.lineWidth = 1;
  for (const e of visibleEdges) {
    if (path && path.edgeKeys.has([e.a, e.b].sort().join('<>'))) continue; // drawn below
    const a = state.graph.nodes.get(e.a), b = state.graph.nodes.get(e.b);
    if (!a || !b) continue;
    const pa = w2s(a, scale, tx, ty), pb = w2s(b, scale, tx, ty);
    ctx.beginPath(); ctx.moveTo(pa.x, pa.y); ctx.lineTo(pb.x, pb.y); ctx.stroke();
  }
  ctx.globalAlpha = 1;
  if (path) drawPathEdges(ctx, path, scale, tx, ty, accent, isLight);

  const ordered = [...visibleNodes].sort((a, b) => degreeOf(b) - degreeOf(a));
  for (const n of ordered) {
    const p = w2s(n, scale, tx, ty);
    if (!Number.isFinite(p.x) || !Number.isFinite(p.y)) continue; // never draw NaN
    if (p.x < -40 || p.x > W + 40 || p.y < -40 || p.y > H + 40) continue;
    const r = Math.max(7, 5 + Math.min(9, Math.sqrt(degreeOf(n)) * 2));
    ctx.globalAlpha = onPath && !onPath.has(nodeKey(n)) ? 0.3 : 1;
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
    ctx.globalAlpha = 1;
    if (onPath && onPath.has(nodeKey(n))) drawHopBadge(ctx, p, r, path.keys.indexOf(nodeKey(n)), accent);
  }

  // labels for the most-connected nodes
  ctx.font = '11px -apple-system, sans-serif';
  // with a path shown, label only the path (plus whatever is hovered) to keep the chain readable
  const labelled = path
    ? [...ordered.filter((n) => hoverNode && nodeKey(n) === nodeKey(hoverNode) && !onPath.has(nodeKey(n))), ...ordered.filter((n) => onPath.has(nodeKey(n)))]
    : ordered.slice(0, 26);
  for (const n of labelled) {
    const p = w2s(n, scale, tx, ty);
    const isPathNode = onPath && onPath.has(nodeKey(n));
    ctx.globalAlpha = onPath && !isPathNode ? 0.55 : 1;
    ctx.font = isPathNode ? '600 12px -apple-system, sans-serif' : '11px -apple-system, sans-serif';
    if (p.x < -60 || p.x > W + 60 || p.y < -20 || p.y > H + 20) continue;
    const r = Math.max(7, 5 + Math.min(9, Math.sqrt(degreeOf(n)) * 2));
    const w = ctx.measureText(n.name).width;
    const labelBg = isLight ? 'rgba(255,255,255,0.92)' : 'rgba(13,17,23,0.85)';
    ctx.fillStyle = labelBg;
    ctx.fillRect(p.x - w / 2 - 4, p.y - 24, w + 8, 16);
    ctx.fillStyle = isLight ? '#0f172a' : '#e6edf3';
    ctx.fillText(n.name, p.x - w / 2, p.y - 12);
  }
  ctx.globalAlpha = 1;
}

/** Thick directional edges along the attack path, with arrowheads and relationship labels. */
function drawPathEdges(ctx, path, scale, tx, ty, accent, isLight) {
  path.hops.forEach((h) => {
    const src = state.graph.nodes.get(h.forward ? h.from : h.to);
    const dst = state.graph.nodes.get(h.forward ? h.to : h.from);
    if (!src || !dst) return;
    const a = w2s(src, scale, tx, ty), b = w2s(dst, scale, tx, ty);
    const ang = Math.atan2(b.y - a.y, b.x - a.x);
    const rDst = Math.max(7, 5 + Math.min(9, Math.sqrt(degreeOf(dst)) * 2)) + 6;
    const ex = b.x - Math.cos(ang) * rDst, ey = b.y - Math.sin(ang) * rDst;
    ctx.strokeStyle = accent;
    ctx.fillStyle = accent;
    ctx.lineWidth = 3.5;
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(ex, ey); ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(ex, ey);
    ctx.lineTo(ex - Math.cos(ang - 0.45) * 13, ey - Math.sin(ang - 0.45) * 13);
    ctx.lineTo(ex - Math.cos(ang + 0.45) * 13, ey - Math.sin(ang + 0.45) * 13);
    ctx.closePath(); ctx.fill();
    // relationship label at the midpoint
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
    ctx.font = '600 10px ui-monospace, SFMono-Regular, Menlo, monospace';
    const w = ctx.measureText(h.type).width;
    ctx.fillStyle = isLight ? '#eef2ff' : '#1c2a40';
    ctx.fillRect(mx - w / 2 - 5, my + 6, w + 10, 15);
    ctx.fillStyle = accent;
    ctx.fillText(h.type, mx - w / 2, my + 17);
  });
}

function drawHopBadge(ctx, p, r, i, accent) {
  ctx.beginPath();
  ctx.arc(p.x, p.y, r + 5, 0, Math.PI * 2);
  ctx.strokeStyle = accent; ctx.lineWidth = 2.5; ctx.stroke();
  const bx = p.x + r + 4, by = p.y + r + 2;
  ctx.beginPath(); ctx.arc(bx, by, 8, 0, Math.PI * 2);
  ctx.fillStyle = accent; ctx.fill();
  ctx.fillStyle = '#ffffff';
  ctx.font = '700 10px -apple-system, sans-serif';
  const t = String(i + 1);
  ctx.fillText(t, bx - ctx.measureText(t).width / 2, by + 3.5);
}

/* ---- canvas events: hover, drag-pan, wheel-zoom, click-expand ---- */
const canvas = $('#graph-canvas');
const wrap = $('#graph-canvas-wrap');

canvas.addEventListener('pointermove', (e) => {
  const rect = wrap.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  const wpt = s2w(mx, my, state.graph.view.scale, state.graph.view.tx, state.graph.view.ty);
  const hit = nodeAt(wpt.x, wpt.y);
  hoverNode = hit;
  canvas.style.cursor = hit ? 'pointer' : dragState ? 'grabbing' : 'grab';
  if (dragState) {
    if (Math.hypot(mx - dragState.x, my - dragState.y) > 4) clickMoved = true;
    state.graph.view.tx = dragState.tx + (mx - dragState.x);
    state.graph.view.ty = dragState.ty + (my - dragState.y);
    layoutGraph();
  } else {
    layoutGraph();
  }
});

canvas.addEventListener('pointerleave', () => { if (!dragState) { hoverNode = null; layoutGraph(); } });

// pointer events cover mouse, pen and touch (drag-to-pan works on tablets/phones)
canvas.addEventListener('pointerdown', (e) => {
  try { canvas.setPointerCapture(e.pointerId); } catch (err) { /* capture is best-effort */ }
  const rect = wrap.getBoundingClientRect();
  dragState = { x: e.clientX - rect.left, y: e.clientY - rect.top, tx: state.graph.view.tx, ty: state.graph.view.ty };
  clickMoved = false;
});
canvas.addEventListener('pointercancel', () => { dragState = null; });

canvas.addEventListener('pointerup', (e) => {
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

function zoomBy(factor) {
  const { scale, tx, ty } = state.graph.view;
  const W = wrap.clientWidth, H = wrap.clientHeight;
  const ns = Math.min(6, Math.max(0.12, scale * factor));
  state.graph.view.tx = W / 2 - ((W / 2 - tx) / scale) * ns;
  state.graph.view.ty = H / 2 - ((H / 2 - ty) / scale) * ns;
  state.graph.view.scale = ns;
  layoutGraph();
}
$('#zoom-in').addEventListener('click', () => zoomBy(1.25));
$('#zoom-out').addEventListener('click', () => zoomBy(0.8));
$('#zoom-fit').addEventListener('click', () => fitAfterLayout());

$('#graph-label-filter').addEventListener('change', layoutGraph);
$('#graph-reset').addEventListener('click', () => {
  state.graph = { nodes: new Map(), edges: new Map(), view: { scale: 1, tx: 0, ty: 0 } };
  clearPathUi();
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
    clearPathUi();
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

/* ---- attack path: shortest path rendered as a pinned, directional chain ---- */
const PATH_CONTEXT_PER_HOP = 6; // faded neighbours per hop, for context

function clearPathUi() {
  if (state.graph) state.graph.path = null;
  $('#path-steps').classList.add('hidden');
  $('#path-steps').innerHTML = '';
  $('#path-clear').classList.add('hidden');
}

async function showAttackPath() {
  const from = $('#path-from').value.trim();
  const to = $('#path-to').value.trim();
  if (!from || !to) { $('#graph-status').textContent = 'Enter a software name and a threat actor.'; return; }
  const btn = $('#path-btn');
  btn.disabled = true;
  btn.textContent = 'Finding path…';
  $('#graph-status').textContent = '';
  try {
    const sp = await api(`/api/algorithms/shortest-path?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
    if (!sp.found) { $('#graph-status').textContent = `No path between ${from} and ${to}.`; return; }

    state.graph = { nodes: new Map(), edges: new Map(), view: { scale: 1, tx: 0, ty: 0 } };
    $('#node-detail').hidden = true;
    const n = sp.path.length;
    const nodes = sp.path.map((p, i) => {
      const node = addNode(p.label, p.key, p.name);
      node.x = (i - (n - 1) / 2) * 200;
      node.y = 0;
      node.pinned = true;
      return node;
    });
    const hops = sp.rels.map((r, i) => {
      addEdge(nodes[i], nodes[i + 1], r.type, r.forward ? 'out' : 'in');
      return { from: nodeKey(nodes[i]), to: nodeKey(nodes[i + 1]), type: r.type, forward: r.forward };
    });

    // context: a few neighbours of every hop, fanned out in rows above/below it so they
    // never land on the path line (placed, not simulated)
    const keys = new Set(nodes.map(nodeKey));
    const neighbourLists = await Promise.all(nodes.map((nd) =>
      api(`/api/graph/${encodeURIComponent(nd.label)}/${encodeURIComponent(nd.key)}/neighbors`).catch(() => ({ neighbors: [] }))));
    neighbourLists.forEach((body, i) => {
      let added = 0;
      for (const nb of body.neighbors) {
        if (added >= PATH_CONTEXT_PER_HOP) break;
        const k = nodeKey(nb);
        if (keys.has(k)) continue;
        const side = added % 2 ? 1 : -1;
        const slot = Math.floor(added / 2); // 0,1,2 per side
        const ctxNode = addNode(nb.label, nb.key, nb.name);
        ctxNode.x = nodes[i].x + (slot - 1) * 55;
        ctxNode.y = side * (115 + (slot % 2) * 45);
        ctxNode.pinned = true;
        keys.add(k);
        addEdge(nodes[i], ctxNode, nb.rel, nb.direction);
        added++;
      }
    });

    state.graph.path = { keys: nodes.map(nodeKey), hops, edgeKeys: new Set(hops.map((h) => [h.from, h.to].sort().join('<>'))) };
    updateGraphEmpty();
    fitAfterLayout();
    renderPathSteps(sp, hops);
  } catch (err) {
    $('#graph-status').textContent = err.message;
    console.error('[attackPath]', err);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Show attack path';
  }
}

function renderPathSteps(sp, hops) {
  let html = `<span class="path-summary">${sp.hops} hops · ${sp.latencyMs} ms</span>`;
  sp.path.forEach((p, i) => {
    html += `<span class="path-node"><b>${i + 1}</b><i class="dot" style="background:${COLORS[p.label] || '#888'}"></i>${escapeHtml(p.name)}</span>`;
    if (hops[i]) html += `<span class="path-rel">${hops[i].forward ? '' : '←'}${escapeHtml(hops[i].type)}${hops[i].forward ? '→' : ''}</span>`;
  });
  $('#path-steps').innerHTML = html;
  $('#path-steps').classList.remove('hidden');
  $('#path-clear').classList.remove('hidden');
}

$('#path-btn').addEventListener('click', showAttackPath);
['#path-from', '#path-to'].forEach((sel) => $(sel).addEventListener('keydown', (e) => { if (e.key === 'Enter') showAttackPath(); }));
$('#path-clear').addEventListener('click', () => {
  for (const n of state.graph.nodes.values()) n.pinned = false;
  clearPathUi();
  layoutGraph();
});

/** Open an entity in the Graph page (used by the Insights page). */
function openInGraph(name) {
  $('#graph-search').value = name;
  navigate('graph');
  setTimeout(() => $('#graph-search-btn').click(), 50);
}

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

/* ---- saved queries ---- */
let savedQueries = [];

function savedStatus(msg, isError = false) {
  const el = $('#saved-status');
  el.textContent = msg;
  el.classList.toggle('error-text', isError);
  if (msg) setTimeout(() => { if (el.textContent === msg) el.textContent = ''; }, 3500);
}

function renderSavedQueries() {
  const box = $('#saved-list');
  if (!savedQueries.length) {
    box.innerHTML = '<span class="hint">No saved questions yet. Click ☆ Save to keep one.</span>';
    return;
  }
  box.innerHTML = savedQueries.map((q, i) => `
    <span class="saved-chip" data-i="${i}">
      <button class="saved-run" title="${escapeAttr(q.question)} (depth ${q.depth}, ${q.mode})">
        <span class="saved-name">${escapeHtml(q.name)}</span><small>${q.mode === 'llm' ? 'LLM' : 'template'} · d${q.depth}</small>
      </button>
      <button class="saved-del" title="Delete saved question" aria-label="Delete saved question ${escapeAttr(q.name)}">×</button>
    </span>`).join('');
  box.querySelectorAll('.saved-chip').forEach((chip) => {
    const q = savedQueries[Number(chip.dataset.i)];
    chip.querySelector('.saved-run').addEventListener('click', () => runSavedQuery(q));
    chip.querySelector('.saved-del').addEventListener('click', () => deleteSavedQuery(q));
  });
}

async function loadSavedQueries() {
  try {
    const body = await api('/api/users/me/saved-queries');
    savedQueries = body.savedQueries;
    renderSavedQueries();
  } catch (err) {
    $('#saved-list').innerHTML = `<span class="error-text">${escapeHtml(err.message)}</span>`;
  }
}

function runSavedQuery(q) {
  $('#ask-input').value = q.question;
  $('#ask-depth').value = String(q.depth);
  const llmOpt = $('#ask-mode option[value="llm"]');
  $('#ask-mode').value = q.mode === 'llm' && !llmOpt.disabled ? 'llm' : 'template';
  askQuestion();
}

async function deleteSavedQuery(q) {
  try {
    await api(`/api/users/me/saved-queries/${encodeURIComponent(q._id)}`, { method: 'DELETE' });
    savedQueries = savedQueries.filter((x) => x._id !== q._id);
    renderSavedQueries();
    savedStatus('Deleted.');
  } catch (err) {
    savedStatus(err.message, true);
  }
}

$('#ask-save').addEventListener('click', async () => {
  const question = $('#ask-input').value.trim();
  if (!question) { savedStatus('Type a question first.', true); return; }
  try {
    const body = await api('/api/users/me/saved-queries', {
      method: 'POST',
      body: JSON.stringify({ question, depth: Number($('#ask-depth').value) || 2, mode: $('#ask-mode').value }),
    });
    savedQueries = [body.savedQuery, ...savedQueries];
    renderSavedQueries();
    savedStatus('Saved.');
  } catch (err) {
    savedStatus(err.message, true);
  }
});

function escapeHtml(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function escapeAttr(s) { return escapeHtml(s); }

/* ============================ Insights page ============================ */
function barRows(items, { value, max, label, sub, right, onClick }) {
  if (!items.length) return '<p class="hint list-empty">No results.</p>';
  const top = max || Math.max(...items.map(value), 1);
  return items.map((it, i) => `
    <div class="bar-row${onClick ? ' clickable' : ''}" data-i="${i}" ${onClick ? 'role="button" tabindex="0"' : ''}>
      <div class="bar-text"><span class="bar-label">${escapeHtml(label(it))}</span><span class="bar-value">${escapeHtml(right(it))}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, (value(it) / top) * 100).toFixed(1)}%"></div></div>
      ${sub ? `<div class="bar-sub">${escapeHtml(sub(it))}</div>` : ''}
    </div>`).join('');
}

function wireBarClicks(container, items, onClick) {
  container.querySelectorAll('.bar-row.clickable').forEach((row) => {
    const go = () => onClick(items[Number(row.dataset.i)]);
    row.addEventListener('click', go);
    row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
  });
}

async function loadCriticality() {
  const box = $('#crit-list');
  box.innerHTML = '<p class="hint">Loading…</p>';
  try {
    const body = await api('/api/algorithms/technique-criticality');
    const items = body.techniques.slice(0, 12);
    box.innerHTML = barRows(items, {
      value: (t) => t.criticality,
      label: (t) => `${t.name} (${t.mitreId})`,
      right: (t) => String(t.criticality),
      sub: (t) => `${t.malwareCount} malware · ${t.actorCount} actors`,
      onClick: true,
    });
    wireBarClicks(box, items, (t) => openInGraph(t.mitreId));
  } catch (err) {
    box.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

async function loadSimilar() {
  const actor = $('#sim-actor').value.trim();
  const box = $('#sim-list');
  if (!actor) { box.innerHTML = '<p class="hint">Enter a threat actor name or ID.</p>'; return; }
  box.innerHTML = '<p class="hint">Loading…</p>';
  try {
    const body = await api(`/api/algorithms/similar-actors?actor=${encodeURIComponent(actor)}`);
    if (!body.similar.length) { box.innerHTML = `<p class="hint">No threat actor named “${escapeHtml(actor)}” with known techniques.</p>`; return; }
    const head = `<p class="hint list-meta">${escapeHtml(body.actorName)} performs ${body.actorTechniques} techniques · ${body.latencyMs} ms</p>`;
    box.innerHTML = head + barRows(body.similar, {
      value: (a) => a.jaccard,
      max: 1,
      label: (a) => `${a.name} (${a.mitreId})`,
      right: (a) => `${(a.jaccard * 100).toFixed(0)}%`,
      sub: (a) => `${a.sharedTechniques} shared of ${a.techniqueCount} techniques`,
      onClick: true,
    });
    wireBarClicks(box, body.similar, (a) => openInGraph(a.name));
  } catch (err) {
    box.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

async function loadMitigations() {
  const actor = $('#mit-actor').value.trim();
  const box = $('#mit-list');
  box.innerHTML = '<p class="hint">Loading…</p>';
  try {
    const body = await api(`/api/algorithms/mitigation-priorities${actor ? `?actor=${encodeURIComponent(actor)}` : ''}`);
    const scope = body.actor ? `${escapeHtml(body.actor.name)}'s techniques` : 'the 50 most-used techniques';
    const total = body.mitigations[0] ? body.mitigations[0].total : 0;
    const head = `<p class="hint list-meta">Coverage of ${scope}${total ? ` (${total})` : ''} · ${body.latencyMs} ms</p>`;
    box.innerHTML = head + barRows(body.mitigations, {
      value: (m) => m.score,
      label: (m) => `${m.name} (${m.mitreId})`,
      right: (m) => `${m.coverage}/${m.total}`,
      sub: (m) => `e.g. ${m.examples.slice(0, 3).join(', ')}`,
    });
  } catch (err) {
    box.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

let insightsLoaded = false;
function loadInsights() {
  if (insightsLoaded) return;
  insightsLoaded = true;
  loadCriticality();
  loadSimilar();
  loadMitigations();
}

$('#sim-form').addEventListener('submit', (e) => { e.preventDefault(); loadSimilar(); });
$('#mit-form').addEventListener('submit', (e) => { e.preventDefault(); loadMitigations(); });

/* ============================ Admin page ============================ */
function flash(sel, msg, isError = false) {
  const el = $(sel);
  el.textContent = msg;
  el.classList.toggle('error-text', isError);
}
const fmtDay = (d) => (d ? new Date(d).toISOString().slice(0, 10) : '');

let entityRows = [];
async function searchEntities() {
  const q = $('#ent-q').value.trim();
  const type = $('#ent-filter').value;
  const params = new URLSearchParams({ limit: '20' });
  if (q) params.set('q', q);
  if (type) params.set('entityType', type);
  $('#ent-list').innerHTML = '<p class="hint">Loading…</p>';
  try {
    const body = await api(`/api/entities?${params}`);
    entityRows = body.entities;
    renderEntities();
  } catch (err) {
    $('#ent-list').innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

function renderEntities(editingId = null) {
  if (!entityRows.length) { $('#ent-list').innerHTML = '<p class="hint list-empty">No entities match.</p>'; return; }
  let html = '<table class="matrix admin-table"><thead><tr><th>MITRE ID</th><th>Type</th><th>Name</th><th></th></tr></thead><tbody>';
  entityRows.forEach((e, i) => {
    if (e.mitreId === editingId) {
      html += `<tr class="editing" data-i="${i}"><td>${escapeHtml(e.mitreId)}</td><td>${escapeHtml(e.entityType)}</td>
        <td colspan="2"><form class="edit-form">
          <input name="name" value="${escapeAttr(e.name)}" aria-label="Name" required />
          <input name="aliases" value="${escapeAttr((e.aliases || []).join(', '))}" placeholder="Aliases, comma separated" aria-label="Aliases" />
          <input name="description" value="${escapeAttr(e.description || '')}" placeholder="Description" aria-label="Description" />
          <span class="row-actions"><button class="btn btn-sm btn-primary">Save</button><button type="button" class="btn btn-sm btn-ghost act-cancel">Cancel</button></span>
        </form></td></tr>`;
    } else {
      html += `<tr data-i="${i}"><td class="mono">${escapeHtml(e.mitreId)}</td><td>${escapeHtml(e.entityType)}</td><td>${escapeHtml(e.name)}</td>
        <td class="row-actions"><button class="btn btn-sm act-graph" title="Open in graph">Graph</button><button class="btn btn-sm act-edit">Edit</button><button class="btn btn-sm act-del">Delete</button></td></tr>`;
    }
  });
  $('#ent-list').innerHTML = html + '</tbody></table>';
  $('#ent-list').querySelectorAll('tr[data-i]').forEach((row) => {
    const e = entityRows[Number(row.dataset.i)];
    const on = (sel, fn) => { const b = row.querySelector(sel); if (b) b.addEventListener('click', fn); };
    on('.act-graph', () => openInGraph(e.name || e.mitreId));
    on('.act-edit', () => renderEntities(e.mitreId));
    on('.act-cancel', () => renderEntities());
    on('.act-del', (ev) => confirmDelete(ev.currentTarget, e));
    const form = row.querySelector('.edit-form');
    if (form) form.addEventListener('submit', (ev) => { ev.preventDefault(); saveEntity(e, new FormData(form)); });
  });
}

/** Two-step delete (no blocking browser dialog): first click arms, second click deletes. */
function confirmDelete(btn, e) {
  if (btn.dataset.armed) { deleteEntity(e); return; }
  btn.dataset.armed = '1';
  btn.textContent = 'Confirm?';
  btn.classList.add('btn-danger');
  setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = 'Delete'; btn.classList.remove('btn-danger'); } }, 4000);
}

async function saveEntity(e, fd) {
  const body = {
    name: String(fd.get('name')).trim(),
    aliases: String(fd.get('aliases')).split(',').map((a) => a.trim()).filter(Boolean),
    description: String(fd.get('description')).trim(),
  };
  try {
    const out = await api(`/api/entities/${encodeURIComponent(e.mitreId)}`, { method: 'PUT', body: JSON.stringify(body) });
    entityRows = entityRows.map((x) => (x.mitreId === e.mitreId ? out.entity : x));
    renderEntities();
    flash('#ent-status', `Updated ${e.mitreId} in MongoDB and Neo4j.`);
  } catch (err) { flash('#ent-status', err.message, true); }
}

async function deleteEntity(e) {
  try {
    await api(`/api/entities/${encodeURIComponent(e.mitreId)}`, { method: 'DELETE' });
    entityRows = entityRows.filter((x) => x.mitreId !== e.mitreId);
    renderEntities();
    flash('#ent-status', `Deleted ${e.mitreId} from MongoDB and DETACH DELETEd its graph node.`);
  } catch (err) { flash('#ent-status', err.message, true); }
}

$('#ent-search').addEventListener('submit', (ev) => { ev.preventDefault(); searchEntities(); });
$('#ent-create').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const body = {
    mitreId: $('#ent-id').value.trim(),
    entityType: $('#ent-type').value,
    name: $('#ent-name').value.trim() || undefined,
    description: $('#ent-desc').value.trim() || undefined,
  };
  try {
    const out = await api('/api/entities', { method: 'POST', body: JSON.stringify(body) });
    flash('#ent-status', `Created ${out.entity.mitreId} (${out.entity.entityType}) in both stores.`);
    $('#ent-create').reset();
    entityRows = [out.entity, ...entityRows.filter((x) => x.mitreId !== out.entity.mitreId)];
    renderEntities();
  } catch (err) { flash('#ent-status', err.message, true); }
});

async function loadUsers() {
  $('#user-list').innerHTML = '<p class="hint">Loading…</p>';
  try {
    const body = await api('/api/users');
    const me = state.user && state.user.email;
    let html = '<table class="matrix admin-table"><thead><tr><th>Email</th><th>Role</th><th>Saved</th><th>Created</th></tr></thead><tbody>';
    for (const u of body.users) {
      const self = u.email === me;
      html += `<tr><td>${escapeHtml(u.email)}${self ? ' <span class="hint">(you)</span>' : ''}</td>
        <td><select class="select select-sm role-select" data-id="${escapeAttr(u._id)}" ${self ? 'disabled title="You cannot change your own role"' : ''} aria-label="Role for ${escapeAttr(u.email)}">
          <option value="analyst" ${u.role === 'analyst' ? 'selected' : ''}>analyst</option>
          <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>admin</option></select></td>
        <td>${(u.savedQueries || []).length}</td><td>${fmtDay(u.createdAt)}</td></tr>`;
    }
    $('#user-list').innerHTML = html + '</tbody></table>';
    $('#user-list').querySelectorAll('.role-select').forEach((sel) => sel.addEventListener('change', async () => {
      try {
        const out = await api(`/api/users/${encodeURIComponent(sel.dataset.id)}/role`, { method: 'PATCH', body: JSON.stringify({ role: sel.value }) });
        flash('#user-status', `${out.user.email} is now ${out.user.role}.`);
      } catch (err) { flash('#user-status', err.message, true); loadUsers(); }
    }));
  } catch (err) {
    $('#user-list').innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

$('#user-create').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const body = {
    email: $('#user-email').value.trim(),
    name: $('#user-name').value.trim() || undefined,
    password: $('#user-pass').value,
    role: $('#user-role-new').value,
  };
  try {
    const out = await api('/api/auth/register', { method: 'POST', body: JSON.stringify(body) });
    flash('#user-status', `Registered ${out.user.email} as ${out.user.role}.`);
    $('#user-create').reset();
    loadUsers();
  } catch (err) { flash('#user-status', err.message, true); }
});

$('#health-run').addEventListener('click', async () => {
  const btn = $('#health-run');
  btn.disabled = true;
  btn.textContent = 'Checking…';
  try {
    const { drift, latencyMs, report: r } = await api('/api/admin/reconcile');
    const row = (label, m, g, a, b) => `<tr><td>${label}</td><td class="num">${m.toLocaleString()}</td><td class="num">${g.toLocaleString()}</td><td class="num">${a}</td><td class="num">${b}</td></tr>`;
    $('#health-out').innerHTML = `
      <p class="health-verdict ${drift ? 'bad' : 'good'}">${drift ? `⚠ ${drift} key(s) out of sync` : '✓ Both stores agree on every join key'} <span class="hint">· ${latencyMs} ms</span></p>
      <table class="matrix"><thead><tr><th>Keys</th><th>MongoDB</th><th>Neo4j</th><th>Only Mongo</th><th>Only Neo4j</th></tr></thead><tbody>
      ${row('mitreId', r.entities.mongoCount, r.entities.graphCount, r.entities.missingInGraph.length, r.entities.missingInMongo.length)}
      ${row('cveId', r.vulnerabilities.mongoCount, r.vulnerabilities.graphCount, r.vulnerabilities.missingInGraph.length, r.vulnerabilities.missingInMongo.length)}
      </tbody></table>`;
  } catch (err) {
    $('#health-out').innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run consistency check';
  }
});

let adminLoaded = false;
function loadAdmin() {
  if (adminLoaded) return;
  adminLoaded = true;
  searchEntities();
  loadUsers();
}

/* ============================ Reports page ============================ */
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEVERITY_COLORS = { CRITICAL: '#e5484d', HIGH: '#f76b15', MEDIUM: '#e3b341', LOW: '#8b949e' };
const reportsData = { years: null };

/** Stacked bars: items = [{ label, parts: { CRITICAL: n, ... } }]. Theme-aware, thins labels when crowded. */
function drawStacked(canvas, items) {
  const box = canvas && canvas.parentElement;
  if (!box || box.clientWidth === 0) return;
  const dpr = window.devicePixelRatio || 1;
  const W = box.clientWidth, H = Math.max(160, box.clientHeight);
  canvas.width = W * dpr; canvas.height = H * dpr;
  canvas.style.width = `${W}px`; canvas.style.height = `${H}px`;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);
  const isLight = document.body.dataset.theme === 'light';
  const muted = isLight ? '#64748b' : '#8b949e';
  const grid = isLight ? '#e2e8f0' : '#30363d';
  const totals = items.map((it) => Object.values(it.parts).reduce((a, b) => a + b, 0));
  const max = Math.max(1, ...totals);
  const padL = 36, padB = 22, padT = 16;
  const plotH = H - padB - padT;
  const bw = (W - padL - 4) / Math.max(1, items.length);
  ctx.font = '10px -apple-system, sans-serif';
  // gridlines + y labels
  for (const f of [0, 0.5, 1]) {
    const y = padT + plotH * (1 - f);
    ctx.strokeStyle = grid; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - 4, y); ctx.stroke();
    ctx.fillStyle = muted;
    const t = String(Math.round(max * f));
    ctx.fillText(t, padL - 6 - ctx.measureText(t).width, y + 3);
  }
  const labelEvery = Math.ceil(items.length / Math.max(1, Math.floor((W - padL) / 38)));
  items.forEach((it, i) => {
    let y = padT + plotH;
    const x = padL + i * bw + bw * 0.15, w = Math.max(2, bw * 0.7);
    for (const sev of SEVERITY_ORDER) {
      const v = it.parts[sev] || 0;
      if (!v) continue;
      const h = (v / max) * plotH;
      ctx.fillStyle = SEVERITY_COLORS[sev];
      ctx.fillRect(x, y - h, w, h);
      y -= h;
    }
    if (i % labelEvery === 0) {
      ctx.fillStyle = muted;
      const t = String(it.label);
      ctx.fillText(t, padL + i * bw + bw / 2 - ctx.measureText(t).width / 2, H - 6);
    }
  });
}

const cardError = (sel, err) => { $(sel).innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`; };
const pipelineNote = (body) => `${body.pipeline || 'aggregation pipeline'} · ${body.latencyMs} ms`;

async function loadSeverityByYear() {
  try {
    const body = await api('/api/analytics/cve-severity-by-month');
    const byYear = new Map();
    for (const r of body.rows) {
      const y = r._id.year;
      if (!byYear.has(y)) byYear.set(y, {});
      const parts = byYear.get(y);
      parts[r._id.severity] = (parts[r._id.severity] || 0) + r.count;
    }
    const years = [...byYear.keys()].sort((a, b) => a - b).slice(-15);
    reportsData.years = years.map((y) => ({ label: y, parts: byYear.get(y) }));
    $('#sub-sev-year').textContent = `${pipelineNote(body)} · last ${years.length} years with data`;
    const present = SEVERITY_ORDER.filter((sev) => reportsData.years.some((it) => it.parts[sev]));
    $('#legend-sev-year').innerHTML = present.map((sev) => `<span class="lg"><i style="background:${SEVERITY_COLORS[sev]}"></i>${sev.toLowerCase()}</span>`).join('');
    drawStacked($('#chart-sev-year'), reportsData.years);
  } catch (err) {
    $('#sub-sev-year').innerHTML = `<span class="error-text">${escapeHtml(err.message)}</span>`;
  }
}

async function loadSources() {
  try {
    const body = await api('/api/analytics/most-cited-sources');
    $('#sub-sources').textContent = `${pipelineNote(body)} · citations in Q&A answers`;
    $('#sources-list').innerHTML = body.rows.length
      ? barRows(body.rows, { value: (r) => r.citations, label: (r) => String(r._id), right: (r) => String(r.citations) })
      : '<p class="hint list-empty">No citations yet. Ask a question first.</p>';
  } catch (err) { cardError('#sources-list', err); }
}

async function loadCrosstab() {
  try {
    const body = await api('/api/analytics/severity-exploited-crosstab');
    $('#sub-crosstab').textContent = pipelineNote(body);
    const bySev = new Map();
    for (const r of body.rows) {
      const sev = r._id.severity;
      if (!bySev.has(sev)) bySev.set(sev, { kev: 0, not: 0, scoreSum: 0 });
      const row = bySev.get(sev);
      row[r._id.knownExploited ? 'kev' : 'not'] += r.count;
      row.scoreSum += (r.avgScore || 0) * r.count;
    }
    const sevs = SEVERITY_ORDER.filter((s) => bySev.has(s));
    const fmt = (n) => n.toLocaleString();
    let html = '<table class="matrix"><thead><tr><th>Severity</th><th>In KEV</th><th>Not in KEV</th><th>% exploited</th><th>Avg CVSS</th></tr></thead><tbody>';
    let tk = 0, tn = 0;
    for (const sev of sevs) {
      const r = bySev.get(sev); const total = r.kev + r.not; tk += r.kev; tn += r.not;
      html += `<tr><td class="cap"><i class="sev-dot" style="background:${SEVERITY_COLORS[sev]}"></i>${sev.toLowerCase()}</td>` +
        `<td class="num strong">${fmt(r.kev)}</td><td class="num">${fmt(r.not)}</td>` +
        `<td class="num">${((r.kev / total) * 100).toFixed(1)}%</td><td class="num">${(r.scoreSum / total).toFixed(1)}</td></tr>`;
    }
    html += `</tbody><tfoot><tr><td>Total</td><td class="num strong">${fmt(tk)}</td><td class="num">${fmt(tn)}</td>` +
      `<td class="num">${((tk / Math.max(1, tk + tn)) * 100).toFixed(1)}%</td><td></td></tr></tfoot></table>`;
    $('#crosstab-table').innerHTML = html;
  } catch (err) { cardError('#crosstab-table', err); }
}

async function loadChunksPerEntity() {
  try {
    const body = await api('/api/analytics/chunks-per-entity');
    $('#sub-chunks').textContent = pipelineNote(body);
    $('#chunks-entity-list').innerHTML = body.rows.slice(0, 12)
      .map((r) => `<div><span title="${escapeAttr(r._id)}">${escapeHtml(r.entityName || r.entityId || r._id)}</span><span class="n">${r.chunkCount} chunks</span></div>`)
      .join('') || '<p class="hint list-empty">No chunks yet.</p>';
  } catch (err) { cardError('#chunks-entity-list', err); }
}

function loadReports() {
  for (const sel of ['#sources-list', '#crosstab-table', '#chunks-entity-list']) {
    if (!$(sel).innerHTML.trim()) $(sel).innerHTML = '<p class="hint">Loading…</p>';
  }
  loadSeverityByYear();
  loadSources();
  loadCrosstab();
  loadChunksPerEntity();
}

function redrawCharts() {
  layoutGraph();
  if (reportsData.years && currentRoute() === 'reports') drawStacked($('#chart-sev-year'), reportsData.years);
}
window.addEventListener('resize', () => { if (currentRoute() === 'reports' && reportsData.years) drawStacked($('#chart-sev-year'), reportsData.years); });

/* ============================ Boot ============================ */
$('#theme-toggle').addEventListener('click', () => {
  applyTheme(document.body.dataset.theme === 'light' ? 'dark' : 'light');
  redrawCharts(); // canvases read theme colours at draw time
});

if (/[?&]debug\b/.test(location.search)) document.body.classList.add('debug');

initTheme();

if (state.token && state.user) {
  showUser();
  navigate(currentRoute()); // a reload keeps the page you were on
} else {
  navigate('login');
}
window.__sg_login_ready = true;