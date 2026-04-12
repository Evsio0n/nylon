// nylon Web UI — app.js
// Zero-dependency SPA with client-side routing

const API = '/api/v1';
let currentPage = 'dashboard';
let ws = null;

// --- Navigation ---

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    navigateTo(link.dataset.page);
  });
});

function navigateTo(page) {
  currentPage = page;
  document.querySelectorAll('.page').forEach(p => p.hidden = true);
  const target = document.getElementById('page-' + page);
  if (target) target.hidden = false;
  document.querySelectorAll('.nav-link').forEach(l => {
    l.classList.toggle('active', l.dataset.page === page);
  });
  loadPage(page);
}

// --- API helpers ---

async function apiFetch(endpoint) {
  const resp = await fetch(API + endpoint);
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || resp.statusText);
  }
  return resp.json();
}

async function apiPost(endpoint) {
  const resp = await fetch(API + endpoint, { method: 'POST' });
  return resp.json();
}

// --- Data loading ---

async function loadPage(page) {
  try {
    switch (page) {
      case 'dashboard': await loadDashboard(); break;
      case 'nodes': await loadNodes(); break;
      case 'routes': await loadRoutes(); break;
      case 'neighbours': await loadNeighbours(); break;
      case 'prefixes': await loadPrefixes(); break;
      case 'forward': await loadForward(); break;
      // 'log' page doesn't need data fetch
    }
  } catch (err) {
    console.error('Failed to load page:', page, err);
  }
}

// --- Dashboard ---

async function loadDashboard() {
  const [status, nodes, routes, neighbours, prefixes] = await Promise.allSettled([
    apiFetch('/status'),
    apiFetch('/nodes'),
    apiFetch('/routes'),
    apiFetch('/neighbours'),
    apiFetch('/prefixes'),
  ]);

  // Stats
  if (status.status === 'fulfilled') {
    const s = status.value;
    document.getElementById('stat-node-id').textContent = s.node_id;
    document.getElementById('stat-role').textContent = s.is_router ? 'Router' : 'Client';
    document.getElementById('nav-title').textContent = 'nylon · ' + s.node_id.substring(0, 8);
  }

  document.getElementById('stat-routes').textContent =
    routes.status === 'fulfilled' ? routes.value.length : '—';
  document.getElementById('stat-neighbours').textContent =
    neighbours.status === 'fulfilled' ? neighbours.value.length : '—';
  document.getElementById('stat-prefixes').textContent =
    prefixes.status === 'fulfilled' ? prefixes.value.length : '—';

  // Node table
  if (nodes.status === 'fulfilled') {
    const tbody = document.querySelector('#tbl-dashboard-nodes tbody');
    tbody.innerHTML = nodes.value.map(n => `
      <tr>
        <td><code>${esc(n.id)}</code></td>
        <td>${roleBadge(n.is_router)}</td>
        <td>${(n.addresses || []).map(a => '<code>' + esc(a) + '</code>').join(', ') || '—'}</td>
      </tr>
    `).join('');
  }
}

// --- Nodes ---

async function loadNodes() {
  const nodes = await apiFetch('/nodes');
  const tbody = document.querySelector('#tbl-nodes tbody');
  tbody.innerHTML = nodes.map(n => `
    <tr>
      <td><code>${esc(n.id)}</code></td>
      <td>${roleBadge(n.is_router)}</td>
      <td>${(n.addresses || []).map(a => '<code>' + esc(a) + '</code>').join(', ') || '—'}</td>
      <td><code title="${esc(n.public_key)}">${esc(n.public_key ? n.public_key.substring(0, 12) + '…' : '—')}</code></td>
    </tr>
  `).join('');
}

// --- Routes ---

async function loadRoutes() {
  const routes = await apiFetch('/routes');
  const tbody = document.querySelector('#tbl-routes tbody');
  tbody.innerHTML = routes.map(r => `
    <tr>
      <td><code>${esc(r.prefix)}</code></td>
      <td><code>${esc(r.next_hop)}</code></td>
      <td><code>${esc(r.router_id)}</code></td>
      <td>${r.seqno}</td>
      <td>${r.metric}</td>
      <td>${esc(r.expires_at || '—')}</td>
    </tr>
  `).join('');
}

// --- Neighbours ---

async function loadNeighbours() {
  const neighbours = await apiFetch('/neighbours');
  const container = document.getElementById('neighbour-cards');
  container.innerHTML = neighbours.map(n => `
    <article class="neigh-card">
      <details open>
        <summary>
          <code>${esc(n.id)}</code>
          ${n.best_metric > 0 ? `<span class="badge active">metric ${n.best_metric}</span>` : ''}
        </summary>
        <div class="neigh-meta">
          <span>Endpoints: <strong>${n.endpoints ? n.endpoints.length : 0}</strong></span>
          <span>Routes: <strong>${n.routes ? n.routes.length : 0}</strong></span>
        </div>
        ${n.endpoints && n.endpoints.length > 0 ? `
        <table class="endpoint-list">
          <thead><tr><th>Address</th><th>Resolved</th><th>Active</th><th>Metric</th><th>Remote</th></tr></thead>
          <tbody>
            ${n.endpoints.map(ep => `
              <tr>
                <td><code>${esc(ep.address)}</code></td>
                <td><code>${esc(ep.resolved || '—')}</code></td>
                <td>${ep.active ? '✓' : '✗'}</td>
                <td>${ep.metric}</td>
                <td>${ep.is_remote ? '✓' : '✗'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        ` : '<p><small>No endpoints</small></p>'}
        ${n.routes && n.routes.length > 0 ? `
        <footer><small>Routes: ${n.routes.map(r => '<code>' + esc(r) + '</code>').join(', ')}</small></footer>
        ` : ''}
      </details>
    </article>
  `).join('');
}

// --- Prefixes ---

async function loadPrefixes() {
  const prefixes = await apiFetch('/prefixes');
  const tbody = document.querySelector('#tbl-prefixes tbody');
  tbody.innerHTML = prefixes.map(p => `
    <tr>
      <td><code>${esc(p.prefix)}</code></td>
      <td><code>${esc(p.router_id)}</code></td>
      <td>${p.metric}</td>
      <td><span class="badge ${p.type}">${esc(p.type)}</span></td>
      <td>${esc(p.expires_at || '—')}</td>
    </tr>
  `).join('');
}

// --- Forward ---

async function loadForward() {
  const entries = await apiFetch('/forward');
  const tbody = document.querySelector('#tbl-forward tbody');
  tbody.innerHTML = entries.map(e => `
    <tr>
      <td><code>${esc(e.prefix)}</code></td>
      <td><code>${esc(e.next_hop)}</code></td>
    </tr>
  `).join('');
}

// --- WebSocket Live Log ---

const btnConnect = document.getElementById('btn-log-connect');
const btnClear = document.getElementById('btn-log-clear');
const logOutput = document.getElementById('log-output');
const wsStatus = document.getElementById('ws-status');

btnConnect.addEventListener('click', () => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.close();
  } else {
    connectWS();
  }
});

btnClear.addEventListener('click', () => {
  logOutput.innerHTML = '';
});

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = proto + '//' + location.host + API + '/ws';
  wsStatus.textContent = 'connecting';
  wsStatus.className = 'ws-status connecting';
  btnConnect.textContent = 'Connecting…';

  ws = new WebSocket(url, ['ws']);

  ws.onopen = () => {
    wsStatus.textContent = 'connected';
    wsStatus.className = 'ws-status connected';
    btnConnect.textContent = 'Disconnect';
    appendLog('--- connected ---', 'system');
  };

  ws.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      if (msg.type === 'trace' && msg.data) {
        const data = typeof msg.data === 'string' ? JSON.parse(msg.data) : msg.data;
        appendLog(data.message || JSON.stringify(data), 'trace', data.ts);
      } else if (msg.type === 'pong') {
        appendLog('pong', 'system');
      } else if (msg.type === 'error') {
        const data = typeof msg.data === 'string' ? JSON.parse(msg.data) : msg.data;
        appendLog('error: ' + (data.error || JSON.stringify(data)), 'error');
      } else {
        appendLog(JSON.stringify(msg), 'unknown');
      }
    } catch {
      appendLog(evt.data, 'raw');
    }
  };

  ws.onclose = () => {
    wsStatus.textContent = 'disconnected';
    wsStatus.className = 'ws-status disconnected';
    btnConnect.textContent = 'Connect';
    appendLog('--- disconnected ---', 'system');
  };

  ws.onerror = () => {
    appendLog('--- connection error ---', 'error');
  };
}

function appendLog(text, type, ts) {
  const line = document.createElement('div');
  line.className = 'log-line';
  const time = ts ? new Date(ts).toLocaleTimeString() : new Date().toLocaleTimeString();
  line.innerHTML = `<span class="log-ts">${esc(time)}</span>${esc(text)}`;
  logOutput.appendChild(line);
  // Auto-scroll
  logOutput.scrollTop = logOutput.scrollHeight;
  // Keep max 500 lines
  while (logOutput.children.length > 500) {
    logOutput.removeChild(logOutput.firstChild);
  }
}

// --- Actions ---

document.getElementById('btn-reload').addEventListener('click', async () => {
  await doAction('/reload', 'btn-reload');
  // Reload will restart the node, so refresh after delay
  setTimeout(() => loadDashboard(), 3000);
});

document.getElementById('btn-flush').addEventListener('click', async () => {
  await doAction('/flush_routes', 'btn-flush');
});

async function doAction(endpoint, btnId) {
  const result = document.getElementById('action-result');
  const btn = document.getElementById(btnId);
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  result.hidden = true;

  try {
    const resp = await apiPost(endpoint);
    if (resp.success) {
      result.textContent = '✓ ' + (resp.message || 'OK');
      result.className = 'success';
    } else {
      result.textContent = '✗ ' + (resp.message || resp.error || 'Unknown error');
      result.className = 'error';
    }
  } catch (err) {
    result.textContent = '✗ ' + err.message;
    result.className = 'error';
  }

  result.hidden = false;
  btn.disabled = false;
  btn.removeAttribute('aria-busy');
  setTimeout(() => { result.hidden = true; }, 5000);
}

// --- Helpers ---

function esc(s) {
  if (s == null) return '';
  const div = document.createElement('div');
  div.textContent = String(s);
  return div.innerHTML;
}

function roleBadge(isRouter) {
  return isRouter
    ? '<span class="badge router">Router</span>'
    : '<span class="badge client">Client</span>';
}

// --- Auto-refresh ---

let refreshTimer = null;

function startAutoRefresh() {
  stopAutoRefresh();
  refreshTimer = setInterval(() => {
    if (currentPage !== 'log') {
      loadPage(currentPage);
    }
  }, 10000); // every 10s
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

// --- Init ---

loadDashboard();
startAutoRefresh();
