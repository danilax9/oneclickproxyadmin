let SERVER_IP = '';
let CONNECTION_HOST = '';
let HTTPS_ALLOWED = false;
let DOMAIN_SETTINGS = {};
let PORTS = [];
let USERS = [];

const COPY_BTN_HTML = `
  <span class="copy-icon-wrap">
    <svg class="copy-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    <svg class="check-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline class="check-path" points="20 6 9 17 4 12"/></svg>
  </span>`;

const copyResetTimers = new WeakMap();

async function api(path, options = {}) {
  const resp = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (resp.status === 401) {
    window.location.href = '/login';
    throw new Error('unauthorized');
  }
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.detail || 'Ошибка запроса');
  }
  return data;
}

function openModal(id) {
  document.getElementById(id).classList.remove('hidden');
}

function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
}

async function copyText(text) {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch { /* fallback below */ }
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.cssText = 'position:fixed;top:0;left:0;width:2em;height:2em;padding:0;border:none;outline:none;opacity:0';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  ta.setSelectionRange(0, text.length);
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch { /* ignore */ }
  document.body.removeChild(ta);
  return ok;
}

function showCopySuccess(btn) {
  const prev = copyResetTimers.get(btn);
  if (prev) clearTimeout(prev);
  btn.classList.remove('copied');
  void btn.offsetWidth; // restart CSS animation
  btn.classList.add('copied');
  copyResetTimers.set(btn, setTimeout(() => {
    btn.classList.remove('copied');
    copyResetTimers.delete(btn);
  }, 2000));
}

async function copyToClipboard(text, btn) {
  const ok = await copyText(text);
  if (ok) showCopySuccess(btn);
}

function updateStats() {
  document.getElementById('statPorts').textContent = PORTS.length;
  document.getElementById('statUsers').textContent = USERS.length;
  const domainEl = document.getElementById('statDomain');
  if (DOMAIN_SETTINGS.ssl_active && DOMAIN_SETTINGS.domain) {
    domainEl.textContent = DOMAIN_SETTINGS.domain;
    domainEl.title = DOMAIN_SETTINGS.domain;
  } else {
    domainEl.textContent = '—';
    domainEl.title = '';
  }
}

const SSL_LABELS = {
  none: { text: 'Не настроен', cls: 'badge-ssl-none' },
  pending: { text: 'Ожидает DNS', cls: 'badge-ssl-pending' },
  verified: { text: 'DNS проверен', cls: 'badge-ssl-pending' },
  issuing: { text: 'Выпуск SSL…', cls: 'badge-ssl-pending' },
  active: { text: 'SSL активен', cls: 'badge-ssl-active' },
  error: { text: 'Ошибка', cls: 'badge-ssl-error' },
};

function syncHttpsPortOption() {
  const opt = document.getElementById('httpsPortOption');
  const hint = document.getElementById('httpsPortHint');
  const select = document.getElementById('portTypeInput');
  opt.disabled = !HTTPS_ALLOWED;
  hint.classList.toggle('hidden', HTTPS_ALLOWED);
  if (!HTTPS_ALLOWED && select.value === 'https') {
    select.value = 'http';
  }
}

const SSL_MODE_HINTS = {
  caddy: 'Caddy займёт порты 80 и 443. Не подходит, если 443 уже занят Xray.',
  dns: 'Сертификат через DNS Cloudflare. Порт 443 не занимается — совместимо с Xray.',
  external: 'Используйте сертификаты Xray/acme.sh. Панель пробрасывается через fallback Xray.',
};

function renderDomainUI() {
  const s = DOMAIN_SETTINGS;
  const badge = document.getElementById('sslBadge');
  const label = SSL_LABELS[s.ssl_status] || SSL_LABELS.none;
  badge.textContent = label.text;
  badge.className = `badge ${label.cls}`;

  document.getElementById('domainInput').value = s.domain || '';
  document.getElementById('dnsValue').textContent = s.server_ip || SERVER_IP || '—';
  document.getElementById('dnsName').textContent = s.domain || 'ваш домен';

  const mode = s.ssl_mode || 'dns';
  document.getElementById('sslModeInput').value = mode;
  document.getElementById('sslModeHint').textContent = SSL_MODE_HINTS[mode] || '';
  document.getElementById('externalCertFields').classList.toggle('hidden', mode !== 'external');
  document.getElementById('dnsModeFields').classList.toggle('hidden', mode !== 'dns');
  document.getElementById('certPathInput').value = s.cert_path || '';
  document.getElementById('keyPathInput').value = s.key_path || '';

  const hasDomain = Boolean(s.domain);
  document.getElementById('verifyDomainBtn').disabled = !hasDomain || s.ssl_status === 'issuing';
  document.getElementById('activateSslBtn').disabled = !hasDomain || !['verified', 'error', 'active'].includes(s.ssl_status) || s.ssl_status === 'issuing';
  document.getElementById('removeDomainBtn').disabled = !hasDomain || s.ssl_status === 'issuing';
  document.getElementById('activateSslBtn').textContent = s.ssl_status === 'active' ? 'Перевыпустить SSL' : 'Выпустить SSL';

  const statusBox = document.getElementById('domainStatusBox');
  const statusText = document.getElementById('domainStatusText');
  const panelUrlBox = document.getElementById('panelUrlBox');
  const panelUrlLink = document.getElementById('panelUrlLink');

  if (s.ssl_error) {
    statusBox.classList.remove('hidden');
    statusText.textContent = s.ssl_error;
    statusText.style.color = 'var(--danger)';
  } else if (s.ssl_status === 'issuing') {
    statusBox.classList.remove('hidden');
    statusText.textContent = 'Выпуск сертификата Let\'s Encrypt… Подождите до 2 минут.';
    statusText.style.color = 'var(--text-secondary)';
  } else if (s.ssl_active) {
    statusBox.classList.remove('hidden');
    const modeNote = mode === 'caddy'
      ? 'Caddy обслуживает HTTPS-панель.'
      : 'Сертификат готов. Настройте Xray fallback для HTTPS-панели (см. ниже).';
    statusText.textContent = `Домен подключён. ${modeNote}`;
    statusText.style.color = 'var(--success)';
  } else if (hasDomain) {
    statusBox.classList.remove('hidden');
    statusText.textContent = 'Добавьте A-запись, проверьте DNS и выпустите SSL.';
    statusText.style.color = 'var(--text-secondary)';
  } else {
    statusBox.classList.add('hidden');
  }

  if (s.ssl_active && s.panel_url) {
    panelUrlBox.classList.remove('hidden');
    panelUrlLink.href = s.panel_url;
    panelUrlLink.textContent = s.panel_url;
  } else {
    panelUrlBox.classList.add('hidden');
  }

  const xrayBox = document.getElementById('xrayHintBox');
  if (s.ssl_active && s.xray_hint && mode !== 'caddy') {
    xrayBox.classList.remove('hidden');
    document.getElementById('xrayHintTitle').textContent = s.xray_hint.title;
    const stepsEl = document.getElementById('xrayHintSteps');
    stepsEl.innerHTML = (s.xray_hint.steps || []).map(st => `<li>${escapeHtml(st)}</li>`).join('');
    document.getElementById('xraySnippet').textContent = s.xray_hint.snippet || '';
  } else {
    xrayBox.classList.add('hidden');
  }

  syncHttpsPortOption();
  updateStats();
}

function applyDomainSettings(info) {
  DOMAIN_SETTINGS = {
    domain: info.domain,
    ssl_mode: info.ssl_mode || 'dns',
    ssl_status: info.ssl_status,
    ssl_error: info.ssl_error,
    ssl_active: info.ssl_active,
    https_allowed: info.https_allowed,
    panel_url: info.panel_url,
    server_ip: info.server_ip || info.ip,
    cert_path: info.cert_path,
    key_path: info.key_path,
    xray_hint: info.xray_hint,
  };
  HTTPS_ALLOWED = Boolean(info.https_allowed);
  CONNECTION_HOST = info.connection_host || info.ip || SERVER_IP;
  renderDomainUI();
}

// ----------------------------------------------------------- Server info --

async function loadServerInfo() {
  const info = await api('/api/server-info');
  SERVER_IP = info.ip;
  CONNECTION_HOST = info.connection_host || info.ip;
  HTTPS_ALLOWED = Boolean(info.https_allowed);
  document.getElementById('serverIp').textContent = info.ip;

  const statusEl = document.getElementById('proxyStatus');
  const dotEl = document.getElementById('proxyDot');
  const running = info.proxy_running;
  statusEl.textContent = running ? 'Работает' : 'Остановлен';
  dotEl.className = `status-dot ${running ? 'online' : 'offline'}`;

  applyDomainSettings(info);
}

// -------------------------------------------------------------- Domain ---

document.getElementById('saveDomainBtn').addEventListener('click', async () => {
  const domain = document.getElementById('domainInput').value.trim();
  const ssl_mode = document.getElementById('sslModeInput').value;
  const errorEl = document.getElementById('domainError');
  errorEl.classList.add('hidden');
  try {
    await api('/api/domain', { method: 'PUT', body: JSON.stringify({ domain, ssl_mode }) });
    if (ssl_mode === 'external') {
      await saveSslModePaths(false);
    }
    await loadServerInfo();
  } catch (e) {
    errorEl.textContent = e.message;
    errorEl.classList.remove('hidden');
  }
});

document.getElementById('sslModeInput').addEventListener('change', () => {
  const mode = document.getElementById('sslModeInput').value;
  document.getElementById('sslModeHint').textContent = SSL_MODE_HINTS[mode] || '';
  document.getElementById('externalCertFields').classList.toggle('hidden', mode !== 'external');
  document.getElementById('dnsModeFields').classList.toggle('hidden', mode !== 'dns');
});

async function saveSslModePaths(reload = true) {
  const ssl_mode = document.getElementById('sslModeInput').value;
  const cert_path = document.getElementById('certPathInput').value.trim();
  const key_path = document.getElementById('keyPathInput').value.trim();
  await api('/api/domain/ssl', {
    method: 'PATCH',
    body: JSON.stringify({ ssl_mode, cert_path: cert_path || null, key_path: key_path || null }),
  });
  if (reload) await loadServerInfo();
}

document.getElementById('saveSslModeBtn').addEventListener('click', async () => {
  const errorEl = document.getElementById('domainError');
  errorEl.classList.add('hidden');
  try {
    await saveSslModePaths(true);
  } catch (e) {
    errorEl.textContent = e.message;
    errorEl.classList.remove('hidden');
  }
});

document.getElementById('verifyDomainBtn').addEventListener('click', async () => {
  const errorEl = document.getElementById('domainError');
  errorEl.classList.add('hidden');
  const btn = document.getElementById('verifyDomainBtn');
  btn.disabled = true;
  try {
    await api('/api/domain/verify', { method: 'POST' });
    await loadServerInfo();
  } catch (e) {
    errorEl.textContent = e.message;
    errorEl.classList.remove('hidden');
    await loadServerInfo();
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('activateSslBtn').addEventListener('click', async () => {
  const errorEl = document.getElementById('domainError');
  errorEl.classList.add('hidden');
  const btn = document.getElementById('activateSslBtn');
  btn.disabled = true;
  btn.textContent = 'Выпуск SSL…';
  try {
    const mode = document.getElementById('sslModeInput').value;
    if (mode === 'external') {
      await saveSslModePaths(false);
    } else {
      await api('/api/domain/ssl', {
        method: 'PATCH',
        body: JSON.stringify({ ssl_mode: mode }),
      });
    }
    await api('/api/domain/activate', { method: 'POST' });
    await loadServerInfo();
    await loadPorts();
    await loadUsers();
  } catch (e) {
    errorEl.textContent = e.message;
    errorEl.classList.remove('hidden');
    await loadServerInfo();
  } finally {
    btn.disabled = false;
    renderDomainUI();
  }
});

document.getElementById('removeDomainBtn').addEventListener('click', async () => {
  if (!confirm('Отключить домен и SSL? HTTPS-порты нужно будет удалить заранее.')) return;
  const errorEl = document.getElementById('domainError');
  errorEl.classList.add('hidden');
  try {
    await api('/api/domain', { method: 'DELETE' });
    await loadServerInfo();
    await loadPorts();
    await loadUsers();
  } catch (e) {
    errorEl.textContent = e.message;
    errorEl.classList.remove('hidden');
  }
});

document.getElementById('copyDnsBtn').addEventListener('click', async function () {
  const ip = document.getElementById('dnsValue').textContent;
  if (ip && ip !== '—') await copyToClipboard(ip, this);
});

// ------------------------------------------------------------------ Ports --

async function loadPorts() {
  PORTS = await api('/api/ports');
  const list = document.getElementById('portsList');
  const empty = document.getElementById('portsEmpty');
  const table = document.getElementById('portsTable');

  list.innerHTML = '';
  const hasPorts = PORTS.length > 0;
  empty.classList.toggle('hidden', hasPorts);
  table.classList.toggle('hidden', !hasPorts);

  for (const p of PORTS) {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="td-mono">${p.port}</td>
      <td><span class="badge badge-${p.type}">${p.type.toUpperCase()}</span></td>
      <td class="td-actions">
        <button class="btn btn-danger btn-sm delete-btn">Удалить</button>
      </td>
    `;
    row.querySelector('.delete-btn').addEventListener('click', async () => {
      if (!confirm(`Удалить порт ${p.port}? Пользователи потеряют к нему доступ.`)) return;
      await api(`/api/ports/${p.id}`, { method: 'DELETE' });
      await Promise.all([loadPorts(), loadUsers()]);
      updateStats();
    });
    list.appendChild(row);
  }
  updateStats();
}

document.getElementById('addPortBtn').addEventListener('click', () => {
  document.getElementById('portInput').value = '';
  document.getElementById('portError').classList.add('hidden');
  syncHttpsPortOption();
  openModal('portModal');
});

document.getElementById('portSubmitBtn').addEventListener('click', async () => {
  const port = parseInt(document.getElementById('portInput').value, 10);
  const type = document.getElementById('portTypeInput').value;
  const errorEl = document.getElementById('portError');
  errorEl.classList.add('hidden');
  if (!port) {
    errorEl.textContent = 'Укажите номер порта';
    errorEl.classList.remove('hidden');
    return;
  }
  try {
    await api('/api/ports', { method: 'POST', body: JSON.stringify({ port, type }) });
    closeModal('portModal');
    await loadPorts();
  } catch (e) {
    errorEl.textContent = e.message;
    errorEl.classList.remove('hidden');
  }
});

// ------------------------------------------------------------------ Users --

async function loadUsers() {
  USERS = await api('/api/users');
  const list = document.getElementById('usersList');
  const empty = document.getElementById('usersEmpty');

  list.innerHTML = '';
  empty.classList.toggle('hidden', USERS.length > 0);

  for (const u of USERS) {
    const item = document.createElement('div');
    item.className = 'user-item';

    const linksHtml = (u.ports || []).map(() => `
      <div class="proxy-link-row">
        <div class="proxy-link"></div>
        <button type="button" class="btn btn-icon copy-btn" title="Копировать">${COPY_BTN_HTML}</button>
      </div>
    `).join('');

    item.innerHTML = `
      <div class="user-item-header">
        <div>
          <div class="user-name-row">
            <span class="user-name">${escapeHtml(u.username)}</span>
            <span class="badge ${u.blocked ? 'badge-blocked' : 'badge-active'}">${u.blocked ? 'Заблокирован' : 'Активен'}</span>
          </div>
          <div class="user-password">Пароль: <code>${escapeHtml(u.password)}</code></div>
        </div>
        <div class="user-actions">
          <button class="btn btn-secondary btn-sm block-btn">${u.blocked ? 'Разблокировать' : 'Заблокировать'}</button>
          <button class="btn btn-danger btn-sm delete-btn">Удалить</button>
        </div>
      </div>
      ${linksHtml
        ? `<div class="proxy-links">${linksHtml}</div>`
        : '<p class="no-links">Нет доступа к портам</p>'}
    `;

    const linkEls = item.querySelectorAll('.proxy-link');
    const copyBtns = item.querySelectorAll('.copy-btn');
    (u.ports || []).forEach((p, idx) => {
      const host = p.type === 'https' ? CONNECTION_HOST : SERVER_IP;
      const link = `${p.type}://${u.username}:${u.password}@${host}:${p.port}`;
      linkEls[idx].textContent = link;
      copyBtns[idx].addEventListener('click', () => copyToClipboard(link, copyBtns[idx]));
    });

    item.querySelector('.block-btn').addEventListener('click', async () => {
      await api(`/api/users/${u.id}/block`, {
        method: 'PATCH',
        body: JSON.stringify({ blocked: !u.blocked }),
      });
      await loadUsers();
    });

    item.querySelector('.delete-btn').addEventListener('click', async () => {
      if (!confirm(`Удалить пользователя ${u.username}?`)) return;
      await api(`/api/users/${u.id}`, { method: 'DELETE' });
      await loadUsers();
    });

    list.appendChild(item);
  }
  updateStats();
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

document.getElementById('addUserBtn').addEventListener('click', () => {
  document.getElementById('userNameInput').value = '';
  document.getElementById('userPassInput').value = '';
  document.getElementById('userError').classList.add('hidden');

  const box = document.getElementById('userPortsCheckboxes');
  box.innerHTML = '';
  if (PORTS.length === 0) {
    box.innerHTML = '<span style="font-size:13px;color:var(--text-muted)">Сначала создайте хотя бы один порт</span>';
  }
  for (const p of PORTS) {
    const label = document.createElement('label');
    label.className = 'checkbox-label';
    label.innerHTML = `<input type="checkbox" value="${p.id}" class="port-checkbox"> ${p.port} · ${p.type.toUpperCase()}`;
    box.appendChild(label);
  }
  openModal('userModal');
});

document.getElementById('userSubmitBtn').addEventListener('click', async () => {
  const username = document.getElementById('userNameInput').value.trim();
  const password = document.getElementById('userPassInput').value.trim();
  const port_ids = [...document.querySelectorAll('.port-checkbox:checked')].map(cb => parseInt(cb.value, 10));
  const errorEl = document.getElementById('userError');
  errorEl.classList.add('hidden');
  try {
    await api('/api/users', {
      method: 'POST',
      body: JSON.stringify({ username: username || null, password: password || null, port_ids }),
    });
    closeModal('userModal');
    await loadUsers();
  } catch (e) {
    errorEl.textContent = e.message;
    errorEl.classList.remove('hidden');
  }
});

// ---------------------------------------------------------- Modal close --

document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal(overlay.id);
  });
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay:not(.hidden)').forEach(m => closeModal(m.id));
  }
});

// ----------------------------------------------------------------- Logout --

document.getElementById('logoutBtn').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' });
  window.location.href = '/login';
});

// ------------------------------------------------------------------- Init --

(async function init() {
  try {
    await api('/api/me');
    await loadServerInfo();
    await loadPorts();
    await loadUsers();
  } catch (e) {
    console.error(e);
  }
})();
