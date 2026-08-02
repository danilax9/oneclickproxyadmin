let SERVER_IP = '';
let PORTS = [];
let USERS = [];

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
  const el = document.getElementById(id);
  el.classList.remove('hidden');
  el.classList.add('flex');
}
function closeModal(id) {
  const el = document.getElementById(id);
  el.classList.add('hidden');
  el.classList.remove('flex');
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const original = btn.textContent;
    btn.textContent = '✅';
    setTimeout(() => (btn.textContent = original), 1200);
  });
}

// ----------------------------------------------------------- Server info --

async function loadServerInfo() {
  const info = await api('/api/server-info');
  SERVER_IP = info.ip;
  document.getElementById('serverIp').textContent = info.ip;
  const statusEl = document.getElementById('proxyStatus');
  if (info.proxy_running) {
    statusEl.textContent = '● работает';
    statusEl.className = 'badge badge-active ml-2';
  } else {
    statusEl.textContent = '● остановлен';
    statusEl.className = 'badge badge-blocked ml-2';
  }
}

// ------------------------------------------------------------------ Ports --

async function loadPorts() {
  PORTS = await api('/api/ports');
  const list = document.getElementById('portsList');
  const empty = document.getElementById('portsEmpty');
  list.innerHTML = '';
  empty.classList.toggle('hidden', PORTS.length > 0);

  for (const p of PORTS) {
    const row = document.createElement('div');
    row.className = 'flex items-center justify-between p-3 rounded-xl';
    row.style.border = '1px solid var(--card-border)';
    row.innerHTML = `
      <div class="flex items-center gap-3">
        <span class="font-mono font-semibold">${p.port}</span>
        <span class="badge badge-${p.type}">${p.type.toUpperCase()}</span>
      </div>
      <button class="btn btn-danger text-sm" data-id="${p.id}">Удалить</button>
    `;
    row.querySelector('button').addEventListener('click', async () => {
      if (!confirm(`Удалить порт ${p.port}? Пользователи потеряют к нему доступ.`)) return;
      await api(`/api/ports/${p.id}`, { method: 'DELETE' });
      await Promise.all([loadPorts(), loadUsers()]);
    });
    list.appendChild(row);
  }
}

document.getElementById('addPortBtn').addEventListener('click', () => {
  document.getElementById('portInput').value = '';
  document.getElementById('portError').classList.add('hidden');
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
    const card = document.createElement('div');
    card.className = 'card p-4';

    const linksHtml = (u.ports || []).map(p => {
      const link = `${p.type}://${u.username}:${u.password}@${SERVER_IP}:${p.port}`;
      return `
        <div class="flex items-center gap-2 mt-1">
          <span class="link-mono flex-1">${link}</span>
          <button class="btn btn-ghost text-sm copy-btn">📋</button>
        </div>
      `;
    }).join('') || `<p class="text-sm mt-1" style="color: var(--muted)">Нет доступа ни к одному порту</p>`;

    card.innerHTML = `
      <div class="flex items-start justify-between flex-wrap gap-3">
        <div>
          <div class="flex items-center gap-2">
            <span class="font-semibold">${u.username}</span>
            <span class="badge ${u.blocked ? 'badge-blocked' : 'badge-active'}">${u.blocked ? 'заблокирован' : 'активен'}</span>
          </div>
          <p class="text-sm mt-1" style="color: var(--muted)">пароль: <span class="font-mono">${u.password}</span></p>
        </div>
        <div class="flex gap-2">
          <button class="btn btn-ghost text-sm block-btn">${u.blocked ? 'Разблокировать' : 'Заблокировать'}</button>
          <button class="btn btn-danger text-sm delete-btn">Удалить</button>
        </div>
      </div>
      <div class="mt-3">${linksHtml}</div>
    `;

    // copy buttons
    const copyBtns = card.querySelectorAll('.copy-btn');
    (u.ports || []).forEach((p, idx) => {
      const link = `${p.type}://${u.username}:${u.password}@${SERVER_IP}:${p.port}`;
      copyBtns[idx].addEventListener('click', () => copyToClipboard(link, copyBtns[idx]));
    });

    card.querySelector('.block-btn').addEventListener('click', async () => {
      await api(`/api/users/${u.id}/block`, {
        method: 'PATCH',
        body: JSON.stringify({ blocked: !u.blocked }),
      });
      await loadUsers();
    });

    card.querySelector('.delete-btn').addEventListener('click', async () => {
      if (!confirm(`Удалить пользователя ${u.username}?`)) return;
      await api(`/api/users/${u.id}`, { method: 'DELETE' });
      await loadUsers();
    });

    list.appendChild(card);
  }
}

document.getElementById('addUserBtn').addEventListener('click', () => {
  document.getElementById('userNameInput').value = '';
  document.getElementById('userPassInput').value = '';
  document.getElementById('userError').classList.add('hidden');

  const box = document.getElementById('userPortsCheckboxes');
  box.innerHTML = '';
  if (PORTS.length === 0) {
    box.innerHTML = '<p class="text-sm" style="color: var(--muted)">Сначала создайте хотя бы один порт</p>';
  }
  for (const p of PORTS) {
    const label = document.createElement('label');
    label.className = 'flex items-center gap-2 text-sm';
    label.innerHTML = `<input type="checkbox" value="${p.id}" class="port-checkbox"> ${p.port} (${p.type.toUpperCase()})`;
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
