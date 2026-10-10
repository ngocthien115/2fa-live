const GROUP_INDEX_KEY = 'totp_vault_groups_index_v1';
const LEGACY_TEXT_KEY = 'totp_vault_text';
let groupStore = [];
let selectedGroupId = null;
let groupCodeCache = {};

function groupKey(id) {
  return 'totp_vault_group_' + id;
}
function newId() {
  return crypto.randomUUID
    ? crypto.randomUUID()
    : Date.now().toString(36) + Math.random().toString(36).slice(2);
}
function jsonRead(key, fallback) {
  try {
    return JSON.parse(localStorage.getItem(key) || '') || fallback;
  } catch (e) {
    return fallback;
  }
}
function selectedGroup() {
  return groupStore.find((group) => group.id === selectedGroupId) || null;
}
function saveGroupIndex() {
  localStorage.setItem(
    GROUP_INDEX_KEY,
    JSON.stringify(groupStore.map((group) => ({ id: group.id, name: group.name }))),
  );
}
function saveGroup(group) {
  localStorage.setItem(
    groupKey(group.id),
    JSON.stringify({ id: group.id, name: group.name, accounts: group.accounts }),
  );
}
function parseGroupText(text) {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const accounts = [];
  for (let i = 0; i + 1 < lines.length; i += 2) {
    accounts.push({ id: newId(), name: lines[i], secret: lines[i + 1].replace(/\s/g, '') });
  }
  return accounts;
}
function groupText(accounts) {
  return accounts.map((account) => account.name + '\n' + account.secret).join('\n');
}
function loadGroups() {
  const index = jsonRead(GROUP_INDEX_KEY, null);
  if (Array.isArray(index) && index.length) {
    groupStore = index.map((meta) => {
      const stored = jsonRead(groupKey(meta.id), {});
      return {
        id: meta.id,
        name: stored.name || meta.name || 'Không tên',
        accounts: Array.isArray(stored.accounts) ? stored.accounts : [],
      };
    });
  } else {
    const legacyText = localStorage.getItem(LEGACY_TEXT_KEY) || '';
    const defaultGroup = { id: newId(), name: 'Mặc định', accounts: parseGroupText(legacyText) };
    groupStore = [defaultGroup];
    saveGroup(defaultGroup);
    saveGroupIndex();
    if (legacyText) localStorage.removeItem(LEGACY_TEXT_KEY);
  }
  selectedGroupId = groupStore[0]?.id || null;
}
function groupEscape(value) {
  return String(value).replace(
    /[&<>"']/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char],
  );
}
function notifyGroup(message) {
  const toast = document.getElementById('group-toast');
  toast.textContent = message;
  toast.classList.add('g-toast-show');
  clearTimeout(notifyGroup.timer);
  notifyGroup.timer = setTimeout(() => toast.classList.remove('g-toast-show'), 1600);
}
function groupRing(remaining) {
  const radius = 18,
    circumference = 2 * Math.PI * radius;
  const tone = remaining <= 5 ? 'danger' : remaining <= 10 ? 'warn' : '';
  return `<svg class="g-ring ${tone}" width="44" height="44" viewBox="0 0 44 44" aria-hidden="true">
    <circle class="track" cx="22" cy="22" r="${radius}" fill="none" stroke-width="3"/>
    <circle class="progress" cx="22" cy="22" r="${radius}" fill="none" stroke-width="3" stroke-dasharray="${circumference}" stroke-dashoffset="${circumference * (1 - remaining / 30)}" transform="rotate(-90 22 22)" stroke-linecap="round"/>
    <text x="22" y="23">${remaining}</text>
  </svg>`;
}
function renderGroupList() {
  document.getElementById('g-total-groups').textContent = groupStore.length;
  document.getElementById('g-group-list').innerHTML = groupStore
    .map(
      (
        group,
      ) => `<button type="button" class="g-group-item ${group.id === selectedGroupId ? 'active' : ''}" data-group-id="${groupEscape(group.id)}" aria-pressed="${group.id === selectedGroupId}" title="${groupEscape(group.name)}">
    <span class="g-group-dot"></span><span class="g-group-name">${groupEscape(group.name)}</span><span class="g-group-count">${group.accounts.length}</span>
  </button>`,
    )
    .join('');
}
function renderGroupWorkspace() {
  const workspace = document.getElementById('g-workspace');
  const group = selectedGroup();
  if (!group) {
    workspace.innerHTML =
      '<div class="g-empty"><b>Chưa có group nào</b>Tạo một group để bắt đầu quản lý mã 2FA.</div>';
    return;
  }

  workspace.innerHTML = `
    <div class="g-main-head">
      <div class="g-heading">
        <p class="g-eyebrow">Active group</p>
        <h2>${groupEscape(group.name)}</h2>
        <p class="g-sub" id="g-account-count">${group.accounts.length} tài khoản · Chạm vào mã để sao chép</p>
      </div>
      <div class="g-actions">
        <button type="button" class="g-btn ghost" id="g-rename-group">Đổi tên</button>
        <button type="button" class="g-btn danger" id="g-delete-group">Xoá group</button>
      </div>
    </div>
    <section class="g-panel g-import" aria-label="Nạp dữ liệu">
      <div class="g-import-head">
        <div class="g-import-description">
          <label class="g-import-title" for="g-paste">Nạp dữ liệu vào group này</label>
          <p class="g-sub" id="g-paste-help">name / secret xen kẽ từng dòng</p>
        </div>
        <button type="button" class="g-btn primary g-update-group" id="g-confirm" title="Cập nhật group" aria-label="Cập nhật group">↻</button>
      </div>
      <textarea id="g-paste" aria-describedby="g-paste-help" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="Ví dụ:\nGitHub\nJBSWY3DPEHPK3PXP\nGoogle\nKRSXG5A3N5XA..."></textarea>
    </section>
    <input class="g-search" id="g-search" type="text" aria-label="Tìm tài khoản trong group" autocomplete="off" placeholder="Tìm trong ${groupEscape(group.name)}...">
    <div id="g-accounts"></div>`;

  document.getElementById('g-paste').value = groupText(group.accounts);
  renderGroupAccounts();
}

// Filtering only replaces the account list, keeping focus and import drafts intact.
function renderGroupAccounts() {
  const group = selectedGroup();
  const list = document.getElementById('g-accounts');
  if (!group || !list) return;
  const query = document.getElementById('g-search').value.trim().toLowerCase();
  const visible = group.accounts.filter((account) => account.name.toLowerCase().includes(query));
  const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
  let accountContent;
  if (!visible.length) {
    accountContent = `<div class="g-empty"><b>${query ? 'Không tìm thấy tài khoản' : 'Group đang trống'}</b>${query ? `Không có tài khoản khớp “${groupEscape(query)}”.` : 'Dán name/secret xen kẽ dòng vào ô phía trên để thêm dữ liệu.'}</div>`;
  } else {
    accountContent = `<div class="g-cards">${visible
      .map((account) => {
        const cached = groupCodeCache[account.id];
        const code = cached ? cached.code : '------';
        return `
        <div class="g-card" data-account-id="${groupEscape(account.id)}">
          <button type="button" class="g-copy" aria-label="Sao chép mã của ${groupEscape(account.name)}">
            ${groupRing(remaining)}
            <span class="g-info">
              <span class="g-name" title="${groupEscape(account.name)}">${groupEscape(account.name)}</span>
              <span class="g-code">${code.slice(0, 3)} ${code.slice(3)}</span>
            </span>
          </button>
          <button type="button" class="g-del" data-account-id="${groupEscape(account.id)}" title="Xoá tài khoản" aria-label="Xoá tài khoản ${groupEscape(account.name)}">✕</button>
        </div>`;
      })
      .join('')}</div>`;
  }
  list.innerHTML = accountContent;
}
function renderGroups() {
  renderGroupList();
  renderGroupWorkspace();
}
function persistSelectedGroup() {
  const group = selectedGroup();
  if (group) {
    saveGroup(group);
    saveGroupIndex();
  }
}

function base32GroupDecode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}
async function groupTotp(secret) {
  const keyBytes = base32GroupDecode(secret);
  if (!keyBytes.length) return null;
  const counter = Math.floor(Date.now() / 1000 / 30);
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setBigUint64(0, BigInt(counter), false);
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign'],
    );
    const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, buffer));
    const offset = signature[signature.length - 1] & 15;
    const binary =
      ((signature[offset] & 127) << 24) |
      ((signature[offset + 1] & 255) << 16) |
      ((signature[offset + 2] & 255) << 8) |
      (signature[offset + 3] & 255);
    return { code: (binary % 1000000).toString().padStart(6, '0'), counter };
  } catch (e) {
    return null;
  }
}
async function refreshGroupCodes() {
  const group = selectedGroup();
  if (!group) return;
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (const account of group.accounts) {
    if (!groupCodeCache[account.id] || groupCodeCache[account.id].counter !== counter) {
      const result = await groupTotp(account.secret);
      // A group switch or import can happen while crypto is still running.
      if (selectedGroup() !== group || !group.accounts.includes(account)) return;
      if (result) groupCodeCache[account.id] = result;
    }
  }
  const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
  document.querySelectorAll('#g-workspace .g-card').forEach((card) => {
    const cached = groupCodeCache[card.dataset.accountId];
    const code = cached ? cached.code : '------';
    card.querySelector('.g-code').textContent = `${code.slice(0, 3)} ${code.slice(3)}`;
    card.querySelector('.g-ring').outerHTML = groupRing(remaining);
  });
}

document.getElementById('g-new-group').addEventListener('click', () => {
  const name = prompt('Tên group mới:', 'Công việc');
  if (!name || !name.trim()) return;
  const group = { id: newId(), name: name.trim(), accounts: [] };
  groupStore.push(group);
  selectedGroupId = group.id;
  groupCodeCache = {};
  saveGroup(group);
  saveGroupIndex();
  renderGroups();
  notifyGroup('Đã tạo group');
});
document.getElementById('g-group-list').addEventListener('click', (event) => {
  const item = event.target.closest('.g-group-item');
  if (!item) return;
  if (item.dataset.groupId === selectedGroupId) return;
  selectedGroupId = item.dataset.groupId;
  groupCodeCache = {};
  renderGroups();
  document
    .querySelector('.g-group-item.active')
    .scrollIntoView({ block: 'nearest', inline: 'nearest' });
  refreshGroupCodes();
});
document.getElementById('g-workspace').addEventListener('input', (event) => {
  if (event.target.id === 'g-search') renderGroupAccounts();
});
document.getElementById('g-workspace').addEventListener('click', (event) => {
  const group = selectedGroup();
  if (!group) return;
  if (event.target.closest('#g-rename-group')) {
    const name = prompt('Tên group mới:', group.name);
    if (name && name.trim()) {
      group.name = name.trim();
      persistSelectedGroup();
      renderGroups();
      notifyGroup('Đã đổi tên group');
    }
    return;
  }
  if (event.target.closest('#g-delete-group')) {
    if (groupStore.length === 1) {
      notifyGroup('Phải giữ lại ít nhất một group');
      return;
    }
    if (!confirm(`Xoá group “${group.name}” và toàn bộ dữ liệu?`)) return;
    const removedId = group.id;
    groupStore = groupStore.filter((item) => item.id !== removedId);
    localStorage.removeItem(groupKey(removedId));
    selectedGroupId = groupStore[0].id;
    groupCodeCache = {};
    saveGroupIndex();
    renderGroups();
    refreshGroupCodes();
    notifyGroup('Đã xoá group');
    return;
  }
  if (event.target.closest('#g-confirm')) {
    const parsed = parseGroupText(document.getElementById('g-paste').value);
    if (!parsed.length) {
      notifyGroup('Dữ liệu không đúng định dạng');
      return;
    }
    group.accounts = parsed;
    persistSelectedGroup();
    groupCodeCache = {};
    renderGroups();
    refreshGroupCodes();
    notifyGroup(`Đã cập nhật ${parsed.length} tài khoản`);
    return;
  }
  const deleteButton = event.target.closest('.g-del');
  if (deleteButton) {
    group.accounts = group.accounts.filter(
      (account) => account.id !== deleteButton.dataset.accountId,
    );
    delete groupCodeCache[deleteButton.dataset.accountId];
    persistSelectedGroup();
    renderGroupList();
    renderGroupAccounts();
    document.getElementById('g-paste').value = groupText(group.accounts);
    document.getElementById('g-account-count').textContent =
      `${group.accounts.length} tài khoản · Chạm vào mã để sao chép`;
    return;
  }
  const copyButton = event.target.closest('.g-copy');
  const card = copyButton && copyButton.closest('.g-card');
  const cached = card && groupCodeCache[card.dataset.accountId];
  if (!card) return;
  if (!cached) {
    notifyGroup('Mã chưa sẵn sàng');
    return;
  }
  if (!navigator.clipboard) {
    notifyGroup('Không thể copy tự động');
    return;
  }
  navigator.clipboard
    .writeText(cached.code)
    .then(() => notifyGroup('Đã copy mã'))
    .catch(() => notifyGroup('Không thể copy tự động'));
});

loadGroups();
renderGroups();
refreshGroupCodes();
setInterval(refreshGroupCodes, 1000);
