'use strict';

/* =========================================================
 * Storage (same keys as the previous version → data carries over)
 * ======================================================= */
const GROUP_INDEX_KEY = 'totp_vault_groups_index_v1';
const LEGACY_TEXT_KEY = 'totp_vault_text';
const PANEL_KEY = 'totp_vault_panel_open';
const WIDE_MQ = window.matchMedia('(min-width: 1100px)');

const ALGORITHMS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
const AVATAR_PALETTE = [
  ['#14302A', '#7BE8CC'],
  ['#1A2740', '#8DB4FF'],
  ['#2E2614', '#F5C46B'],
  ['#2A1A33', '#D3A6F5'],
  ['#2E1B1B', '#F7A9A6'],
  ['#1C2A2E', '#86D3E8'],
];

const state = {
  groups: [], // [{ id, name, accounts: [account] }]
  activeId: null,
  query: '',
  newGroupOpen: false,
  newGroupName: '',
  renaming: false,
  renameValue: '',
  confirmGroupDelete: false,
  menuId: null,
  confirmId: null,
  copiedId: null,
  panelOpen: false,
  tab: 'single',
  editingId: null,
  form: { name: '', secret: '', groupId: null, showSecret: false },
  bulk: '',
};

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
function storageSet(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch (e) {
    toast('Không lưu được vào localStorage');
  }
}
function saveGroupIndex() {
  storageSet(
    GROUP_INDEX_KEY,
    JSON.stringify(state.groups.map((group) => ({ id: group.id, name: group.name }))),
  );
}
function saveGroup(group) {
  storageSet(
    groupKey(group.id),
    JSON.stringify({ id: group.id, name: group.name, accounts: group.accounts }),
  );
}
function saveAll() {
  state.groups.forEach(saveGroup);
  saveGroupIndex();
}

/* =========================================================
 * Account helpers
 * ======================================================= */
function cleanSecret(value) {
  return String(value || '')
    .replace(/[\s-]/g, '')
    .toUpperCase();
}
function isValidBase32(secret) {
  return /^[A-Z2-7]+=*$/.test(secret) && secret.replace(/=/g, '').length >= 8;
}
function normalizeAccount(raw) {
  const digits = Number(raw.digits);
  const period = Number(raw.period);
  const algorithm = String(raw.algorithm || '')
    .toUpperCase()
    .replace('-', '');
  return {
    id: raw.id || newId(),
    name: String(raw.name || '').trim() || 'Không tên',
    secret: cleanSecret(raw.secret),
    issuer: raw.issuer ? String(raw.issuer).trim() : '',
    digits: digits >= 6 && digits <= 8 ? digits : 6,
    period: period >= 1 && period <= 300 ? Math.floor(period) : 30,
    algorithm: ALGORITHMS[algorithm] ? algorithm : 'SHA1',
  };
}

// otpauth://totp/Issuer:account?secret=...&issuer=...&digits=6&period=30&algorithm=SHA1
function parseOtpauth(raw) {
  let url;
  try {
    url = new URL(String(raw).trim());
  } catch (e) {
    return { error: 'URI otpauth:// không hợp lệ.' };
  }
  if (url.protocol !== 'otpauth:') return { error: 'URI otpauth:// không hợp lệ.' };
  if (url.host.toLowerCase() !== 'totp') return { error: 'Chỉ hỗ trợ otpauth://totp (không hỗ trợ HOTP).' };
  let label = url.pathname.replace(/^\/+/, '');
  try {
    label = decodeURIComponent(label);
  } catch (e) {
    /* keep raw label */
  }
  let issuer = (url.searchParams.get('issuer') || '').trim();
  let name = label.trim();
  const colon = label.indexOf(':');
  if (colon > -1) {
    if (!issuer) issuer = label.slice(0, colon).trim();
    name = label.slice(colon + 1).trim();
  }
  const secret = cleanSecret(url.searchParams.get('secret'));
  if (!isValidBase32(secret)) return { error: 'URI không chứa secret Base32 hợp lệ.' };
  return {
    name: name || issuer,
    issuer,
    secret,
    digits: url.searchParams.get('digits'),
    period: url.searchParams.get('period'),
    algorithm: url.searchParams.get('algorithm'),
  };
}

// Accepts: "name" + "secret" on two lines, "name,secret" on one line, or an otpauth:// URI.
function parseBulk(text, group) {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const byName = new Map();
  let bad = 0;
  for (let i = 0; i < lines.length; ) {
    const line = lines[i];
    if (/^otpauth:\/\//i.test(line)) {
      const parsed = parseOtpauth(line);
      if (!parsed.error && parsed.name) byName.set(parsed.name, parsed);
      else bad++;
      i++;
      continue;
    }
    const comma = line.lastIndexOf(',');
    if (comma > -1) {
      const name = line.slice(0, comma).trim();
      const secret = cleanSecret(line.slice(comma + 1));
      if (name && isValidBase32(secret)) byName.set(name, { name, secret });
      else bad++;
      i++;
      continue;
    }
    const next = lines[i + 1];
    if (next && next.indexOf(',') < 0 && !/^otpauth:/i.test(next) && isValidBase32(cleanSecret(next))) {
      byName.set(line, { name: line, secret: cleanSecret(next) });
      i += 2;
      continue;
    }
    bad++;
    i++;
  }
  const entries = [...byName.values()];
  const existing = new Set(group ? group.accounts.map((account) => account.name) : []);
  const updated = entries.filter((entry) => existing.has(entry.name)).length;
  return { entries, created: entries.length - updated, updated, bad };
}

/* =========================================================
 * Load (incl. migration from the single-textarea version)
 * ======================================================= */
function parseLegacyText(text) {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const accounts = [];
  for (let i = 0; i + 1 < lines.length; i += 2) {
    accounts.push(normalizeAccount({ name: lines[i], secret: lines[i + 1] }));
  }
  return accounts;
}
function loadGroups() {
  const index = jsonRead(GROUP_INDEX_KEY, null);
  if (Array.isArray(index) && index.length) {
    state.groups = index.map((meta) => {
      const stored = jsonRead(groupKey(meta.id), {});
      return {
        id: meta.id,
        name: stored.name || meta.name || 'Không tên',
        accounts: Array.isArray(stored.accounts) ? stored.accounts.map(normalizeAccount) : [],
      };
    });
  } else {
    let legacyText = '';
    try {
      legacyText = localStorage.getItem(LEGACY_TEXT_KEY) || '';
    } catch (e) {
      /* storage blocked */
    }
    state.groups = [{ id: newId(), name: 'Mặc định', accounts: parseLegacyText(legacyText) }];
    saveAll();
    if (legacyText) localStorage.removeItem(LEGACY_TEXT_KEY);
  }
  state.activeId = state.groups[0] ? state.groups[0].id : null;
  state.form.groupId = state.activeId;
}

/* =========================================================
 * TOTP
 * ======================================================= */
// crypto.subtle only exists in secure contexts (https, localhost, file://).
const CRYPTO_OK = !!(window.crypto && window.crypto.subtle);
const keyCache = new Map();
const codeCache = {}; // accountId -> { sig, counter, code, next }

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const char of clean) {
    buffer = (buffer << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}
function hmacKey(secret, algorithm) {
  const cacheKey = algorithm + ':' + secret;
  if (!keyCache.has(cacheKey)) {
    const bytes = base32Decode(secret);
    keyCache.set(
      cacheKey,
      bytes.length
        ? crypto.subtle
            .importKey('raw', bytes, { name: 'HMAC', hash: ALGORITHMS[algorithm] }, false, ['sign'])
            .catch(() => null)
        : Promise.resolve(null),
    );
  }
  return keyCache.get(cacheKey);
}
async function generateCode(account, counter) {
  const key = await hmacKey(account.secret, account.algorithm);
  if (!key) return null;
  const message = new ArrayBuffer(8);
  new DataView(message).setBigUint64(0, BigInt(counter), false);
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const offset = signature[signature.length - 1] & 15;
  const binary =
    ((signature[offset] & 127) << 24) |
    ((signature[offset + 1] & 255) << 16) |
    ((signature[offset + 2] & 255) << 8) |
    (signature[offset + 3] & 255);
  return (binary % 10 ** account.digits).toString().padStart(account.digits, '0');
}
function accountSig(account) {
  return [account.secret, account.algorithm, account.digits, account.period].join('|');
}
function counterOf(account, nowSeconds) {
  return Math.floor(nowSeconds / account.period);
}
async function ensureCodes(account, nowSeconds) {
  const counter = counterOf(account, nowSeconds);
  const sig = accountSig(account);
  const cached = codeCache[account.id];
  if (cached && cached.counter === counter && cached.sig === sig) return;
  try {
    const [code, next] = await Promise.all([
      generateCode(account, counter),
      generateCode(account, counter + 1),
    ]);
    codeCache[account.id] = { sig, counter, code, next, invalid: code === null };
  } catch (e) {
    codeCache[account.id] = { sig, counter, code: null, next: null, invalid: true };
  }
}
function formatCode(code) {
  if (!code) return '';
  const half = Math.ceil(code.length / 2);
  return code.length >= 6 ? code.slice(0, half) + ' ' + code.slice(half) : code;
}
function placeholderCode(digits) {
  return formatCode('•'.repeat(digits));
}

/* =========================================================
 * Selectors
 * ======================================================= */
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function activeGroup() {
  return state.groups.find((group) => group.id === state.activeId) || null;
}
function groupById(id) {
  return state.groups.find((group) => group.id === id) || null;
}
function findAccount(id) {
  for (const group of state.groups) {
    const account = group.accounts.find((item) => item.id === id);
    if (account) return { account, group };
  }
  return null;
}
function searchQuery() {
  return state.query.trim().toLowerCase();
}
function visibleItems() {
  const query = searchQuery();
  if (query) {
    const items = [];
    state.groups.forEach((group) =>
      group.accounts.forEach((account) => {
        if ((account.name + ' ' + account.issuer).toLowerCase().includes(query)) {
          items.push({ account, group });
        }
      }),
    );
    return items;
  }
  const group = activeGroup();
  return group ? group.accounts.map((account) => ({ account, group })) : [];
}
function isOverlayPanel() {
  return !WIDE_MQ.matches;
}

/* =========================================================
 * Rendering
 * ======================================================= */
const ICON = {
  plus: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" aria-hidden="true"><path d="M12 5v14M5 12h14"></path></svg>',
  plusSm: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M12 5v14M5 12h14"></path></svg>',
  pencil: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"></path></svg>',
  trash: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"></path></svg>',
  trashSm: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"></path></svg>',
  kebab: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="12" cy="5" r="1.8"></circle><circle cx="12" cy="12" r="1.8"></circle><circle cx="12" cy="19" r="1.8"></circle></svg>',
  copy: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2"></rect><path d="M5 15V5a2 2 0 0 1 2-2h10"></path></svg>',
  check: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12l5 5L20 7"></path></svg>',
  key: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zM15.5 7.5l3 3L22 7l-3-3"></path></svg>',
  arrow: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"></path></svg>',
  close: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"></path></svg>',
  eye: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"></path><circle cx="12" cy="12" r="3"></circle></svg>',
};
const RING =
  '<svg class="ring" width="26" height="26" viewBox="0 0 44 44" aria-hidden="true"><circle class="ring-track" cx="22" cy="22" r="18"></circle><circle class="ring-fill" cx="22" cy="22" r="18"></circle></svg>';

function esc(value) {
  return String(value).replace(
    /[&<>"']/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char],
  );
}
function hash(text) {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function newGroupFormHtml() {
  return `<form class="new-group-form" data-form="new-group">
    <input class="input" name="name" aria-label="Tên group mới" placeholder="Tên group…" autocomplete="off" maxlength="60" value="${esc(state.newGroupName)}">
    <button type="submit" class="btn primary">Tạo</button>
  </form>`;
}

function renderGroups() {
  const searching = !!searchQuery();
  $('#group-list').innerHTML = state.groups
    .map((group) => {
      const on = !searching && group.id === state.activeId;
      return `<button type="button" class="group-item${on ? ' active' : ''}" data-action="pick-group" data-id="${esc(group.id)}"${on ? ' aria-current="true"' : ''} title="${esc(group.name)}">
        <span class="dot"></span><span class="group-name">${esc(group.name)}</span><span class="count">${group.accounts.length}</span>
      </button>`;
    })
    .join('');

  $('#group-chips').innerHTML =
    state.groups
      .map((group) => {
        const on = !searching && group.id === state.activeId;
        return `<button type="button" class="group-chip${on ? ' active' : ''}" data-action="pick-group" data-id="${esc(group.id)}"${on ? ' aria-current="true"' : ''}>
          ${esc(group.name)} <span class="count">${group.accounts.length}</span>
        </button>`;
      })
      .join('') +
    `<button type="button" class="group-chip add" data-action="toggle-new-group" aria-label="Tạo group mới" aria-expanded="${state.newGroupOpen}">${ICON.plusSm}</button>`;

  $$('[data-slot="new-group"]').forEach((slot) => {
    slot.innerHTML = state.newGroupOpen ? newGroupFormHtml() : '';
  });
  $$('[data-action="toggle-new-group"]').forEach((button) =>
    button.setAttribute('aria-expanded', String(state.newGroupOpen)),
  );
}

function renderHeader() {
  const group = activeGroup();
  const searching = !!searchQuery();
  const canEdit = !searching && !!group;
  const count = group ? group.accounts.length : 0;
  const title = searching ? 'Kết quả tìm kiếm' : group ? group.name : 'Chưa có group';
  const subtitle = searching
    ? `${visibleItems().length} tài khoản khớp “${state.query.trim()}”`
    : `${count} tài khoản · Chạm vào mã để sao chép`;

  const titleBlock =
    state.renaming && canEdit
      ? `<form class="rename-form" data-form="rename">
          <input class="input" name="name" aria-label="Tên group" value="${esc(state.renameValue)}" autocomplete="off" maxlength="60">
          <button type="submit" class="btn primary">Lưu</button>
          <button type="button" class="btn outline" data-action="cancel-rename">Huỷ</button>
        </form>`
      : `<div class="ws-title-row">
          <h1 class="ws-title" title="${esc(title)}">${esc(title)}</h1>
          ${
            canEdit
              ? `<button type="button" class="icon-btn" data-action="start-rename" aria-label="Đổi tên group">${ICON.pencil}</button>
                 <button type="button" class="icon-btn danger mobile-only" data-action="ask-delete-group" aria-label="Xoá group">${ICON.trashSm}</button>`
              : ''
          }
        </div>`;

  $('#ws-head').innerHTML = `
    <div class="ws-title-wrap">
      ${titleBlock}
      <span class="ws-sub">${esc(subtitle)}</span>
    </div>
    <div class="ws-actions desktop-only">
      <div class="timer-pill">${RING}<span>Mã mới sau <b class="timer-value">30s</b></span></div>
      ${canEdit ? `<button type="button" class="icon-btn lg outline danger" data-action="ask-delete-group" aria-label="Xoá group">${ICON.trash}</button>` : ''}
      <button type="button" class="btn primary" data-action="open-add">${ICON.plus} Thêm tài khoản</button>
    </div>`;

  $('#group-delete-banner').innerHTML =
    state.confirmGroupDelete && canEdit
      ? `<div class="banner-danger" role="alert">
          <span>Xoá group <b>${esc(group.name)}</b> cùng ${count} tài khoản? Không thể hoàn tác.</span>
          <button type="button" class="btn outline" data-action="cancel-delete-group">Huỷ</button>
          <button type="button" class="btn danger" data-action="do-delete-group">Xoá group</button>
        </div>`
      : '';

  paintTimer();
}

function cardHtml({ account, group }, searching) {
  const [avBg, avFg] = AVATAR_PALETTE[hash(account.name) % AVATAR_PALETTE.length];
  const baseMeta = account.issuer || `TOTP · ${account.digits} số · ${account.period}s`;
  const meta = searching ? `${baseMeta} · ${group.name}` : baseMeta;
  const copied = state.copiedId === account.id;
  const menu =
    state.menuId === account.id
      ? `<div class="card-menu" role="menu" aria-label="Tuỳ chọn ${esc(account.name)}">
          <button type="button" class="menu-item" role="menuitem" data-action="edit-secret">${ICON.key} Đổi secret key</button>
          <button type="button" class="menu-item" role="menuitem" data-action="move">${ICON.arrow} Chuyển group</button>
          <div class="menu-sep"></div>
          <button type="button" class="menu-item danger" role="menuitem" data-action="ask-delete">${ICON.trashSm} Xoá tài khoản</button>
        </div>`
      : '';
  const confirm =
    state.confirmId === account.id
      ? `<div class="card-confirm" role="alertdialog" aria-label="Xác nhận xoá ${esc(account.name)}">
          <span>Xoá <b>${esc(account.name)}</b>?</span>
          <span class="hint">Bạn sẽ mất mã 2FA nếu chưa backup secret.</span>
          <div class="row">
            <button type="button" class="btn outline" data-action="cancel-delete">Huỷ</button>
            <button type="button" class="btn danger" data-action="do-delete">Xoá</button>
          </div>
        </div>`
      : '';
  return `<article class="card${copied ? ' copied' : ''}" data-id="${esc(account.id)}">
    <div class="card-head">
      <div class="avatar" style="--av-bg:${avBg};--av-fg:${avFg}" aria-hidden="true">${esc(account.name.charAt(0))}</div>
      <div class="card-title">
        <span class="card-name" title="${esc(account.name)}">${esc(account.name)}</span>
        <span class="card-meta" title="${esc(meta)}">${esc(meta)}</span>
      </div>
      <button type="button" class="icon-btn" data-action="menu" aria-label="Tuỳ chọn tài khoản ${esc(account.name)}" aria-haspopup="menu" aria-expanded="${state.menuId === account.id}">${ICON.kebab}</button>
    </div>
    <button type="button" class="code-btn" data-action="copy" aria-label="Sao chép mã của ${esc(account.name)}">
      <span class="code">${placeholderCode(account.digits)}</span>
      <span class="copy-state">${copied ? `${ICON.check} Đã chép` : ICON.copy}</span>
    </button>
    <div class="card-foot">
      <div class="bar"><div class="bar-fill"></div></div>
      <span class="next-label">Tiếp theo <span class="next">${placeholderCode(account.digits)}</span></span>
    </div>
    ${menu}${confirm}
  </article>`;
}

function renderGrid() {
  const items = visibleItems();
  const searching = !!searchQuery();
  $('#grid').innerHTML = items.map((item) => cardHtml(item, searching)).join('');

  let empty = '';
  if (!items.length) {
    if (!state.groups.length) {
      empty = `<div class="empty"><b>Chưa có group nào</b><span>Tạo một group để bắt đầu quản lý mã 2FA.</span></div>`;
    } else if (searching) {
      empty = `<div class="empty"><b>Không tìm thấy tài khoản nào</b><span>Không có tài khoản khớp “${esc(state.query.trim())}”.</span></div>`;
    } else {
      empty = `<div class="empty"><b>Group này chưa có tài khoản</b><span>Thêm thủ công hoặc dán danh sách name / secret để nhập hàng loạt.</span><button type="button" class="btn primary" data-action="open-add">Thêm tài khoản</button></div>`;
    }
  }
  $('#empty').innerHTML = empty;
  paintCodes();
  refreshCodes();
}

function renderMain() {
  renderGroups();
  renderHeader();
  renderGrid();
}

/* ----- Live parts (run every second without touching focus) ----- */
function paintTimer() {
  const now = Math.floor(Date.now() / 1000);
  const remaining = 30 - (now % 30);
  const urgent = remaining <= 5;
  $$('.timer-pill').forEach((pill) => {
    pill.classList.toggle('urgent', urgent);
    pill.querySelector('.timer-value').textContent = remaining + 's';
    pill.querySelector('.ring-fill').style.strokeDashoffset = (113.1 * (1 - remaining / 30)).toFixed(1);
  });
}
function paintCodes() {
  const now = Date.now() / 1000;
  $$('#grid .card').forEach((card) => {
    const found = findAccount(card.dataset.id);
    if (!found) return;
    const { account } = found;
    const counter = counterOf(account, now);
    const remaining = account.period - (Math.floor(now) % account.period);
    const cached = codeCache[account.id];
    const fresh = cached && cached.counter === counter && cached.sig === accountSig(account);
    const invalid = fresh && cached.invalid;
    card.classList.toggle('urgent', remaining <= 5 && !invalid);
    card.classList.toggle('invalid', !!invalid);
    card.querySelector('.code').textContent = invalid
      ? CRYPTO_OK
        ? 'Secret không hợp lệ'
        : 'Cần HTTPS / localhost'
      : fresh
        ? formatCode(cached.code)
        : placeholderCode(account.digits);
    card.querySelector('.next').textContent = fresh && !invalid ? formatCode(cached.next) : '—';
    card.querySelector('.bar-fill').style.width = ((remaining / account.period) * 100).toFixed(1) + '%';
  });
}
let refreshing = false;
let refreshPending = false;
async function refreshCodes() {
  if (refreshing) {
    refreshPending = true; // the view changed mid-run; run again afterwards
    return;
  }
  refreshing = true;
  try {
    do {
      refreshPending = false;
      const now = Date.now() / 1000;
      await Promise.all(visibleItems().map(({ account }) => ensureCodes(account, now)));
      paintCodes();
    } while (refreshPending);
  } finally {
    refreshing = false;
  }
}
function tick() {
  paintTimer();
  paintCodes();
  refreshCodes();
}

/* ----- Panel ----- */
function syncPanelVisibility() {
  const open = state.panelOpen;
  $('#app').classList.toggle('panel-open', open);
  $('#panel').hidden = !open;
  $('#backdrop').hidden = !(open && isOverlayPanel());
  $('#fab').hidden = open;
  document.body.classList.toggle('scroll-lock', open && isOverlayPanel());
}

function groupChipsHtml() {
  return state.groups
    .map(
      (group) =>
        `<button type="button" class="chip" data-action="form-group" data-id="${esc(group.id)}" aria-pressed="${group.id === state.form.groupId}">${esc(group.name)}</button>`,
    )
    .join('');
}
function submitLabel() {
  if (state.editingId) return 'Lưu thay đổi';
  const group = groupById(state.form.groupId);
  return 'Thêm vào ' + (group ? group.name : 'group');
}

function renderPanel() {
  if (state.editingId && !findAccount(state.editingId)) state.editingId = null;
  const editing = !!state.editingId;
  const title = editing ? 'Cập nhật tài khoản' : 'Thêm tài khoản';
  const panel = $('#panel');
  panel.setAttribute('aria-label', title);

  let body;
  if (state.tab === 'single') {
    body = `<form class="form" data-form="single" novalidate>
      <div class="field">
        <label class="field-label" for="f-name">Tên tài khoản</label>
        <input class="input" id="f-name" name="name" placeholder="vd. admin_prod" autocomplete="off" spellcheck="false" autocapitalize="off" value="${esc(state.form.name)}">
      </div>
      <div class="field">
        <label class="field-label" for="f-secret">Secret key (Base32) hoặc otpauth:// URI</label>
        <div class="secret-wrap">
          <input class="input" id="f-secret" name="secret" type="${state.form.showSecret ? 'text' : 'password'}" placeholder="${editing ? 'Để trống nếu giữ nguyên key' : 'JBSWY3DPEHPK3PXP'}" autocomplete="off" spellcheck="false" autocapitalize="off" value="${esc(state.form.secret)}">
          <button type="button" class="icon-btn" data-action="toggle-secret" aria-label="Hiện hoặc ẩn secret" aria-pressed="${state.form.showSecret}">${ICON.eye}</button>
        </div>
      </div>
      <div class="field">
        <span class="field-label" id="f-group-label">Group</span>
        <div class="chip-row" id="f-groups" role="group" aria-labelledby="f-group-label">${groupChipsHtml()}</div>
      </div>
      <p class="form-error" id="f-error" role="alert"></p>
      <button type="submit" class="btn primary block" id="f-submit">${esc(submitLabel())}</button>
    </form>`;
  } else {
    const group = activeGroup();
    body = `<div class="form">
      <p class="hint-text">Mỗi tài khoản 2 dòng (<code>name</code> rồi <code>secret</code>), 1 dòng <code>name,secret</code> hoặc một <code>otpauth://</code> URI. Trùng tên trong group sẽ cập nhật key.</p>
      <textarea class="bulk-input" id="bulk" aria-label="Danh sách name và secret" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="admin&#10;JBSWY3DPEHPK3PXP&#10;dash,KRSXG5CTMVRXEZLU">${esc(state.bulk)}</textarea>
      <div class="stat-pills" aria-live="polite">
        <span class="stat-pill new" id="bulk-new"></span>
        <span class="stat-pill update" id="bulk-update"></span>
        <span class="stat-pill bad" id="bulk-bad"></span>
      </div>
      <button type="button" class="btn primary block" data-action="import-bulk" id="bulk-submit"${group ? '' : ' disabled'}>Nhập vào ${esc(group ? group.name : 'group')}</button>
    </div>`;
  }

  panel.innerHTML = `
    <div class="sheet-handle mobile-only" aria-hidden="true"></div>
    <div class="panel-head">
      <h2>${title}</h2>
      <button type="button" class="icon-btn" data-action="close-panel" aria-label="Đóng">${ICON.close}</button>
    </div>
    <div class="tabs" role="tablist" aria-label="Cách thêm">
      <button type="button" class="tab" role="tab" data-action="tab" data-tab="single" aria-selected="${state.tab === 'single'}">${editing ? 'Tài khoản' : 'Một tài khoản'}</button>
      <button type="button" class="tab" role="tab" data-action="tab" data-tab="bulk" aria-selected="${state.tab === 'bulk'}">Nhập hàng loạt</button>
    </div>
    ${body}`;
  if (state.tab === 'bulk') updateBulkStats();
}
function updateBulkStats() {
  const stats = parseBulk(state.bulk, activeGroup());
  $('#bulk-new').textContent = `${stats.created} mới`;
  $('#bulk-update').textContent = `${stats.updated} cập nhật key`;
  $('#bulk-bad').textContent = `${stats.bad} lỗi`;
}
function setFormError(message) {
  const el = $('#f-error');
  if (el) el.textContent = message;
}

function openPanel({ editingId = null, focus = 'name' } = {}) {
  const found = editingId ? findAccount(editingId) : null;
  state.panelOpen = true;
  state.editingId = found ? editingId : null;
  state.tab = 'single';
  state.form = {
    name: found ? found.account.name : '',
    secret: '',
    groupId: found ? found.group.id : state.activeId,
    showSecret: false,
  };
  persistPanel();
  renderPanel();
  syncPanelVisibility();
  const target =
    focus === 'secret' ? '#f-secret' : focus === 'group' ? '#f-groups [aria-pressed="true"]' : '#f-name';
  const el = $(target);
  if (el) el.focus();
}
function closePanel() {
  state.panelOpen = false;
  state.editingId = null;
  persistPanel();
  syncPanelVisibility();
}
function persistPanel() {
  if (!isOverlayPanel()) storageSet(PANEL_KEY, state.panelOpen ? '1' : '0');
}

/* ----- Toast ----- */
function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove('show'), 1800);
}

/* =========================================================
 * Actions
 * ======================================================= */
function resetTransient() {
  state.menuId = null;
  state.confirmId = null;
  state.renaming = false;
  state.confirmGroupDelete = false;
}
function setQuery(value) {
  state.query = value;
  const input = $('#search');
  if (input.value !== value) input.value = value;
}

function pickGroup(id) {
  if (!groupById(id)) return;
  const sameView = id === state.activeId && !searchQuery();
  state.activeId = id;
  resetTransient();
  setQuery('');
  if (!state.editingId) state.form.groupId = id;
  renderMain();
  if (state.panelOpen) {
    // Keep typed input, refresh labels that mention the active group.
    if (state.tab === 'bulk') renderPanel();
    else refreshFormGroupChips();
  }
  if (!sameView) {
    const chip = $('#group-chips .group-chip.active');
    if (chip) chip.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }
}

function createGroup(name) {
  name = name.trim();
  if (!name) return;
  const group = { id: newId(), name, accounts: [] };
  state.groups.push(group);
  saveGroup(group);
  saveGroupIndex();
  state.newGroupOpen = false;
  state.newGroupName = '';
  pickGroup(group.id);
  if (state.panelOpen) renderPanel();
  toast('Đã tạo group ' + name);
}

function saveRename(name) {
  const group = activeGroup();
  name = name.trim();
  if (!group || !name) return;
  group.name = name;
  saveGroup(group);
  saveGroupIndex();
  state.renaming = false;
  renderMain();
  if (state.panelOpen) renderPanel();
  toast('Đã đổi tên group');
}

function deleteActiveGroup() {
  const group = activeGroup();
  if (!group) return;
  if (state.groups.length === 1) {
    state.confirmGroupDelete = false;
    renderHeader();
    toast('Phải giữ lại ít nhất một group');
    return;
  }
  state.groups = state.groups.filter((item) => item.id !== group.id);
  group.accounts.forEach((account) => delete codeCache[account.id]);
  try {
    localStorage.removeItem(groupKey(group.id));
  } catch (e) {
    /* ignore */
  }
  saveGroupIndex();
  state.confirmGroupDelete = false;
  if (state.editingId && !findAccount(state.editingId)) state.editingId = null;
  pickGroup(state.groups[0].id);
  if (state.panelOpen) renderPanel();
  toast('Đã xoá group ' + group.name);
}

function deleteAccount(id) {
  const found = findAccount(id);
  if (!found) return;
  found.group.accounts = found.group.accounts.filter((account) => account.id !== id);
  delete codeCache[id];
  saveGroup(found.group);
  state.confirmId = null;
  if (state.editingId === id) closePanel();
  renderMain();
  toast('Đã xoá ' + found.account.name);
}

async function copyCode(id) {
  const found = findAccount(id);
  if (!found) return;
  const now = Date.now() / 1000;
  const isFresh = (entry) =>
    entry &&
    entry.counter === counterOf(found.account, now) &&
    entry.sig === accountSig(found.account);
  // Write synchronously when the code is cached: an await before the clipboard
  // call can drop the click's user activation (iOS Safari rejects the write).
  if (!isFresh(codeCache[id])) await ensureCodes(found.account, now);
  const cached = codeCache[id];
  if (!cached || cached.invalid || !cached.code) {
    toast(cached && cached.invalid ? 'Secret không hợp lệ' : 'Mã chưa sẵn sàng');
    return;
  }
  try {
    await writeClipboard(cached.code);
  } catch (e) {
    toast('Không thể copy tự động');
    return;
  }
  state.copiedId = id;
  state.menuId = null;
  renderGrid();
  clearTimeout(copyCode.timer);
  copyCode.timer = setTimeout(() => {
    state.copiedId = null;
    const card = $(`#grid .card[data-id="${CSS.escape(id)}"]`);
    if (card) {
      card.classList.remove('copied');
      card.querySelector('.copy-state').innerHTML = ICON.copy;
    }
  }, 1500);
}
function writeClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  return new Promise((resolve, reject) => {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    ok ? resolve() : reject(new Error('copy failed'));
  });
}

function submitSingle() {
  const nameInput = state.form.name.trim();
  const rawSecret = state.form.secret.trim();
  const target = groupById(state.form.groupId);
  if (!target) return setFormError('Chọn một group.');

  let parsed = null;
  if (rawSecret) {
    if (/^otpauth:/i.test(rawSecret)) {
      parsed = parseOtpauth(rawSecret);
      if (parsed.error) return setFormError(parsed.error);
    } else {
      const secret = cleanSecret(rawSecret);
      if (!isValidBase32(secret)) {
        return setFormError('Secret không hợp lệ — cần Base32 (A–Z, 2–7) hoặc otpauth:// URI.');
      }
      parsed = { secret };
    }
  }
  const name = nameInput || (parsed && parsed.name) || '';
  if (!name) return setFormError('Nhập tên tài khoản.');

  if (state.editingId) {
    const found = findAccount(state.editingId);
    if (!found) return closePanel();
    const { account, group: fromGroup } = found;
    account.name = name;
    if (parsed) {
      Object.assign(
        account,
        normalizeAccount({ ...account, ...parsed, name, issuer: parsed.issuer || account.issuer }),
      );
    }
    let moved = false;
    if (target.id !== fromGroup.id) {
      fromGroup.accounts = fromGroup.accounts.filter((item) => item !== account);
      target.accounts.push(account);
      saveGroup(fromGroup);
      moved = true;
    }
    saveGroup(target);
    delete codeCache[account.id];
    toast(moved ? `Đã chuyển ${name} sang ${target.name}` : 'Đã cập nhật ' + name);
    if (isOverlayPanel()) closePanel();
    else openPanel(); // back to "add" mode, panel stays as a column
    renderMain();
    return;
  }

  if (!parsed) return setFormError('Nhập secret key.');
  const account = normalizeAccount({ ...parsed, name });
  target.accounts.push(account);
  saveGroup(target);
  state.activeId = target.id;
  resetTransient();
  setQuery('');
  state.form.name = '';
  state.form.secret = '';
  renderPanel();
  renderMain();
  const nameField = $('#f-name');
  if (nameField && !isOverlayPanel()) nameField.focus();
  toast('Đã thêm ' + name);
}

function importBulk() {
  const group = activeGroup();
  if (!group) return;
  const result = parseBulk(state.bulk, group);
  if (!result.entries.length) {
    toast('Không có dòng hợp lệ để nhập');
    return;
  }
  result.entries.forEach((entry) => {
    const existing = group.accounts.find((account) => account.name === entry.name);
    if (existing) {
      Object.assign(
        existing,
        normalizeAccount({ ...existing, ...entry, issuer: entry.issuer || existing.issuer }),
      );
      delete codeCache[existing.id];
    } else {
      group.accounts.push(normalizeAccount(entry));
    }
  });
  saveGroup(group);
  state.bulk = '';
  renderPanel();
  setQuery('');
  renderMain();
  toast(`Đã nhập ${result.entries.length} tài khoản vào ${group.name}`);
}

function refreshFormGroupChips() {
  const chips = $('#f-groups');
  if (chips) chips.innerHTML = groupChipsHtml();
  const submit = $('#f-submit');
  if (submit) submit.textContent = submitLabel();
}

/* ----- Backup ----- */
function exportBackup() {
  const data = {
    app: 'totp-vault',
    version: 1,
    exportedAt: new Date().toISOString(),
    groups: state.groups.map((group) => ({
      name: group.name,
      accounts: group.accounts.map(({ name, secret, issuer, digits, period, algorithm }) => ({
        name,
        secret,
        issuer,
        digits,
        period,
        algorithm,
      })),
    })),
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `totp-vault-backup-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  toast('Đã xuất backup — file chứa secret, hãy cất giữ cẩn thận');
}

function importBackup(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    toast('File backup không phải JSON hợp lệ');
    return;
  }
  const groups = data && Array.isArray(data.groups) ? data.groups : null;
  if (!groups) {
    toast('File backup không đúng định dạng');
    return;
  }
  let added = 0;
  let updated = 0;
  let newGroups = 0;
  groups.forEach((incoming) => {
    const name = String((incoming && incoming.name) || '').trim();
    if (!name || !Array.isArray(incoming.accounts)) return;
    let group = state.groups.find((item) => item.name === name);
    if (!group) {
      group = { id: newId(), name, accounts: [] };
      state.groups.push(group);
      newGroups++;
    }
    incoming.accounts.forEach((raw) => {
      if (!raw || !raw.name || !isValidBase32(cleanSecret(raw.secret))) return;
      const account = normalizeAccount({ ...raw, id: undefined });
      const existing = group.accounts.find((item) => item.name === account.name);
      if (existing) {
        Object.assign(existing, { ...account, id: existing.id });
        delete codeCache[existing.id];
        updated++;
      } else {
        group.accounts.push(account);
        added++;
      }
    });
  });
  saveAll();
  if (!activeGroup()) state.activeId = state.groups[0] ? state.groups[0].id : null;
  renderMain();
  if (state.panelOpen) renderPanel();
  toast(`Đã nhập backup: ${added} mới, ${updated} cập nhật${newGroups ? `, ${newGroups} group mới` : ''}`);
}

/* =========================================================
 * Events
 * ======================================================= */
function focusVisibleNewGroupInput() {
  const input = $$('[data-slot="new-group"] input').find((el) => el.offsetParent !== null);
  if (input) input.focus();
}

document.addEventListener('click', (event) => {
  const trigger = event.target.closest('[data-action]');
  const action = trigger ? trigger.dataset.action : null;
  const card = event.target.closest('.card');
  const cardId = card ? card.dataset.id : null;

  // Click outside an open menu closes it.
  if (state.menuId && !event.target.closest('.card-menu') && action !== 'menu') {
    state.menuId = null;
    renderGrid();
  }
  if (!action) return;

  switch (action) {
    case 'pick-group':
      pickGroup(trigger.dataset.id);
      break;
    case 'toggle-new-group':
      state.newGroupOpen = !state.newGroupOpen;
      state.newGroupName = '';
      renderGroups();
      if (state.newGroupOpen) focusVisibleNewGroupInput();
      break;
    case 'start-rename': {
      const group = activeGroup();
      if (!group) break;
      state.renaming = true;
      state.renameValue = group.name;
      state.confirmGroupDelete = false;
      renderHeader();
      const input = $('.rename-form input');
      input.focus();
      input.select();
      break;
    }
    case 'cancel-rename':
      state.renaming = false;
      renderHeader();
      break;
    case 'ask-delete-group':
      state.confirmGroupDelete = true;
      state.renaming = false;
      renderHeader();
      break;
    case 'cancel-delete-group':
      state.confirmGroupDelete = false;
      renderHeader();
      break;
    case 'do-delete-group':
      deleteActiveGroup();
      break;
    case 'open-add':
      openPanel();
      break;
    case 'close-panel':
      closePanel();
      break;
    case 'tab':
      state.tab = trigger.dataset.tab;
      if (state.tab === 'bulk') state.editingId = null;
      renderPanel();
      break;
    case 'toggle-secret': {
      state.form.showSecret = !state.form.showSecret;
      $('#f-secret').type = state.form.showSecret ? 'text' : 'password';
      trigger.setAttribute('aria-pressed', String(state.form.showSecret));
      break;
    }
    case 'form-group':
      state.form.groupId = trigger.dataset.id;
      refreshFormGroupChips();
      break;
    case 'import-bulk':
      importBulk();
      break;
    case 'menu':
      state.menuId = state.menuId === cardId ? null : cardId;
      state.confirmId = null;
      renderGrid();
      if (state.menuId) {
        const first = $('.card-menu .menu-item');
        if (first) first.focus();
      }
      break;
    case 'edit-secret':
      state.menuId = null;
      renderGrid();
      openPanel({ editingId: cardId, focus: 'secret' });
      break;
    case 'move':
      state.menuId = null;
      renderGrid();
      openPanel({ editingId: cardId, focus: 'group' });
      break;
    case 'ask-delete':
      state.menuId = null;
      state.confirmId = cardId;
      renderGrid();
      break;
    case 'cancel-delete':
      state.confirmId = null;
      renderGrid();
      break;
    case 'do-delete':
      deleteAccount(cardId);
      break;
    case 'copy':
      copyCode(cardId);
      break;
    case 'export':
      exportBackup();
      break;
    case 'import':
      $('#import-file').click();
      break;
  }
});

document.addEventListener('input', (event) => {
  const el = event.target;
  if (el.id === 'search') {
    state.query = el.value;
    resetTransient();
    renderGroups();
    renderHeader();
    renderGrid();
  } else if (el.closest('[data-form="single"]')) {
    state.form[el.name] = el.value;
    setFormError('');
  } else if (el.id === 'bulk') {
    state.bulk = el.value;
    updateBulkStats();
  } else if (el.closest('[data-form="rename"]')) {
    state.renameValue = el.value;
  } else if (el.closest('[data-form="new-group"]')) {
    state.newGroupName = el.value;
  }
});

document.addEventListener('submit', (event) => {
  const form = event.target.closest('[data-form]');
  if (!form) return;
  event.preventDefault();
  const kind = form.dataset.form;
  if (kind === 'new-group') createGroup(form.elements.name.value);
  else if (kind === 'rename') saveRename(form.elements.name.value);
  else if (kind === 'single') submitSingle();
});

document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  if (state.menuId || state.confirmId) {
    const id = state.menuId || state.confirmId;
    state.menuId = null;
    state.confirmId = null;
    renderGrid();
    const button = $(`#grid .card[data-id="${CSS.escape(id)}"] [data-action="menu"]`);
    if (button) button.focus();
  } else if (state.renaming || state.confirmGroupDelete) {
    state.renaming = false;
    state.confirmGroupDelete = false;
    renderHeader();
  } else if (state.newGroupOpen) {
    state.newGroupOpen = false;
    renderGroups();
  } else if (state.panelOpen && isOverlayPanel()) {
    closePanel();
  }
});

$('#import-file').addEventListener('change', (event) => {
  const file = event.target.files && event.target.files[0];
  event.target.value = '';
  if (!file) return;
  file
    .text()
    .then(importBackup)
    .catch(() => toast('Không đọc được file backup'));
});

WIDE_MQ.addEventListener('change', syncPanelVisibility);
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) tick();
});

/* =========================================================
 * Boot
 * ======================================================= */
loadGroups();
let storedPanel = null;
try {
  storedPanel = localStorage.getItem(PANEL_KEY);
} catch (e) {
  /* ignore */
}
state.panelOpen = !isOverlayPanel() && storedPanel !== '0';
renderMain();
renderPanel();
syncPanelVisibility();
setInterval(tick, 1000);
if (!CRYPTO_OK) toast('Trình duyệt chặn Web Crypto — hãy mở qua https hoặc localhost');
