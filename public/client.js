import {
  getMyPublicKeyB64, getMyIdentityPublicKeyB64, getDeviceKeyPackage, verifyDeviceSignature,
  encryptMsg, decryptMsg, encryptFile, decryptFile, isEncrypted, cryptoSupported,
  setMyDeviceId, getSafetyNumber, getKeySyncCode, setOwnDeviceKeys,
  encryptKeyForSync, decryptSyncedKey, hasSyncedKeys, clearAllSessions,
  pinPeerKeys, getPeerPin, acknowledgePeerKeys, setPeerVerified, isPeerBlocked,
  stripImageMetadata, encryptMeta, decryptMeta, saveImportedHistory, getHistoryForChat
} from './crypto.js?v=3';

const state = {
  account:    null,
  chats:      [],
  activeChatUid: null,
  systemOpen: false,
  sysMessages: [],
  sysUnread:  0,
  myPendingKeyRequestId: null,
  myDeviceId: null,
  socket:     null,
  ignored:    false,
  pendingFile: null,
  burnConfirmPending: null,
  peerKeys:   new Map(),
  presence:   new Map(),
  pollTimer:  null,
  _pendingPlaintext: null,
  isMobile:   () => window.innerWidth <= 640,
  burnSeconds: null,
  activeBurnTimers: new Map(),
  isLoadingHistory: false,
  hasMoreHistory: true,
  sendSeq: 0,
  pendingSends: [],
  outbox: [],
  flushing: false,
  deviceApproved: false,
  keyRequest: null,
  peerPin: null,
  peerSecurityOpen: false,
};

const $   = id => document.getElementById(id);
const show = el => el?.classList.remove('hidden');
const hide = el => el?.classList.add('hidden');

const twemojiLocalOpts = { base: '/vendor/twemoji/', size: 'svg', ext: '.svg' };
function twParse(str) {
  if (window.twemoji && typeof twemoji.parse === 'function') {
    try { return twemoji.parse(str, twemojiLocalOpts); } catch (e) { return str; }
  }
  return str;
}

const twemojiSafe = (str) => twParse(str);

let currentRenderToken = 0;
let refreshSeq = 0;

function dialog({ title, body, input, inputPlaceholder, inputDefault, inputType, okText = 'OK', cancelText = 'Cancel', danger = false }) {
  return new Promise(resolve => {
    $('dialog-title').textContent = title || '';
    $('dialog-body').textContent  = body  || '';
    $('dialog-error').textContent = '';
    const inp = $('dialog-input');
    if (input) {
      inp.type        = inputType || 'text';
      inp.value       = inputDefault !== undefined ? inputDefault : '';
      inp.placeholder = inputPlaceholder || '';
      show(inp);
      setTimeout(() => { inp.focus(); inp.select(); }, 50);
    } else hide(inp);
    $('dialog-ok').textContent     = okText;
    $('dialog-ok').className       = danger ? 'btn-danger' : 'btn-primary';
    $('dialog-cancel').textContent = cancelText;
    show($('modal-dialog'));
    const ok     = () => { hide($('modal-dialog')); cleanup(); resolve(input ? inp.value.trim() : true); };
    const cancel = () => { hide($('modal-dialog')); cleanup(); resolve(false); };
    const onKey  = e => { if (e.key === 'Enter' && input) ok(); if (e.key === 'Escape') cancel(); };
    $('dialog-ok').onclick     = ok;
    $('dialog-cancel').onclick = cancel;
    document.addEventListener('keydown', onKey);
    function cleanup() { $('dialog-ok').onclick = null; $('dialog-cancel').onclick = null; document.removeEventListener('keydown', onKey); }
  });
}

function toast(title, msg = '', type = 'info', duration = 4000, onClick = null) {
  const icons = {
    info: 'fa-circle-info',
    ok: 'fa-check',
    warn: 'fa-triangle-exclamation',
    err: 'fa-circle-xmark',
    key: 'fa-key',
    msg: 'fa-comment'
  };
  const iconClass = icons[type] || 'fa-circle-info';
  const c = $('toast-container');
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  if (onClick) t.style.cursor = 'pointer';
  t.innerHTML = `
    <span class="toast-icon"><i class="fa-solid ${iconClass}"></i></span>
    <div class="toast-body">
      <div class="toast-title">${esc(title)}</div>
      ${msg ? `<div class="toast-msg">${esc(msg)}</div>` : ''}
    </div>
    <button class="toast-close" aria-label="Close"><i class="fa-solid fa-xmark"></i></button>
  `;
  const remove = () => { t.classList.add('removing'); setTimeout(() => t.remove(), 180); };
  t.querySelector('.toast-close').onclick = e => { e.stopPropagation(); remove(); };
  if (onClick) t.onclick = () => { remove(); onClick(); };
  c.appendChild(t);
  if (duration > 0) setTimeout(remove, duration);
  return remove;
}

async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' }, credentials: 'include' };
  if (body) opts.body = JSON.stringify(body);
  try {
    const r = await fetch(path, opts);
    return r.json();
  } catch {
    return { error: 'Network error' };
  }
}

let pendingAccountData = null;

async function withButtonLoading(button, label, task) {
  if (!button || button.disabled) return;
  const original = button.innerHTML;
  button.disabled = true;
  button.classList.add('loading');
  button.innerHTML = `<span class="btn-spinner" aria-hidden="true"></span><span>${label}</span>`;
  try {
    return await task();
  } finally {
    button.disabled = false;
    button.classList.remove('loading');
    button.innerHTML = original;
  }
}

 $('btn-register').onclick = () => withButtonLoading($('btn-register'), 'Creating account...', async () => {
  $('auth-error').textContent = '';
  localStorage.removeItem('taupe_active_chat');
  let pow;
  try {
    const challenge = await api('GET', '/api/register/challenge');
    if (challenge.error) { $('auth-error').textContent = challenge.error; return; }
    const prefix = '0'.repeat(challenge.difficulty);
    let nonce = 0;
    while (true) {
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(challenge.challenge + nonce));
      const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
      if (hex.startsWith(prefix)) { pow = { challenge: challenge.challenge, nonce }; break; }
      nonce++;
      if (nonce % 4096 === 0) await new Promise(resolve => setTimeout(resolve, 0));
    }
  } catch (e) {
    $('auth-error').textContent = 'Registration proof failed';
    return;
  }
  const d = await api('POST', '/api/register', pow);
  if (d.error) { $('auth-error').textContent = d.error; return; }


  pendingAccountData = d;
  $('save-number-text').textContent = fmtPrivate(d.accountNumber);
  show($('modal-save-number'));
});

 $('btn-login').onclick = () => withButtonLoading($('btn-login'), 'Signing in...', async () => {
  $('auth-error').textContent = '';
  localStorage.removeItem('taupe_active_chat');
  const raw = $('input-number').value.replace(/\D/g, '');
  if (raw.length !== 16) { $('auth-error').textContent = 'Enter your 16-digit private number'; return; }
  const d = await api('POST', '/api/login', { number: raw });

  if (d.error === 'Max 5 devices. Kick one first.') {
    showKickDevicesModal(raw);
    return;
  }

  if (d.error) { $('auth-error').textContent = d.error; return; }
  pendingAccountData = d;
  await bootApp(d, false);
});

async function showKickDevicesModal(number) {
  const d = await api('POST', '/api/login/devices', { number });
  if (d.error) { $('auth-error').textContent = d.error; return; }

  const list = $('kick-devices-list');
  list.innerHTML = '';
  (d.devices || []).forEach(dev => {
    const div = document.createElement('div');
    div.className = 'alias-item';
    const lastSeen = dev.last_seen ? new Date(dev.last_seen * 1000).toLocaleString() : 'Unknown';
    div.innerHTML = `<span style="display:flex; flex-direction:column;">
                        <span style="font-weight:600">${esc(dev.device_name)}</span>
                        <span style="font-size:10px;color:var(--text2)">Last seen: ${lastSeen}</span>
                      </span>
                      <button class="device-kick" data-id="${dev.id}">kick</button>`;
    div.querySelector('.device-kick').onclick = async (e) => {
      e.stopPropagation();
      const kickRes = await api('POST', '/api/login/kick', { number, deviceId: parseInt(e.target.dataset.id) });
      if (kickRes.ok) {
        showKickDevicesModal(number);
      }
    };
    list.appendChild(div);
  });

  $('btn-kick-signin').disabled = (d.devices || []).length >= 5;
  $('btn-kick-signin').onclick = () => withButtonLoading($('btn-kick-signin'), 'Signing in...', async () => {
    hide($('modal-kick-devices'));
    const loginRes = await api('POST', '/api/login', { number });
    if (loginRes.error) { $('auth-error').textContent = loginRes.error; return; }
    await bootApp(loginRes, false);
  });
  $('kick-cancel').onclick = () => hide($('modal-kick-devices'));
  show($('modal-kick-devices'));
}

document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    $('tab-' + t.dataset.tab).classList.add('active');
  };
});

localStorage.removeItem('lastNumber');
localStorage.removeItem('taupe_check_done');

$('input-number').addEventListener('input', e => {
  const el    = e.target;
  const raw   = el.value.replace(/\D/g, '').slice(0, 16);

  const parts = [];
  for (let i = 0; i < raw.length; i += 4) parts.push(raw.slice(i, i + 4));
  const fmt = parts.join('-');
  el.value = fmt;
});

async function init() {
  const me = await api('GET', '/api/me');
  if (me.error) { switchScreen('auth'); return; }
  await bootApp(me);
}

async function bootApp(me, isNewAccount = false) {
  state.account = me;
  $('my-number-display').textContent = fmtNum(me.chatNumber || me.accountNumber?.slice(-8));
  switchScreen('main');

  if (me.deviceId) { await setMyDeviceId(me.deviceId); state.myDeviceId = me.deviceId; }
  try {
    if (!me.devices) {
      const full = await api('GET', '/api/me');
      if (!full.error && Array.isArray(full.devices)) {
        me = { ...full, accountNumber: me.accountNumber, chatNumber: me.chatNumber || full.chatNumber };
      }
    }
    if (Array.isArray(me.devices)) {
      await setOwnDeviceKeys(me.devices.filter(d => d.public_key).map(d => ({ deviceId: d.id, key: d.public_key })));
    }
  } catch {}
  state.deviceApproved = me.deviceApproved === true;
  await uploadMyPublicKey();
  await loadChats();
  await loadSystemMessages();
  connectSocket();
  startPolling();

  const savedChat = localStorage.getItem('taupe_active_chat');
  if (savedChat && state.chats.find(c => c.uid === savedChat)) {
    openChat(savedChat);
  } else {
    localStorage.removeItem('taupe_active_chat');
    hide($('chat-view'));
    show($('empty-state'));
  }
}

function switchScreen(name) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  $('screen-' + name).classList.add('active');
}

async function uploadMyPublicKey() {
  if (!cryptoSupported()) {
    console.warn('[E2E] WebCrypto not supported');
    return;
  }
  try {
    const deviceId = state.account.deviceId || await getMyDeviceId();
    const keyPackage = await getDeviceKeyPackage(deviceId);
    const d = await api('POST', '/api/me/pubkey', keyPackage);
    if (d.error) {
      if (d.code === 'identity_mismatch') {
        state.waitingForKeySync = true;
      } else {
        toast('Encryption key rejected', d.error, 'err');
      }
      return;
    }
    state.deviceApproved = !!d.approved;
    state.keyRequest = d.request || null;
    if (d.approved) {
      state.waitingForKeyApproval = false;
      toast('E2E key registered', '', 'ok', 2000);
    } else {
      state.waitingForKeyApproval = true;
      state.waitingForKeySync = !!d.requiresIdentity;
      if (d.request?.id) state.myPendingKeyRequestId = d.request.id;
      const code = d.request?.payload?.code;
      toast(
        d.requiresIdentity ? 'Identity sync required' : 'Device approval needed',
        code ? `Compare code ${code} on an existing device.` : 'Approve this device from another device.',
        'warn',
        8000
      );
    }
  } catch (e) {
    console.warn('[E2E] key upload failed', e);
  }
}

async function getMyDevicesKeys() {
  const me = await api('GET', '/api/me');
  if (me.error || !me.devices) return [];
  return me.devices
    .filter(d => d.public_key && d.approved)
    .map(d => ({ deviceId: d.id, key: d.public_key }));
}

async function getPeerKey(peerChatNumber, force = false) {
  if (!peerChatNumber) return null;
  const cached = state.peerKeys.get(peerChatNumber) || null;
  if (!force && cached) return cached;
  try {
    const d = await api('GET', `/api/pubkey/${peerChatNumber}`);
    if (d.error) return cached;
    const identity = d.identityKey || null;
    if (!identity) return cached;
    const devices = [];
    const invalid = [];
    for (const item of d.publicKeys || []) {
      const ok = await verifyDeviceSignature(identity, item.deviceId, item.key, item.sig);
      if (ok) devices.push({ deviceId: item.deviceId, key: item.key });
      else invalid.push(item.deviceId);
    }
    if (!devices.length) {
      toast('Key verification failed', 'Peer device keys could not be verified.', 'err', 6000);
      return cached;
    }
    const report = await pinPeerKeys(peerChatNumber, identity, devices.map(item => ({ d: item.deviceId, k: item.key })));
    state.peerPin = await getPeerPin(peerChatNumber);
    if (report.blocking || invalid.length) {
      notifyKeyAlert(peerChatNumber, report, invalid);
    }
    state.peerKeys.set(peerChatNumber, devices);
    return devices;
  } catch (e) {
    console.warn('[E2E] getPeerKey failed', e);
  }
  return cached;
}

function notifyKeyAlert(peerChatNumber, report, invalid) {
  const changed = report?.identityChanged || (report?.changed && report.changed.length);
  const added = report?.added && report.added.length;
  const text = changed
    ? 'The peer security key changed. Sending is blocked until you review it.'
    : added
      ? 'A new device key appeared for this peer.'
      : 'A peer device key could not be verified.';
  if (invalid && invalid.length && !changed) {
    toast('Invalid device key', 'A peer device key failed signature verification.', 'err', 7000);
  } else {
    toast('Security key changed', text, 'warn', 8000);
  }
  const banner = $('key-alert-banner');
  if (banner) {
    $('key-alert-text').textContent = text;
    show(banner);
  }
}

async function ensurePeerTrusted(peerChatNumber) {
  if (!peerChatNumber) return false;
  await getPeerKey(peerChatNumber);
  const pin = await getPeerPin(peerChatNumber);
  if (pin?.blocking) {
    notifyKeyAlert(peerChatNumber, { identityChanged: true, added: [], changed: [] }, []);
    openPeerSecurity();
    return false;
  }
  return true;
}

async function openPeerSecurity() {
  const peerChatNumber = await getActivePeerChatNum();
  if (!peerChatNumber) return;
  await getPeerKey(peerChatNumber);
  const pin = await getPeerPin(peerChatNumber);
  const myIdentity = await getMyIdentityPublicKeyB64();
  const safety = pin?.identityPub ? await getSafetyNumber(myIdentity, pin.identityPub) : null;
  $('security-safety-number').textContent = safety || 'Unavailable, peer identity key is missing';
  $('security-peer-title').textContent = fmtNum(peerChatNumber);
  $('security-devices').innerHTML = (pin?.devices || []).map(device => `
    <div class="security-device">
      <span>Device ${esc(String(device.d))}</span>
      <span class="mono">${esc(String(device.k).slice(0, 16))}...</span>
    </div>
  `).join('');
  updateSecurityVerifyButton(pin);
  $('security-blocked').classList.toggle('hidden', !pin?.blocking);
  state.peerPin = pin;
  show($('modal-security'));
}

async function acknowledgeCurrentPeer() {
  const peerChatNumber = await getActivePeerChatNum();
  if (!peerChatNumber) return;
  await acknowledgePeerKeys(peerChatNumber, false);
  state.peerPin = await getPeerPin(peerChatNumber);
  hide($('key-alert-banner'));
  hide($('modal-security'));
  updateVerifiedBadge(peerChatNumber);
  toast('New keys trusted', 'The peer security keys were accepted without verification.', 'warn', 4000);
}

function updateSecurityVerifyButton(pin) {
  const button = $('security-verify');
  if (!button) return;
  const verified = pin?.verified === true;
  button.textContent = verified ? 'Mark unverified' : 'Mark verified';
  button.className = verified ? 'btn-ghost' : 'btn-primary';
}

async function updateVerifiedBadge(peerChatNumber) {
  const badge = $('chat-verified-badge');
  if (!badge) return;
  const pin = await getPeerPin(peerChatNumber);
  if (pin?.verified) {
    badge.textContent = 'verified';
    badge.className = 'verified-badge';
  } else {
    badge.textContent = pin?.blocking ? 'key changed' : 'unverified';
    badge.className = 'verified-badge ' + (pin?.blocking ? 'danger' : 'muted');
  }
}

let infoTipTarget = null;
let infoTipShownAt = 0;

function hideInfoTip() {
  const tooltip = $('info-tooltip');
  if (!tooltip) return;
  tooltip.classList.remove('visible');
  tooltip.setAttribute('aria-hidden', 'true');
  document.querySelectorAll('.info-tip.show-tip').forEach(item => item.classList.remove('show-tip'));
  infoTipTarget = null;
}

function showInfoTip(button) {
  const tooltip = $('info-tooltip');
  if (!tooltip || !button) return;
  const text = button.dataset.tip;
  if (!text) return;
  document.querySelectorAll('.info-tip.show-tip').forEach(item => {
    if (item !== button) item.classList.remove('show-tip');
  });
  infoTipTarget = button;
  infoTipShownAt = Date.now();
  button.classList.add('show-tip');
  tooltip.textContent = text;
  tooltip.style.left = '0px';
  tooltip.style.top = '0px';
  tooltip.classList.add('visible');
  tooltip.setAttribute('aria-hidden', 'false');
  const anchor = button.getBoundingClientRect();
  const box = tooltip.getBoundingClientRect();
  let left = anchor.left + anchor.width / 2 - box.width / 2;
  left = Math.max(8, Math.min(left, window.innerWidth - box.width - 8));
  let top = anchor.bottom + 8;
  if (top + box.height > window.innerHeight - 8 && anchor.top - box.height - 8 > 8) {
    top = anchor.top - box.height - 8;
  }
  tooltip.style.left = left + 'px';
  tooltip.style.top = top + 'px';
}

document.addEventListener('pointerover', event => {
  const button = event.target.closest('.info-tip');
  if (button && button !== infoTipTarget) showInfoTip(button);
});
document.addEventListener('pointerout', event => {
  const button = event.target.closest('.info-tip');
  if (!button) return;
  const next = event.relatedTarget;
  if (next && button.contains(next)) return;
  if (infoTipTarget === button) hideInfoTip();
});
document.addEventListener('click', event => {
  const button = event.target.closest('.info-tip');
  if (!button) {
    if (!event.target.closest('.info-tooltip')) hideInfoTip();
    return;
  }
  event.preventDefault();
  event.stopPropagation();
  if (infoTipTarget === button && Date.now() - infoTipShownAt > 500) hideInfoTip();
  else showInfoTip(button);
});
document.addEventListener('focusin', event => {
  const button = event.target.closest('.info-tip');
  if (button) showInfoTip(button);
});
document.addEventListener('focusout', event => {
  const button = event.target.closest('.info-tip');
  if (button && infoTipTarget === button) hideInfoTip();
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') hideInfoTip();
});
window.addEventListener('scroll', hideInfoTip, true);
window.addEventListener('resize', hideInfoTip);

document.addEventListener('DOMContentLoaded', () => {
  hideInfoTip();
  $('security-close')?.addEventListener('click', () => hide($('modal-security')));
  $('security-copy')?.addEventListener('click', () => copyToClipboard($('security-safety-number').textContent, 'Copied', 'Safety number copied'));
  $('security-verify')?.addEventListener('click', async () => {
    const peerChatNumber = await getActivePeerChatNum();
    if (!peerChatNumber) return;
    const pin = await getPeerPin(peerChatNumber);
    const verified = pin?.verified !== true;
    await setPeerVerified(peerChatNumber, verified);
    state.peerPin = await getPeerPin(peerChatNumber);
    updateSecurityVerifyButton(state.peerPin);
    updateVerifiedBadge(peerChatNumber);
    if (verified) hide($('key-alert-banner'));
    toast(
      verified ? 'Verified' : 'Unverified',
      verified ? 'Safety number marked as verified.' : 'Verification removed for this peer.',
      verified ? 'ok' : 'warn'
    );
  });
  $('security-trust')?.addEventListener('click', acknowledgeCurrentPeer);
  $('key-alert-review')?.addEventListener('click', openPeerSecurity);
  $('key-alert-trust')?.addEventListener('click', acknowledgeCurrentPeer);
  $('chat-verified-badge')?.addEventListener('click', openPeerSecurity);
});
async function getActivePeerChatNum() {
  const c = state.chats.find(x => x.uid === state.activeChatUid);
  if (!c) return null;
  const myId = state.account.accountId;
  return c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
}

function formatLastSeenTs(sec) {
  try {
    return new Date(sec * 1000).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
  } catch { return ''; }
}

function renderPresence() {
  const el = $('chat-presence');
  if (!el) return;
  const c = state.chats.find(x => x.uid === state.activeChatUid);
  if (!c) { el.className = 'hidden'; el.textContent = ''; return; }
  const myId = state.account.accountId;
  const num = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
  const p = state.presence.get(num);
  if (!p) { el.className = 'hidden'; el.textContent = ''; return; }
  if (p.online) {
    el.textContent = 'online';
    el.className = 'online';
  } else if (p.lastSeen) {
    el.textContent = 'last seen: ' + formatLastSeenTs(p.lastSeen);
    el.className = 'lastseen';
  } else {
    el.textContent = 'offline';
    el.className = 'offline';
  }
}

function startPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    if (!state.socket?.connected) {

      await loadChats();
      if (state.activeChatUid) await refreshActiveChat();
    }
  }, 3000);
}

async function refreshActiveChat() {
  if (!state.activeChatUid) return;
  const uid = state.activeChatUid;
  const myRefreshToken = ++refreshSeq;
  const msgs = await api('GET', `/api/chats/${uid}/messages`);
  if (myRefreshToken !== refreshSeq) return;
  if (!Array.isArray(msgs)) return;
  if (state.activeChatUid !== uid) return;
  await applyLocalHistory(uid, msgs);
  const cont = $('messages-container');
  const rendered = new Set([...cont.querySelectorAll('[data-msg-id]')].map(el => el.dataset.msgId));
  const peerChatNum = await getActivePeerChatNum();
  const peerPub = peerChatNum ? await getPeerKey(peerChatNum, true) : null;
  const decryptKeys = peerPub ? [...peerPub, ...await getMyDevicesKeys()] : null;
  if (myRefreshToken !== refreshSeq || state.activeChatUid !== uid) return;
  for (const m of msgs) {
    if (myRefreshToken !== refreshSeq || state.activeChatUid !== uid) return;
    if (rendered.has(String(m.id))) continue;
    if (m.sender_id == state.account.accountId && state.pendingSends.length) {
      const p = takePending(uid);
      if (p) {
        removePendingBubble(p.pid);
        if (isEncrypted(m.content)) m._plaintext = p.text;
      }
    }
    m._history = true;
    await renderMessage(m, peerChatNum, decryptKeys);
  }

  if (document.visibilityState === 'visible') {
    state.socket?.emit('msg:read', { chatUid: uid });
  }
}

function getToken() {
  return document.cookie.split(';').find(c => c.trim().startsWith('token='))?.split('=')[1];
}

function connectSocket() {
  if (state.socket) state.socket.disconnect();
  state.socket = io({
    auth: { token: getToken() },
    reconnection: true, reconnectionDelay: 1000, reconnectionAttempts: Infinity,
  });

  state.socket.on('connect', async () => {
    hideUnstable();
    const indicator = $('e2e-indicator');
    if (indicator) indicator.title = 'E2E active';
    flushOutbox();
    if (state.waitingForKeySync) {
      if (state.socket) state.socket.emit('key:request', {});
    }
  });
  state.socket.on('disconnect', () => { if (!state.ignored) showUnstable(); });
  state.socket.on('connect_error', () => { if (!state.ignored) showUnstable(); });

  state.socket.emit('key:presence', { myPublicKey: 'online' });

  state.socket.on('sys:new', ({ message }) => {
    if (!message || state.sysMessages.some(m => m.id === message.id)) return;
    state.sysMessages.unshift(message);
    if (message.type === 'key_request' && Number(message.payload?.deviceId) === Number(state.myDeviceId)) {
      state.myPendingKeyRequestId = message.id;
      if (state.waitingForKeySync) toast('Waiting for approval', 'Another device must confirm the key transfer.', 'info', 6000);
    }
    if (state.systemOpen) {
      renderSystemMessages();
    } else {
      state.sysUnread++;
      updateSystemBadge();
    }
    refreshSystemChatItem();
  });

  state.socket.on('sys:updated', ({ id, status }) => {
    const m = state.sysMessages.find(x => x.id === id);
    if (m) m.status = status;
    if (status === 'declined' && id === state.myPendingKeyRequestId) {
      state.myPendingKeyRequestId = null;
      state.waitingForKeySync = false;
      toast('Key transfer declined', 'The request was rejected by another device.', 'warn', 5000);
    }
    if (state.systemOpen) renderSystemMessages();
    refreshSystemChatItem();
  });

  state.socket.on('key:sync', async ({ fromPublicKey, encryptedKey }) => {
    try {
      await decryptSyncedKey(encryptedKey, fromPublicKey);
      state.waitingForKeySync = false;
      toast('Identity synced', 'Re-registering this device key.', 'ok', 3000);
      await uploadMyPublicKey();
      const rid = state.myPendingKeyRequestId;
      if (rid) {
        state.myPendingKeyRequestId = null;
        state.socket.emit('key:sync:done', { id: rid });
      }
      if (state.activeChatUid) openChat(state.activeChatUid);
      else loadChats();
    } catch (e) {
      console.error('[Key Sync] Failed to decrypt synced identity:', e);
      toast('Sync failed', 'The identity key could not be imported.', 'err');
    }
  });

  state.socket.on('key:approved', async () => {
    state.waitingForKeyApproval = false;
    await uploadMyPublicKey();
    toast('Device approved', 'This device can now receive encrypted messages.', 'ok', 4000);
  });

  state.socket.on('msg:new', async ({ chatUid, msg, preview }) => {
    updateChatPreviewUI(chatUid, preview);
    const isMyMsg = msg.sender_id == state.account.accountId;
    let pendingInfo = null;
    if (isMyMsg) {
      pendingInfo = takePending(chatUid);
      if (pendingInfo && state.activeChatUid === chatUid) removePendingBubble(pendingInfo.pid);
    }
    if (state.activeChatUid === chatUid) {
      if (document.querySelector(`[data-msg-id="${msg.id}"]`)) return;

      const peerChatNum = await getActivePeerChatNum();
      const peerPub = peerChatNum ? await getPeerKey(peerChatNum, true) : null;
      const decryptKeys = peerPub ? [...peerPub, ...await getMyDevicesKeys()] : null;

      if (pendingInfo) {
        msg = { ...msg, _plaintext: pendingInfo.text };
      } else if (isMyMsg && state._pendingPlaintext && isEncrypted(msg.content)) {
        msg = { ...msg, _plaintext: state._pendingPlaintext };
        state._pendingPlaintext = null;
      }
      await renderMessage(msg, peerChatNum, decryptKeys);
      scrollBottom();
      if (!isMyMsg) state.socket.emit('msg:read', { chatUid });
    } else {
      const c = state.chats.find(x => x.uid === chatUid);
      if (c) {
        c.unread = (c.unread || 0) + 1;
        const b = $('badge-' + chatUid);
        if (b) { show(b); b.textContent = c.unread; }
      }
      let preview2 = msg.content || (msg.file_type === 'image' ? '[image]' : '[file]');
      if (isEncrypted(preview2)) preview2 = '[encrypted]';
      toast(c ? chatLabel(c) : 'New message', preview2, 'msg', 6000, () => openChat(chatUid));

      const avatarEl = document.querySelector(`[data-chat-uid="${chatUid}"] .chat-avatar`);
      if (avatarEl) {
        avatarEl.classList.remove('ping');
        void avatarEl.offsetWidth;
        avatarEl.classList.add('ping');
        setTimeout(() => avatarEl.classList.remove('ping'), 700);
      }
    }
  });

  state.socket.on('peer:profile_update', ({ chatUid, accountId, username, isPublic, avatarPath }) => {
    const c = state.chats.find(x => x.uid === chatUid);
    if (c) {
      if (c.initiator_id == accountId) {
        c.initiator_username = username;
        c.initiator_avatar = avatarPath;
      }
      if (c.peer_id == accountId) {
        c.peer_username = username;
        c.peer_avatar = avatarPath;
      }

      renderChatList();

      if (state.activeChatUid === chatUid) {
        $('chat-title-display').textContent = chatLabel(c);
        const myId = state.account.accountId;
        const avatarSrc = c.initiator_id == myId ? c.peer_avatar : c.initiator_avatar;
        const headerAvatar = $('chat-header-avatar');
        if (avatarSrc) {
          headerAvatar.src = avatarSrc;
          headerAvatar.classList.remove('hidden');
        } else {
          headerAvatar.classList.add('hidden');
        }
      }
    }
  });

  state.socket.on('msg:burned', ({ chatUid, ids, preview }) => {
    ids.forEach(id => {

      const timer = state.activeBurnTimers.get(id);
      if (timer) { clearInterval(timer); state.activeBurnTimers.delete(id); }
      document.querySelector(`[data-msg-id="${id}"]`)?.closest('.msg-wrap')?.remove();
    });
    if (preview !== undefined) updateChatPreviewUI(chatUid, preview);
  });

  state.socket.on('msg:burn:countdown', async ({ msgId, chatUid, burnAt, burnSeconds, content, filePath, fileType, fileName }) => {
    await startBurnCountdown(msgId, chatUid, burnAt, burnSeconds, { content, filePath, fileType, fileName });
  });

  state.socket.on('msg:error', ({ chatUid, error }) => {
    console.warn('[msg:error]', error);
    toast('Not sent', error || 'The server rejected the message.', 'err');
  });

  state.socket.on('peer:presence', ({ chatUid, number, online, lastSeen }) => {
    if (!number) return;
    state.presence.set(number, { online: !!online, lastSeen: lastSeen || null });
    if (chatUid && chatUid === state.activeChatUid) renderPresence();
  });

  state.socket.on('msg:read:ack', ({ chatUid, by }) => {

    if (state.activeChatUid === chatUid && by != state.account.accountId) markAllRead();
  });

  state.socket.on('msg:deleted', ({ msgId, forWhom, by, previewInit, previewPeer, initiatorId, peerId }) => {
    const el = document.querySelector(`[data-msg-id="${msgId}"]`);
    const isMe = String(by) === String(state.account.accountId);
    const amInitiator = String(state.account.accountId) === String(initiatorId);
    const myPreview = amInitiator ? previewInit : previewPeer;

    if (el) {
      const shouldHide =
        forWhom === 'both' ||
        (forWhom === 'self' && isMe) ||
        (forWhom === 'peer' && !isMe);
      if (shouldHide) el.closest('.msg-wrap')?.remove();
    }

    if (state.activeChatUid) updateChatPreviewUI(state.activeChatUid, myPreview ?? '');
  });

  state.socket.on('msg:reaction', async ({ msgId, reactions }) => {
    const wrap = document.querySelector(`.msg-bubble[data-msg-id="${msgId}"]`)?.closest('.msg-wrap');
    if (!wrap) return;

    let reactionsBar = wrap.querySelector('.msg-reactions');

    const peerChatNum = await getActivePeerChatNum();
    const peerPub = peerChatNum ? await getPeerKey(peerChatNum, true) : null;
    const decryptKeys = peerPub ? [...peerPub, ...await getMyDevicesKeys()] : null;

    const grouped = {};
    const myEncEmojis = {};

    for (const r of reactions) {
      let emoji = r.emoji;
      if (isEncrypted(emoji) && decryptKeys) {
        try { emoji = await decryptMsg(emoji, state.activeChatUid || peerChatNum, decryptKeys, { enforceReplay: false }); }
        catch { emoji = '?'; }
      } else if (isEncrypted(emoji)) {
        emoji = '?';
      }
      if (!isSingleEmoji(emoji)) emoji = '?';
      grouped[emoji] = grouped[emoji] || [];
      grouped[emoji].push(r.account_id);

      if (r.account_id === Number(state.account.accountId)) {
        myEncEmojis[emoji] = r.emoji;
      }
    }

    if (Object.keys(grouped).length === 0) {
      if (reactionsBar) reactionsBar.remove();
      return;
    }

    if (!reactionsBar) {
      reactionsBar = document.createElement('div');
      reactionsBar.className = 'msg-reactions';
      wrap.appendChild(reactionsBar);
    }

    reactionsBar.innerHTML = '';
    for (const [emoji, users] of Object.entries(grouped)) {
      const isMine = users.includes(Number(state.account.accountId));
      const btn = document.createElement('button');
      btn.className = `msg-reaction ${isMine ? 'mine' : ''}`;
      btn.dataset.msgId = msgId;
      btn.dataset.emoji = emoji;
      if (isMine) {
        btn.dataset.encEmoji = myEncEmojis[emoji];
      }
      btn.innerHTML = `${reactionHtml(emoji)} <span>${users.length}</span>`;
      btn.onclick = (ev) => {
        ev.stopPropagation();
        const encEmoji = btn.dataset.encEmoji;
        if (encEmoji) {
          state.socket.emit('msg:react', { msgId, emoji: encEmoji });
        } else {
          sendReaction(msgId, emoji);
        }
      };
      reactionsBar.appendChild(btn);
    }
  });

  state.socket.on('msg:played', ({ msgId }) => {
    const dot = document.querySelector(`.msg-bubble[data-msg-id="${msgId}"] .audio-unplayed`);
    if (dot) dot.remove();
  });

  state.socket.on('chat:deleted', ({ chatUid, forWhom, by }) => {
    const isMe = String(by) === String(state.account.accountId);
    if (forWhom === 'both' || (forWhom === 'peer' && !isMe)) {
      const chatEl = document.querySelector(`.chat-item[data-uid="${chatUid}"]`);

      if (chatEl) {
        chatEl.classList.add('removing');
        setTimeout(() => {
          chatEl.remove();
          state.chats = state.chats.filter(c => c.uid !== chatUid);
          if (state.activeChatUid === chatUid) closeChat();
          if (!isMe) toast('Chat deleted', 'The other party deleted this chat', 'warn');
        }, 200);
      } else {
        state.chats = state.chats.filter(c => c.uid !== chatUid);
        renderChatList();
        if (state.activeChatUid === chatUid) closeChat();
      }
    }
  });

  state.socket.on('chat:new', async ({ chat }) => {

    if (state.chats.find(c => c.uid === chat.uid)) return;

    const myId = state.account.accountId;
    const peerChatNum = chat.initiator_id == myId ? chat.peer_chat_number : chat.initiator_chat_number;
    const aliases = await api('GET', '/api/aliases');

    if (state.chats.find(c => c.uid === chat.uid)) return;

    const aliasMap = {};
    (aliases || []).forEach(a => aliasMap[a.target_number] = a.alias);
    chat.peer_alias = await decryptMeta(aliasMap[peerChatNum] || null);
    chat.label_initiator = await decryptMeta(chat.label_initiator || null);
    chat.label_peer = await decryptMeta(chat.label_peer || null);
    state.chats.unshift(chat);
    renderChatList();

    state.socket.emit('chat:join', { chatUid: chat.uid });
  });

  state.socket.on('chat:request', ({ chatUid, fromNumber }) => {
    state.pendingChatRequest = { chatUid, fromNumber };
    $('chat-request-text').textContent = `Account ${fmtNum(fromNumber)} wants to start a chat.`;
    show($('modal-chat-request'));
    toast('Chat request', `Account ${fmtNum(fromNumber)} wants to chat`, 'info', 6000);
  });

  state.socket.on('chat:accepted', async ({ chatUid }) => {
    toast('Chat accepted', 'The chat request was accepted.', 'ok', 3000);
    await loadChats();
    if (state.activeChatUid === chatUid) openChat(chatUid);
  });

  state.socket.on('chat:declined', ({ chatUid }) => {
    state.chats = state.chats.filter(c => c.uid !== chatUid);
    renderChatList();
    if (state.activeChatUid === chatUid) closeChat();
    toast('Chat declined', 'The chat request was declined.', 'warn', 3000);
  });

  state.socket.on('chat:burn:pending', ({ chatUid, mode, customMin, by }) => {
    if (Number(by) === Number(state.account.accountId)) return;
    showBurnConfirmModal(chatUid, mode, customMin);
  });

  state.socket.on('chat:history:pending', async ({ chatUid, max, by }) => {
    if (Number(by) === Number(state.account.accountId)) return;
    const ok = await dialog({ title: 'History limit', body: `Peer requests a history limit of ${max === -1 ? 'unlimited' : max + ' messages'}. Accept?`, okText: 'Accept' });
    if (ok) state.socket.emit('chat:history:confirm', { chatUid });
  });

  state.socket.on('chat:burn:confirmed', ({ chatUid }) => {
    const c = state.chats.find(x => x.uid === chatUid);
    if (c) c.burn_confirmed = 1;
    renderChatList();
    toast('Burn confirmed', 'Long retention confirmed by both', 'warn');
  });

  state.socket.on('chat:history:changed', ({ chatUid, max, sysMsg }) => {
    const c = state.chats.find(x => x.uid === chatUid);
    if (c) c.max_messages = max;
    if (state.activeChatUid === chatUid && sysMsg) {
      renderSystemMessage(sysMsg.text);
    }
  });

  state.socket.on('typing:start', ({ chatUid }) => {
    if (state.activeChatUid === chatUid) {
      $('typing-indicator').textContent = 'typing...';
      show($('typing-indicator'));
    }
  });
  state.socket.on('typing:stop', ({ chatUid }) => {
    if (state.activeChatUid === chatUid) hide($('typing-indicator'));
  });

  state.socket.on('peer:key_update', async ({ chatUid }) => {
    const c = state.chats.find(x => x.uid === chatUid);
    if (c) {
      const myId = state.account.accountId;
      const peerChatNum = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
      state.peerKeys.delete(peerChatNum);
      const fresh = await getPeerKey(peerChatNum);
      if (fresh) {
        updateVerifiedBadge(peerChatNum);
        const pin = await getPeerPin(peerChatNum);
        const banner = $('key-alert-banner');
        if (banner) banner.classList.toggle('hidden', !pin?.blocking);
      }
    }
  });
}

function showUnstable() { $('screen-main').classList.add('blurred'); show($('overlay-unstable')); }
function hideUnstable() {
  $('screen-main').classList.remove('blurred');
  hide($('overlay-unstable')); hide($('btn-unstable-indicator'));
  state.ignored = false;
}
$('btn-retry').onclick  = () => state.socket.connect();
$('btn-ignore').onclick = () => {
  state.ignored = true; hide($('overlay-unstable'));
  $('screen-main').classList.remove('blurred'); show($('btn-unstable-indicator'));
};
$('btn-unstable-indicator').onclick = showUnstable;

function renderChatListSkeleton() {
  const list = $('chat-list');
  if (!list) return;
  list.innerHTML = '';
  for (let i = 0; i < 9; i++) {
    const div = document.createElement('div');
    div.className = 'skel-chat';
    div.innerHTML = '<div class="skel skel-ava"></div><div class="skel-lines"><div class="skel skel-bar l1"></div><div class="skel skel-bar l2"></div></div>';
    list.appendChild(div);
  }
}

function renderMessagesSkeleton() {
  const cont = $('messages-container');
  if (!cont) return;
  cont.innerHTML = '';
  const widths = ['55%', '38%', '62%', '30%', '50%', '58%'];
  for (let i = 0; i < 6; i++) {
    const row = document.createElement('div');
    row.className = 'skel-msg-row ' + (i % 2 ? 'me' : 'them');
    const h = i % 3 === 0 ? 46 : 34;
    row.innerHTML = `<div class="skel skel-msg" style="width:${widths[i]};height:${h}px"></div>`;
    cont.appendChild(row);
  }
}

async function decryptChatLabels(chats) {
  for (const chat of chats) {
    if (chat.label_initiator) chat.label_initiator = await decryptMeta(chat.label_initiator);
    if (chat.label_peer) chat.label_peer = await decryptMeta(chat.label_peer);
    if (chat.peer_alias) chat.peer_alias = await decryptMeta(chat.peer_alias);
  }
  return chats;
}

async function loadChats() {
  if (!state.chats.length) renderChatListSkeleton();
  const data = await api('GET', '/api/chats');
  if (!Array.isArray(data)) return;
  state.chats = await decryptChatLabels(data);
  renderChatList();
}

function sysMsgText(m) {
  const p = m.payload || {};
  if (m.type === 'device_login') return `Sign-in from a new device: "${p.deviceName || 'device'}"`;
  if (m.type === 'key_request') {
    const bits = [];
    if (p.code) bits.push(`code ${p.code}`);
    if (p.ip) bits.push(`IP ${p.ip}`);
    if (p.country && p.country !== 'unknown') bits.push(String(p.country));
    if (p.expiresAt) bits.push(`expires ${new Date(p.expiresAt * 1000).toLocaleTimeString()}`);
    return `Device "${p.deviceName || 'new device'}" requests approval${bits.length ? ' (' + bits.join(', ') + ')' : ''}.`;
  }
  if (m.type === 'key_transfer_done') return `Identity key transferred to "${p.deviceName || 'device'}".`;
  if (m.type === 'chat_request') return 'Incoming chat request.';
  return 'System event';
}

async function loadSystemMessages() {
  const d = await api('GET', '/api/system/messages');
  if (!d || d.error || !Array.isArray(d.messages)) return;
  state.sysMessages = d.messages;
  state.sysUnread = d.unread || 0;
  const mine = state.sysMessages.find(m => m.type === 'key_request' && m.status === 'pending' &&
    Number(m.payload?.deviceId) === Number(state.myDeviceId));
  if (mine) state.myPendingKeyRequestId = mine.id;
  refreshSystemChatItem();
  updateSystemBadge();
}

function refreshSystemChatItem() {
  const list = $('chat-list');
  if (!list) return;
  const old = $('chat-item-system');
  if (old) old.remove();
  const div = document.createElement('div');
  div.className = 'chat-item chat-item-system' + (state.systemOpen ? ' active active-chat' : '');
  div.id = 'chat-item-system';
  const last = state.sysMessages[0];
  const preview = last ? sysMsgText(last) : 'Account events and security alerts';
  div.innerHTML = `
    <div class="chat-avatar sys-avatar"><i class="fa-solid fa-bell-ring"></i></div>
    <div class="chat-item-info">
      <div class="chat-item-top"><span class="chat-item-name">Taupe</span></div>
      <div class="chat-item-preview" id="sys-preview">${esc(preview)}</div>
    </div>
    <span class="chat-item-badge sys-badge ${state.sysUnread > 0 ? '' : 'hidden'}" id="sys-badge">${state.sysUnread || ''}</span>
  `;
  div.onclick = () => openSystemChat();
  const empty = list.querySelector('.chat-list-empty');
  if (empty) list.insertBefore(div, empty);
  else list.prepend(div);
}

function updateSystemBadge() {
  const b = $('sys-badge');
  if (!b) return;
  b.textContent = state.sysUnread || '';
  b.classList.toggle('hidden', !(state.sysUnread > 0));
  const p = $('sys-preview');
  const last = state.sysMessages[0];
  if (p && last) p.textContent = sysMsgText(last);
}

async function openSystemChat() {
  state.systemOpen = true;
  state.activeChatUid = null;
  localStorage.removeItem('taupe_active_chat');
  hide($('empty-state'));
  const cv = $('chat-view');
  cv.classList.remove('hidden'); cv.style.display = 'flex';
  showChatArea();

  $('chat-title-display').textContent = 'Taupe';
  $('chat-title-display').style.cursor = '';
  $('chat-title-display').onclick = null;
  $('chat-header-avatar').classList.add('hidden');
  $('chat-subtitle').textContent = 'Account events and security';
  $('chat-subtitle').onclick = null;
  show($('chat-subtitle'));
  hide($('msg-input-area'));
  hide($('btn-chat-menu'));

  document.querySelectorAll('.chat-item').forEach(el => el.classList.remove('active', 'active-chat'));
  const item = $('chat-item-system');
  if (item) item.classList.add('active', 'active-chat');

  renderSystemMessages();
  const d = await api('POST', '/api/system/read', {});
  if (d && !d.error) { state.sysUnread = 0; updateSystemBadge(); }
}

async function renderSystemMessages() {
  const cont = $('messages-container');
  cont.innerHTML = '';
  if (!state.sysMessages.length) {
    cont.innerHTML = '<div class="sys-empty">No events yet.<br>Sign-ins and key-transfer requests will appear here.</div>';
    return;
  }
  for (const m of [...state.sysMessages].reverse()) {
    const card = document.createElement('div');
    card.className = 'sys-card sys-' + m.type;
    const icon = m.type === 'key_request' ? 'fa-key'
      : m.type === 'device_login' ? 'fa-mobile-screen-button'
      : m.type === 'key_transfer_done' ? 'fa-shield-halved' : 'fa-bell';
    const when = new Date((m.created_at || 0) * 1000);
    const time = when.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ', ' + when.toLocaleDateString();
    let statusHtml = '';
    if (m.type === 'key_request') {
      const st = m.status || 'pending';
      const chips = { approved: 'Approved, waiting for identity sync', declined: 'Declined', completed: 'Identity transferred', expired: 'Expired' };
      if (st === 'pending') {
        const own = await isOwnKeyRequest(m);
        const code = m.payload?.code ? `<div class="sys-code">${esc(m.payload.code)}</div>` : '';
        statusHtml = own
          ? `<div class="sys-status pending-self">Compare this code on another device: ${esc(m.payload?.code || '')}. Approve there.</div>`
          : `${code}
          <div class="sys-actions">
            <button class="sys-btn approve" data-id="${m.id}"><i class="fa-solid fa-check"></i> Approve</button>
            <button class="sys-btn deny" data-id="${m.id}"><i class="fa-solid fa-xmark"></i> Deny</button>
          </div>`;
      } else if (chips[st]) {
        statusHtml = `<div class="sys-status ${st}">${esc(chips[st])}</div>`;
      }
    }
    card.innerHTML = `
      <div class="sys-icon"><i class="fa-solid ${icon}"></i></div>
      <div class="sys-body">
        <div class="sys-text">${esc(sysMsgText(m))}</div>
        ${statusHtml}
        <div class="sys-time">${esc(time)}</div>
      </div>`;
    cont.appendChild(card);
  }
  cont.querySelectorAll('.sys-btn').forEach(btn => {
    btn.onclick = () => resolveKeyRequest(parseInt(btn.dataset.id), btn.classList.contains('approve'));
  });
  cont.style.scrollBehavior = 'auto';
  cont.scrollTop = cont.scrollHeight;
  cont.style.scrollBehavior = '';
}

async function isOwnKeyRequest(m) {
  if (!m || m.type !== 'key_request') return false;
  if (Number(m.payload?.deviceId) === Number(state.myDeviceId)) return true;
  try {
    const pub = m.payload?.publicKey;
    return !!pub && pub === await getMyPublicKeyB64();
  } catch { return false; }
}

async function resolveKeyRequest(id, approve) {
  const m = state.sysMessages.find(x => x.id === id);
  if (!m) return;
  if (approve && await isOwnKeyRequest(m)) {
    toast('Not allowed', 'Approve this request on another device.', 'warn', 5000);
    return;
  }
  if (approve) {
    try {
      const r = await api('POST', `/api/system/${id}/resolve`, { action: 'approved' });
      if (r.error) { toast('Not approved', r.error, 'warn', 4000); return; }
      const encryptedKey = await encryptKeyForSync(null, m.payload.publicKey);
      if (!state.socket?.connected) { toast('Not connected', 'Reconnect and approve again to send the identity key.', 'warn'); return; }
      state.socket.emit('key:sync', { targetDeviceId: m.payload.deviceId, requestId: id, encryptedKey });
      toast('Identity sent', 'Encrypted identity key was sent to the approved device.', 'ok', 4000);
    } catch (e) {
      console.error('[Key Sync] approve failed:', e);
      toast('Approve failed', 'Could not export or encrypt keys on this device.', 'warn', 4000);
      return;
    }
  } else {
    const r = await api('POST', `/api/system/${id}/resolve`, { action: 'declined' });
    if (r.error) { toast('Not declined', r.error, 'warn', 4000); return; }
  }
  m.status = approve ? 'approved' : 'declined';
  renderSystemMessages();
  refreshSystemChatItem();
}

function renderChatList() {
  const list = $('chat-list');
  list.innerHTML = '';
  if (!state.chats.length) {
    list.innerHTML = '<div class="chat-list-empty">No chats yet</div>';
    refreshSystemChatItem();
    return;
  }
  const seenUids = new Set();
  state.chats.forEach(c => {
    if (seenUids.has(c.uid)) return;
    seenUids.add(c.uid);
    const div = document.createElement('div');
    div.className = 'chat-item' +
      (c.uid === state.activeChatUid ? ' active active-chat' : '') +
      (c.burn_confirmed ? ' yellow' : '');
    div.dataset.uid = c.uid;
    div.dataset.chatUid = c.uid;
    const myId       = state.account.accountId;
    const peerChatNum = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
    const alias      = c.peer_alias || null;
    const lbl = c.initiator_id == myId ? c.label_initiator : c.label_peer;
    const peerUsername = c.initiator_id == myId ? c.peer_username : c.initiator_username;
    const displayName = alias || lbl || peerUsername || null;
    const nameHtml   = displayName
      ? `${esc(displayName)} <span class="num-dim">${fmtNum(peerChatNum)}</span>`
      : `<span class="mono">${fmtNum(peerChatNum)}</span>`;
    const avatarSrc  = c.initiator_id == myId ? c.peer_avatar : c.initiator_avatar;

    let previewText = c.last_message_preview || '';
    if (isEncrypted(previewText)) {
      previewText = '[encrypted]';
    }
    previewText = parseSystemPreview(esc(previewText));

    div.innerHTML = `
      <div class="chat-avatar">${safeAvatarPath(avatarSrc)
        ? `<img src="${esc(safeAvatarPath(avatarSrc))}" alt="">`
        : `<span>${esc((alias||peerChatNum).charAt(0).toUpperCase())}</span>`}</div>
      <div class="chat-item-info">
        <div class="chat-item-top">
          <span class="chat-item-name">${nameHtml}</span>
        </div>
        <div class="chat-item-preview" id="preview-${c.uid}">${previewText}</div>
      </div>
            <span class="chat-item-badge ${(c.unread || 0) > 0 ? '' : 'hidden'}" id="badge-${c.uid}">${c.unread || 0}</span>
    `;
    div.onclick = () => openChat(c.uid);
    if (c.uid === state.activeChatUid) div.classList.add('active-chat');
    list.appendChild(div);

    if (isEncrypted(c.last_message_preview)) {
      state.peerKeys.delete(peerChatNum);
      getPeerKey(peerChatNum).then(async (peerPub) => {
        if (!peerPub) return;
        try {
          const decrypted = await decryptMsg(c.last_message_preview, c.uid, peerPub, { enforceReplay: false });
          const previewEl = document.getElementById(`preview-${c.uid}`);
          if (previewEl) previewEl.textContent = decrypted;
        } catch (e) {
          state.peerKeys.delete(peerChatNum);
          const freshKeys = await getPeerKey(peerChatNum);
          if (freshKeys) {
            try {
              const decrypted = await decryptMsg(c.last_message_preview, c.uid, freshKeys, { enforceReplay: false });
              const previewEl = document.getElementById(`preview-${c.uid}`);
              if (previewEl) previewEl.textContent = decrypted;
            } catch (e2) {
              const previewEl = document.getElementById(`preview-${c.uid}`);
              if (previewEl) previewEl.textContent = '[encrypted]';
            }
          }
        }
      });
    }
  });
  refreshSystemChatItem();
}

function chatLabel(c) {
  const myId = state.account.accountId;
  const peerChatNum = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
  if (c.peer_alias) return c.peer_alias;
  const lbl = c.initiator_id == myId ? c.label_initiator : c.label_peer;
  if (lbl) return lbl;
  const peerUsername = c.initiator_id == myId ? c.peer_username : c.initiator_username;
  if (peerUsername) return peerUsername;
  return fmtNum(peerChatNum);
}

function getPeerDisplayName(c) {
  if (!c) return 'Peer';
  const myId = state.account.accountId;
  if (c.initiator_id == myId) {
    const lbl = c.label_initiator;
    if (lbl) return lbl;
    return c.peer_alias || c.peer_username || fmtNum(c.peer_chat_number);
  }
  const lbl = c.label_peer;
  if (lbl) return lbl;
  return c.initiator_username || fmtNum(c.initiator_chat_number);
}

function burnBadgeHtml(mode) {
  const labels = { baf: 'BAF', '1min': '1m', '5min': '5m', '10min': '10m', custom: '?m', never: 'keep' };
  const cls    = mode === 'never' ? 'burn-badge burn-badge-red' : 'burn-badge';
  return `<span class="${cls}">${labels[mode] || ''}</span>`;
}
function burnLabel(m, min) {
  return { baf:'Burn after read','1min':'1 min','5min':'5 min','10min':'10 min',custom:`${min} min`,never:'Never' }[m] || m;
}

function bumpUnread(uid) {
  const b = $('badge-' + uid); if (!b) return;
  show(b); b.textContent = (parseInt(b.textContent) || 0) + 1;
}

function updateChatPreviewUI(uid, preview) {
  const el = $('preview-' + uid);
  if (el) {
    const cleanText = (preview || '').replace(/^e2e:/, '');
    if (preview && preview.startsWith('e2e:')) {
      el.textContent = '[Encrypted]';
    } else {
      el.innerHTML = parseSystemPreview(esc(preview || ''));
    }
  }
  const c = state.chats.find(x => x.uid === uid);
  if (c) c.last_message_preview = preview;
}
async function openChat(uid) {
  state.systemOpen = false;
  show($('msg-input-area'));
  show($('btn-chat-menu'));
  state.activeChatUid = uid;
  localStorage.setItem('taupe_active_chat', uid);
  hide($('empty-state'));
  const c = state.chats.find(x => x.uid === uid);
  if (c) c.unread = 0;
  const cv = $('chat-view');
  cv.classList.remove('hidden'); cv.style.display = 'flex';
  showChatArea();

  const b = $('badge-' + uid); if (b) { hide(b); b.textContent = ''; }

  if (!c) return;
  const myId  = state.account.accountId;
  const peerChatNum = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;

  state.socket.emit('presence:get', { number: peerChatNum });
  renderPresence();

  $('chat-title-display').textContent = chatLabel(c);
  $('chat-title-display').style.cursor = 'pointer';
  $('chat-title-display').onclick = () => {
    copyToClipboard(peerChatNum, 'Copied', fmtNum(peerChatNum));
  };

  const avatarSrc = c.initiator_id == myId ? c.peer_avatar : c.initiator_avatar;
  const headerAvatar = $('chat-header-avatar');
  const safeAvatar = safeAvatarPath(avatarSrc);
  if (safeAvatar) {
    headerAvatar.src = safeAvatar;
    headerAvatar.classList.remove('hidden');
  } else {
    headerAvatar.classList.add('hidden');
  }

  state.peerKeys.delete(peerChatNum);
  let peerPub = await getPeerKey(peerChatNum);
  if (!peerPub) {
    await new Promise(r => setTimeout(r, 800));
    peerPub = await getPeerKey(peerChatNum);
  }

  const pin = await getPeerPin(peerChatNum);
  const decryptKeys = peerPub ? [...peerPub, ...await getMyDevicesKeys()] : null;
  if (!pin?.identityPub) {
    toast('No E2E key', 'Peer has not set up encryption yet', 'warn', 5000);
  }

  const peerUsername = c.initiator_id == myId ? c.peer_username : c.initiator_username;
  const subtitleText = peerUsername ? '@' + peerUsername : '';
  $('chat-subtitle').textContent = subtitleText;
  $('chat-subtitle').style.cursor = subtitleText ? 'pointer' : '';
  $('chat-subtitle').onclick = subtitleText ? () => openPeerSecurity() : null;
  if (subtitleText) show($('chat-subtitle'));
  else hide($('chat-subtitle'));
  updateVerifiedBadge(peerChatNum);

  const alertBanner = $('key-alert-banner');
  if (alertBanner) {
    alertBanner.classList.toggle('hidden', !pin?.blocking);
  }

  document.querySelectorAll('.chat-item').forEach(el => {
    const isActive = el.dataset.uid === uid;
    el.classList.toggle('active', isActive);
    el.classList.toggle('active-chat', isActive);
  });

  state.peerKeys.delete(peerChatNum);

  currentRenderToken++;
  refreshSeq++;
  const myRenderToken = currentRenderToken;

  const cont = $('messages-container');
  cont.innerHTML = '';
  renderMessagesSkeleton();

  const msgs = await api('GET', `/api/chats/${uid}/messages`);
  if (myRenderToken !== currentRenderToken) return;

  cont.innerHTML = '';
  if (Array.isArray(msgs)) {
    await applyLocalHistory(uid, msgs);
    for (const m of msgs) {
      if (myRenderToken !== currentRenderToken) return;
      m._history = true;
      try { await renderMessage(m, peerChatNum, decryptKeys); }
      catch (e) { console.error('[render error]', e); }
    }
  }
  cont.style.scrollBehavior = 'auto';
  scrollBottom();
  cont.style.scrollBehavior = '';
  state.socket?.emit('msg:read', { chatUid: uid });

  state.hasMoreHistory = true;
  state.isLoadingHistory = false;

  cont.onscroll = async () => {
    if (myRenderToken !== currentRenderToken) return;
    if (!state.hasMoreHistory || state.isLoadingHistory) return;
    if (cont.scrollTop > 80) return;

    const firstMsg = cont.querySelector('[data-msg-id]');
    if (!firstMsg) return;

    state.isLoadingHistory = true;
    const savedHandler = cont.onscroll;
    cont.onscroll = null;

    const oldScrollHeight = cont.scrollHeight;
    const oldScrollTop    = cont.scrollTop;

    const olderMsgs = await api('GET', `/api/chats/${uid}/messages?beforeId=${firstMsg.dataset.msgId}`);

    if (myRenderToken !== currentRenderToken) return;

    if (!Array.isArray(olderMsgs) || olderMsgs.length === 0) {
      state.hasMoreHistory = false;
      state.isLoadingHistory = false;
      cont.onscroll = savedHandler;
      return;
    }
    await applyLocalHistory(uid, olderMsgs);

    const scrollPeerNum = await getActivePeerChatNum();
    const scrollPeerPub = scrollPeerNum ? await getPeerKey(scrollPeerNum) : null;
    const scrollDecryptKeys = scrollPeerPub ? [...scrollPeerPub, ...await getMyDevicesKeys()] : null;

    for (const m of [...olderMsgs].reverse()) {
      if (myRenderToken !== currentRenderToken) return;
      m._prepend = true;
      m._history = true;
      try { await renderMessage(m, scrollPeerNum, scrollDecryptKeys); }
      catch (e) { console.error('[render error]', e); }
    }

    const newScrollHeight = cont.scrollHeight;
    cont.style.scrollBehavior = 'auto';
    cont.scrollTop = newScrollHeight - oldScrollHeight + oldScrollTop;
    cont.style.scrollBehavior = '';

    state.isLoadingHistory = false;
    setTimeout(() => { cont.onscroll = savedHandler; }, 100);
  };
}

function closeChat() {
  state.activeChatUid = null;
  currentRenderToken++;
  localStorage.removeItem('taupe_active_chat');
  hide($('chat-view'));
  show($('empty-state'));
  if (state.isMobile()) showSidebar();
  renderChatList();
}

function showSidebar() {
  $('sidebar').classList.remove('mob-hidden');
  $('chat-area').classList.add('mob-hidden');
}
function showChatArea() {
  if (state.isMobile()) {
    $('sidebar').classList.add('mob-hidden');
    $('chat-area').classList.remove('mob-hidden');
  }
}
$('back-btn').onclick = () => { state.activeChatUid = null; showSidebar(); hide($('chat-view')); show($('empty-state')); };
window.addEventListener('resize', () => {
  if (!state.isMobile()) {
    $('sidebar').classList.remove('mob-hidden');
    $('chat-area').classList.remove('mob-hidden');
  }
});

async function renderMessage(msg, peerChatNum, peerPubB64) {
  const cont  = $('messages-container');
  if (!cont) return;
  const myId  = state.account.accountId;
  const isMe  = msg.sender_id == myId;

  let prevWrap = null;
  if (msg._prepend) {
    prevWrap = cont.firstElementChild;
  } else {
    prevWrap = cont.lastElementChild;
  }

  const showLabel = false
  const prevTime = prevWrap ? parseInt(prevWrap.dataset.ts || '0') : 0;
  const showTime = true

  const wrap = document.createElement('div');
  wrap.className = 'msg-wrap ' + (isMe ? 'me' : 'them');
  wrap.dataset.sender = msg.sender_id;

  const decryptKeys    = peerPubB64;
  const decryptChatNum = state.activeChatUid || peerChatNum;
  const decryptOptions = msg._history ? { enforceReplay: false } : undefined;

  let inner = '';
  if (showLabel && !isMe && peerChatNum) {
    const c   = state.chats.find(x => x.uid === state.activeChatUid);
    const alias = c?.peer_alias || null;
    const peerUsername = c ? (c.initiator_id == state.account.accountId ? c.peer_username : c.initiator_username) : null;
    const displayName = alias || peerUsername || null;
    const lbl = displayName
      ? `${esc(displayName)} <span class="label-num">${fmtNum(peerChatNum)}</span>`
      : `<span class="mono">${fmtNum(peerChatNum)}</span>`;
    inner += `<button class="msg-sender-label" data-num="${peerChatNum}" title="Copy number">${lbl}</button>`;
  }

  let replyHtml = '';
  if (msg.reply_to_id) {
    try {
      const origMsg = await api('GET', `/api/messages/${msg.reply_to_id}`);
      if (origMsg && !origMsg.error) {
        let origText = '';
        let isSystem = false;

        if (origMsg.file_path) {
          isSystem = true;
          if (origMsg.file_type === 'image') origText = '<i class="fa-solid fa-image"></i> Photo';
          else if (origMsg.file_type === 'audio') origText = '<i class="fa-solid fa-microphone"></i> Voice';
          else origText = '<i class="fa-solid fa-paperclip"></i> File';
        } else {
          origText = origMsg.content || '';
        }

        if (origText && isEncrypted(origText) && decryptKeys) {
          try { origText = await decryptMsg(origText, decryptChatNum, decryptKeys, decryptOptions); }
          catch { origText = '[decryption failed]'; }
        }

        if (!isSystem && typeof origText === 'string' && origText.startsWith('gif:')) {
          isSystem = true;
          origText = '<i class="fa-solid fa-film"></i> GIF';
        }

        const c = state.chats.find(x => x.uid === state.activeChatUid);
        let senderName = 'Peer';
        if (String(origMsg.sender_id) === String(state.account.accountId)) {
          senderName = 'You';
        } else {
          senderName = getPeerDisplayName(c);
        }

        const finalText = isSystem ? origText : twemojiSafe(esc(origText || '[Media]'));
        replyHtml = `<div class="msg-reply"><div class="msg-reply-name">${esc(senderName)}</div><div class="msg-reply-text">${finalText}</div></div>`;
      } else {
        replyHtml = `<div class="msg-reply"><div class="msg-reply-text">[Deleted message]</div></div>`;
      }
    } catch (e) { console.error('[reply fetch]', e); }
  }

  let content = '';
  const hasBurn = !!msg.burn_seconds;
  const isFile  = (msg.file_type === 'image' || msg.file_type === 'file' || msg.file_type === 'audio') && msg.file_path;

  if (hasBurn && !msg._spoilerOpened) {
    if (isMe) {
      if (isFile) {
        content = await buildFileHtml(msg, decryptChatNum, decryptKeys, isMe, '', decryptOptions);
      } else if (msg.content) {
        let text = msg._plaintext || msg.content;
        if (!msg._plaintext && isEncrypted(text) && decryptKeys) {
          try { text = await decryptMsg(text, decryptChatNum, decryptKeys, decryptOptions); }
          catch {
            const peerNum = await getActivePeerChatNum();
            if (peerNum) state.peerKeys.delete(peerNum);
            const freshKeys = peerNum ? await getPeerKey(peerNum) : null;
            if (freshKeys) {
              try { text = await decryptMsg(text, decryptChatNum, freshKeys, decryptOptions); }
              catch { text = state.waitingForKeySync ? '[Waiting for key from another device...]' : '[key mismatch]'; }
            } else {
              text = state.waitingForKeySync ? '[Waiting for key from another device...]' : '[key mismatch]';
            }
          }
        } else if (!msg._plaintext && isEncrypted(text)) { text = '[encrypted]'; }

        if (typeof text === 'string' && text.includes('gif:')) {
          const gifData = parseGifContent(text);
          if (gifData) {
            const imgTag = `<img class="msg-img msg-gif" src="${esc(gifData.url)}" loading="lazy" data-msg-id="${msg.id}">`;
            const safeText = esc(gifData.text).replace(/\n/g, '<br>');
            content = `${imgTag}${safeText ? `<br>${safeText}` : ''}`;
          } else {
            content = twemojiSafe(esc(text).replace(/\n/g, '<br>'));
          }
        } else if (isSingleEmoji(text)) {
          content = `<div class="msg-emoji-only">${twParse(text)}</div>`;
        } else {
          content = twemojiSafe(esc(text).replace(/\n/g, '<br>'));
        }
      }
      const burnLabel = formatBurnSecs(msg.burn_seconds);
      content = `<div class="msg-burn-open" data-msg-id="${msg.id}">${content}</div>`;
    } else {
      const burnLabel = formatBurnSecs(msg.burn_seconds);
      content = `<button class="msg-spoiler" data-msg-id="${msg.id}" data-chat-uid="${state.activeChatUid}" data-burn-secs="${msg.burn_seconds}">Show</button>`;
    }
  } else if (isFile) {
    content = await buildFileHtml(msg, decryptChatNum, decryptKeys, isMe, '', decryptOptions);
  } else if (msg.content) {
    let text = msg._plaintext || msg.content;
    if (!msg._plaintext && isEncrypted(text) && decryptKeys) {
      try { text = await decryptMsg(text, decryptChatNum, decryptKeys, decryptOptions); }
      catch {
        const peerNum = await getActivePeerChatNum();
        if (peerNum) state.peerKeys.delete(peerNum);
        const freshKeys = peerNum ? await getPeerKey(peerNum) : null;
        if (freshKeys) {
          try { text = await decryptMsg(text, decryptChatNum, freshKeys, decryptOptions); }
          catch { text = state.waitingForKeySync ? '[Waiting for key from another device...]' : '[key mismatch]'; }
        } else {
          text = state.waitingForKeySync ? '[Waiting for key from another device...]' : '[key mismatch]';
        }
      }
    } else if (!msg._plaintext && isEncrypted(text)) { text = '[encrypted]'; }

    if (typeof text === 'string' && text.includes('gif:')) {
      const gifData = parseGifContent(text);
      if (gifData) {
        const imgTag = `<img class="msg-img msg-gif" src="${esc(gifData.url)}" loading="lazy" data-msg-id="${msg.id}">`;
        const safeText = esc(gifData.text).replace(/\n/g, '<br>');
        content = `${imgTag}${safeText ? `<br>${safeText}` : ''}`;
      } else {
        content = twemojiSafe(esc(text).replace(/\n/g, '<br>'));
      }
    } else if (isSingleEmoji(text)) {
      content = `<div class="msg-emoji-only">${twParse(text)}</div>`;
    } else {
      content = twemojiSafe(esc(text).replace(/\n/g, '<br>'));
    }
  }

  const time = new Date(msg.created_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    let tickHtml = '';
  if (isMe) {
    if (msg._pending) {
      tickHtml = '<span class="read-tick pending"><i class="fa-solid fa-clock"></i></span>';
    } else if (msg.is_read) {
      tickHtml = '<span class="read-tick read"><i class="fa-solid fa-check-double"></i></span>';
    } else {
      tickHtml = '<span class="read-tick"><i class="fa-solid fa-check"></i></span>';
    }
  }

  const isEncryptedPayload = isEncrypted(msg.content) || (msg.file_path && msg.file_path.endsWith('.bin'));
  const lockIcon = isEncryptedPayload ? '<span class="e2e-lock" title="E2E encrypted"><i class="fa-solid fa-lock"></i></span>' : '';
  const burnMetaHtml = (hasBurn && !msg._spoilerOpened) ? `<span class="burn-countdown">${formatBurnSecs(msg.burn_seconds)}</span>` : '';
  const metaHtml = `<span class="msg-meta-inline">${burnMetaHtml}${lockIcon}${showTime ? `<span>${time}</span>` : ''}${tickHtml}</span>`;
  const isMediaContent = content.includes('msg-img') || content.includes('msg-gif') || content.includes('msg-audio-player');
  const isAudio = content.includes('msg-audio-player');

  const isEmojiOnly = content.includes('msg-emoji-only');
  let bubbleContent = content;
  let bubbleClasses = `msg-bubble ${isMe ? 'me' : 'them'}`;
  if (isEmojiOnly) bubbleClasses += ' emoji-only';

  if (isEmojiOnly) {
    bubbleContent = `<div class="msg-text-content">${content}</div>${metaHtml}`;
  } else if (isMediaContent) {
    bubbleClasses += ' is-media';
    if (isAudio) {
      bubbleClasses += ' has-audio';
      bubbleContent = `<div class="msg-media-wrap">${content}${metaHtml}</div>`;
    } else {
      bubbleContent = `<div class="msg-media-wrap">${content}${metaHtml}</div>`;
    }
  } else {
    bubbleContent = `<div class="msg-text-content">${content}</div>${metaHtml}`;
  }

  let reactionsHtml = '';
  if (msg.reactions && msg.reactions.length > 0) {
    const grouped = {};
    const myEncEmojis = {};

    for (const r of msg.reactions) {
      let emoji = r.emoji;
      if (isEncrypted(emoji) && decryptKeys) {
        try { emoji = await decryptMsg(emoji, decryptChatNum, decryptKeys, decryptOptions); }
        catch { emoji = '?'; }
      } else if (isEncrypted(emoji)) {
        emoji = '?';
      }
      if (!isSingleEmoji(emoji)) emoji = '?';
      grouped[emoji] = grouped[emoji] || [];
      grouped[emoji].push(r.account_id);

      if (r.account_id === Number(state.account.accountId)) {
        myEncEmojis[emoji] = r.emoji;
      }
    }

    reactionsHtml = '<div class="msg-reactions">';
    for (const [emoji, users] of Object.entries(grouped)) {
      const isMine = users.includes(Number(state.account.accountId));
      const encAttr = isMine && myEncEmojis[emoji] ? `data-enc-emoji="${esc(myEncEmojis[emoji])}"` : '';
      reactionsHtml += `<button class="msg-reaction ${isMine ? 'mine' : ''}" data-msg-id="${msg.id}" data-emoji="${esc(emoji)}" ${encAttr}>${reactionHtml(emoji)} <span>${users.length}</span></button>`;
    }
    reactionsHtml += '</div>';
  }

  inner += `
    <div class="${bubbleClasses}" data-msg-id="${msg.id}">${replyHtml}${bubbleContent}</div>
    ${reactionsHtml}
  `;
  wrap.innerHTML = inner;

  wrap.querySelectorAll('img.msg-img, img.msg-gif').forEach(img => {
    if (img.complete) {
      img.classList.add('loaded');
      if (img.src.startsWith('blob:')) setTimeout(() => URL.revokeObjectURL(img.src), 1000);
    } else {
      img.addEventListener('load', () => {
        img.classList.add('loaded');
        if (img.src.startsWith('blob:')) setTimeout(() => URL.revokeObjectURL(img.src), 1000);
      });
    }
  });

  wrap.querySelectorAll('.msg-audio-player').forEach(p => initAudioPlayer(p, msg, isMe));

  wrap.querySelectorAll('.msg-reaction').forEach(btn => {
    btn.onclick = (ev) => {
      ev.stopPropagation();
      const encEmoji = btn.dataset.encEmoji;
      if (encEmoji) {
        state.socket.emit('msg:react', { msgId: parseInt(btn.dataset.msgId), emoji: encEmoji });
      } else {
        sendReaction(parseInt(btn.dataset.msgId), btn.dataset.emoji);
      }
    };
  });

  const replyDiv = wrap.querySelector('.msg-reply');
  if (replyDiv && msg.reply_to_id) {
    replyDiv.style.cursor = 'pointer';
    replyDiv.addEventListener('click', (e) => {
      e.stopPropagation();
      scrollToMessage(msg.reply_to_id);
    });
  }

  wrap.querySelector('.msg-sender-label')?.addEventListener('click', () => {
    copyToClipboard(peerChatNum, 'Copied', fmtNum(peerChatNum));
  });

  const bubble = wrap.querySelector('.msg-bubble');
  bubble.addEventListener('contextmenu', e => { e.preventDefault(); showMsgCtx(e, msg.id, isMe); });
  let pressTimer;
  bubble.addEventListener('touchstart', e => { pressTimer = setTimeout(() => showMsgCtx(e.touches[0], msg.id, isMe), 500); }, { passive: true });
  bubble.addEventListener('touchend', () => clearTimeout(pressTimer));

  const spoiler = wrap.querySelector('.msg-spoiler');
  if (spoiler) {
    spoiler.addEventListener('click', () => {
      state.socket?.emit('msg:spoiler:open', { msgId: msg.id, chatUid: state.activeChatUid });
      spoiler.innerHTML = '<span style="opacity:.5;font-size:12px">Opening…</span>';
    });
  }

  if (msg.burn_at && !isMe) {
    const remaining = msg.burn_at - Math.floor(Date.now() / 1000);
    if (remaining > 0) {
      setTimeout(() => state.socket?.emit('msg:spoiler:open', { msgId: msg.id, chatUid: state.activeChatUid }), 100);
    } else {
      state.socket?.emit('msg:burn:done', { msgId: msg.id, chatUid: state.activeChatUid });
    }
  }

  if (msg._prepend) {
    cont.prepend(wrap);
  } else {
    cont.appendChild(wrap);
  }

  if (prevWrap && prevWrap.dataset.sender === String(msg.sender_id)) {
    const pTime = parseInt(prevWrap.dataset.ts || '0');
    if (msg.created_at - pTime <= 120) {
      wrap.classList.add('same-sender');
      prevWrap.classList.remove('grouped-last');
    }
  }
  wrap.classList.add('grouped-last');
  wrap.dataset.ts = msg.created_at || Math.floor(Date.now() / 1000);
}

function safeUploadPath(value) {
  if (typeof value !== 'string') return null;
  if (!/^\/uploads\/[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) return null;
  if (value.includes('..')) return null;
  return value;
}

async function buildFileHtml(msg, decryptChatNum, decryptKeys, isMe, metaHtml, decryptOptions) {
  if (!msg.file_path) return '';
  const filePath = safeUploadPath(msg.file_path);
  if (!filePath) return '<span style="color:var(--danger)">[invalid file]</span>';
  const isEncryptedFile = filePath.endsWith('.bin');

  if (isEncryptedFile) {
    if (!decryptKeys) return '<span style="color:var(--warn)">[encrypted file]</span>';
    try {
      const resp = await fetch(filePath, { credentials: 'include' });
      if (!resp.ok) throw new Error('File fetch failed');
      const encBlob = await resp.blob();
      const decrypted = await decryptFile(encBlob, decryptChatNum, decryptKeys, decryptOptions);
      const blobUrl = URL.createObjectURL(decrypted.blob);
      const type = decrypted.type || 'application/octet-stream';
      if (type.startsWith('image/')) {
        return `<img class="msg-img" src="${blobUrl}" loading="lazy" data-msg-id="${msg.id}">`;
      }
      if (type.startsWith('audio/') || type === 'video/webm') {
        return getAudioPlayerHtml(blobUrl, msg, isMe, metaHtml);
      }
      const dlName = decrypted.name || 'file';
      return `<div class="msg-file">[ <a href="${blobUrl}" download="${esc(dlName)}" target="_blank" rel="noreferrer">${esc(dlName)}</a> ]</div>`;
    } catch (e) {
      console.error('[file decrypt]', e);
      return '<span style="color:var(--danger)">[decryption failed]</span>';
    }
  }

  const isImageType = msg.file_type === 'image';
  const isAudioType = msg.file_type === 'audio';
  if (isImageType) {
    return `<img class="msg-img" src="${esc(filePath)}" loading="lazy" data-msg-id="${msg.id}">`;
  }
  if (isAudioType) {
    return getAudioPlayerHtml(esc(filePath), msg, isMe, metaHtml);
  }
  return `<div class="msg-file">[ <a href="${esc(filePath)}" target="_blank" rel="noreferrer">${esc(msg.file_name || 'file')}</a> ]</div>`;
}

function markAllRead() {
  document.querySelectorAll('.read-tick:not(.pending)').forEach(t => {
    t.classList.add('read');
    t.innerHTML = '<i class="fa-solid fa-check-double"></i>';
  });
}
function scrollBottom() { const c = $('messages-container'); c.scrollTop = c.scrollHeight; }

document.addEventListener('click', e => {
  const img = e.target.closest('.msg-img');
  if (!img) return;
  const src = img.src;
  $('lightbox-img').src = src;
  $('lightbox-download').href = src;
  $('lightbox-download').download = src.split('/').pop();
  $('lightbox').classList.remove('hidden');
});
$('lightbox-backdrop').onclick = () => $('lightbox').classList.add('hidden');
$('lightbox-close').onclick    = () => $('lightbox').classList.add('hidden');
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') $('lightbox').classList.add('hidden');
});

function renderSystemMessage(text) {
  const cont = $('messages-container');
  if (!cont) return;
  const el = document.createElement('div');
  el.className = 'sys-msg';
  el.textContent = text;
  cont.appendChild(el);
  scrollBottom();
}

const quick_reacts = ['❤️', '👍', '🔥', '😂', '😱', '😭'];
let pendingReactionMsgId = null;

function getRecentReactions() {
  const saved = localStorage.getItem('taupe_recent_reactions');
  return saved ? JSON.parse(saved) : [...quick_reacts];
}

function addRecentReaction(emoji) {
  let recent = getRecentReactions();
  recent = recent.filter(e => e !== emoji);
  recent.unshift(emoji);
  if (recent.length > 6) recent = recent.slice(0, 6);
  localStorage.setItem('taupe_recent_reactions', JSON.stringify(recent));
}

async function sendReaction(msgId, emoji) {
  if (!isSingleEmoji(emoji)) return;
  const peerChatNum = await getActivePeerChatNum();
  if (!await ensurePeerTrusted(peerChatNum)) return;
  const peerPub = peerChatNum ? await getPeerKey(peerChatNum, true) : null;
  if (!peerPub) return;
  const recipients = [...peerPub, ...await getMyDevicesKeys()];
  let encEmoji;
  try {
    encEmoji = await encryptMsg(emoji, state.activeChatUid, state.account.deviceId, recipients);
  } catch (e) {
    console.error('[E2E] react encrypt failed', e);
    return;
  }
  state.socket.emit('msg:react', { msgId, emoji: encEmoji });
}

function showMsgCtx(e, msgId, isMe) {
  if (typeof msgId !== 'number' && !/^\d+$/.test(String(msgId))) return;
  removeCtx();
  const menu = document.createElement('div');
  menu.className = 'ctx-menu'; menu.id = 'ctx-menu';

  const reactBar = document.createElement('div');
  reactBar.className = 'ctx-reactions';

  const recent = getRecentReactions();
  recent.forEach(emoji => {
    const btn = document.createElement('button');
    btn.className = 'ctx-react-btn';
    if (!isSingleEmoji(emoji)) return;
    btn.innerHTML = reactionHtml(emoji);
    btn.onclick = async (ev) => {
      ev.stopPropagation();
      addRecentReaction(emoji);
      const peerChatNum = await getActivePeerChatNum();
      if (!await ensurePeerTrusted(peerChatNum)) return;
      const peerPub = peerChatNum ? await getPeerKey(peerChatNum, true) : null;
      if (!peerPub) return;
      const recipients = [...peerPub, ...await getMyDevicesKeys()];
      let encEmoji;
      try { encEmoji = await encryptMsg(emoji, state.activeChatUid, state.account.deviceId, recipients); }
      catch (e) { return; }
      state.socket.emit('msg:react', { msgId, emoji: encEmoji });
      removeCtx();
    };
    reactBar.appendChild(btn);
  });

  const plusBtn = document.createElement('button');
  plusBtn.className = 'ctx-react-btn';
  plusBtn.style.fontSize = '20px';
  plusBtn.style.color = 'var(--text2)';
  plusBtn.innerHTML = '<i class="fa-solid fa-plus"></i>';
  plusBtn.onclick = (ev) => {
    ev.stopPropagation();
    pendingReactionMsgId = msgId;
    removeCtx();
    document.querySelector('.eg-tab[data-tab="emoji"]').click();
    egSearch.value = '';
    egPanel.classList.remove('hidden');
  };
  reactBar.appendChild(plusBtn);
  menu.appendChild(reactBar);

  const items = isMe
    ? [['Reply', 'reply', false], ['Delete for me', 'self', false], ['Delete for both', 'both', true]]
    : [['Reply', 'reply', false], ['Delete for me', 'self', false]];

  items.forEach(([lbl, action, danger]) => {
    const d = document.createElement('div');
    d.className = 'ctx-item' + (danger ? ' danger' : '');
    d.textContent = lbl;
    d.onclick = () => {
      if (action === 'reply') setReplyTo(msgId);
      else state.socket.emit('msg:delete', { msgId, forWhom: action });
      removeCtx();
    };
    menu.appendChild(d);
  });

  const x = Math.min(e.clientX ?? 100, window.innerWidth - 190);
  const y = Math.min(e.clientY ?? 100, window.innerHeight - 130);
  menu.style.left = x + 'px'; menu.style.top = y + 'px';
  document.body.appendChild(menu);

  const rect = menu.getBoundingClientRect();
  let finalX = e.clientX ?? 100;
  let finalY = e.clientY ?? 100;
  if (finalX + rect.width > window.innerWidth - 20) {
    finalX = window.innerWidth - rect.width - 20;
  }
  if (finalY + rect.height > window.innerHeight - 10) {
    finalY = window.innerHeight - rect.height - 10;
  }
  if (finalX < 10) finalX = 10;
  if (finalY < 10) finalY = 10;
  menu.style.left = finalX + 'px';
  menu.style.top = finalY + 'px';
  setTimeout(() => document.addEventListener('click', removeCtx, { once: true }), 40);
}

function removeCtx() { $('ctx-menu')?.remove(); }

$('btn-send').onclick = () => {
  const btn = $('btn-send');
  btn.classList.remove('sending');
  void btn.offsetWidth;
  btn.classList.add('sending');
  sendMsg();
  setTimeout(() => btn.classList.remove('sending'), 250);
};
$('msg-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMsg(); }
});

let typingTimer;
$('msg-input').addEventListener('input', () => {
  if (!state.activeChatUid) return;
  state.socket?.emit('typing:start', { chatUid: state.activeChatUid });
  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => state.socket?.emit('typing:stop', { chatUid: state.activeChatUid }), 1500);
  const ta = $('msg-input');
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
});

function scrollToMessage(msgId) {
  const container = $('messages-container');
  const targetBubble = container.querySelector(`.msg-bubble[data-msg-id="${msgId}"]`);

  if (!targetBubble) {
    toast('Message not found', 'It might be too old or deleted', 'warn', 2000);
    return;
  }
  targetBubble.scrollIntoView({ behavior: 'smooth', block: 'center' });
  targetBubble.classList.remove('msg-highlight');
  targetBubble.classList.add('msg-highlight');
  setTimeout(() => targetBubble.classList.remove('msg-highlight'), 1500);
}

let replyTo = null;

function setReplyTo(msgId) {
  const bubble = document.querySelector(`.msg-bubble[data-msg-id="${msgId}"]`);
  if (!bubble) return;

  let text = bubble.innerText;
  let iconHtml = '';

  if (bubble.querySelector('.msg-gif') || text.startsWith('gif:')) {
    iconHtml = '<i class="fa-solid fa-film"></i> GIF';
    text = '';
  } else if (bubble.querySelector('.msg-img')) {
    iconHtml = '<i class="fa-solid fa-image"></i> Photo';
    text = '';
  } else if (bubble.querySelector('.msg-audio-player')) {
    iconHtml = '<i class="fa-solid fa-microphone"></i> Voice';
    text = '';
  } else if (bubble.querySelector('.msg-file')) {
    iconHtml = '<i class="fa-solid fa-paperclip"></i> File';
    text = '';
  }

  const replyContent = iconHtml || esc(text);
  const wrap = bubble.closest('.msg-wrap');
  const isMe = wrap.classList.contains('me');
  let senderName = 'Peer';

  if (isMe) {
    senderName = 'You';
  } else {
    const label = wrap.querySelector('.msg-sender-label');
    if (label) {
      senderName = label.textContent.split(' ')[0];
    } else {
      const c = state.chats.find(x => x.uid === state.activeChatUid);
      senderName = getPeerDisplayName(c);
    }
  }

  replyTo = { id: msgId, text: iconHtml || text };

  const preview = document.getElementById('reply-preview');
  if (preview) {
    preview.querySelector('.reply-preview-name').textContent = senderName;
    preview.querySelector('.reply-preview-text').innerHTML = replyContent;
    preview.classList.remove('hidden');
    document.getElementById('msg-input').focus();
  }
}

function cancelReply() {
  replyTo = null;
  document.getElementById('reply-preview')?.classList.add('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('reply-close')?.addEventListener('click', cancelReply);
});

function peerChatNumFor(uid) {
  const c = state.chats.find(x => x.uid === uid);
  if (!c) return null;
  const myId = state.account.accountId;
  return c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
}

function renderPendingBubble(chatUid, text) {
  state.sendSeq += 1;
  const pid = `pending-${state.sendSeq}`;
  const fake = {
    id: pid,
    sender_id: state.account.accountId,
    content: text,
    created_at: Math.floor(Date.now() / 1000),
    _pending: true,
  };
  state.pendingSends.push({ pid, chatUid, text });
  if (state.activeChatUid === chatUid) {
    renderMessage(fake, null, null).then(() => scrollBottom());
  }
  return pid;
}

function takePending(chatUid) {
  const idx = state.pendingSends.findIndex(p => p.chatUid === chatUid);
  if (idx === -1) return null;
  return state.pendingSends.splice(idx, 1)[0];
}

function removePendingBubble(pid) {
  document.querySelector(`[data-msg-id="${pid}"]`)?.closest('.msg-wrap')?.remove();
}

function enqueueSend(job) {
  state.outbox.push({ attempts: 0, ...job });
}

async function flushOutbox() {
  if (state.flushing || !state.outbox.length) return;
  state.flushing = true;
  try {
    while (state.outbox.length) {
      const ok = await transmitJob(state.outbox[0]);
      if (!ok) break;
      state.outbox.shift();
    }
  } finally {
    state.flushing = false;
  }
}

function failJob(job) {
  const idx = state.pendingSends.findIndex(x => x.chatUid === job.chatUid && x.text === job.text);
  if (idx !== -1) {
    removePendingBubble(state.pendingSends[idx].pid);
    state.pendingSends.splice(idx, 1);
  }
  toast('Not sent', 'Could not deliver the message. Try again.', 'err');
}

async function transmitJob(job) {
  try {
    if (!state.socket?.connected) return false;
    const peerChatNum = peerChatNumFor(job.chatUid);
    if (!peerChatNum) { failJob(job); return true; }
    if (!await ensurePeerTrusted(peerChatNum)) { failJob(job); return true; }
    const peerPub = await getPeerKey(peerChatNum, true);
    if (!peerPub || peerPub.length === 0) {
      job.attempts += 1;
      if (job.attempts >= 3) { failJob(job); return true; }
      return false;
    }
    const myDevices = await getMyDevicesKeys();
    const allRecipients = [...peerPub, ...myDevices];
    let content;
    try {
      content = await encryptMsg(job.text, job.chatUid, state.account.deviceId, allRecipients);
    } catch (e) {
      console.error('[E2E] encrypt failed', e);
      failJob(job);
      return true;
    }
    state.socket.emit('msg:send', {
      chatUid: job.chatUid,
      content,
      preview: null,
      fileUrl: null,
      fileType: null,
      fileName: null,
      burnSeconds: state.burnSeconds || null,
      replyToId: job.replyToId || null,
    });
    return true;
  } catch (e) {
    console.error('[send]', e);
    return false;
  }
}

async function sendMsg() {
  if (!state.activeChatUid) return;
  const text = $('msg-input').value.trim();
  const file = state.pendingFile;
  if (!text && !file) return;
  const chatUid = state.activeChatUid;
  const replyId = replyTo?.id || null;

  if (file && !state.socket?.connected) {
    toast('Not connected', 'Waiting for connection before sending the file', 'warn');
    return;
  }

  $('msg-input').value = '';
  $('msg-input').style.height = 'auto';
  state.pendingFile = null;
  hide($('file-preview'));
  state.socket?.emit('typing:stop', { chatUid });
  cancelReply();

  if (file) {
    const peerChatNum = await getActivePeerChatNum();
    if (!await ensurePeerTrusted(peerChatNum)) return;
    const peerPub = peerChatNum ? await getPeerKey(peerChatNum, true) : [];
    const myDevices = await getMyDevicesKeys();
    const allRecipients = [...peerPub, ...myDevices];
    if (peerPub.length === 0) {
      toast('Cannot send', 'Peer has not set up E2E encryption yet. Wait for them to come online.', 'err', 5000);
      return;
    }
    let content = text || null;
    if (content) {
      try {
        content = await encryptMsg(content, chatUid, state.account.deviceId, allRecipients);
      } catch (e) {
        console.error('[E2E] encrypt failed', e);
        toast('Not sent', 'Encryption failed, message was not sent.', 'err');
        return;
      }
    }
    state.socket.emit('msg:send', {
      chatUid,
      content,
      preview: null,
      fileUrl: file.url || null,
      fileType: file.fileType || null,
      fileName: null,
      burnSeconds: state.burnSeconds || null,
      replyToId: replyId,
    });
    if (text) state._pendingPlaintext = text;
    return;
  }

  renderPendingBubble(chatUid, text);
  enqueueSend({ chatUid, text, replyToId: replyId });
  flushOutbox();
}

const maxFileSize   = 25 * 1024 * 1024;
const maxAvatarSize =  5 * 1024 * 1024;

async function readUploadResp(r) {
  try { return await r.json(); }
  catch { return { error: `Server error (HTTP ${r.status})` }; }
}

$('file-input').onchange = async e => {
  const file = e.target.files[0]; if (!file) return;
  if (file.type.startsWith('video/')) { toast('No video', 'Video files are not supported', 'warn'); e.target.value = ''; return; }
  if (file.size > maxFileSize) { toast('Too large', 'File must be under 25 MB', 'warn'); e.target.value = ''; return; }
  const rm = toast('Uploading...', file.name, 'info', 0);

  const chatUid = state.activeChatUid;
  const peerChatNum = await getActivePeerChatNum();
  if (!await ensurePeerTrusted(peerChatNum)) { rm(); e.target.value = ''; return; }
  const peerPub = peerChatNum ? await getPeerKey(peerChatNum) : [];
  const myDevices = await getMyDevicesKeys();
  const allRecipients = [...peerPub, ...myDevices];
  if (!peerPub.length) {
    rm();
    toast('Cannot send', 'Peer encryption keys are unavailable.', 'err');
    e.target.value = '';
    return;
  }

  let fileToUpload;
  try {
    const clean = await stripImageMetadata(file);
    fileToUpload = await encryptFile(clean, chatUid, state.account.deviceId, allRecipients);
  } catch (err) {
    rm();
    console.error('[E2E] File encryption failed', err);
    toast('Not sent', 'Encryption failed, file was not uploaded.', 'err');
    e.target.value = '';
    return;
  }
  const finalName = (crypto.randomUUID ? crypto.randomUUID() : String(Date.now())) + '.bin';

  const fd = new FormData();
  fd.append('file', fileToUpload, finalName);
  let d;
  try {
    const r = await fetch('/api/upload', { method: 'POST', body: fd, credentials: 'include' });
    d = await readUploadResp(r);
  } catch (err) {
    console.error('[upload]', err);
    d = { error: 'Network error' };
  }
  rm();
  if (d.error) { toast('Upload failed', d.error, 'err'); e.target.value = ''; return; }
  state.pendingFile = { ...d, displayName: file.name, fileType: file.type.startsWith('image/') ? 'image' : 'file' };
  const prev = $('file-preview');
  if (prev) {
    prev.innerHTML = `${d.type === 'image' ? '<i class="fa-solid fa-image"></i>' : '<i class="fa-solid fa-file"></i>'} ${esc(file.name)} <button id="btn-clear-file"><i class="fa-solid fa-xmark"></i></button>`;
    show(prev);
    $('btn-clear-file').onclick = () => { state.pendingFile = null; hide(prev); };
  }
  e.target.value = '';
};

$('btn-new-chat').onclick  = () => { $('nc-error').textContent=''; show($('modal-new-chat')); };
$('btn-start-chat').onclick = () => { $('nc-error').textContent=''; show($('modal-new-chat')); };
$('nc-cancel').onclick     = () => hide($('modal-new-chat'));

$('nc-create').onclick = async () => {
  let raw = $('nc-peer-number').value.trim();
  let peerNumber;

  if (raw.startsWith('@')) {
    const lu = await api('GET', `/api/lookup/${encodeURIComponent(raw)}`);
    if (lu.error) { $('nc-error').textContent = lu.error; return; }
    peerNumber = lu.number;
  } else {
    peerNumber = raw.replace(/-/g, '');
    if (peerNumber.length < 8 || peerNumber.length > 12) { $('nc-error').textContent = 'Enter a chat number or @username'; return; }
  }

  const label = $('nc-label').value.trim() || null;

  $('nc-create').disabled = true;
  const d = await api('POST', '/api/chats', { peerNumber, label, burnMode: 'baf', burnCustom: null });
  $('nc-create').disabled = false;

  if (d.error) { $('nc-error').textContent = d.error; return; }
  hide($('modal-new-chat'));
  $('nc-peer-number').value = ''; $('nc-label').value = ''; $('nc-error').textContent = '';

  if (!state.chats.find(c => c.uid === d.uid)) {
    await loadChats();
  }
  openChat(d.uid);
};

async function openChatHistory(uid) {
  const c = state.chats.find(x => x.uid === uid);
  if (!c) return;
  const current = c.max_messages ?? -1;
  const v = await dialog({
    title: 'Chat History',
    body: 'Number of max messages to keep. -1 = Unlimited.',
    input: true,
    inputType: 'number',
    inputPlaceholder: '-1',
    inputDefault: String(current),
    okText: 'Apply',
  });
  if (v === null || v === undefined) return;
  const n = parseInt(v);
  if (isNaN(n) || n < -1 || n === 0) { toast('Invalid', 'Enter -1 for unlimited or a positive limit', 'warn'); return; }
  state.socket?.emit('chat:history', { chatUid: uid, max: n });
  c.max_messages = n;
}

function showBurnConfirmModal(chatUid, mode, customMin) {
  state.burnConfirmPending = { chatUid, mode, customMin };
  $('burn-confirm-text').innerHTML =
    `Peer wants to set burn to <strong>${burnLabel(mode, customMin)}</strong>. Messages will persist a long time. Confirm?`;
  show($('modal-burn-confirm'));
}
$('burn-accept').onclick = () => {
  if (!state.burnConfirmPending) return;
  state.socket.emit('chat:burn:confirm', { chatUid: state.burnConfirmPending.chatUid });
  const c = state.chats.find(x => x.uid === state.burnConfirmPending.chatUid);
  if (c) c.burn_confirmed = 1;
  renderChatList(); hide($('modal-burn-confirm')); state.burnConfirmPending = null;
};
$('burn-deny').onclick = () => { hide($('modal-burn-confirm')); state.burnConfirmPending = null; };

$('chat-request-accept').onclick = async () => {
  const request = state.pendingChatRequest;
  if (!request) return;
  const d = await api('POST', `/api/chats/${request.chatUid}/accept`);
  hide($('modal-chat-request'));
  state.pendingChatRequest = null;
  if (d.error) { toast('Error', d.error, 'err'); return; }
  await loadChats();
  openChat(request.chatUid);
};
$('chat-request-decline').onclick = async () => {
  const request = state.pendingChatRequest;
  if (!request) return;
  await api('POST', `/api/chats/${request.chatUid}/decline`);
  hide($('modal-chat-request'));
  state.pendingChatRequest = null;
};

async function renameChat(uid) {
  const c = state.chats.find(x => x.uid === uid);
  if (!c) return;
  const name = await dialog({ title: 'Rename chat', body: 'New label:', input: true, inputPlaceholder: 'chat1' });
  if (!name) return;
  const encryptedLabel = await encryptMeta(name);
  const d = await api('PATCH', `/api/chats/${uid}/label`, { label: encryptedLabel });
  if (d.error) { toast('Error', d.error, 'err'); return; }
  if (c.initiator_id == state.account.accountId) c.label_initiator = name;
  else c.label_peer = name;
  if (state.activeChatUid === uid) $('chat-title-display').textContent = chatLabel(c);
  renderChatList();
}

async function deleteChatFromMenu(uid, forWhom) {
  const c = state.chats.find(x => x.uid === uid);
  if (!c) return;
  const ok = await dialog({
    title: 'Delete chat',
    body: `Delete for ${forWhom === 'both' ? 'everyone' : 'me'}?`,
    okText: 'Delete',
    danger: true
  });
  if (!ok) return;
  state.socket?.emit('chat:delete', { chatUid: uid, forWhom });
  state.chats = state.chats.filter(x => x.uid !== uid);
  renderChatList();
  if (state.activeChatUid === uid) closeChat();
}

async function blockChat(uid) {
  const c = state.chats.find(x => x.uid === uid);
  if (!c) return;
  const myId = state.account.accountId;
  const peerNumber = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
  const ok = await dialog({ title: 'Block peer', body: 'Block this account and remove the chat?', okText: 'Block', danger: true });
  if (!ok) return;
  const d = await api('POST', '/api/blocks', { number: peerNumber });
  if (d.error) { toast('Error', d.error, 'err'); return; }
  await api('DELETE', `/api/chats/${uid}`, { forWhom: 'self' });
  state.chats = state.chats.filter(x => x.uid !== uid);
  renderChatList();
  if (state.activeChatUid === uid) closeChat();
  toast('Blocked', 'The account was blocked.', 'ok');
}

$('btn-chat-menu').onclick = () => {
  if (!state.activeChatUid) return;
  show($('modal-chat-menu'));
};
$('cm-cancel').onclick = () => hide($('modal-chat-menu'));
$('cm-rename').onclick = () => {
  const uid = state.activeChatUid;
  hide($('modal-chat-menu'));
  if (uid) renameChat(uid);
};
$('cm-history').onclick = () => {
  const uid = state.activeChatUid;
  hide($('modal-chat-menu'));
  if (uid) openChatHistory(uid);
};
['self','both'].forEach(forWhom => {
  $(`cm-delete-${forWhom}`).onclick = () => {
    const uid = state.activeChatUid;
    hide($('modal-chat-menu'));
    if (uid) deleteChatFromMenu(uid, forWhom);
  };
});
$('cm-block').onclick = () => {
  const uid = state.activeChatUid;
  hide($('modal-chat-menu'));
  if (uid) blockChat(uid);
};

let chatContextUid = null;
let chatContextTimer = null;

function openChatContext(uid, x, y) {
  const menu = $('chat-list-ctx');
  if (!menu) return;
  clearTimeout(chatContextTimer);
  menu.classList.remove('closing', 'open');
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
  menu.classList.add('open');
  const box = menu.getBoundingClientRect();
  const left = Math.max(8, Math.min(x, window.innerWidth - box.width - 8));
  const top = Math.max(8, Math.min(y, window.innerHeight - box.height - 8));
  menu.style.left = left + 'px';
  menu.style.top = top + 'px';
  chatContextUid = uid;
}

function hideChatContext() {
  chatContextUid = null;
  const menu = $('chat-list-ctx');
  if (!menu || !menu.classList.contains('open')) return;
  menu.classList.remove('open');
  menu.classList.add('closing');
  clearTimeout(chatContextTimer);
  chatContextTimer = setTimeout(() => menu.classList.remove('closing'), 160);
}

$('chat-list').addEventListener('contextmenu', event => {
  const item = event.target.closest('.chat-item[data-uid]');
  if (!item) return;
  event.preventDefault();
  openChatContext(item.dataset.uid, event.clientX, event.clientY);
});

$('chat-list-ctx').addEventListener('click', event => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const uid = chatContextUid;
  hideChatContext();
  if (!uid) return;
  const action = button.dataset.action;
  if (action === 'rename') renameChat(uid);
  else if (action === 'history') openChatHistory(uid);
  else if (action === 'delete-self') deleteChatFromMenu(uid, 'self');
  else if (action === 'delete-both') deleteChatFromMenu(uid, 'both');
  else if (action === 'block') blockChat(uid);
});

document.addEventListener('click', event => {
  if (!chatContextUid) return;
  if (event.target.closest('#chat-list-ctx')) return;
  hideChatContext();
});
document.addEventListener('contextmenu', event => {
  if (!chatContextUid) return;
  if (event.target.closest('#chat-list-ctx') || event.target.closest('.chat-item[data-uid]')) return;
  hideChatContext();
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') hideChatContext();
});
window.addEventListener('scroll', hideChatContext, true);
window.addEventListener('resize', hideChatContext);

$('btn-settings').onclick  = openSettings;
$('settings-close').onclick = () => { hideInfoTip(); hide($('modal-settings')); };

async function openSettings() {
  const me = await api('GET', '/api/me');
  state.account = { ...state.account, ...me };
  $('settings-chat-number').textContent = fmtNum(me.chatNumber);
  $('settings-username').value      = me.username || '';
  $('settings-username-public').checked = !!me.usernamePublic;
  $('settings-show-presence').checked = me.showPresence === true;
  $('settings-gif-enabled').checked = me.gifEnabled === true;
  const av = $('my-avatar-preview');
  av.innerHTML = me.avatarPath
    ? `<img src="${esc(safeAvatarPath(me.avatarPath) || '')}" style="width:64px;height:64px;border-radius:50%;object-fit:cover" alt="">`
    : '<i class="fa-solid fa-user" style="font-size:24px"></i>';
  const list = $('devices-list'); list.innerHTML = '';
  (me.devices || []).forEach(d => {
    const li = document.createElement('li');
    const isCur = d.id === me.deviceId;
    li.innerHTML = `<span>${esc(d.device_name)}${isCur ? ' <em class="cur-device">(this)</em>' : ''}</span>
      ${!isCur ? `<button class="device-kick" data-id="${d.id}">kick</button>` : ''}`;
    list.appendChild(li);
  });
  list.querySelectorAll('.device-kick').forEach(b => {
    b.onclick = async () => { await api('DELETE', `/api/devices/${b.dataset.id}`); openSettings(); };
  });
  const blocked = await api('GET', '/api/blocks');
  const blockedList = $('blocked-list');
  blockedList.innerHTML = '';
  for (const item of Array.isArray(blocked) ? blocked : []) {
    const li = document.createElement('li');
    li.innerHTML = `<span class="mono">${fmtNum(item.chat_number)}</span><button class="device-kick" data-number="${esc(item.chat_number)}">unblock</button>`;
    li.querySelector('.device-kick').onclick = async () => {
      await api('DELETE', `/api/blocks/${item.chat_number}`);
      openSettings();
    };
    blockedList.appendChild(li);
  }
  show($('modal-settings'));
}

 $('my-number-display').onclick = () => {
  const number = state.account?.chatNumber;
  if (!number) return;
  copyToClipboard(fmtNum(number), 'Copied', 'Chat number copied');
};

$('settings-chat-number-box').onclick = () => {
  copyToClipboard(state.account.chatNumber, 'Copied', 'Chat number copied');
};

const historyKdfIterations = 250000;

function bufferToB64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b64ToBuffer(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveHistoryKey(passphrase, salt, iterations) {
  const material = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function fetchAllMessages(chatUid) {
  let all = [];
  let before = null;
  while (true) {
    const suffix = before ? `?beforeId=${before}` : '';
    const page = await api('GET', `/api/chats/${chatUid}/messages${suffix}`);
    if (!Array.isArray(page) || page.length === 0) break;
    all = page.concat(all);
    before = page[0].id;
    if (page.length < 200) break;
  }
  return all;
}

async function buildHistoryBundle() {
  const chats = await api('GET', '/api/chats');
  if (!Array.isArray(chats)) return { chats: [], count: 0 };
  const result = [];
  let count = 0;
  for (const chat of chats) {
    const myId = state.account.accountId;
    const peerChatNumber = chat.initiator_id == myId ? chat.peer_chat_number : chat.initiator_chat_number;
    const peerPub = peerChatNumber ? await getPeerKey(peerChatNumber, true) : null;
    if (!peerPub) continue;
    const messages = await fetchAllMessages(chat.uid);
    const exported = [];
    for (const msg of messages) {
      if (!msg.content || msg.file_path) continue;
      let text = msg.content;
      if (isEncrypted(text)) {
        try { text = await decryptMsg(text, chat.uid, peerPub, { enforceReplay: false }); }
        catch { continue; }
      }
      if (typeof text !== 'string') continue;
      if (text.startsWith('[encrypted') || text.startsWith('[decryption') || text.startsWith('[key mismatch')) continue;
      exported.push({
        id: msg.id,
        sender_id: msg.sender_id,
        created_at: msg.created_at,
        text
      });
      count++;
    }
    if (exported.length) result.push({ uid: chat.uid, messages: exported });
  }
  return { chats: result, count };
}

async function exportHistory() {
  const passphrase = await dialog({
    title: 'Export encrypted history',
    body: 'Set a passphrase of at least 8 characters. You will need it on the new device. Text messages only, files are not included.',
    input: true,
    inputType: 'password',
    inputPlaceholder: 'Passphrase',
    okText: 'Export'
  });
  if (!passphrase) return;
  if (passphrase.length < 8) { toast('Weak passphrase', 'Use at least 8 characters.', 'warn'); return; }
  await withButtonLoading($('btn-export-history'), 'Exporting...', async () => {
    const bundle = await buildHistoryBundle();
    if (!bundle.count) { toast('Nothing to export', 'No readable text messages found.', 'warn'); return; }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveHistoryKey(passphrase, salt, historyKdfIterations);
    const payload = new TextEncoder().encode(JSON.stringify({
      v: 1,
      exportedAt: Math.floor(Date.now() / 1000),
      chats: bundle.chats
    }));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, payload);
    const file = JSON.stringify({
      v: 1,
      kdf: 'PBKDF2-SHA256',
      iterations: historyKdfIterations,
      salt: bufferToB64(salt),
      iv: bufferToB64(iv),
      data: bufferToB64(ciphertext)
    });
    const blob = new Blob([file], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `taupe-history-${new Date().toISOString().slice(0, 10)}.json.enc`;
    a.click();
    URL.revokeObjectURL(url);
    toast('History exported', `${bundle.count} messages encrypted with your passphrase.`, 'ok', 5000);
  });
}

async function importHistoryFile(file) {
  if (!file) return;
  const passphrase = await dialog({
    title: 'Import encrypted history',
    body: 'Enter the passphrase that was used when exporting this history file.',
    input: true,
    inputType: 'password',
    inputPlaceholder: 'Passphrase',
    okText: 'Import'
  });
  if (!passphrase) return;
  try {
    const parsed = JSON.parse(await file.text());
    if (!parsed || parsed.v !== 1 || parsed.kdf !== 'PBKDF2-SHA256' || !parsed.salt || !parsed.iv || !parsed.data) {
      throw new Error('Unsupported history file');
    }
    const salt = b64ToBuffer(parsed.salt);
    const iv = b64ToBuffer(parsed.iv);
    const iterations = Math.max(100000, Math.min(Number(parsed.iterations) || historyKdfIterations, 1000000));
    const key = await deriveHistoryKey(passphrase, salt, iterations);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, b64ToBuffer(parsed.data));
    const bundle = JSON.parse(new TextDecoder().decode(plaintext));
    const saved = await saveImportedHistory(bundle);
    if (!saved) { toast('Nothing imported', 'The file contained no messages.', 'warn'); return; }
    toast('History imported', `${saved} messages added to this device.`, 'ok', 5000);
    if (state.activeChatUid) openChat(state.activeChatUid);
    else loadChats();
  } catch (e) {
    console.error('[history import]', e);
    toast('Import failed', 'Wrong passphrase or damaged file.', 'err', 5000);
  }
}

async function applyLocalHistory(chatUid, messages) {
  if (!Array.isArray(messages) || !messages.length) return messages;
  const local = await getHistoryForChat(chatUid);
  if (!local.length) return messages;
  const map = new Map(local.map(message => [String(message.id), message]));
  for (const message of messages) {
    const saved = map.get(String(message.id));
    if (saved && typeof saved.text === 'string') message._plaintext = saved.text;
  }
  return messages;
}

$('btn-export-history').onclick = exportHistory;
$('btn-import-history').onclick = () => $('history-file-input').click();
$('history-file-input').onchange = async event => {
  const file = event.target.files[0];
  event.target.value = '';
  await importHistoryFile(file);
};

$('btn-save-username').onclick = async () => {
  const username = $('settings-username').value.trim();
  const isPublic = $('settings-username-public').checked;
  const d = await api('PATCH', '/api/me/username', { username, isPublic });
  if (d.error) { toast('Error', d.error, 'err'); return; }
  const saved = d.username || username.toLowerCase();
  $('settings-username').value = saved;
  toast('Saved', 'Username updated', 'ok');
  state.account.username = saved; state.account.usernamePublic = isPublic;
};

$('settings-gif-enabled').onchange = async () => {
  const enabled = $('settings-gif-enabled').checked;
  const d = await api('PATCH', '/api/me/gif', { enabled });
  if (d.error) {
    $('settings-gif-enabled').checked = !enabled;
    toast('Error', d.error, 'err');
    return;
  }
  state.account.gifEnabled = enabled;
  gifGrid.innerHTML = '';
  toast('Saved', enabled ? 'GIF search enabled, search terms go to Giphy' : 'GIF search disabled', 'ok');
};

$('settings-show-presence').onchange = async () => {
  const show = $('settings-show-presence').checked;
  const d = await api('PATCH', '/api/me/presence', { show });
  if (d.error) {
    $('settings-show-presence').checked = !show;
    toast('Error', d.error, 'err');
    return;
  }
  toast('Saved', show ? 'Presence visible to others' : 'Presence hidden from others', 'ok');
};

$('my-avatar-preview').onclick  = () => $('avatar-file-input').click();
$('avatar-file-input').onchange = e => {
  const file = e.target.files[0]; if (!file) return;
  e.target.value = '';
  if (file.size > maxAvatarSize) { toast('Too large', 'Image must be under 5 MB', 'warn'); return; }
  openCropEditor(file);
};

let _cropState = null;
let _cropOriginalFile = null;

function openCropEditor(file) {
  _cropOriginalFile = file;
  const objectUrl = URL.createObjectURL(file);
  const img = new Image();

  img.onload = () => {
    const canvas  = $('crop-canvas');
    const viewSize   = 280;
    canvas.width  = viewSize;
    canvas.height = viewSize;

    const maxDim = Math.max(img.width, img.height);
    const initialScale = viewSize / maxDim;

    const scaleInput = $('crop-scale');
    scaleInput.min = initialScale * 0.8;
    scaleInput.max = initialScale * 4;
    scaleInput.step = 0.01;
    scaleInput.value = initialScale;

    _cropState = {
      img, scale: initialScale, offsetX: 0, offsetY: 0,
      dragging: false, lastX: 0, lastY: 0,
    };
    drawCrop();
    show($('modal-crop'));
    URL.revokeObjectURL(objectUrl);
  };

  img.onerror = () => {
     toast('Error', 'Failed to load image', 'err');
     URL.revokeObjectURL(objectUrl);
  };

  img.src = objectUrl;
}

function drawCrop() {
  if (!_cropState) return;
  const { img, scale, offsetX, offsetY } = _cropState;
  const canvas = $('crop-canvas');
  const ctx = canvas.getContext('2d');
  const canvasSize  = 280;
  ctx.clearRect(0, 0, canvasSize, canvasSize);
  const w = img.width * scale, h = img.height * scale;
  ctx.drawImage(img, offsetX + (canvasSize - w) / 2, offsetY + (canvasSize - h) / 2, w, h);
}

const cropCanvas = $('crop-canvas');
cropCanvas.addEventListener('mousedown',  e => { if(_cropState){ _cropState.dragging=true; _cropState.lastX=e.clientX; _cropState.lastY=e.clientY; }});
cropCanvas.addEventListener('touchstart', e => { if(_cropState){ _cropState.dragging=true; _cropState.lastX=e.touches[0].clientX; _cropState.lastY=e.touches[0].clientY; }}, { passive:true });
document.addEventListener('mouseup',  () => { if (_cropState) _cropState.dragging=false; });
document.addEventListener('touchend', () => { if (_cropState) _cropState.dragging=false; });
document.addEventListener('mousemove', e => {
  if (!_cropState?.dragging) return;
  _cropState.offsetX += e.clientX - _cropState.lastX;
  _cropState.offsetY += e.clientY - _cropState.lastY;
  _cropState.lastX = e.clientX; _cropState.lastY = e.clientY;
  drawCrop();
});
document.addEventListener('touchmove', e => {
  if (!_cropState?.dragging) return;
  _cropState.offsetX += e.touches[0].clientX - _cropState.lastX;
  _cropState.offsetY += e.touches[0].clientY - _cropState.lastY;
  _cropState.lastX = e.touches[0].clientX; _cropState.lastY = e.touches[0].clientY;
  drawCrop();
}, { passive:true });

 $('crop-scale').addEventListener('input', e => {
  if (!_cropState) return;
  _cropState.scale = parseFloat(e.target.value);
  drawCrop();
});

 $('crop-cancel').onclick = () => { hide($('modal-crop')); _cropState = null; };

  $('crop-apply').onclick = async () => {
  if (!_cropState || !_cropOriginalFile) return;

  const viewSize = 280;
  const cropSize = 220;
  const cropOffset = (viewSize - cropSize) / 2;

  const scale = _cropState.scale;
  const offX = _cropState.offsetX;
  const offY = _cropState.offsetY;
  const imgW = _cropState.img.width;
  const imgH = _cropState.img.height;

  const drawX = offX + (viewSize - imgW * scale) / 2;
  const drawY = offY + (viewSize - imgH * scale) / 2;

  let cropX = Math.round((cropOffset - drawX) / scale);
  let cropY = Math.round((cropOffset - drawY) / scale);
  let cropW = Math.round(cropSize / scale);
  let cropH = Math.round(cropSize / scale);

  cropX = Math.max(0, cropX);
  cropY = Math.max(0, cropY);
  cropW = Math.min(imgW - cropX, cropW);
  cropH = Math.min(imgH - cropY, cropH);

  hide($('modal-crop'));

  const rm = toast('Uploading...', '', 'info', 0);
  const fd = new FormData();

  fd.append('avatar', _cropOriginalFile);
  fd.append('crop', JSON.stringify({ x: cropX, y: cropY, w: cropW, h: cropH }));

  try {
    const r = await fetch('/api/me/avatar', { method: 'POST', body: fd, credentials: 'include' });
    const d = await readUploadResp(r);
    rm();
    if (d.error) { toast('Error', d.error, 'err'); return; }
    state.account.avatarPath = d.avatarPath;
    $('my-avatar-preview').innerHTML = `<img src="${esc((safeAvatarPath(d.avatarPath) || '') + '?t=' + Date.now())}" style="width:64px;height:64px;border-radius:50%;object-fit:cover" alt="">`;
    toast('Avatar updated', '', 'ok');
  } catch (err) {
    console.error('[avatar upload]', err);
    rm();
    toast('Network Error', 'Upload failed', 'err');
  }
  _cropState = null;
};

$('btn-logout').onclick = async () => {
  await api('POST', '/api/logout');
  localStorage.removeItem('taupe_active_chat');
  location.reload();
};
$('btn-kick-all').onclick = async () => { await api('POST', '/api/devices/kick-all'); openSettings(); };
$('btn-delete-account').onclick = async () => {
  const number = await dialog({
    title: 'Delete account',
    body: 'Permanent. Re-enter your 16-digit private number to confirm.',
    input: true,
    inputType: 'password',
    inputPlaceholder: '0000000000000000',
    okText: 'Delete',
    danger: true
  });
  if (!number) return;
  const d = await api('DELETE', '/api/account', { number });
  if (d.error) { toast('Not deleted', d.error, 'err'); return; }
  localStorage.removeItem('taupe_active_chat');
  location.reload();
};

$('btn-aliases').onclick  = openAliases;
$('alias-cancel').onclick = () => hide($('modal-aliases'));

async function openAliases() {
  await renderAliasList();
  if (state.activeChatUid) {
    const c = state.chats.find(x => x.uid === state.activeChatUid);
    if (c) {
      const myId = state.account.accountId;
      const peerNum = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
      $('alias-number-input').value = fmtNum(peerNum);
    }
  }
  show($('modal-aliases'));
}

async function renderAliasList() {
  const aliases = await api('GET', '/api/aliases');
  const list    = $('alias-list'); list.innerHTML = '';
  for (const a of aliases || []) {
    const aliasText = await decryptMeta(a.alias);
    const div = document.createElement('div');
    div.className = 'alias-item';
      div.innerHTML = `<span class="alias-name">${esc(aliasText)}</span><span class="alias-num mono">${fmtNum(a.target_number)}</span><button class="alias-del" data-n="${a.target_number}"><i class="fa-solid fa-xmark"></i></button>`;
    div.onclick = e => {
      if (e.target.classList.contains('alias-del')) return;
      copyToClipboard(a.target_number, 'Copied', `${aliasText} - ${fmtNum(a.target_number)}`);
    };
    div.querySelector('.alias-del').onclick = async e => {
      e.stopPropagation();
      await api('DELETE', `/api/aliases/${a.target_number}`);
      await renderAliasList();
      await loadChats();
    };
    list.appendChild(div);
  }
}

$('alias-save').onclick = async () => {
  const num   = $('alias-number-input').value.replace(/-/g, '').trim();
  const alias = $('alias-name-input').value.trim();
  if (num.length < 8 || num.length > 12) { $('alias-error').textContent = 'Enter a chat number'; return; }
  if (!alias)           { $('alias-error').textContent = 'Enter alias name'; return; }
  const d = await api('PUT', '/api/aliases', { targetNumber: num, alias: await encryptMeta(alias) });
  if (d.error) { $('alias-error').textContent = d.error; return; }
  $('alias-error').textContent = ''; $('alias-name-input').value = '';
  await renderAliasList();
  await loadChats();
  toast('Alias saved', `${alias} → ${fmtNum(num)}`, 'ok');
};

$('alias-number-input').addEventListener('input', e => {
  let v = e.target.value.replace(/\D/g, '').slice(0, 12);
  e.target.value = v.length > 4 ? v.replace(/(\d{4})(?=\d)/g, '$1-') : v;
});

function copyToClipboard(text, successTitle = 'Copied', successMsg = '') {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      toast(successTitle, successMsg, 'ok', 1500);
    }).catch(err => {
      fallbackCopyText(text, successTitle, successMsg);
    });
  } else {
    fallbackCopyText(text, successTitle, successMsg);
  }
}

function fallbackCopyText(text, successTitle, successMsg) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.left = "-9999px";
  textArea.style.top = "0";
  textArea.setAttribute("readonly", "");
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    const successful = document.execCommand('copy');
    if (successful) {
      toast(successTitle, successMsg, 'ok', 1500);
    } else {
      toast('Copy failed', 'Please copy manually', 'err');
    }
  } catch (err) {
    toast('Copy failed', 'Please copy manually', 'err');
  }
  document.body.removeChild(textArea);
}
function safeAvatarPath(value) {
  if (typeof value !== 'string') return null;
  return /^\/uploads\/avatars\/[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value) ? value : null;
}

function reactionHtml(emoji) {
  return isSingleEmoji(emoji) ? twParse(emoji) : esc(emoji);
}

function isSingleEmoji(text) {
  if (!text) return false;
  const cleanText = text.trim();
  if (!cleanText) return false;
  if (Intl.Segmenter) {
    const segmenter = new Intl.Segmenter('en', { granularity: 'grapheme' });
    const segments = Array.from(segmenter.segment(cleanText));
    if (segments.length !== 1) return false;
    return /\p{Extended_Pictographic}/u.test(segments[0].segment);
  }
  const regex = /^(\p{Extended_Pictographic}(\p{Emoji_Modifier}|\uFE0F\u20E3?|[\u{E0020}-\u{E007E}]+\u{E007F})?(\u200D\p{Extended_Pictographic}(\p{Emoji_Modifier}|\uFE0F\u20E3?|[\u{E0020}-\u{E007E}]+\u{E007F})?)*)$/u;
  return regex.test(cleanText);
}

function parseSystemPreview(text) {
  if (!text) return '';
  return text
    .replace('📷 Image', '<i class="fa-solid fa-image"></i> Photo')
    .replace('📷 Photo', '<i class="fa-solid fa-image"></i> Photo')
    .replace('🎞️ GIF', '<i class="fa-solid fa-film"></i> GIF')
    .replace('ᯤ Voice', '<i class="fa-solid fa-microphone"></i> Voice')
    .replace('📎 File', '<i class="fa-solid fa-paperclip"></i> File')
    .replace('[burns after read]', '<i class="fa-solid fa-fire"></i> Burns after read')
    .replace('[encrypted]', '<i class="fa-solid fa-lock"></i> Encrypted');
}
function parseGifContent(text) {
  if (typeof text !== 'string' || !text.includes('gif:')) return null;
  const gifIndex = text.indexOf('gif:');
  const rest = text.substring(gifIndex + 4);

  let urlEnd = rest.length;
  for (let i = 0; i < rest.length; i++) {
    if (/\s/.test(rest[i])) {
      urlEnd = i;
      break;
    }
  }

  const gifUrl = rest.substring(0, urlEnd);
  const giphyRe = /^https:\/\/([a-z0-9-]+\.)*giphy\.com\//i;
  let url = gifUrl;
  if (giphyRe.test(gifUrl)) {
    url = '/api/gifs/media?u=' + encodeURIComponent(gifUrl);
  } else if (!gifUrl.startsWith('/api/gifs/media?u=')) {
    return null;
  }

  const remainingText = text.substring(0, gifIndex) + text.substring(gifIndex + 4 + urlEnd);
  return { url, text: remainingText.trim() };
}
function esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
function fmtNum(n) {
  const s = String(n || '').replace(/\D/g, '');
  if (s.length >= 8 && s.length <= 12) return s.replace(/(\d{4})(?=\d)/g, '$1-');
  return s;
}
function fmtPrivate(n) {
  const s = String(n || '').replace(/\D/g, '');
  if (s.length !== 16) return s;
  return s.replace(/(\d{4})(?=\d)/g, '$1-');
}

const burnSteps = [5, 10, 30, 60, 300, 600, 1800, 3600];
const minFileBurn = 60;

function formatBurnSecs(secs) {
  if (!secs) return '';
  if (secs < 60)   return `${secs}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  return `${Math.round(secs / 3600)}h`;
}

(function initBurnTimerUI() {
  const btn       = $('btn-burn-timer');
  const panel     = $('burn-timer-panel');
  const clear     = $('burn-timer-clear');
  const customRow = $('burn-custom-row');
  const customIn  = $('burn-custom-input');
  const customSet = $('burn-custom-set');
  if (!btn) return;

  function setActive(secs) {
    state.burnSeconds = secs;

    document.querySelectorAll('.burn-pill').forEach(p => {
      p.classList.toggle('selected',
        secs !== null && (
          (p.dataset.secs === 'custom' && !burnSteps.includes(secs)) ||
          parseInt(p.dataset.secs) === secs
        )
      );
    });

    if (secs) {
      btn.innerHTML = `<i class="fa-solid fa-fire"></i> ${formatBurnSecs(secs)}`;
      btn.classList.add('active');
      localStorage.setItem('taupe_burn_secs', secs);
    } else {
      btn.innerHTML = '<i class="fa-solid fa-fire"></i>';
      btn.classList.remove('active');
      localStorage.removeItem('taupe_burn_secs');
    }
  }

  const saved = parseInt(localStorage.getItem('taupe_burn_secs') || '0');
  if (saved > 0) setActive(saved);

  document.querySelectorAll('.burn-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      if (pill.dataset.secs === 'custom') {
        customRow.classList.remove('hidden');
        customIn.focus();
      } else {
        customRow.classList.add('hidden');
        setActive(parseInt(pill.dataset.secs));
      }
    });
  });

  customSet.addEventListener('click', () => {
    const v = parseInt(customIn.value);
    if (!v || v < 5) return;
    customRow.classList.add('hidden');
    setActive(v);
    panel.classList.add('hidden');
  });
  customIn.addEventListener('keydown', e => { if (e.key === 'Enter') customSet.click(); });

  clear.addEventListener('click', () => {
    customRow.classList.add('hidden');
    setActive(null);
  });

  btn.addEventListener('click', () => panel.classList.toggle('hidden'));

  document.addEventListener('click', e => {
    if (!panel.classList.contains('hidden') &&
        !panel.contains(e.target) && e.target !== btn)
      panel.classList.add('hidden');
  });
})();

let emojiCatalog = [];
let allEmojisData = {};
const egPanel = $('emoji-gif-panel');
const egSearch = $('eg-search-input');
const emojiGrid = $('eg-emoji-grid');
const gifGrid = $('eg-gif-grid');

async function loadEmojis() {
  try {
    const enRes = await fetch('/vendor/emojilib/emoji-en-US.json');
    const enData = await enRes.json();

    let ruData = {};
    try {
      const ruRes = await fetch('/vendor/emojilib/emoji-short-ru.json');
      if (ruRes.ok) {
        const ruRaw = await ruRes.json();
        for (const key in ruRaw) {
          const words = ruRaw[key].keywords || [];
          ruData[ruRaw[key].char] = words;
        }
      }
    } catch (e) { console.warn('RU dict failed, using EN only'); }

    allEmojisData = {};

    for (const emoji in enData) {
      const enWords = enData[emoji] || [];
      const ruWords = ruData[emoji] || [];
      allEmojisData[emoji] = [...new Set([...enWords, ...ruWords])];
    }

    emojiCatalog = Object.keys(allEmojisData);
    renderEmojis(emojiCatalog);
  } catch (e) {
    console.error('Emoji load failed', e);
  }
}

function renderEmojis(emojiList = emojiCatalog) {
  const grid = document.createElement('div');
  grid.className = 'eg-grid';
  emojiList.forEach(e => {
    const span = document.createElement('span');
    span.className = 'eg-emoji';
    span.innerHTML = twParse(e);
    span.onclick = async () => {
      if (pendingReactionMsgId) {
        addRecentReaction(e);
        await sendReaction(pendingReactionMsgId, e);
        pendingReactionMsgId = null;
        egPanel.classList.add('hidden');
      } else {
        const inp = $('msg-input');
        inp.value += e;
        inp.focus();
      }
    };
    grid.appendChild(span);
  });
  emojiGrid.innerHTML = '';
  emojiGrid.appendChild(grid);
}

loadEmojis();

 $('btn-emoji-gif').addEventListener('click', (e) => {
  e.preventDefault();
  e.stopPropagation();
  if (egPanel) {
    egPanel.classList.toggle('hidden');
  }
});

document.addEventListener('click', (e) => {
  if (!egPanel) return;
  if (!egPanel.classList.contains('hidden') && !egPanel.contains(e.target) && e.target.id !== 'btn-emoji-gif') {
    egPanel.classList.add('hidden');
    pendingReactionMsgId = null;
  }
});

document.querySelectorAll('.eg-tab').forEach(tab => {
  tab.onclick = () => {
    document.querySelectorAll('.eg-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    egSearch.placeholder = tab.dataset.tab === 'emoji' ? 'Search...' : 'Search GIFs...';
    if (tab.dataset.tab === 'emoji') {
      emojiGrid.classList.remove('hidden');
      gifGrid.classList.add('hidden');
    } else {
      emojiGrid.classList.add('hidden');
      gifGrid.classList.remove('hidden');
      if (!gifGrid.innerHTML || /Failed to load GIFs|disabled in Settings/.test(gifGrid.textContent)) loadGifs('speed', true);
    }
  };
});

let currentGifReqId = 0;
let gifSearchOffset = 0;
let currentGifQuery = 'speed';
let isFetchingGifs = false;

let emojiSearchTimer;
let gifSearchTimer;

egSearch.oninput = () => {
  clearTimeout(emojiSearchTimer);
  clearTimeout(gifSearchTimer);

  const q = egSearch.value.trim().toLowerCase();
  const activeTab = document.querySelector('.eg-tab.active').dataset.tab;

  if (activeTab === 'emoji') {
    emojiSearchTimer = setTimeout(() => {
      if (!q) {
        renderEmojis(emojiCatalog);
        return;
      }

      const filtered = emojiCatalog.filter(e => {
        if (e.includes(q)) return true;

        const keywords = allEmojisData[e] || [];
        return keywords.some(kw => kw.toLowerCase().includes(q));
      });

      renderEmojis(filtered);
    }, 150);
  } else if (activeTab === 'gif') {
    gifSearchTimer = setTimeout(() => {
      if (q) loadGifs(q, true);
      else loadGifs('speed', true);
    }, 400);
  }
};

gifGrid.addEventListener('scroll', () => {
  if (gifGrid.scrollTop + gifGrid.clientHeight >= gifGrid.scrollHeight - 50) {
    if (!isFetchingGifs && gifSearchOffset > 0) {
      loadGifs(currentGifQuery, false);
    }
  }
});

async function loadGifs(query, isNewSearch) {
  if (isFetchingGifs) return;

  if (isNewSearch) {
    currentGifQuery = query;
    gifSearchOffset = 0;
    gifGrid.innerHTML = '<div style="color:var(--text2);padding:10px;font-size:12px">Loading...</div>';
  }

  isFetchingGifs = true;
  const reqId = ++currentGifReqId;

  try {
    const res = await fetch(`/api/gifs?q=${encodeURIComponent(currentGifQuery)}&offset=${gifSearchOffset}`, {
      credentials: 'include',
      cache: 'no-store'
    });
    const data = await res.json();

    if (reqId !== currentGifReqId) return;
    if (data.error) {
      if (res.status === 403) {
        gifGrid.innerHTML = '<div style="color:var(--text2);padding:10px;font-size:12px">GIF search is disabled in Settings.</div>';
        return;
      }
      throw new Error(data.error);
    }

    if (isNewSearch) {
      gifGrid.innerHTML = '';
    }

    let grid = gifGrid.querySelector('.eg-grid');
    if (!grid) {
      grid = document.createElement('div');
      grid.className = 'eg-grid';
      gifGrid.appendChild(grid);
    }

    (data.gifs || []).forEach(url => {
      const img = document.createElement('img');
      img.className = 'eg-gif-item';
      img.src = url;
      img.loading = 'lazy';
      img.onclick = () => {
        sendGif(url);
        egPanel.classList.add('hidden');
      };
      grid.appendChild(img);
    });

    gifSearchOffset += (data.gifs || []).length;

    if ((data.gifs || []).length === 0 && isNewSearch) {
       gifGrid.innerHTML = '<div style="color:var(--text2);padding:10px;font-size:12px">No GIFs found.</div>';
    }

  } catch (e) {
    if (reqId !== currentGifReqId) return;
    console.error('[GIF]', e);
    if (isNewSearch) {
      gifGrid.innerHTML = `<div style="color:var(--text2);padding:10px;font-size:12px">Failed to load GIFs: ${esc(e.message || 'unknown error')}</div>`;
    }
  } finally {
    isFetchingGifs = false;
  }
}

async function sendGif(url) {
  const chatUid = state.activeChatUid;
  if (!chatUid) return;
  const replyId = replyTo?.id || null;
  cancelReply();
  renderPendingBubble(chatUid, 'gif:' + url);
  enqueueSend({ chatUid, text: 'gif:' + url, isGif: true, replyToId: replyId });
  flushOutbox();
}

 $('save-number-box').onclick = () => {
  $('save-number-box').classList.toggle('revealed');
};

 $('btn-copy-save-number').onclick = () => {
  copyToClipboard(pendingAccountData.accountNumber, 'Copied', 'Private number copied to clipboard');
};

 $('btn-download-save-number').onclick = () => {
  const text = `Taupe Private Number: ${pendingAccountData.accountNumber}\nDO NOT SHARE THIS WITH ANYONE.`;
  const blob = new Blob([text], {type: "text/plain"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'taupe_keys.txt';
  a.click();
  URL.revokeObjectURL(url);
  toast('Downloaded', 'Save this file in a safe place', 'ok', 2000);
};

 $('btn-proceed-check').onclick = () => {
  hide($('modal-save-number'));
  startVerificationStep();
};

let verifyPositions = [];

function startVerificationStep() {
  verifyPositions = [];
  while(verifyPositions.length < 3) {
    let r = Math.floor(Math.random() * 16) + 1;
    if(!verifyPositions.includes(r)) verifyPositions.push(r);
  }
  verifyPositions.sort((a,b) => a-b);

  const container = $('verify-inputs-container');
  container.innerHTML = '';

  verifyPositions.forEach(pos => {
    const row = document.createElement('div');
    row.className = 'verify-input-row';
    row.innerHTML = `<label>Digit ${pos}:</label><input type="text" maxlength="1" inputmode="numeric" data-pos="${pos}">`;
    container.appendChild(row);
  });

  $('verify-error').textContent = '';
  show($('modal-verify-number'));
}

 $('btn-verify-check').onclick = () => {
  const inputs = $('verify-inputs-container').querySelectorAll('input');
  let isValid = true;

  inputs.forEach(inp => {
    const pos = parseInt(inp.dataset.pos);
    const expectedDigit = pendingAccountData.accountNumber[pos - 1];
    if (inp.value.trim() !== expectedDigit) {
      isValid = false;
    }
  });

  if (isValid) {
    finishSecurityCheck();
  } else {
    $('verify-error').textContent = 'Incorrect digits. Please check your number and try again.';
    inputs.forEach(inp => inp.value = '');
  }
};

function finishSecurityCheck() {
  hide($('modal-verify-number'));
  localStorage.removeItem('taupe_active_chat');
  bootApp(pendingAccountData, true);
  toast('Welcome to taupe', '', 'ok', 5000);
}

document.querySelectorAll('.skip-btn').forEach(btn => {
  btn.onclick = () => {
    hide($('modal-save-number'));
    hide($('modal-verify-number'));
    if (pendingAccountData) {
      localStorage.removeItem('taupe_active_chat');
      bootApp(pendingAccountData, true);
    }
    toast('Welcome to taupe', '', 'ok', 5000);
  };
});

const themeDefaults = {
  bg: '#0f0f0f',
  bg2: '#161616',
  bg3: '#1e1e1e',
  accent: '#4f8ef7',
  text: '#e8e8e8',
  border: '#2a2a2a'
};

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function hsvToRgb(h, s, v) {
  h = ((h % 360) + 360) % 360;
  s = clamp(s, 0, 100) / 100;
  v = clamp(v, 0, 100) / 100;
  const c = v * s;
  const x = c * (1 - Math.abs((h / 60) % 2 - 1));
  const m = v - c;
  let r = 0, g = 0, b = 0;
  if (h < 60) { r = c; g = x; }
  else if (h < 120) { r = x; g = c; }
  else if (h < 180) { g = c; b = x; }
  else if (h < 240) { g = x; b = c; }
  else if (h < 300) { r = x; b = c; }
  else { r = c; b = x; }
  return [Math.round((r + m) * 255), Math.round((g + m) * 255), Math.round((b + m) * 255)];
}

function rgbToHsv(r, g, b) {
  r /= 255; g /= 255; b /= 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const d = max - min;
  let h = 0;
  if (d !== 0) {
    if (max === r) h = 60 * (((g - b) / d) % 6);
    else if (max === g) h = 60 * ((b - r) / d + 2);
    else h = 60 * ((r - g) / d + 4);
  }
  h = (h + 360) % 360;
  return [h, max === 0 ? 0 : (d / max) * 100, max * 100];
}

function rgbToHsl(r, g, b) {
  r /= 255; g /= 255; b /= 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  const d = max - min;
  let h = 0;
  let s = 0;
  if (d !== 0) {
    s = d / (1 - Math.abs(2 * l - 1));
    if (max === r) h = 60 * (((g - b) / d) % 6);
    else if (max === g) h = 60 * ((b - r) / d + 2);
    else h = 60 * ((r - g) / d + 4);
  }
  h = (h + 360) % 360;
  return [h, s * 100, l * 100];
}

function hslToRgb(h, s, l) {
  h = ((h % 360) + 360) % 360;
  s = clamp(s, 0, 100) / 100;
  l = clamp(l, 0, 100) / 100;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs((h / 60) % 2 - 1));
  const m = l - c / 2;
  let r = 0, g = 0, b = 0;
  if (h < 60) { r = c; g = x; }
  else if (h < 120) { r = x; g = c; }
  else if (h < 180) { g = c; b = x; }
  else if (h < 240) { g = x; b = c; }
  else if (h < 300) { r = x; b = c; }
  else { r = c; b = x; }
  return [Math.round((r + m) * 255), Math.round((g + m) * 255), Math.round((b + m) * 255)];
}

function rgbToHex(r, g, b) {
  return '#' + [r, g, b].map(value => clamp(Math.round(value), 0, 255).toString(16).padStart(2, '0')).join('');
}

function hexToRgb(value) {
  const match = String(value || '').trim().match(/^#?([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (!match) return null;
  let hex = match[1];
  if (hex.length === 3) hex = hex.split('').map(char => char + char).join('');
  return [parseInt(hex.slice(0, 2), 16), parseInt(hex.slice(2, 4), 16), parseInt(hex.slice(4, 6), 16)];
}

const colorPresets = [
  '#000000', '#1a1a1a', '#333333', '#666666', '#999999', '#cccccc', '#f2f2f2', '#ffffff',
  '#e63946', '#f77f00', '#fcbf49', '#2a9d8f', '#2ec4b6', '#4f8ef7', '#5e60ce', '#9b5de5',
  '#f15bb5', '#ff8fab', '#00bbf9', '#00f5d4', '#80ed99', '#a7c957', '#d4a373', '#7f5539'
];

const colorState = { key: null, h: 0, s: 0, v: 100, mode: 'hex', picking: false };
let colorWheelDrawn = false;

function drawColorWheel() {
  if (colorWheelDrawn) return;
  const canvas = $('color-wheel');
  if (!canvas) return;
  const size = canvas.width;
  const ctx = canvas.getContext('2d');
  const image = ctx.createImageData(size, size);
  const center = size / 2;
  const radius = center - 1;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = x - center;
      const dy = y - center;
      const distance = Math.sqrt(dx * dx + dy * dy);
      const index = (y * size + x) * 4;
      if (distance > radius) {
        image.data[index + 3] = 0;
        continue;
      }
      const hue = (Math.atan2(dy, dx) * 180 / Math.PI + 360) % 360;
      const saturation = Math.min(1, distance / radius) * 100;
      const [r, g, b] = hsvToRgb(hue, saturation, 100);
      image.data[index] = r;
      image.data[index + 1] = g;
      image.data[index + 2] = b;
      image.data[index + 3] = 255;
    }
  }
  ctx.putImageData(image, 0, 0);
  colorWheelDrawn = true;
}

function currentColorHex() {
  return rgbToHex(...hsvToRgb(colorState.h, colorState.s, colorState.v));
}

function updateColorPickerUI() {
  const hex = currentColorHex();
  const preview = $('color-preview');
  const hexValue = $('color-hex-value');
  if (preview) preview.style.background = hex;
  if (hexValue) hexValue.textContent = hex;
  $('color-brightness').value = String(Math.round(colorState.v));
  $('color-wheel-dim').style.opacity = String((100 - colorState.v) / 100);
  const marker = $('color-wheel-marker');
  if (marker) {
    const angle = colorState.h * Math.PI / 180;
    const radius = (colorState.s / 100) * 48;
    marker.style.left = (50 + Math.cos(angle) * radius) + '%';
    marker.style.top = (50 + Math.sin(angle) * radius) + '%';
    marker.style.background = hex;
  }
}

function setColorFromRgb(r, g, b, refreshFields) {
  const hsv = rgbToHsv(clamp(r, 0, 255), clamp(g, 0, 255), clamp(b, 0, 255));
  colorState.h = hsv[0];
  colorState.s = hsv[1];
  colorState.v = hsv[2];
  updateColorPickerUI();
  if (refreshFields) renderColorFields();
}

function renderColorFields() {
  const container = $('color-fields');
  if (!container) return;
  const [r, g, b] = hsvToRgb(colorState.h, colorState.s, colorState.v);
  if (colorState.mode === 'hex') {
    container.className = 'color-fields single';
    container.innerHTML = `<label>HEX<input id="cf-hex" maxlength="7" value="${rgbToHex(r, g, b)}"></label>`;
    $('cf-hex').oninput = event => {
      const rgb = hexToRgb(event.target.value);
      if (rgb) setColorFromRgb(rgb[0], rgb[1], rgb[2], false);
    };
    return;
  }
  if (colorState.mode === 'rgb') {
    container.className = 'color-fields';
    container.innerHTML = `
      <label>R<input id="cf-r" type="number" min="0" max="255" value="${r}"></label>
      <label>G<input id="cf-g" type="number" min="0" max="255" value="${g}"></label>
      <label>B<input id="cf-b" type="number" min="0" max="255" value="${b}"></label>`;
    const read = () => {
      const rr = parseInt($('cf-r').value, 10);
      const gg = parseInt($('cf-g').value, 10);
      const bb = parseInt($('cf-b').value, 10);
      if ([rr, gg, bb].every(Number.isFinite)) setColorFromRgb(rr, gg, bb, false);
    };
    ['cf-r', 'cf-g', 'cf-b'].forEach(id => { $(id).oninput = read; });
    return;
  }
  if (colorState.mode === 'hsl') {
    const [h, s, l] = rgbToHsl(r, g, b);
    container.className = 'color-fields';
    container.innerHTML = `
      <label>H<input id="cf-h" type="number" min="0" max="360" value="${Math.round(h)}"></label>
      <label>S<input id="cf-s" type="number" min="0" max="100" value="${Math.round(s)}"></label>
      <label>L<input id="cf-l" type="number" min="0" max="100" value="${Math.round(l)}"></label>`;
    const read = () => {
      const hh = parseInt($('cf-h').value, 10);
      const ss = parseInt($('cf-s').value, 10);
      const ll = parseInt($('cf-l').value, 10);
      if ([hh, ss, ll].every(Number.isFinite)) setColorFromRgb(...hslToRgb(hh, ss, ll), false);
    };
    ['cf-h', 'cf-s', 'cf-l'].forEach(id => { $(id).oninput = read; });
    return;
  }
  container.className = 'color-fields';
  container.innerHTML = `
    <label>H<input id="cf-h" type="number" min="0" max="360" value="${Math.round(colorState.h)}"></label>
    <label>S<input id="cf-s" type="number" min="0" max="100" value="${Math.round(colorState.s)}"></label>
    <label>V<input id="cf-v" type="number" min="0" max="100" value="${Math.round(colorState.v)}"></label>`;
  const read = () => {
    const hh = parseInt($('cf-h').value, 10);
    const ss = parseInt($('cf-s').value, 10);
    const vv = parseInt($('cf-v').value, 10);
    if (![hh, ss, vv].every(Number.isFinite)) return;
    colorState.h = ((hh % 360) + 360) % 360;
    colorState.s = clamp(ss, 0, 100);
    colorState.v = clamp(vv, 0, 100);
    updateColorPickerUI();
  };
  ['cf-h', 'cf-s', 'cf-v'].forEach(id => { $(id).oninput = read; });
}

function openColorPicker(key) {
  const custom = JSON.parse(localStorage.getItem('taupe_custom_theme') || '{}');
  const rgb = hexToRgb(custom[key] || themeDefaults[key]);
  colorState.key = key;
  colorState.mode = 'hex';
  colorState.picking = false;
  setColorFromRgb(rgb[0], rgb[1], rgb[2], true);
  document.querySelectorAll('.color-tabs button').forEach(button => {
    button.classList.toggle('active', button.dataset.colorMode === 'hex');
  });
  drawColorWheel();
  show($('modal-color-picker'));
}

function pickColorFromWheel(event) {
  const canvas = $('color-wheel');
  const rect = canvas.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  const center = rect.width / 2;
  const dx = x - center;
  const dy = y - center;
  const distance = Math.sqrt(dx * dx + dy * dy);
  if (distance > center) return;
  colorState.h = (Math.atan2(dy, dx) * 180 / Math.PI + 360) % 360;
  colorState.s = Math.min(100, (distance / center) * 100);
  updateColorPickerUI();
}

function initColorPicker() {
  document.querySelectorAll('.color-row').forEach(row => {
    row.onclick = () => openColorPicker(row.dataset.colorKey);
  });
  const presetContainer = $('color-presets');
  colorPresets.forEach(hex => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'color-preset';
    button.style.background = hex;
    button.title = hex;
    button.onclick = () => {
      const rgb = hexToRgb(hex);
      if (rgb) setColorFromRgb(rgb[0], rgb[1], rgb[2], true);
    };
    presetContainer.appendChild(button);
  });
  const wheel = $('color-wheel');
  wheel.addEventListener('pointerdown', event => {
    colorState.picking = true;
    wheel.setPointerCapture?.(event.pointerId);
    pickColorFromWheel(event);
  });
  wheel.addEventListener('pointermove', event => {
    if (colorState.picking) pickColorFromWheel(event);
  });
  wheel.addEventListener('pointerup', () => {
    colorState.picking = false;
    renderColorFields();
  });
  wheel.addEventListener('pointercancel', () => { colorState.picking = false; });
  $('color-brightness').oninput = event => {
    colorState.v = clamp(parseInt(event.target.value, 10) || 0, 0, 100);
    updateColorPickerUI();
    renderColorFields();
  };
  document.querySelectorAll('.color-tabs button').forEach(button => {
    button.onclick = () => {
      colorState.mode = button.dataset.colorMode;
      document.querySelectorAll('.color-tabs button').forEach(item => item.classList.toggle('active', item === button));
      renderColorFields();
    };
  });
  $('color-cancel').onclick = () => hide($('modal-color-picker'));
  $('color-select').onclick = () => {
    if (!colorState.key) return;
    const custom = JSON.parse(localStorage.getItem('taupe_custom_theme') || '{}');
    custom[colorState.key] = currentColorHex();
    localStorage.setItem('taupe_custom_theme', JSON.stringify(custom));
    applyTheme('custom');
    hide($('modal-color-picker'));
  };
}

function applyTheme(theme) {
  localStorage.setItem('taupe_theme', theme);

  if (theme !== 'custom') {
    document.documentElement.style.cssText = '';
  }

  const custom = JSON.parse(localStorage.getItem('taupe_custom_theme') || '{}');
  if (theme === 'system') {
    const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  } else if (theme === 'custom') {
    document.documentElement.setAttribute('data-theme', 'custom');
    const root = document.documentElement.style;
    root.setProperty('--bg', custom.bg || themeDefaults.bg);
    root.setProperty('--bg2', custom.bg2 || themeDefaults.bg2);
    root.setProperty('--bg3', custom.bg3 || themeDefaults.bg3);
    root.setProperty('--accent', custom.accent || themeDefaults.accent);
    root.setProperty('--text', custom.text || themeDefaults.text);
    root.setProperty('--border', custom.border || themeDefaults.border);
  } else {
    document.documentElement.setAttribute('data-theme', theme);
  }
  document.querySelectorAll('[data-swatch]').forEach(swatch => {
    const key = swatch.dataset.swatch;
    swatch.style.background = custom[key] || themeDefaults[key];
  });

  document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.setTheme === theme);
  });

  $('custom-theme-editor').classList.toggle('hidden', theme !== 'custom');
}

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (localStorage.getItem('taupe_theme') === 'system') applyTheme('system');
});

 $('btn-theme').onclick = () => {
  applyTheme(localStorage.getItem('taupe_theme') || 'dark');
  show($('modal-theme'));
};
 $('theme-close').onclick = () => { hide($('modal-color-picker')); hide($('modal-theme')); };

document.querySelectorAll('.theme-btn').forEach(btn => {
  btn.onclick = () => applyTheme(btn.dataset.setTheme);
});

initColorPicker();
applyTheme(localStorage.getItem('taupe_theme') || 'dark');

let mediaRecorder;
let audioChunks = [];
let recordTimerInterval;
let recordStartTime;
let recordingStream = null;

 $('btn-mic').onclick = async () => {
  try {
    recordingStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(recordingStream);
    audioChunks = [];

    mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
    mediaRecorder.onstop = async () => {
      if (recordingStream) {
        recordingStream.getTracks().forEach(track => track.stop());
        recordingStream = null;
      }
      if (mediaRecorder._send) {
        const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
        await sendVoiceMessage(audioBlob);
      }
    };

    mediaRecorder.start();
    recordStartTime = Date.now();
    updateRecordTimer();

    $('record-ui').classList.remove('hidden');
    requestAnimationFrame(() => $('record-ui').classList.add('active'));

    recordTimerInterval = setInterval(updateRecordTimer, 10);
  } catch (e) {
    toast('Mic Error', 'Cannot access microphone', 'err');
  }
};

function updateRecordTimer() {
  const elapsed = Date.now() - recordStartTime;
  const m = String(Math.floor(elapsed / 60000)).padStart(2, '0');
  const s = String(Math.floor((elapsed % 60000) / 1000)).padStart(2, '0');
  const ms = String(Math.floor((elapsed % 1000) / 10)).padStart(2, '0');
  $('record-timer').textContent = `${m}:${s}.${ms}`;

  if (elapsed >= 120000) stopRecording(true);
}

function stopRecording(send) {
  if (!mediaRecorder || mediaRecorder.state === 'inactive') return;
  clearInterval(recordTimerInterval);
  mediaRecorder._send = send;
  mediaRecorder.stop();

  $('record-ui').classList.remove('active');
}

 $('btn-stop-record').onclick = () => stopRecording(true);
 $('btn-cancel-record').onclick = () => stopRecording(false);

async function sendVoiceMessage(blob) {
  if (!state.activeChatUid) return;
  if (blob.size > maxFileSize) { toast('Too long', 'Recording must be under 25 MB', 'warn'); return; }
  const peerChatNum = await getActivePeerChatNum();
  if (!await ensurePeerTrusted(peerChatNum)) return;
  const peerPub = peerChatNum ? await getPeerKey(peerChatNum, true) : [];
  if (!peerPub.length) { toast('Cannot send', 'Peer encryption keys are unavailable.', 'err'); return; }
  const myDevices = await getMyDevicesKeys();
  const allRecipients = [...peerPub, ...myDevices];

  let fileToUpload;
  try {
    fileToUpload = await encryptFile(blob, state.activeChatUid, state.account.deviceId, allRecipients);
  } catch (e) {
    console.error('[E2E] Voice encryption failed', e);
    toast('Not sent', 'Encryption failed, voice message was not uploaded.', 'err');
    return;
  }
  const finalName = (crypto.randomUUID ? crypto.randomUUID() : String(Date.now())) + '.bin';

  const fd = new FormData();
  fd.append('file', fileToUpload, finalName);

  const rm = toast('Uploading...', 'Voice message', 'info', 0);
  let d;
  try {
    const r = await fetch('/api/upload', { method: 'POST', body: fd, credentials: 'include' });
    d = await readUploadResp(r);
  } catch (err) {
    console.error('[voice upload]', err);
    d = { error: 'Network error' };
  }
  rm();

  if (d.error) { toast('Upload failed', d.error, 'err'); return; }

  state.socket?.emit('msg:send', {
    chatUid: state.activeChatUid,
    content: null,
    fileUrl: d.url,
    fileType: 'audio',
    fileName: d.name,
    burnSeconds: state.burnSeconds || null,
    replyToId: replyTo?.id || null,
  });
  cancelReply();
}

function formatAudioTime(seconds) {
  if (isNaN(seconds) || seconds < 0 || seconds === Infinity) seconds = 0;
  if (seconds < 60) {
    const s = Math.floor(seconds);
    const ms = Math.floor((seconds - s) * 100);
    return `${s}.${String(ms).padStart(2, '0')}`;
  } else {
    const m = Math.floor(seconds / 60);
    const s = Math.floor(seconds % 60);
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }
}

function getAudioPlayerHtml(blobUrl, msg, isMe, metaHtml = '') {
  let bars = '';
  for(let i=0; i<30; i++) {
    bars += `<div class="wave-bar" style="height:4px"></div>`;
  }
  return `
    <div class="msg-audio-player" data-blob="${blobUrl}">
      <div class="audio-controls">
        <button class="audio-play-btn"><i class="fa-solid fa-play"></i></button>
        <div class="audio-waveform">${bars}</div>
      </div>
      <div class="audio-meta">
        <span class="audio-time">0.00</span>
        ${isMe && !msg.is_played ? '<span class="audio-unplayed">•</span>' : ''}
        ${metaHtml}
      </div>
    </div>
  `;
}

async function generateWaveform(blobUrl) {
  try {
    const response = await fetch(blobUrl);
    const arrayBuffer = await response.arrayBuffer();
    const audioContext = new (window.AudioContext || window.webkitAudioContext)();
    const audioBuffer = await audioContext.decodeAudioData(arrayBuffer);
    const channelData = audioBuffer.getChannelData(0);
    const samples = 30;
    const blockSize = Math.floor(channelData.length / samples);
    let heights = [];
    for (let i = 0; i < samples; i++) {
      let sum = 0;
      for (let j = 0; j < blockSize; j++) {
        sum += Math.abs(channelData[i * blockSize + j]);
      }
      const avg = sum / blockSize;
      heights.push(avg);
    }
    const max = Math.max(...heights);
    if (max === 0) return new Array(samples).fill(4);
    return heights.map(h => Math.max(4, Math.round((h / max) * 28)));
  } catch (e) {
    return null;
  }
}

function initAudioPlayer(playerEl, msg, isMe) {
  const url = playerEl.dataset.blob;
  const audio = new Audio(url);
  audio.preload = 'metadata';

  const playBtn = playerEl.querySelector('.audio-play-btn');
  const timeEl = playerEl.querySelector('.audio-time');
  const bars = playerEl.querySelectorAll('.wave-bar');
  const waveform = playerEl.querySelector('.audio-waveform');

  let isPlaying = false;
  let rafId = null;

  generateWaveform(url).then(heights => {
    if (heights) {
      bars.forEach((bar, i) => {
        bar.style.height = heights[i] + 'px';
      });
    } else {
      const seed = msg.id || Math.random();
      bars.forEach((bar, i) => {
        bar.style.height = (Math.floor(Math.abs(Math.sin(seed * (i+1))) * 12) + 4) + 'px';
      });
    }
  });

  const updateTime = () => {
    if (audio.duration) {
      timeEl.textContent = formatAudioTime(audio.currentTime);
      const progress = audio.currentTime / audio.duration;
      const playedBars = Math.floor(progress * bars.length);
      bars.forEach((bar, i) => {
        bar.classList.toggle('played', i < playedBars);
      });
    }
    if (!audio.paused && !audio.ended) {
      rafId = requestAnimationFrame(updateTime);
    }
  };

  audio.addEventListener('loadedmetadata', () => {
    timeEl.textContent = formatAudioTime(audio.duration);
  });

  audio.addEventListener('play', () => {
    isPlaying = true;
    playBtn.innerHTML = '<i class="fa-solid fa-pause"></i>';
    if (!isMe && !msg.is_played) {
      state.socket.emit('msg:played', { msgId: msg.id });
    }
    rafId = requestAnimationFrame(updateTime);
  });

  audio.addEventListener('pause', () => {
    isPlaying = false;
    playBtn.innerHTML = '<i class="fa-solid fa-play"></i>';
    if (rafId) cancelAnimationFrame(rafId);
    updateTime();
  });

  audio.addEventListener('ended', () => {
    isPlaying = false;
    playBtn.innerHTML = '<i class="fa-solid fa-play"></i>';
    if (rafId) cancelAnimationFrame(rafId);
    timeEl.textContent = formatAudioTime(audio.duration);
    bars.forEach(b => b.classList.remove('played'));
  });

  playBtn.onclick = (e) => {
    e.stopPropagation();
    if (isPlaying) {
      audio.pause();
    } else {
      audio.play();
    }
  };

  waveform.onclick = (e) => {
    e.stopPropagation();
    const rect = waveform.getBoundingClientRect();
    const ratio = (e.clientX - rect.left) / rect.width;
    if (audio.duration) {
      audio.currentTime = ratio * audio.duration;
      updateTime();
    }
  };
}

async function startBurnCountdown(msgId, chatUid, burnAt, burnSeconds, payload) {
  if (state.activeBurnTimers.has(msgId)) return;

  const getWrap = () => {
    const el = document.querySelector(`[data-msg-id="${msgId}"]`);
    return el?.closest('.msg-wrap') || null;
  };

  const spoilerBtn = document.querySelector(`.msg-spoiler[data-msg-id="${msgId}"]`);
  if (spoilerBtn && payload) {
    let html = '';
    const burnPath = safeUploadPath(payload.filePath);
    if (burnPath) {
      const peerChatNum = await getActivePeerChatNum();
      const peerPub = peerChatNum ? await getPeerKey(peerChatNum) : null;
      const decryptKeys = peerPub ? [...peerPub, ...await getMyDevicesKeys()] : null;
      html = await buildFileHtml({
        id: msgId,
        file_path: burnPath,
        file_type: payload.fileType,
        file_name: payload.fileName
      }, chatUid, decryptKeys, false, '', { enforceReplay: false });
    } else if (payload.content) {
      let text = payload.content;
      if (isEncrypted(text)) {
        const peerChatNum = await getActivePeerChatNum();
        const peerPub = peerChatNum ? await getPeerKey(peerChatNum) : null;
        const decryptKeys = peerPub ? [...peerPub, ...await getMyDevicesKeys()] : null;
        if (decryptKeys) {
          try { text = await decryptMsg(text, chatUid, decryptKeys, { enforceReplay: false }); }
          catch { text = '[decryption failed]'; }
        } else { text = '[encrypted]'; }
      }
      if (typeof text === 'string' && text.includes('gif:')) {
        const gifData = parseGifContent(text);
        if (gifData) {
          const imgTag = `<img class="msg-img msg-gif" src="${esc(gifData.url)}" loading="lazy">`;
          const safeText = esc(gifData.text).replace(/\n/g, '<br>');
          html = `${imgTag}${safeText ? `<br>${safeText}` : ''}`;
        } else {
          html = twParse(esc(text).replace(/\n/g, '<br>'));
        }
      } else {
        html = twParse(esc(text).replace(/\n/g, '<br>'));
      }
    }

    const burnDiv = document.createElement('div');
    burnDiv.className = 'msg-burn-open';
    burnDiv.dataset.msgId = msgId;
    burnDiv.innerHTML = `${html}`;
    spoilerBtn.replaceWith(burnDiv);

    const wrap = getWrap();
    const metaInline = wrap?.querySelector('.msg-meta-inline');
    if (metaInline && !metaInline.querySelector('.burn-countdown')) {
      const timerSpan = document.createElement('span');
      timerSpan.className = 'burn-countdown';
      metaInline.prepend(timerSpan);
    }
  }

  const interval = setInterval(() => {
    const remaining = Math.ceil(burnAt - Date.now() / 1000);
    const wrap = getWrap();
    const countdownEl = wrap?.querySelector('.msg-meta-inline .burn-countdown');
    if (countdownEl) {
      countdownEl.textContent = formatBurnSecs(Math.max(0, remaining));
      countdownEl.classList.toggle('urgent', remaining <= 10);
    }

    if (remaining <= 0) {
      clearInterval(interval);
      state.activeBurnTimers.delete(msgId);
      getWrap()?.remove();
      state.socket?.emit('msg:burn:done', { msgId, chatUid });
    }
  }, 500);

  state.activeBurnTimers.set(msgId, interval);
}

init();