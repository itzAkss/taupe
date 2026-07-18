import {
  getMyPublicKeyB64, encryptMsg, decryptMsg,
  encryptFile, decryptFile, isEncrypted, cryptoSupported, invalidateSession,
  setMyDeviceId, getSafetyNumber,
} from './crypto.js';

const S = {
  account:    null,
  chats:      [],
  activeChatUid: null,
  socket:     null,
  ignored:    false,
  pendingFile: null,
  burnConfirmPending: null,
  peerKeys:   new Map(),
  pollTimer:  null,
  _pendingPlaintext: null,
  isMobile:   () => window.innerWidth <= 640,
  burnSeconds: null,
  activeBurnTimers: new Map(),
  isLoadingHistory: false,
  hasMoreHistory: true,
};

const $   = id => document.getElementById(id);
const show = el => el?.classList.remove('hidden');
const hide = el => el?.classList.add('hidden');

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
  const icons = { info: 'i', ok: '✓', warn: '!', err: 'x', key: '#', msg: '>' };
  const icon  = icons[type] || 'i';
  const c = $('toast-container');
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  if (onClick) t.style.cursor = 'pointer';
  t.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <div class="toast-body">
      <div class="toast-title">${esc(title)}</div>
      ${msg ? `<div class="toast-msg">${esc(msg)}</div>` : ''}
    </div>
    <button class="toast-close" aria-label="Close">×</button>
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

$('btn-register').onclick = async () => {
  $('auth-error').textContent = '';
  const d = await api('POST', '/api/register');
  if (d.error) { $('auth-error').textContent = d.error; return; }
  localStorage.setItem('lastNumber', d.accountNumber);
  await bootApp(d, true);
  toast('Account created', `Private: ${fmtPrivate(d.accountNumber)}  Chat: ${fmtNum(d.chatNumber)}`, 'key', 0);
};

$('btn-login').onclick = async () => {
  $('auth-error').textContent = '';
  const raw = $('input-number').value.replace(/\D/g, '');
  if (raw.length !== 16) { $('auth-error').textContent = 'Enter your 16-digit private number'; return; }
  const d = await api('POST', '/api/login', { number: raw });
  if (d.error) { $('auth-error').textContent = d.error; return; }
  localStorage.setItem('lastNumber', d.accountNumber);
  await bootApp(d, false);
};

document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    $('tab-' + t.dataset.tab).classList.add('active');
  };
});

const saved = localStorage.getItem('lastNumber');
if (saved) $('input-number').value = fmtPrivate(saved);

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
  S.account = me;
  $('my-number-display').textContent = fmtNum(me.chatNumber || me.accountNumber?.slice(-8));
  switchScreen('main');

  if (me.deviceId) await setMyDeviceId(me.deviceId);

  await uploadMyPublicKey();
  await loadChats();
  connectSocket();
  startPolling();
  
  const savedChat = localStorage.getItem('taupe_active_chat');
  if (savedChat) openChat(savedChat);
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
    const pubKey = await getMyPublicKeyB64();
    const d = await api('POST', '/api/me/pubkey', { publicKey: pubKey });
    if (d.ok) console.log('[E2E] public key uploaded');
  } catch (e) { console.warn('[E2E] key upload failed', e); }
}

async function getPeerKey(peerChatNumber) {
  if (!peerChatNumber) return null;
  if (S.peerKeys.has(peerChatNumber)) return S.peerKeys.get(peerChatNumber);
  try {
    const d = await api('GET', `/api/pubkey/${peerChatNumber}`);

    const keys = d.publicKeys?.length
      ? d.publicKeys.map(dk => ({ deviceId: dk.deviceId, key: dk.key }))
      : d.publicKey ? [{ deviceId: 0, key: d.publicKey }] : null;
    if (keys) {
      S.peerKeys.set(peerChatNumber, keys);
      return keys;
    }
  } catch (e) { console.warn('[E2E] getPeerKey failed', e); }
  return null;
}

async function getActivePeerChatNum() {
  const c = S.chats.find(x => x.uid === S.activeChatUid);
  if (!c) return null;
  const myId = S.account.accountId;
  return c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
}

function startPolling() {
  if (S.pollTimer) clearInterval(S.pollTimer);
  S.pollTimer = setInterval(async () => {
    if (!S.socket?.connected) {

      await loadChats();
      if (S.activeChatUid) await refreshActiveChat();
    }
  }, 3000);
}

async function refreshActiveChat() {
  if (!S.activeChatUid) return;
  const msgs = await api('GET', `/api/chats/${S.activeChatUid}/messages`);
  if (!Array.isArray(msgs)) return;
  const cont = $('messages-container');
  const rendered = new Set([...cont.querySelectorAll('[data-msg-id]')].map(el => el.dataset.msgId));
  const peerChatNum = await getActivePeerChatNum();
  const peerPub = peerChatNum ? await getPeerKey(peerChatNum) : null;
  for (const m of msgs) {
    if (!rendered.has(String(m.id))) {
      await renderMessage(m, peerChatNum, peerPub);
    }
  }

  if (document.visibilityState === 'visible') {
    S.socket?.emit('msg:read', { chatUid: S.activeChatUid });
  }
}

function getToken() {
  return document.cookie.split(';').find(c => c.trim().startsWith('token='))?.split('=')[1];
}

function connectSocket() {
  if (S.socket) S.socket.disconnect();
  S.socket = io({
    auth: { token: getToken() },
    reconnection: true, reconnectionDelay: 1000, reconnectionAttempts: Infinity,
  });

  S.socket.on('connect', () => {
    hideUnstable();
    $('e2e-indicator').title = 'E2E active';
  });
  S.socket.on('disconnect', () => { if (!S.ignored) showUnstable(); });
  S.socket.on('connect_error', () => { if (!S.ignored) showUnstable(); });

  S.socket.on('msg:new', async ({ chatUid, msg, preview }) => {
    updateChatPreviewUI(chatUid, preview);
    if (S.activeChatUid === chatUid) {
      if (document.querySelector(`[data-msg-id="${msg.id}"]`)) return;

      const peerChatNum = await getActivePeerChatNum();
      const peerPub = peerChatNum ? await getPeerKey(peerChatNum) : null;
      const isMyMsg = msg.sender_id == S.account.accountId;

      if (isMyMsg && S._pendingPlaintext && isEncrypted(msg.content)) {
        msg = { ...msg, _plaintext: S._pendingPlaintext };
        S._pendingPlaintext = null;
      }
      await renderMessage(msg, peerChatNum, peerPub);
      scrollBottom();
      if (!isMyMsg) S.socket.emit('msg:read', { chatUid });
    } else {
      const c = S.chats.find(x => x.uid === chatUid);
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

  S.socket.on('msg:burned', ({ chatUid, ids, preview }) => {
    ids.forEach(id => {

      const timer = S.activeBurnTimers.get(id);
      if (timer) { clearInterval(timer); S.activeBurnTimers.delete(id); }
      document.querySelector(`[data-msg-id="${id}"]`)?.closest('.msg-wrap')?.remove();
    });
    if (preview !== undefined) updateChatPreviewUI(chatUid, preview);
  });

  S.socket.on('msg:burn:countdown', async ({ msgId, chatUid, burnAt, burnSeconds, content, filePath, fileType, fileName }) => {
    await startBurnCountdown(msgId, chatUid, burnAt, burnSeconds, { content, filePath, fileType, fileName });
  });

  S.socket.on('msg:read:ack', ({ chatUid, by }) => {

    if (S.activeChatUid === chatUid && by != S.account.accountId) markAllRead();
  });

  S.socket.on('msg:deleted', ({ msgId, forWhom, by, previewInit, previewPeer, initiatorId, peerId }) => {
    const el = document.querySelector(`[data-msg-id="${msgId}"]`);
    const isMe = String(by) === String(S.account.accountId);
    const amInitiator = String(S.account.accountId) === String(initiatorId);
    const myPreview = amInitiator ? previewInit : previewPeer;

    if (el) {
      const shouldHide =
        forWhom === 'both' ||
        (forWhom === 'self' && isMe) ||
        (forWhom === 'peer' && !isMe);
      if (shouldHide) el.closest('.msg-wrap')?.remove();
    }

    if (S.activeChatUid) updateChatPreviewUI(S.activeChatUid, myPreview ?? '');
  });

      S.socket.on('chat:deleted', ({ chatUid, forWhom, by }) => {
    const isMe = String(by) === String(S.account.accountId);
    if (forWhom === 'both' || (forWhom === 'peer' && !isMe)) {
      const chatEl = document.querySelector(`.chat-item[data-uid="${chatUid}"]`);
      
      if (chatEl) {
        chatEl.classList.add('removing');
        setTimeout(() => {
          chatEl.remove();
          S.chats = S.chats.filter(c => c.uid !== chatUid);
          if (S.activeChatUid === chatUid) closeChat();
          if (!isMe) toast('Chat deleted', 'The other party deleted this chat', 'warn');
        }, 200);
      } else {
        S.chats = S.chats.filter(c => c.uid !== chatUid);
        renderChatList();
        if (S.activeChatUid === chatUid) closeChat();
      }
    }
  });

  S.socket.on('chat:new', async ({ chat }) => {

    if (!S.chats.find(c => c.uid === chat.uid)) {

      const myId = S.account.accountId;
      const peerChatNum = chat.initiator_id == myId ? chat.peer_chat_number : chat.initiator_chat_number;
      const aliases = await api('GET', '/api/aliases');
      const aliasMap = {};
      (aliases || []).forEach(a => aliasMap[a.target_number] = a.alias);
      chat.peer_alias = aliasMap[peerChatNum] || null;
      S.chats.unshift(chat);
      renderChatList();

      S.socket.emit('chat:join', { chatUid: chat.uid });
    }
  });

  S.socket.on('chat:burn:confirmed', ({ chatUid }) => {
    const c = S.chats.find(x => x.uid === chatUid);
    if (c) c.burn_confirmed = 1;
    renderChatList();
    toast('Burn confirmed', 'Long retention confirmed by both', 'warn');
  });

  S.socket.on('chat:history:changed', ({ chatUid, max, sysMsg }) => {
    const c = S.chats.find(x => x.uid === chatUid);
    if (c) c.max_messages = max;
    if (S.activeChatUid === chatUid && sysMsg) {
      renderSystemMessage(sysMsg.text);
    }
  });

  S.socket.on('typing:start', ({ chatUid }) => {
    if (S.activeChatUid === chatUid) {
      $('typing-indicator').textContent = 'typing...';
      show($('typing-indicator'));
    }
  });
  S.socket.on('typing:stop', ({ chatUid }) => {
    if (S.activeChatUid === chatUid) hide($('typing-indicator'));
  });
}

function showUnstable() { $('screen-main').classList.add('blurred'); show($('overlay-unstable')); }
function hideUnstable() {
  $('screen-main').classList.remove('blurred');
  hide($('overlay-unstable')); hide($('btn-unstable-indicator'));
  S.ignored = false;
}
$('btn-retry').onclick  = () => S.socket.connect();
$('btn-ignore').onclick = () => {
  S.ignored = true; hide($('overlay-unstable'));
  $('screen-main').classList.remove('blurred'); show($('btn-unstable-indicator'));
};
$('btn-unstable-indicator').onclick = showUnstable;

async function loadChats() {
  const data = await api('GET', '/api/chats');
  if (!Array.isArray(data)) return;
  S.chats = data;
  renderChatList();
}

function renderChatList() {
  const list = $('chat-list');
  list.innerHTML = '';
  if (!S.chats.length) {
    list.innerHTML = '<div class="chat-list-empty">No chats yet</div>';
    return;
  }
  S.chats.forEach(c => {
    const div = document.createElement('div');
    div.className = 'chat-item' +
      (c.uid === S.activeChatUid ? ' active' : '') +
      (c.burn_confirmed ? ' yellow' : '');
    div.dataset.uid = c.uid;
    div.dataset.chatUid = c.uid;
    const myId       = S.account.accountId;
    const peerChatNum = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
    const alias      = c.peer_alias || null;
    const peerUsername = c.initiator_id == myId ? c.peer_username : c.initiator_username;
    const displayName = alias || peerUsername || null;
    const nameHtml   = displayName
      ? `${esc(displayName)} <span class="num-dim">${fmtNum(peerChatNum)}</span>`
      : `<span class="mono">${fmtNum(peerChatNum)}</span>`;
    const avatarSrc  = c.initiator_id == myId ? c.peer_avatar : c.initiator_avatar;
    const preview    = c.last_message_preview || '';

    div.innerHTML = `
      <div class="chat-avatar">${avatarSrc
        ? `<img src="${avatarSrc}" alt="">`
        : `<span>${(alias||peerChatNum).charAt(0).toUpperCase()}</span>`}</div>
      <div class="chat-item-info">
        <div class="chat-item-top">
          <span class="chat-item-name">${nameHtml}</span>
        </div>
        <div class="chat-item-preview" id="preview-${c.uid}">${esc(preview)}</div>
      </div>
            <span class="chat-item-badge ${(c.unread || 0) > 0 ? '' : 'hidden'}" id="badge-${c.uid}">${c.unread || 0}</span>
    `;
    div.onclick = () => openChat(c.uid);
    if (c.uid === S.activeChatUid) div.classList.add('active-chat');
    list.appendChild(div);
  });
}

function chatLabel(c) {
  const myId = S.account.accountId;
  const peerChatNum = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
  if (c.peer_alias) return c.peer_alias;
  const peerUsername = c.initiator_id == myId ? c.peer_username : c.initiator_username;
  if (peerUsername) return peerUsername;
  const lbl = c.initiator_id == myId ? c.label_initiator : c.label_peer;
  return lbl || fmtNum(peerChatNum);
}

function getPeerDisplayName(c) {
  if (!c) return 'Peer';
  const myId = S.account.accountId;
  if (c.initiator_id == myId) {
    return c.peer_alias || c.peer_username || fmtNum(c.peer_chat_number);
  } 
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
  const el = $('preview-' + uid); if (el) el.textContent = preview || '';
  const c  = S.chats.find(x => x.uid === uid);
  if (c) c.last_message_preview = preview;
}

async function openChat(uid) {
  S.activeChatUid = uid;
  localStorage.setItem('taupe_active_chat', uid);
  hide($('empty-state'));
  const c = S.chats.find(x => x.uid === uid);
  if (c) c.unread = 0;
  const cv = $('chat-view');
  cv.classList.remove('hidden'); cv.style.display = 'flex';
  showChatArea();

  const b = $('badge-' + uid); if (b) { hide(b); b.textContent = ''; }

  if (!c) return;
  const myId  = S.account.accountId;
  const peerChatNum = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;

  $('chat-title-display').textContent = chatLabel(c);
  $('chat-title-display').style.cursor = 'pointer';
  $('chat-title-display').onclick = () => {
    navigator.clipboard.writeText(peerChatNum);
    toast('Copied', fmtNum(peerChatNum), 'ok', 1500);
  };

  let peerPub = await getPeerKey(peerChatNum);
  if (!peerPub) {
    await new Promise(r => setTimeout(r, 800));
    peerPub = await getPeerKey(peerChatNum);
  }

  let subtitleText = fmtNum(peerChatNum);
  if (peerPub?.[0]?.key) {
    try {
      const myPub = await getMyPublicKeyB64();
      const safetyNum = await getSafetyNumber(myPub, peerPub[0].key);
      if (safetyNum) subtitleText += ` · ${safetyNum}`;
    } catch {}
  } else {
    toast('No E2E key', 'Peer has not set up encryption yet', 'warn', 5000);
  }

  $('chat-subtitle').textContent = subtitleText;
  $('chat-subtitle').style.cursor = 'pointer';
  $('chat-subtitle').onclick = () => {
    const fpPart = subtitleText.includes('·') ? subtitleText.split('·')[1].trim() : '';
    if (fpPart) {
      navigator.clipboard.writeText(fpPart);
      toast('Fingerprint copied', fpPart, 'ok', 3000);
    } else {
      navigator.clipboard.writeText(peerChatNum);
      toast('Copied', fmtNum(peerChatNum), 'ok', 1500);
    }
  };
  
  updateBurnBtn();
  document.querySelectorAll('.chat-item').forEach(el =>
    el.classList.toggle('active', el.dataset.uid === uid));

  S.peerKeys.delete(peerChatNum);

  const msgs = await api('GET', `/api/chats/${uid}/messages`);
  const cont = $('messages-container');
  cont.innerHTML = '';
  if (Array.isArray(msgs)) {
    for (const m of msgs) {
      try { await renderMessage(m, peerChatNum, peerPub); }
      catch (e) { console.error('[render error]', e); }
    }
  }
  cont.style.scrollBehavior = 'auto';
  scrollBottom();
  cont.style.scrollBehavior = '';
  S.socket?.emit('msg:read', { chatUid: uid });

  S.hasMoreHistory = true;
  S.isLoadingHistory = false;

  cont.onscroll = async () => {
    if (!S.hasMoreHistory || S.isLoadingHistory) return;
    if (cont.scrollTop > 80) return;

    const firstMsg = cont.querySelector('[data-msg-id]');
    if (!firstMsg) return;

    S.isLoadingHistory = true;
    const savedHandler = cont.onscroll;
    cont.onscroll = null;

    const oldScrollHeight = cont.scrollHeight;
    const oldScrollTop    = cont.scrollTop;

    const olderMsgs = await api('GET', `/api/chats/${uid}/messages?beforeId=${firstMsg.dataset.msgId}`);

    if (!Array.isArray(olderMsgs) || olderMsgs.length === 0) {
      S.hasMoreHistory = false;
      S.isLoadingHistory = false;
      cont.onscroll = savedHandler;
      return;
    }

    const scrollPeerNum = await getActivePeerChatNum();
    const scrollPeerPub = scrollPeerNum ? await getPeerKey(scrollPeerNum) : null;

    for (const m of [...olderMsgs].reverse()) {
      m._prepend = true;
      try { await renderMessage(m, scrollPeerNum, scrollPeerPub); }
      catch (e) { console.error('[render error]', e); }
    }

    const newScrollHeight = cont.scrollHeight;
    cont.style.scrollBehavior = 'auto';
    cont.scrollTop = newScrollHeight - oldScrollHeight + oldScrollTop;
    cont.style.scrollBehavior = '';

    S.isLoadingHistory = false;
    setTimeout(() => { cont.onscroll = savedHandler; }, 100);
  };
}

function closeChat() {
  S.activeChatUid = null;
  localStorage.removeItem('taupe_active_chat');
  hide($('chat-view'));
  show($('empty-state'));
  if (S.isMobile()) showSidebar();
  renderChatList();
}

function updateBurnBtn() {
  $('btn-burn-mode').textContent = 'History';
}

function showSidebar() {
  $('sidebar').classList.remove('mob-hidden');
  $('chat-area').classList.add('mob-hidden');
}
function showChatArea() {
  if (S.isMobile()) {
    $('sidebar').classList.add('mob-hidden');
    $('chat-area').classList.remove('mob-hidden');
  }
}
$('back-btn').onclick = () => { S.activeChatUid = null; showSidebar(); hide($('chat-view')); show($('empty-state')); };
window.addEventListener('resize', () => {
  if (!S.isMobile()) {
    $('sidebar').classList.remove('mob-hidden');
    $('chat-area').classList.remove('mob-hidden');
  }
});

async function renderMessage(msg, peerChatNum, peerPubB64) {
  const cont  = $('messages-container');
  if (!cont) return;
  const myId  = S.account.accountId;
  const isMe  = msg.sender_id == myId;
  const prev  = cont.lastElementChild;
  const showLabel = prev?.dataset.sender !== String(msg.sender_id);

  const wrap = document.createElement('div');
  wrap.className = 'msg-wrap ' + (isMe ? 'me' : 'them');
  wrap.dataset.sender = msg.sender_id;

  const decryptKeys    = peerPubB64;
  const decryptChatNum = peerChatNum;

  let inner = '';
  if (showLabel && !isMe && peerChatNum) {
    const c   = S.chats.find(x => x.uid === S.activeChatUid);
    const alias = c?.peer_alias || null;
    const peerUsername = c ? (c.initiator_id == S.account.accountId ? c.peer_username : c.initiator_username) : null;
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
        if (origMsg.file_path) {
          origText = origMsg.file_type === 'image' ? '📷 Photo' : '📎 File';
        } else {
          origText = origMsg.content || '';
          if (origText && origText.startsWith('gif:')) origText = '🎞️ GIF';
        }
        if (origText && isEncrypted(origText) && decryptKeys) {
          try { origText = await decryptMsg(origText, decryptChatNum, decryptKeys); }
          catch { origText = '[decryption failed]'; }
        }
        const c = S.chats.find(x => x.uid === S.activeChatUid);
        let senderName = 'Peer';
        if (String(origMsg.sender_id) === String(S.account.accountId)) {
          senderName = 'You';
        } else {
          senderName = getPeerDisplayName(c);
        }
        
        replyHtml = `<div class="msg-reply"><div class="msg-reply-name">${esc(senderName)}</div><div class="msg-reply-text">${twemoji.parse(esc(origText || '[Media]'))}</div></div>`;
      } else {
        replyHtml = `<div class="msg-reply"><div class="msg-reply-text">[Deleted message]</div></div>`;
      }
    } catch (e) { console.error('[reply fetch]', e); }
  }

  let content = '';
  const hasBurn = !!msg.burn_seconds;
  const isFile  = (msg.file_type === 'image' || msg.file_type === 'file') && msg.file_path;

  if (hasBurn && !msg._spoilerOpened) {

    if (isMe) {

      if ((msg.file_type === 'image' || msg.file_type === 'file') && msg.file_path) {
        content = await buildFileHtml(msg, decryptChatNum, decryptKeys);
            } else if (msg.content) {
              let text = msg._plaintext || msg.content;
              if (!msg._plaintext && isEncrypted(text) && decryptKeys) {
                try { text = await decryptMsg(text, decryptChatNum, decryptKeys); }
                catch { text = '[decryption failed]'; }
              } else if (!msg._plaintext && isEncrypted(text)) {
                text = '[encrypted — no key]';
              }

              if (typeof text === 'string' && text.startsWith('gif:')) {
                const gifUrl = text.slice(4);
                content = `<img class="msg-img msg-gif" src="${esc(gifUrl)}" loading="lazy" data-msg-id="${msg.id}" onload="this.classList.add('loaded')">`;
              } else {
                content = twemoji.parse(esc(text).replace(/\n/g, '<br>'));
              }
            }
      const burnLabel = formatBurnSecs(msg.burn_seconds);
      content = `<div class="msg-burn-open" data-msg-id="${msg.id}">${content}<span class="burn-countdown">${burnLabel}</span></div>`;
    } else {

      const burnLabel = formatBurnSecs(msg.burn_seconds);
      content = `<button class="msg-spoiler" data-msg-id="${msg.id}" data-chat-uid="${S.activeChatUid}" data-burn-secs="${msg.burn_seconds}">Show (${burnLabel})</button>`;
    }
  } else if ((msg.file_type === 'image' || msg.file_type === 'file') && msg.file_path) {
    content = await buildFileHtml(msg, decryptChatNum, decryptKeys);
    } else if (msg.content) {
    let text = msg._plaintext || msg.content;
    if (!msg._plaintext && isEncrypted(text) && decryptKeys) {
      try { text = await decryptMsg(text, decryptChatNum, decryptKeys); }
      catch { text = '[decryption failed]'; }
    } else if (!msg._plaintext && isEncrypted(text)) {
      text = '[encrypted — no key]';
    }
    if (typeof text === 'string' && text.startsWith('gif:')) {
      const gifUrl = text.slice(4);
      content = `<img class="msg-img msg-gif" src="${esc(gifUrl)}" loading="lazy" data-msg-id="${msg.id}" onload="this.classList.add('loaded')">`;
    } else {
      content = twemoji.parse(esc(text).replace(/\n/g, '<br>'));
    }
  }

  const time = new Date(msg.created_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const tick = isMe ? `<span class="read-tick ${msg.is_read ? 'read' : ''}">✓✓</span>` : '';
  const isEncryptedPayload = isEncrypted(msg.content) || (msg.file_path && msg.file_path.endsWith('.bin'));
  const lockIcon = isEncryptedPayload ? '<span class="e2e-lock" title="E2E encrypted">#</span>' : '';

  inner += `
    <div class="msg-bubble ${isMe ? 'me' : 'them'}" data-msg-id="${msg.id}">${replyHtml}${content}</div>
    <div class="msg-meta ${isMe ? 'me' : 'them'}">${lockIcon}<span>${time}</span>${tick}</div>
  `;
  wrap.innerHTML = inner;

  const replyDiv = wrap.querySelector('.msg-reply');
  if (replyDiv && msg.reply_to_id) {
    replyDiv.style.cursor = 'pointer';
    replyDiv.addEventListener('click', (e) => {
      e.stopPropagation();
      scrollToMessage(msg.reply_to_id);
    });
  }

  wrap.querySelector('.msg-sender-label')?.addEventListener('click', () => {
    navigator.clipboard.writeText(peerChatNum);
    toast('Copied', fmtNum(peerChatNum), 'ok', 1200);
  });

  const bubble = wrap.querySelector('.msg-bubble');
  bubble.addEventListener('contextmenu', e => { e.preventDefault(); showMsgCtx(e, msg.id, isMe); });
  let pressTimer;
  bubble.addEventListener('touchstart', e => { pressTimer = setTimeout(() => showMsgCtx(e.touches[0], msg.id, isMe), 500); }, { passive: true });
  bubble.addEventListener('touchend', () => clearTimeout(pressTimer));

  const spoiler = wrap.querySelector('.msg-spoiler');
  if (spoiler) {
    spoiler.addEventListener('click', () => {
      S.socket?.emit('msg:spoiler:open', { msgId: msg.id, chatUid: S.activeChatUid });

      spoiler.innerHTML = '<span style="opacity:.5;font-size:12px">Opening…</span>';
    });
  }

  if (msg.burn_at && !isMe) {
    const remaining = msg.burn_at - Math.floor(Date.now() / 1000);
    if (remaining > 0) {

      setTimeout(() => S.socket?.emit('msg:spoiler:open', { msgId: msg.id, chatUid: S.activeChatUid }), 100);
    } else {
      S.socket?.emit('msg:burn:done', { msgId: msg.id, chatUid: S.activeChatUid });
    }
  }

  if (msg._prepend) {
    cont.prepend(wrap);
  } else {
    cont.appendChild(wrap);
  }

  const allWraps = [...cont.querySelectorAll('.msg-wrap')];
  const idx = allWraps.indexOf(wrap);
  const prevWrap = allWraps[idx - 1];
  const GROUP_WINDOW = 120;

  if (prevWrap && prevWrap.dataset.sender === String(msg.sender_id)) {
    const prevTime = parseInt(prevWrap.dataset.ts || '0');
    const curTime  = parseInt(wrap.dataset.ts || '0');
    if (curTime - prevTime <= GROUP_WINDOW) {
      wrap.classList.add('same-sender');
      prevWrap.classList.remove('grouped-last');
    }
  }
  wrap.classList.add('grouped-last');
  wrap.dataset.ts = msg.created_at || Math.floor(Date.now() / 1000);
}

async function buildFileHtml(msg, decryptChatNum, decryptKeys) {
  if (!msg.file_path) return '';
  const isEncryptedFile = msg.file_path.endsWith('.bin');

  let isImageType = msg.file_type === 'image';
  if (isEncryptedFile && !isImageType && msg.file_name) {
    const baseName = msg.file_name.replace(/\.bin$/, '').toLowerCase();
    if (/\.(png|jpe?g|gif|webp|bmp|svg)$/.test(baseName)) {
      isImageType = true;
    }
  }

  if (isEncryptedFile) {
    if (!decryptKeys) return `<span style="color:var(--warn)">[encrypted file]</span>`;
    try {
      const resp = await fetch(msg.file_path, { credentials: 'include' });
      const encBlob = await resp.blob();
      const decBlob = await decryptFile(encBlob, decryptChatNum, decryptKeys);
      const blobUrl = URL.createObjectURL(decBlob);
      
      if (isImageType) {
        return `<img class="msg-img" src="${blobUrl}" loading="lazy" data-msg-id="${msg.id}" onload="this.classList.add('loaded'); URL.revokeObjectURL(this.src)">`;
      } else {
        const dlName = (msg.file_name || 'file').replace('.bin', '');
        return `<div class="msg-file">[ <a href="${blobUrl}" download="${esc(dlName)}" target="_blank" rel="noreferrer">${esc(dlName)}</a> ]</div>`;
      }
    } catch (e) {
      return `<span style="color:var(--danger)">[decryption failed]</span>`;
    }
  }
  
  if (isImageType) {
    return `<img class="msg-img" src="${msg.file_path}" loading="lazy" data-msg-id="${msg.id}">`;
  }
  return `<div class="msg-file">[ <a href="${msg.file_path}" target="_blank" rel="noreferrer">${esc(msg.file_name || 'file')}</a> ]</div>`;
}

function markAllRead() { document.querySelectorAll('.read-tick').forEach(t => t.classList.add('read')); }
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

function showMsgCtx(e, msgId, isMe) {
  removeCtx();
  const menu = document.createElement('div');
  menu.className = 'ctx-menu'; menu.id = 'ctx-menu';
  
  const items = isMe
    ? [['Reply', 'reply', false], ['Delete for me', 'self', false], ['Delete for peer', 'peer', false], ['Delete for both', 'both', true]]
    : [['Reply', 'reply', false], ['Delete for me', 'self', false], ['Delete for both', 'both', true]];
    
  items.forEach(([lbl, action, danger]) => {
    const d = document.createElement('div');
    d.className = 'ctx-item' + (danger ? ' danger' : '');
    d.textContent = lbl;
    d.onclick = () => {
      if (action === 'reply') {
        setReplyTo(msgId);
      } else {
        S.socket.emit('msg:delete', { msgId, forWhom: action });
      }
      removeCtx();
    };
    menu.appendChild(d);
  });
  
  const x = Math.min(e.clientX ?? 100, window.innerWidth - 190);
  const y = Math.min(e.clientY ?? 100, window.innerHeight - 130);
  menu.style.left = x + 'px'; menu.style.top = y + 'px';
  document.body.appendChild(menu);
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
  if (!S.activeChatUid) return;
  S.socket?.emit('typing:start', { chatUid: S.activeChatUid });
  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => S.socket?.emit('typing:stop', { chatUid: S.activeChatUid }), 1500);
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
  if (bubble.querySelector('.msg-img')) {
    text = '🎞️ GIF';
  }
  else if (bubble.querySelector('.msg-file')) text = '📎 File';

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
      const c = S.chats.find(x => x.uid === S.activeChatUid);
      senderName = getPeerDisplayName(c);
    }
  }

  replyTo = { id: msgId, text };

  const preview = document.getElementById('reply-preview');
  if (preview) {
    preview.querySelector('.reply-preview-name').textContent = senderName;
    preview.querySelector('.reply-preview-text').textContent = text;
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

async function sendMsg() {
  if (!S.activeChatUid) return;
  if (!S.socket?.connected) { toast('Not connected', 'Waiting...', 'warn'); return; }
  const text = $('msg-input').value.trim();
  const file = S.pendingFile;
  if (!text && !file) return;

  const peerChatNum = await getActivePeerChatNum();
  const peerPub     = peerChatNum ? await getPeerKey(peerChatNum) : null;

  let content = text || null;
  if (content && peerPub) {
    try { content = await encryptMsg(content, peerChatNum, peerPub); }
    catch (e) { console.warn('[E2E] encrypt failed', e); }
  }

  $('msg-input').value = '';
  $('msg-input').style.height = 'auto';
  S.pendingFile = null;
  hide($('file-preview'));
  S.socket.emit('typing:stop', { chatUid: S.activeChatUid });

  S.socket.emit('msg:send', {
    chatUid:     S.activeChatUid,
    content,
    fileUrl:     file?.url  || null,
    fileType:    file?.type || null,
    fileName:    file?.name || null,
    burnSeconds: S.burnSeconds || null,
    replyToId:   replyTo?.id || null,
  });

  if (text) S._pendingPlaintext = text;
  cancelReply();
}

$('file-input').onchange = async e => {
  const file = e.target.files[0]; if (!file) return;
  if (file.type.startsWith('video/')) { toast('No video', 'Video files are not supported', 'warn'); return; }
  const rm = toast('Uploading...', file.name, 'info', 0);
  let fileToUpload = file;
  let finalName = file.name;

  const peerChatNum = await getActivePeerChatNum();
  const peerPub = peerChatNum ? await getPeerKey(peerChatNum) : null;

  if (peerPub) {
    try {
      fileToUpload = await encryptFile(file, peerChatNum, peerPub);
      finalName = file.name + '.bin';
    } catch (e) {
      console.warn('[E2E] File encryption failed', e);
      toast('E2E Error', 'File sent unencrypted', 'warn');
    }
  }

  const fd = new FormData(); 
  fd.append('file', fileToUpload, finalName);
  if (peerPub) fd.append('originalType', file.type);
  const r = await fetch('/api/upload', { method: 'POST', body: fd, credentials: 'include' });
  const d = await r.json(); rm();
  if (d.error) { toast('Upload failed', d.error, 'err'); return; }
  S.pendingFile = d;
  const prev = $('file-preview');
  prev.innerHTML = `${d.type === 'image' ? '[img]' : '[file]'} ${esc(d.name)} <button id="btn-clear-file">x</button>`;
  show(prev);
  $('btn-clear-file').onclick = () => { S.pendingFile = null; hide(prev); };
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
    if (peerNumber.length !== 8) { $('nc-error').textContent = 'Enter 8-digit chat number or @username'; return; }
  }

  const label = $('nc-label').value.trim() || null;

  $('nc-create').disabled = true;
  const d = await api('POST', '/api/chats', { peerNumber, label, burnMode: 'baf', burnCustom: null });
  $('nc-create').disabled = false;

  if (d.error) { $('nc-error').textContent = d.error; return; }
  hide($('modal-new-chat'));
  $('nc-peer-number').value = ''; $('nc-label').value = ''; $('nc-error').textContent = '';

  if (!S.chats.find(c => c.uid === d.uid)) {
    await loadChats();
  }
  openChat(d.uid);
};

$('btn-burn-mode').onclick = async () => {
  if (!S.activeChatUid) return;
  const c = S.chats.find(x => x.uid === S.activeChatUid);
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
  if (isNaN(n) || n < -1) { toast('Invalid', 'Enter a number >= -1', 'warn'); return; }
  S.socket.emit('chat:history', { chatUid: S.activeChatUid, max: n });
  c.max_messages = n;
};

function showBurnConfirmModal(chatUid, mode, customMin) {
  S.burnConfirmPending = { chatUid, mode, customMin };
  $('burn-confirm-text').innerHTML =
    `Peer wants to set burn to <strong>${burnLabel(mode, customMin)}</strong>. Messages will persist a long time. Confirm?`;
  show($('modal-burn-confirm'));
}
$('burn-accept').onclick = () => {
  if (!S.burnConfirmPending) return;
  S.socket.emit('chat:burn:confirm', { chatUid: S.burnConfirmPending.chatUid });
  const c = S.chats.find(x => x.uid === S.burnConfirmPending.chatUid);
  if (c) c.burn_confirmed = 1;
  renderChatList(); hide($('modal-burn-confirm')); S.burnConfirmPending = null;
};
$('burn-deny').onclick = () => { hide($('modal-burn-confirm')); S.burnConfirmPending = null; };

$('btn-chat-menu').onclick = () => show($('modal-chat-menu'));
$('cm-cancel').onclick     = () => hide($('modal-chat-menu'));

$('cm-rename').onclick = async () => {
  hide($('modal-chat-menu'));
  const name = await dialog({ title: 'Rename chat', body: 'New label:', input: true, inputPlaceholder: 'chat1' });
  if (!name) return;
  api('PATCH', `/api/chats/${S.activeChatUid}/label`, { label: name });
  const c = S.chats.find(x => x.uid === S.activeChatUid);
  if (c) { c.label_initiator = name; c.label_peer = name; }
  $('chat-title-display').textContent = name; renderChatList();
};

['self','peer','both'].forEach(fw => {
  $(`cm-delete-${fw}`).onclick = async () => {
    hide($('modal-chat-menu'));
    const ok = await dialog({ title: 'Delete chat', body: `Delete for ${fw === 'both' ? 'everyone' : fw}?`, okText: 'Delete', danger: true });
    if (!ok) return;
    S.socket.emit('chat:delete', { chatUid: S.activeChatUid, forWhom: fw });
    if (fw !== 'peer') { S.chats = S.chats.filter(c => c.uid !== S.activeChatUid); renderChatList(); closeChat(); }
  };
});

$('btn-settings').onclick  = openSettings;
$('settings-close').onclick = () => hide($('modal-settings'));

async function openSettings() {
  const me = await api('GET', '/api/me');
  S.account = { ...S.account, ...me };
  $('settings-chat-number').textContent    = fmtNum(me.chatNumber);
  $('settings-private-number').textContent = fmtPrivate(me.accountNumber);
  $('settings-username').value      = me.username || '';
  $('settings-username-public').checked = !!me.usernamePublic;
  const av = $('my-avatar-preview');
  av.innerHTML = me.avatarPath
    ? `<img src="${me.avatarPath}" style="width:64px;height:64px;border-radius:50%;object-fit:cover" alt="">`
    : '<span style="font-size:24px">?</span>';
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
  show($('modal-settings'));
}

$('settings-chat-number-box').onclick = () => {
  navigator.clipboard.writeText(S.account.chatNumber);
  toast('Copied', 'Chat number copied', 'ok', 1500);
};

let privateRevealed = false;
let privateRevealTimer = null;
$('settings-private-number-box').onclick = () => {
  const span = $('settings-private-number');
  if (!privateRevealed) {
    span.style.filter = 'none';
    privateRevealed = true;
    clearTimeout(privateRevealTimer);
    privateRevealTimer = setTimeout(() => {
      span.style.filter = 'blur(6px)';
      privateRevealed = false;
    }, 10000);
  } else {
    navigator.clipboard.writeText(S.account.accountNumber);
    toast('Copied', 'Keep this private!', 'warn', 3000);
  }
};

$('btn-save-username').onclick = async () => {
  const username = $('settings-username').value.trim();
  const isPublic = $('settings-username-public').checked;
  const d = await api('PATCH', '/api/me/username', { username, isPublic });
  if (d.error) { toast('Error', d.error, 'err'); return; }
  const saved = d.username || username.toLowerCase();
  $('settings-username').value = saved;
  toast('Saved', 'Username updated', 'ok');
  S.account.username = saved; S.account.usernamePublic = isPublic;
};

$('my-avatar-preview').onclick  = () => $('avatar-file-input').click();
$('avatar-file-input').onchange = e => {
  const file = e.target.files[0]; if (!file) return;
  e.target.value = '';
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
    const VSIZE   = 280;
    canvas.width  = VSIZE;
    canvas.height = VSIZE;
    
    const maxDim = Math.max(img.width, img.height);
    const initialScale = VSIZE / maxDim; 

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
  const S2  = 280;
  ctx.clearRect(0, 0, S2, S2);
  const w = img.width * scale, h = img.height * scale;
  ctx.drawImage(img, offsetX + (S2 - w) / 2, offsetY + (S2 - h) / 2, w, h);
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

  const VSIZE = 280;
  const CROP_SIZE = 220;
  const CROP_OFFSET = (VSIZE - CROP_SIZE) / 2;

  const scale = _cropState.scale;
  const offX = _cropState.offsetX;
  const offY = _cropState.offsetY;
  const imgW = _cropState.img.width;
  const imgH = _cropState.img.height;

  const drawX = offX + (VSIZE - imgW * scale) / 2;
  const drawY = offY + (VSIZE - imgH * scale) / 2;

  let cropX = Math.round((CROP_OFFSET - drawX) / scale);
  let cropY = Math.round((CROP_OFFSET - drawY) / scale);
  let cropW = Math.round(CROP_SIZE / scale);
  let cropH = Math.round(CROP_SIZE / scale);

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
    const d = await r.json();
    rm();
    if (d.error) { toast('Error', d.error, 'err'); return; }
    S.account.avatarPath = d.avatarPath;
    $('my-avatar-preview').innerHTML = `<img src="${d.avatarPath}?t=${Date.now()}" style="width:64px;height:64px;border-radius:50%;object-fit:cover" alt="">`;
    toast('Avatar updated', '', 'ok');
  } catch (err) {
    rm();
    toast('Network Error', 'Upload failed', 'err');
  }
  _cropState = null;
};

$('btn-logout').onclick = async () => {
  await api('POST', '/api/logout');
  localStorage.removeItem('lastNumber');
  location.reload();
};
$('btn-kick-all').onclick = async () => { await api('POST', '/api/devices/kick-all'); openSettings(); };
$('btn-delete-account').onclick = async () => {
  const ok = await dialog({ title: 'Delete account', body: 'Permanent. Cannot be undone.', okText: 'Delete', danger: true });
  if (!ok) return;
  await api('DELETE', '/api/account');
  localStorage.removeItem('lastNumber');
  location.reload();
};

$('btn-aliases').onclick  = openAliases;
$('alias-cancel').onclick = () => hide($('modal-aliases'));

async function openAliases() {
  await renderAliasList();
  if (S.activeChatUid) {
    const c = S.chats.find(x => x.uid === S.activeChatUid);
    if (c) {
      const myId = S.account.accountId;
      const peerNum = c.initiator_id == myId ? c.peer_chat_number : c.initiator_chat_number;
      $('alias-number-input').value = fmtNum(peerNum);
    }
  }
  show($('modal-aliases'));
}

async function renderAliasList() {
  const aliases = await api('GET', '/api/aliases');
  const list    = $('alias-list'); list.innerHTML = '';
  (aliases || []).forEach(a => {
    const div = document.createElement('div');
    div.className = 'alias-item';
    div.innerHTML = `<span class="alias-name">${esc(a.alias)}</span><span class="alias-num mono">${fmtNum(a.target_number)}</span><button class="alias-del" data-n="${a.target_number}">x</button>`;
    div.onclick = e => {
      if (e.target.classList.contains('alias-del')) return;
      navigator.clipboard.writeText(a.target_number);
      toast('Copied', `${a.alias} — ${fmtNum(a.target_number)}`, 'ok', 2000);
    };
    div.querySelector('.alias-del').onclick = async e => {
      e.stopPropagation();
      await api('DELETE', `/api/aliases/${a.target_number}`);
      await renderAliasList();
      await loadChats();
    };
    list.appendChild(div);
  });
}

$('alias-save').onclick = async () => {
  const num   = $('alias-number-input').value.replace(/-/g, '').trim();
  const alias = $('alias-name-input').value.trim();
  if (num.length !== 8) { $('alias-error').textContent = 'Enter 8-digit chat number'; return; }
  if (!alias)           { $('alias-error').textContent = 'Enter alias name'; return; }
  const d = await api('PUT', '/api/aliases', { targetNumber: num, alias });
  if (d.error) { $('alias-error').textContent = d.error; return; }
  $('alias-error').textContent = ''; $('alias-name-input').value = '';
  await renderAliasList();
  await loadChats();
  toast('Alias saved', `${alias} → ${fmtNum(num)}`, 'ok');
};

$('alias-number-input').addEventListener('input', e => {
  let v = e.target.value.replace(/\D/g, '').slice(0, 8);
  e.target.value = v.length > 4 ? v.slice(0, 4) + '-' + v.slice(4) : v;
});

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function fmtNum(n) {
  const s = String(n || '').replace(/\D/g, '');
  return s.length === 8 ? s.slice(0,4)+'-'+s.slice(4) : s;
}
function fmtPrivate(n) {
  const s = String(n || '').replace(/\D/g, '');
  if (s.length !== 16) return s;
  return s.replace(/(\d{4})(?=\d)/g, '$1-');
}

const BURN_STEPS = [5, 10, 30, 60, 300, 600, 1800, 3600];
const MIN_FILE_BURN = 60;

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
    S.burnSeconds = secs;

    document.querySelectorAll('.burn-pill').forEach(p => {
      p.classList.toggle('selected',
        secs !== null && (
          (p.dataset.secs === 'custom' && !BURN_STEPS.includes(secs)) ||
          parseInt(p.dataset.secs) === secs
        )
      );
    });

    if (secs) {
      btn.textContent = `${formatBurnSecs(secs)}`;
      btn.classList.add('active');
      localStorage.setItem('taupe_burn_secs', secs);
    } else {
      btn.textContent = 'ⴵ';
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

let EMOJIS = [];
let allEmojisData = {};
const egPanel = $('emoji-gif-panel');
const egSearch = $('eg-search-input');
const emojiGrid = $('eg-emoji-grid');
const gifGrid = $('eg-gif-grid');

async function loadEmojis() {
  try {
    const enRes = await fetch('https://raw.githubusercontent.com/muan/emojilib/master/dist/emoji-en-US.json');
    const enData = await enRes.json();
    
    let ruData = {};
    try {
      const ruRes = await fetch('https://raw.githubusercontent.com/emoji-gen/emoji-short-ru/master/emoji.json');
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
    
    EMOJIS = Object.keys(allEmojisData);
    renderEmojis(EMOJIS);
  } catch (e) { 
    console.error('Emoji load failed', e); 
  }
}

function renderEmojis(emojiList = EMOJIS) {
  const grid = document.createElement('div');
  grid.className = 'eg-grid';
  emojiList.forEach(e => {
    const span = document.createElement('span');
    span.className = 'eg-emoji';
    span.innerHTML = twemoji.parse(e);
    span.onclick = () => {
      const inp = $('msg-input');
      inp.value += e;
      inp.focus();
    };
    grid.appendChild(span);
  });
  emojiGrid.innerHTML = '';
  emojiGrid.appendChild(grid);
}

loadEmojis();

 $('btn-emoji-gif').onclick = (e) => {
  e.stopPropagation();
  egPanel.classList.toggle('hidden');
};

document.addEventListener('click', (e) => {
  if (!egPanel.classList.contains('hidden') && !egPanel.contains(e.target) && e.target.id !== 'btn-emoji-gif') {
    egPanel.classList.add('hidden');
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
      if (!gifGrid.innerHTML) loadGifs('hello');
    }
  };
});

let gifSearchTimer;

egSearch.oninput = () => {
  clearTimeout(gifSearchTimer);
  const q = egSearch.value.trim().toLowerCase();
  const activeTab = document.querySelector('.eg-tab.active').dataset.tab;
  
  if (activeTab === 'emoji') {
    const filtered = Object.keys(allEmojisData).filter(emoji => {
      const keywords = allEmojisData[emoji].join(' ');
      return keywords.includes(q);
    });
    renderEmojis(filtered);
    return;
  }

  gifSearchTimer = setTimeout(() => {
    if (q) loadGifs(q);
    else loadGifs('hello');
  }, 400);
};

let currentGifReqId = 0;
async function loadGifs(query) {
  const reqId = ++currentGifReqId;
  gifGrid.innerHTML = '<div style="color:var(--text2);padding:10px;font-size:12px">Loading...</div>';
  
  try {
    const res = await fetch(`/api/gifs?q=${encodeURIComponent(query)}`);
    const data = await res.json();
    
    if (reqId !== currentGifReqId) return; 
    
    if (data.error) throw new Error(data.error);
    
    const grid = document.createElement('div');
    grid.className = 'eg-grid';
    
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
    
    gifGrid.innerHTML = '';
    gifGrid.appendChild(grid);
  } catch (e) {
    if (reqId !== currentGifReqId) return;
    console.error('[GIF]', e);
    gifGrid.innerHTML = '<div style="color:var(--text2);padding:10px;font-size:12px">Failed to load GIFs.</div>';
  }
}

async function sendGif(url) {
  if (!S.activeChatUid) return;
  const peerChatNum = await getActivePeerChatNum();
  const peerPub = peerChatNum ? await getPeerKey(peerChatNum) : null;
  
  let content = 'gif:' + url;
  if (peerPub) {
    try { content = await encryptMsg(content, peerChatNum, peerPub); }
    catch (e) { console.warn('[E2E] encrypt failed', e); }
  }
  
  S.socket.emit('msg:send', {
    chatUid: S.activeChatUid,
    content,
    fileUrl: null,
    fileType: null,
    fileName: null,
    burnSeconds: S.burnSeconds || null,
    replyToId: replyTo?.id || null,
  });
  
  S._pendingPlaintext = 'gif:' + url;
  cancelReply();
}

async function startBurnCountdown(msgId, chatUid, burnAt, burnSeconds, payload) {
  if (S.activeBurnTimers.has(msgId)) return;

  const getWrap = () => {
    const el = document.querySelector(`[data-msg-id="${msgId}"]`);
    return el?.closest('.msg-wrap') || null;
  };

  const spoilerBtn = document.querySelector(`.msg-spoiler[data-msg-id="${msgId}"]`);
  if (spoilerBtn && payload) {
    const wrap = spoilerBtn.closest('.msg-wrap');
    const bubble = spoilerBtn.closest('.msg-bubble');
    if (bubble) {

      let html = '';
      if (payload.fileType === 'image' && payload.filePath) {
        html = `<img class="msg-img" src="${payload.filePath}" loading="lazy">`;
      } else if (payload.fileType === 'file' && payload.filePath) {
        html = `<div class="msg-file">[ <a href="${payload.filePath}" target="_blank" rel="noreferrer">${esc(payload.fileName || 'file')}</a> ]</div>`;
              
      } else if (payload.content) {
        let text = payload.content;
        if (isEncrypted(text)) {
          const peerChatNum = await getActivePeerChatNum();
          const peerPub = peerChatNum ? await getPeerKey(peerChatNum) : null;
          if (peerPub) {
            try { text = await decryptMsg(text, peerChatNum, peerPub); }
            catch { text = '[decryption failed]'; }
          } else { text = '[encrypted — no key]'; }
        }

        if (typeof text === 'string' && text.startsWith('gif:')) {
          const gifUrl = text.slice(4);
          html = `<img class="msg-img msg-gif" src="${esc(gifUrl)}" loading="lazy" onload="this.classList.add('loaded')">`;
        } else {
          html = twemoji.parse(esc(text).replace(/\n/g, '<br>'));
        }
      }
      bubble.innerHTML = `<div class="msg-burn-open" data-msg-id="${msgId}">${html}<span class="burn-countdown"></span></div>`;
    }
  }

  const interval = setInterval(() => {
    const remaining = Math.ceil(burnAt - Date.now() / 1000);
    const el = document.querySelector(`.msg-burn-open[data-msg-id="${msgId}"]`);
    const countdownEl = el?.querySelector('.burn-countdown');
    if (countdownEl) {
      countdownEl.textContent = formatBurnSecs(Math.max(0, remaining));
      countdownEl.classList.toggle('urgent', remaining <= 10);
    }

    if (remaining <= 0) {
      clearInterval(interval);
      S.activeBurnTimers.delete(msgId);

      getWrap()?.remove();

      S.socket?.emit('msg:burn:done', { msgId, chatUid });
    }
  }, 500);

  S.activeBurnTimers.set(msgId, interval);
}

init();