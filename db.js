const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const crypto = require('node:crypto');
const fs = require('node:fs');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'messenger.db');
const raw = new DatabaseSync(DB_PATH);

const db = {
  exec(sql) { raw.exec(sql); },
  pragma(stmt) { raw.exec(`PRAGMA ${stmt}`); },
  prepare(sql) {
    const stmt = raw.prepare(sql);
    return {
      get: (...args) => stmt.get(...args),
      all: (...args) => stmt.all(...args),
      run: (...args) => {
        const info = stmt.run(...args);
        return {
          changes: Number(info.changes),
          lastInsertRowid: Number(info.lastInsertRowid),
        };
      },
    };
  },
};

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    number TEXT UNIQUE NOT NULL,         -- 16-digit login number (private)
    chat_number TEXT UNIQUE NOT NULL,    -- 8-digit public chat number
    username TEXT UNIQUE,
    username_public INTEGER NOT NULL DEFAULT 0,
    avatar_path TEXT,
    public_key TEXT,                     -- ECDH P-256 public key (base64), for E2E
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    device_name TEXT NOT NULL,
    public_key TEXT,
    last_seen INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    target_number TEXT NOT NULL,
    alias TEXT NOT NULL,
    UNIQUE(owner_id, target_number)
  );

  CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT UNIQUE NOT NULL,
    initiator_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    peer_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    label_initiator TEXT,
    label_peer TEXT,
    chat_number_initiator INTEGER NOT NULL DEFAULT 1,
    chat_number_peer INTEGER NOT NULL DEFAULT 1,
    burn_mode TEXT NOT NULL DEFAULT 'baf',
    burn_custom_minutes INTEGER,
    burn_confirmed INTEGER NOT NULL DEFAULT 0,
    deleted_by_initiator INTEGER NOT NULL DEFAULT 0,
    deleted_by_peer INTEGER NOT NULL DEFAULT 0,
    last_message_preview TEXT,
    max_messages INTEGER NOT NULL DEFAULT -1,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    sender_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    content TEXT,
    file_path TEXT,
    file_type TEXT,
    file_name TEXT,
    is_read INTEGER NOT NULL DEFAULT 0,
    deleted_for TEXT NOT NULL DEFAULT '',
    burn_seconds INTEGER,        -- per-message burn timer in seconds (null = no burn)
    burn_at INTEGER,             -- unix timestamp when burn should fire (set when receiver opens spoiler)
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS rate_limits (
    ip TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    blocked_until INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
  );
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);
  CREATE INDEX IF NOT EXISTS idx_messages_burn_at ON messages(burn_at) WHERE burn_at IS NOT NULL;
  CREATE INDEX IF NOT EXISTS idx_devices_account_id ON devices(account_id);
  CREATE INDEX IF NOT EXISTS idx_chats_initiator ON chats(initiator_id);
  CREATE INDEX IF NOT EXISTS idx_chats_peer ON chats(peer_id);
`);

try {
  const cols = db.prepare("PRAGMA table_info(accounts)").all();
  if (!cols.some(c => c.name === 'public_key')) {
    db.exec('ALTER TABLE accounts ADD COLUMN public_key TEXT');
  }
} catch (e) {
  console.error('[migration] public_key column check failed:', e.message);
}

try {
  const cols = db.prepare("PRAGMA table_info(devices)").all();
  if (!cols.some(c => c.name === 'public_key')) {
    db.exec('ALTER TABLE devices ADD COLUMN public_key TEXT');
  }
} catch (e) {
  console.error('[migration] devices.public_key column check failed:', e.message);
}

try {
  const cols = db.prepare("PRAGMA table_info(messages)").all();
  if (!cols.some(c => c.name === 'burn_seconds'))
    db.exec('ALTER TABLE messages ADD COLUMN burn_seconds INTEGER');
  if (!cols.some(c => c.name === 'burn_at'))
    db.exec('ALTER TABLE messages ADD COLUMN burn_at INTEGER');
} catch (e) {
  console.error('[migration] burn columns check failed:', e.message);
}

try {
  const cols = db.prepare("PRAGMA table_info(chats)").all();
  if (!cols.some(c => c.name === 'max_messages'))
    db.exec('ALTER TABLE chats ADD COLUMN max_messages INTEGER NOT NULL DEFAULT -1');
} catch (e) {
  console.error('[migration] max_messages column check failed:', e.message);
}

function generateNumber(len) {
  let n = '';
  for (let i = 0; i < len; i++) n += crypto.randomInt(0, 10);
  return n;
}

function createAccount() {
  const insert = db.prepare('INSERT INTO accounts (number, chat_number) VALUES (?, ?)');
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const number = generateNumber(16);
      const chatNumber = generateNumber(8);
      const r = insert.run(number, chatNumber);
      return { id: r.lastInsertRowid, number, chat_number: chatNumber };
    } catch (e) {
      if (!e.message.includes('UNIQUE')) throw e;
      }
  }
  throw new Error('Failed to generate unique numbers');
}

function getAccountByNumber(number) {
  return db.prepare('SELECT * FROM accounts WHERE number=?').get(number);
}
function getAccountByChatNumber(chatNumber) {
  return db.prepare('SELECT * FROM accounts WHERE chat_number=?').get(chatNumber);
}
function getAccountByUsername(username) {
  return db.prepare('SELECT * FROM accounts WHERE LOWER(username)=LOWER(?) AND username_public=1').get(username);
}
function getAccountById(id) {
  return db.prepare('SELECT * FROM accounts WHERE id=?').get(id);
}
function setUsername(accountId, username, isPublic) {
  db.prepare('UPDATE accounts SET username=?,username_public=? WHERE id=?').run(username||null, isPublic?1:0, accountId);
}
function setAvatar(accountId, path) {
  db.prepare('UPDATE accounts SET avatar_path=? WHERE id=?').run(path, accountId);
}
function deleteAccount(accountId) {
  const acct = db.prepare('SELECT avatar_path FROM accounts WHERE id=?').get(accountId);
  const msgs = db.prepare(
    'SELECT m.file_path FROM messages m JOIN chats c ON c.id=m.chat_id WHERE (c.initiator_id=? OR c.peer_id=?) AND m.file_path IS NOT NULL'
  ).all(accountId, accountId);
  const filesToDelete = [];
  if (acct?.avatar_path) filesToDelete.push(path.join(__dirname, acct.avatar_path));
  for (const { file_path } of msgs) filesToDelete.push(path.join(__dirname, file_path));

  db.prepare('DELETE FROM accounts WHERE id=?').run(accountId);

  for (const filePath of filesToDelete) {
    try { fs.unlinkSync(filePath); } catch {}
  }
}

function setAlias(ownerId, targetNumber, alias) {
  db.prepare(`INSERT INTO aliases (owner_id,target_number,alias) VALUES (?,?,?)
    ON CONFLICT(owner_id,target_number) DO UPDATE SET alias=excluded.alias`)
    .run(ownerId, targetNumber, alias);
}
function getAlias(ownerId, targetNumber) {
  return db.prepare('SELECT alias FROM aliases WHERE owner_id=? AND target_number=?').get(ownerId, targetNumber);
}
function getAliases(ownerId) {
  return db.prepare('SELECT * FROM aliases WHERE owner_id=?').all(ownerId);
}
function deleteAlias(ownerId, targetNumber) {
  db.prepare('DELETE FROM aliases WHERE owner_id=? AND target_number=?').run(ownerId, targetNumber);
}

const ADJECTIVES = ['Silver','Blue','Red','Bald','Golden','Dark','Swift','Pretty','Calm','Brave','Jade','Ash','Neon','Iron','Pale','Wild','Soft'];
const NOUNS      = ['Fox','Hawk','Wolf','Bear','Lynx','Owl','Deer','Alice','Crow','Seal','Parrot','Mink','Hare','Puma','Kite','Dove','Crab'];
function randomDeviceName() {
  const a = crypto.randomInt(0, ADJECTIVES.length);
  const n = crypto.randomInt(0, NOUNS.length);
  return ADJECTIVES[a] + ' ' + NOUNS[n];
}
function countDevices(accountId) {
  return db.prepare('SELECT COUNT(*) as c FROM devices WHERE account_id=?').get(accountId).c;
}
function addDevice(accountId, token) {
  const name = randomDeviceName();
  db.prepare('INSERT INTO devices (account_id,token,device_name) VALUES (?,?,?)').run(accountId, token, name);
  return name;
}
function getDeviceByToken(token) {
  return db.prepare('SELECT * FROM devices WHERE token=?').get(token);
}
function getDevices(accountId) {
  return db.prepare('SELECT id,device_name,last_seen,created_at FROM devices WHERE account_id=? ORDER BY last_seen DESC').all(accountId);
}
function kickDevice(deviceId, accountId) {
  db.prepare('DELETE FROM devices WHERE id=? AND account_id=?').run(deviceId, accountId);
}
function kickAllDevicesExcept(accountId, keepToken) {
  db.prepare('DELETE FROM devices WHERE account_id=? AND token!=?').run(accountId, keepToken);
}
function touchDevice(token) {
  db.prepare('UPDATE devices SET last_seen=unixepoch() WHERE token=?').run(token);
}

function randomUid() {
  return crypto.randomBytes(8).toString('hex') + Date.now().toString(36);
}
function getChatsForAccount(accountId) {
  return db.prepare(`
    SELECT c.*,
      a1.chat_number as initiator_chat_number, a1.username as initiator_username, a1.avatar_path as initiator_avatar,
      a2.chat_number as peer_chat_number, a2.username as peer_username, a2.avatar_path as peer_avatar
    FROM chats c
    JOIN accounts a1 ON a1.id=c.initiator_id
    JOIN accounts a2 ON a2.id=c.peer_id
    WHERE (c.initiator_id=? AND c.deleted_by_initiator=0)
       OR (c.peer_id=? AND c.deleted_by_peer=0)
    ORDER BY c.id DESC
  `).all(accountId, accountId);
}
function getChatByUid(uid) {
  return db.prepare('SELECT * FROM chats WHERE uid=?').get(uid);
}
function getChatById(id) {
  return db.prepare('SELECT * FROM chats WHERE id=?').get(id);
}
function createChat(initiatorId, peerId, label, chatNumber, burnMode, burnCustom) {
  const uid = randomUid();
  const existing = db.prepare(`SELECT COUNT(*) as c FROM chats WHERE initiator_id=? AND peer_id=?`).get(initiatorId, peerId).c;
  const peerExisting = db.prepare(`SELECT COUNT(*) as c FROM chats WHERE initiator_id=? AND peer_id=?`).get(peerId, initiatorId).c;
  const r = db.prepare(`
    INSERT INTO chats (uid,initiator_id,peer_id,label_initiator,chat_number_initiator,chat_number_peer,burn_mode,burn_custom_minutes)
    VALUES (?,?,?,?,?,?,?,?)
  `).run(uid, initiatorId, peerId, label||null, chatNumber||(existing+1), peerExisting+1, burnMode||'baf', burnCustom||null);
  return getChatById(r.lastInsertRowid);
}
function setBurnMode(chatId, mode, customMin) {
  db.prepare('UPDATE chats SET burn_mode=?,burn_custom_minutes=?,burn_confirmed=0 WHERE id=?').run(mode, customMin||null, chatId);
}
function confirmBurn(chatId) {
  db.prepare('UPDATE chats SET burn_confirmed=1 WHERE id=?').run(chatId);
}
function setChatLabel(chatId, accountId, label) {
  const c = getChatById(chatId);
  if (!c) return;
  if (c.initiator_id === accountId)
    db.prepare('UPDATE chats SET label_initiator=? WHERE id=?').run(label, chatId);
  else
    db.prepare('UPDATE chats SET label_peer=? WHERE id=?').run(label, chatId);
}
function deleteChat(chatId, accountId, forWhom) {
  const c = getChatById(chatId);
  if (!c) return;
  const isInit = c.initiator_id === accountId;
  if (forWhom === 'both') db.prepare('UPDATE chats SET deleted_by_initiator=1,deleted_by_peer=1 WHERE id=?').run(chatId);
  else if (forWhom === 'self') {
    if (isInit) db.prepare('UPDATE chats SET deleted_by_initiator=1 WHERE id=?').run(chatId);
    else        db.prepare('UPDATE chats SET deleted_by_peer=1 WHERE id=?').run(chatId);
  } else if (forWhom === 'peer') {
    if (isInit) db.prepare('UPDATE chats SET deleted_by_peer=1 WHERE id=?').run(chatId);
    else        db.prepare('UPDATE chats SET deleted_by_initiator=1 WHERE id=?').run(chatId);
  }
}
function updateChatPreview(chatId, preview) {
  db.prepare('UPDATE chats SET last_message_preview=? WHERE id=?').run(preview, chatId);
}

function getMessages(chatId, accountId, { beforeId = null, limit = 200 } = {}) {
  const c = getChatById(chatId);
  const role = c.initiator_id === accountId ? 'initiator' : 'peer';

  let sql = `
    SELECT * FROM messages
    WHERE chat_id=? AND deleted_for != 'both' AND deleted_for NOT LIKE ?
  `;
  const params = [chatId, `%${role}%`];

  if (beforeId) {
    sql += ` AND id < ?`;
    params.push(beforeId);
  }

  sql += ` ORDER BY id DESC LIMIT ?`;
  params.push(limit);

  return db.prepare(sql).all(...params).reverse();
}
function addMessage(chatId, senderId, content, filePath, fileType, fileName, burnSeconds) {
  const r = db.prepare(`
    INSERT INTO messages (chat_id,sender_id,content,file_path,file_type,file_name,burn_seconds)
    VALUES (?,?,?,?,?,?,?)
  `).run(chatId, senderId, content||null, filePath||null, fileType||null, fileName||null, burnSeconds||null);

  const preview = content ? content.slice(0,60) : (fileType==='image'?'📷 Image':'📎 File');
  updateChatPreview(chatId, preview);
  return db.prepare('SELECT * FROM messages WHERE id=?').get(r.lastInsertRowid);
}
function markRead(chatId, readerAccountId) {
  db.prepare('UPDATE messages SET is_read=1 WHERE chat_id=? AND sender_id!=? AND is_read=0').run(chatId, readerAccountId);
}
function deleteMessage(msgId, accountId, forWhom) {
  const m = db.prepare('SELECT * FROM messages WHERE id=?').get(msgId);
  if (!m) return;
  const chat = getChatById(m.chat_id);
  const role = chat.initiator_id === accountId ? 'initiator' : 'peer';
  const peerRole = role === 'initiator' ? 'peer' : 'initiator';
  let cur = m.deleted_for || '';
  if (forWhom === 'self') { if (!cur.includes(role)) cur = cur ? cur+','+role : role; }
  else if (forWhom === 'peer') { if (!cur.includes(peerRole)) cur = cur ? cur+','+peerRole : peerRole; }
  else cur = 'both';
  db.prepare('UPDATE messages SET deleted_for=? WHERE id=?').run(cur, msgId);

  const last = db.prepare(`SELECT content,file_type FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id DESC LIMIT 1`).get(m.chat_id);
  const preview = last ? (last.content ? last.content.slice(0,60) : (last.file_type==='image'?'📷 Image':'📎 File')) : '';
  updateChatPreview(m.chat_id, preview);
}

function applyBurnBaf(chatId) {
  const msgs = db.prepare("SELECT id FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id ASC").all(chatId);
  if (msgs.length > 5) {
    const ids = msgs.slice(0, msgs.length - 5).map(m => m.id);
    db.prepare(`UPDATE messages SET deleted_for='both' WHERE id IN (${ids.map(()=>'?').join(',')})`).run(...ids);

    const last = db.prepare(`SELECT content,file_type FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id DESC LIMIT 1`).get(chatId);
    updateChatPreview(chatId, last ? (last.content||'').slice(0,60) || (last.file_type==='image'?'📷 Image':'📎 File') : '');
    return ids;
  }
  return [];
}
function hardDeleteMessage(msgId) {
  const msg = db.prepare('SELECT file_path FROM messages WHERE id=?').get(msgId);
  if (!msg) return;
  if (msg.file_path) {

    try {
      const fs   = require('fs');
      const path = require('path');
      const abs  = path.join(__dirname, msg.file_path);
      if (fs.existsSync(abs)) fs.unlinkSync(abs);
    } catch (e) {  }
  }
  db.prepare('DELETE FROM messages WHERE id=?').run(msgId);
}

function setBurnAt(msgId, burnAt) {
  db.prepare('UPDATE messages SET burn_at=? WHERE id=?').run(burnAt, msgId);
}

function collectExpiredBurns() {
  const now = Math.floor(Date.now() / 1000);
  const expired = db.prepare(`
    SELECT m.id, c.uid as chat_uid
    FROM messages m JOIN chats c ON c.id = m.chat_id
    WHERE m.burn_at IS NOT NULL AND m.burn_at <= ?
  `).all(now);
  for (const { id } of expired) hardDeleteMessage(id);
  return expired;
}

function applyBurnTimed(chatId, beforeUnix) {
  const msgs = db.prepare("SELECT id FROM messages WHERE chat_id=? AND created_at<? AND deleted_for!='both'").all(chatId, beforeUnix);
  if (msgs.length) {
    const ids = msgs.map(m=>m.id);
    db.prepare(`UPDATE messages SET deleted_for='both' WHERE id IN (${ids.map(()=>'?').join(',')})`).run(...ids);
    const last = db.prepare(`SELECT content,file_type FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id DESC LIMIT 1`).get(chatId);
    updateChatPreview(chatId, last ? (last.content||'').slice(0,60) || (last.file_type==='image'?'📷 Image':'📎 File') : '');
  }
  return msgs.map(m=>m.id);
}

function getRateLimit(ip) {
  return db.prepare('SELECT * FROM rate_limits WHERE ip=?').get(ip);
}
function recordLoginFailDb(ip) {
  const now = Math.floor(Date.now() / 1000);
  const WINDOW = 15 * 60;
  const MAX_ATTEMPTS = 10;

  const row = getRateLimit(ip) || { count: 0, blocked_until: 0, updated_at: 0 };

  let count = (now - row.updated_at > WINDOW) ? 1 : row.count + 1;
  let blockedUntil = row.blocked_until;

  if (row.blocked_until > now) {
    count = row.count;
  } else if (count >= MAX_ATTEMPTS) {
    blockedUntil = now + WINDOW;
  }

  db.prepare(`
    INSERT INTO rate_limits (ip,count,blocked_until,updated_at) VALUES (?,?,?,?)
    ON CONFLICT(ip) DO UPDATE SET count=excluded.count, blocked_until=excluded.blocked_until, updated_at=excluded.updated_at
  `).run(ip, count, blockedUntil, now);
}
function recordLoginSuccessDb(ip) {
  db.prepare('DELETE FROM rate_limits WHERE ip=?').run(ip);
}
function cleanupRateLimits() {
  const now = Math.floor(Date.now() / 1000);
  db.prepare('DELETE FROM rate_limits WHERE blocked_until < ? AND count = 0').run(now);
}

function setMaxMessages(chatId, max) {
  db.prepare('UPDATE chats SET max_messages=? WHERE id=?').run(max, chatId);
}

function enforceMaxMessages(chatId) {
  const chat = db.prepare('SELECT max_messages FROM chats WHERE id=?').get(chatId);
  if (!chat || chat.max_messages < 0) return [];
  const count = db.prepare("SELECT COUNT(*) as c FROM messages WHERE chat_id=? AND deleted_for!='both'").get(chatId).c;
  if (count <= chat.max_messages) return [];
  const excess = count - chat.max_messages;
  const toDelete = db.prepare(
    "SELECT id, file_path FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id ASC LIMIT ?"
  ).all(chatId, excess);
  for (const msg of toDelete) hardDeleteMessage(msg.id);
  return toDelete.map(m => m.id);
}

module.exports = {
  db,
  createAccount, getAccountByNumber, getAccountByChatNumber, getAccountByUsername, getAccountById,
  setUsername, setAvatar, deleteAccount,
  setAlias, getAlias, getAliases, deleteAlias,
  addDevice, countDevices, getDeviceByToken, getDevices,
  kickDevice, kickAllDevicesExcept, touchDevice,
  getChatsForAccount, getChatByUid, getChatById,
  createChat, setBurnMode, confirmBurn, setChatLabel, deleteChat, updateChatPreview,
  getMessages, addMessage, markRead, deleteMessage,
  applyBurnBaf, applyBurnTimed,
  getRateLimit, recordLoginFailDb, recordLoginSuccessDb, cleanupRateLimits,
  hardDeleteMessage, setBurnAt, collectExpiredBurns,
  setMaxMessages, enforceMaxMessages,
};