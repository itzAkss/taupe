const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');

try { require('dotenv').config(); } catch (e) {}

const pepper = process.env.taupe_pepper || '';
if (!pepper || pepper.length < 32) {
  throw new Error('taupe_pepper is required and must be at least 32 characters');
}

const uploadDir = path.resolve(process.env.upload_dir || path.join(__dirname, 'uploads'));
const dbPath = process.env.db_path || path.join(__dirname, 'messenger.db');
const raw = new DatabaseSync(dbPath);

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
db.pragma('secure_delete = ON');
db.pragma('wal_autocheckpoint = 256');

db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    number TEXT UNIQUE NOT NULL,
    number_lookup TEXT,
    number_hash TEXT,
    number_salt TEXT,
    chat_number TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE,
    username_public INTEGER NOT NULL DEFAULT 0,
    avatar_path TEXT,
    identity_key TEXT,
    gif_enabled INTEGER NOT NULL DEFAULT 0,
    last_seen INTEGER,
    show_presence INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    token_hash TEXT,
    device_name TEXT NOT NULL,
    public_key TEXT,
    identity_key TEXT,
    key_sig TEXT,
    key_approved INTEGER NOT NULL DEFAULT 0,
    approved_by INTEGER,
    approved_at INTEGER,
    push_endpoint TEXT,
    push_provider TEXT,
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

  CREATE TABLE IF NOT EXISTS blocks (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    blocked_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (account_id, blocked_id)
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
    status TEXT NOT NULL DEFAULT 'accepted',
    requested_by INTEGER,
    accepted_at INTEGER,
    burn_mode TEXT NOT NULL DEFAULT 'baf',
    burn_custom_minutes INTEGER,
    burn_confirmed INTEGER NOT NULL DEFAULT 0,
    pending_burn_mode TEXT,
    pending_burn_custom INTEGER,
    pending_burn_by INTEGER,
    pending_max_messages INTEGER,
    pending_max_by INTEGER,
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
    burn_seconds INTEGER,
    burn_at INTEGER,
    reply_to_id INTEGER,
    is_played INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    path TEXT UNIQUE NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    message_id INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    blocked_until INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS reactions (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    emoji TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (message_id, account_id, emoji)
  );

  CREATE TABLE IF NOT EXISTS system_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    status TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    read_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS key_sync_inbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    request_id INTEGER,
    from_public_key TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_sysmsg_acct ON system_messages(account_id, id);
  CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);
  CREATE INDEX IF NOT EXISTS idx_messages_burn_at ON messages(burn_at) WHERE burn_at IS NOT NULL;
  CREATE INDEX IF NOT EXISTS idx_devices_account_id ON devices(account_id);
  CREATE INDEX IF NOT EXISTS idx_chats_initiator ON chats(initiator_id);
  CREATE INDEX IF NOT EXISTS idx_chats_peer ON chats(peer_id);
  CREATE INDEX IF NOT EXISTS idx_uploads_account ON uploads(account_id);
  CREATE INDEX IF NOT EXISTS idx_uploads_message ON uploads(message_id);
`);

function tableColumns(table) {
  try { return db.prepare(`PRAGMA table_info(${table})`).all(); } catch (e) { return []; }
}

function addColumn(table, name, definition) {
  const cols = tableColumns(table);
  if (!cols.some(c => c.name === name)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
  }
}

addColumn('accounts', 'number_lookup', 'TEXT');
addColumn('accounts', 'number_hash', 'TEXT');
addColumn('accounts', 'number_salt', 'TEXT');
addColumn('accounts', 'identity_key', 'TEXT');
addColumn('accounts', 'gif_enabled', 'INTEGER NOT NULL DEFAULT 0');
addColumn('accounts', 'last_seen', 'INTEGER');
addColumn('accounts', 'show_presence', 'INTEGER NOT NULL DEFAULT 0');
addColumn('devices', 'token_hash', 'TEXT');
addColumn('devices', 'identity_key', 'TEXT');
addColumn('devices', 'key_sig', 'TEXT');
addColumn('devices', 'key_approved', 'INTEGER NOT NULL DEFAULT 0');
addColumn('devices', 'approved_by', 'INTEGER');
addColumn('devices', 'approved_at', 'INTEGER');
addColumn('devices', 'push_endpoint', 'TEXT');
addColumn('devices', 'push_provider', 'TEXT');
addColumn('chats', 'status', "TEXT NOT NULL DEFAULT 'accepted'");
addColumn('chats', 'requested_by', 'INTEGER');
addColumn('chats', 'accepted_at', 'INTEGER');
addColumn('chats', 'pending_burn_mode', 'TEXT');
addColumn('chats', 'pending_burn_custom', 'INTEGER');
addColumn('chats', 'pending_burn_by', 'INTEGER');
addColumn('chats', 'pending_max_messages', 'INTEGER');
addColumn('chats', 'pending_max_by', 'INTEGER');
addColumn('chats', 'max_messages', 'INTEGER NOT NULL DEFAULT -1');
addColumn('messages', 'burn_seconds', 'INTEGER');
addColumn('messages', 'burn_at', 'INTEGER');
addColumn('messages', 'reply_to_id', 'INTEGER');
addColumn('messages', 'is_played', 'INTEGER NOT NULL DEFAULT 0');
addColumn('key_sync_inbox', 'request_id', 'INTEGER');

try {
  const rateCols = tableColumns('rate_limits');
  if (rateCols.some(c => c.name === 'ip') && !rateCols.some(c => c.name === 'key')) {
    db.exec('ALTER TABLE rate_limits RENAME COLUMN ip TO key');
  }
} catch (e) {
  console.error('[migration] rate_limits key rename failed:', e.message);
}

try {
  const cols = tableColumns('accounts');
  if (cols.some(c => c.name === 'public_key')) {
    db.exec('ALTER TABLE accounts DROP COLUMN public_key');
  }
} catch (e) {
  console.error('[migration] accounts public_key drop failed:', e.message);
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function lookupNumber(number) {
  return crypto.createHmac('sha256', pepper).update(String(number)).digest('hex');
}

function numberHash(number, salt) {
  return crypto.scryptSync(String(number), String(salt) + pepper, 32, {
    N: 16384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  }).toString('hex');
}

function verifyNumberHash(number, salt, expected) {
  if (!salt || !expected) return false;
  const actual = numberHash(number, salt);
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function legacyNumberMatches(number, expected) {
  const variants = [
    sha256Hex(number + pepper),
    sha256Hex(number + 'undefined'),
    sha256Hex(number),
  ];
  return variants.some(v => {
    const a = Buffer.from(v, 'hex');
    const b = Buffer.from(String(expected), 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
}

function migrateAccountRow(acct, number) {
  const salt = crypto.randomBytes(16).toString('hex');
  const lookup = lookupNumber(number);
  const hash = numberHash(number, salt);
  db.prepare('UPDATE accounts SET number=?, number_lookup=?, number_hash=?, number_salt=? WHERE id=?')
    .run(lookup, lookup, hash, salt, acct.id);
}

try {
  const rows = db.prepare("SELECT id, number, number_lookup, number_hash, number_salt FROM accounts").all();
  for (const row of rows) {
    if (!row.number_lookup) {
      db.prepare('UPDATE accounts SET number_lookup=?, number_hash=?, number_salt=? WHERE id=?')
        .run(row.number, row.number_hash || row.number, row.number_salt || '', row.id);
    }
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_number_lookup ON accounts(number_lookup)');
} catch (e) {
  console.error('[migration] account lookup backfill failed:', e.message);
}

try {
  const rows = db.prepare("SELECT id, token, token_hash FROM devices").all();
  for (const row of rows) {
    if (!row.token_hash && row.token) {
      const hash = sha256Hex(row.token);
      db.prepare('UPDATE devices SET token_hash=?, token=? WHERE id=?').run(hash, hash, row.id);
    }
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash)');
} catch (e) {
  console.error('[migration] device token hash failed:', e.message);
}

function generateNumber(len) {
  let n = '';
  for (let i = 0; i < len; i++) n += crypto.randomInt(0, 10);
  return n;
}

function createAccount() {
  const insert = db.prepare(`
    INSERT INTO accounts (number, number_lookup, number_hash, number_salt, chat_number)
    VALUES (?, ?, ?, ?, ?)
  `);
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const rawNumber = generateNumber(16);
      const rawChatNumber = generateNumber(10);
      const lookup = lookupNumber(rawNumber);
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = numberHash(rawNumber, salt);
      const r = insert.run(lookup, lookup, hash, salt, rawChatNumber);
      return { id: r.lastInsertRowid, number: rawNumber, chat_number: rawChatNumber };
    } catch (e) {
      if (!String(e.message).includes('UNIQUE')) throw e;
    }
  }
  throw new Error('Failed to generate numbers');
}

function getAccountByNumber(rawNumber) {
  const clean = String(rawNumber || '').replace(/\D/g, '');
  if (!clean) return null;
  const lookup = lookupNumber(clean);
  let acct = db.prepare('SELECT * FROM accounts WHERE number_lookup=?').get(lookup);
  if (!acct) {
    acct = db.prepare('SELECT * FROM accounts WHERE number=?').get(lookup);
  }
  if (!acct) {
    const legacyLookup = sha256Hex(clean + pepper);
    acct = db.prepare('SELECT * FROM accounts WHERE number=? OR number_lookup=?').get(legacyLookup, legacyLookup);
  }
  if (!acct) return null;
  if (!acct.number_salt) {
    if (!legacyNumberMatches(clean, acct.number_hash || acct.number)) return null;
    migrateAccountRow(acct, clean);
    return db.prepare('SELECT * FROM accounts WHERE id=?').get(acct.id);
  }
  if (!verifyNumberHash(clean, acct.number_salt, acct.number_hash)) return null;
  return acct;
}

function getAccountByChatNumber(chatNumber) {
  return db.prepare('SELECT * FROM accounts WHERE chat_number=?').get(String(chatNumber || '').replace(/\D/g, ''));
}
function getAccountByUsername(username) {
  return db.prepare('SELECT * FROM accounts WHERE LOWER(username)=LOWER(?) AND username_public=1').get(username);
}
function getAccountById(id) {
  return db.prepare('SELECT * FROM accounts WHERE id=?').get(id);
}
function setUsername(accountId, username, isPublic) {
  db.prepare('UPDATE accounts SET username=?,username_public=? WHERE id=?').run(username || null, isPublic ? 1 : 0, accountId);
}
function setAvatar(accountId, filePath) {
  db.prepare('UPDATE accounts SET avatar_path=? WHERE id=?').run(filePath, accountId);
}
function setAccountIdentity(accountId, identityKey) {
  const acct = getAccountById(accountId);
  if (!acct) return false;
  if (acct.identity_key && acct.identity_key !== identityKey) return false;
  db.prepare('UPDATE accounts SET identity_key=? WHERE id=?').run(identityKey, accountId);
  return true;
}
function getAccountIdentity(accountId) {
  return db.prepare('SELECT identity_key FROM accounts WHERE id=?').get(accountId)?.identity_key || null;
}
function setGifEnabled(accountId, enabled) {
  db.prepare('UPDATE accounts SET gif_enabled=? WHERE id=?').run(enabled ? 1 : 0, accountId);
}

function resolveUploadPath(relPath) {
  let p = String(relPath);
  if (p.startsWith('/uploads/')) p = p.slice('/uploads/'.length);
  else p = p.replace(/^\/+/, '');
  return path.resolve(uploadDir, p);
}

function uploadReferencedByOther(filePath, exceptMessageId) {
  const ref = db.prepare('SELECT COUNT(*) AS c FROM messages WHERE file_path=? AND id!=?').get(filePath, exceptMessageId || -1);
  return ref.c > 0;
}

function safeUnlinkUpload(relPath) {
  if (!relPath || typeof relPath !== 'string') return;
  try {
    const resolved = resolveUploadPath(relPath);
    if (resolved !== uploadDir && !resolved.startsWith(uploadDir + path.sep)) return;
    if (fs.existsSync(resolved)) fs.unlinkSync(resolved);
  } catch (e) {}
}

function unlinkUploadIfUnreferenced(relPath, exceptMessageId) {
  if (!relPath) return;
  if (uploadReferencedByOther(relPath, exceptMessageId)) return;
  safeUnlinkUpload(relPath);
  try { db.prepare('DELETE FROM uploads WHERE path=?').run(relPath); } catch (e) {}
}

function deleteAccount(accountId) {
  const acct = db.prepare('SELECT avatar_path FROM accounts WHERE id=?').get(accountId);
  const uploads = db.prepare('SELECT path FROM uploads WHERE account_id=?').all(accountId);
  const files = [];
  if (acct?.avatar_path) files.push(acct.avatar_path);
  for (const u of uploads) files.push(u.path);
  db.prepare('DELETE FROM accounts WHERE id=?').run(accountId);
  for (const filePath of files) {
    if (!uploadReferencedByOther(filePath, -1)) safeUnlinkUpload(filePath);
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

const adjectives = ['Silver','Blue','Red','Bald','Golden','Dark','Swift','Pretty','Calm','Brave','Jade','Ash','Neon','Iron','Pale','Wild','Soft'];
const nouns = ['Fox','Hawk','Wolf','Bear','Lynx','Owl','Deer','Alice','Crow','Seal','Parrot','Mink','Hare','Puma','Kite','Dove','Crab'];
function randomDeviceName() {
  return adjectives[crypto.randomInt(0, adjectives.length)] + ' ' + nouns[crypto.randomInt(0, nouns.length)];
}
function countDevices(accountId) {
  return db.prepare('SELECT COUNT(*) as c FROM devices WHERE account_id=?').get(accountId).c;
}
function addDevice(accountId, token) {
  const name = randomDeviceName();
  const hash = sha256Hex(token);
  const r = db.prepare('INSERT INTO devices (account_id,token,token_hash,device_name) VALUES (?,?,?,?)')
    .run(accountId, hash, hash, name);
  return { id: r.lastInsertRowid, name };
}
function getDeviceByToken(token) {
  if (!token) return null;
  return db.prepare('SELECT * FROM devices WHERE token_hash=?').get(sha256Hex(token));
}
function getDeviceById(id) {
  return db.prepare('SELECT * FROM devices WHERE id=?').get(id);
}
function getDevices(accountId) {
  return db.prepare(`SELECT id,device_name,last_seen,created_at,public_key,identity_key,key_sig,key_approved
    FROM devices WHERE account_id=? ORDER BY last_seen DESC`).all(accountId);
}
function getApprovedDevices(accountId) {
  return db.prepare(`SELECT id,device_name,public_key,identity_key,key_sig
    FROM devices WHERE account_id=? AND key_approved=1 AND public_key IS NOT NULL ORDER BY id`).all(accountId);
}
function setDeviceKey(deviceId, accountId, publicKey, identityKey, keySig) {
  db.prepare('UPDATE devices SET public_key=?, identity_key=?, key_sig=? WHERE id=? AND account_id=?')
    .run(publicKey, identityKey, keySig, deviceId, accountId);
}
function approveDevice(deviceId, accountId, approverDeviceId) {
  db.prepare('UPDATE devices SET key_approved=1, approved_by=?, approved_at=unixepoch() WHERE id=? AND account_id=?')
    .run(approverDeviceId, deviceId, accountId);
}
function kickDevice(deviceId, accountId) {
  db.prepare('DELETE FROM devices WHERE id=? AND account_id=?').run(deviceId, accountId);
}
function kickAllDevicesExcept(accountId, keepToken) {
  const keep = getDeviceByToken(keepToken);
  if (keep) db.prepare('DELETE FROM devices WHERE account_id=? AND id!=?').run(accountId, keep.id);
  else db.prepare('DELETE FROM devices WHERE account_id=?').run(accountId);
}
function touchDevice(token) {
  const device = getDeviceByToken(token);
  if (device) db.prepare('UPDATE devices SET last_seen=unixepoch() WHERE id=?').run(device.id);
}
function touchDeviceById(deviceId) {
  db.prepare('UPDATE devices SET last_seen=unixepoch() WHERE id=?').run(deviceId);
}

function setPushEndpoint(deviceId, accountId, endpoint, provider) {
  db.prepare('UPDATE devices SET push_endpoint=?, push_provider=? WHERE id=? AND account_id=?')
    .run(endpoint || null, provider || null, deviceId, accountId);
}
function getPushableDevices(accountId, excludeDeviceId) {
  return db.prepare(
    'SELECT id, push_endpoint, push_provider FROM devices WHERE account_id=? AND push_endpoint IS NOT NULL AND id != ?'
  ).all(accountId, excludeDeviceId || -1);
}

function isBlocked(accountId, targetId) {
  return !!db.prepare('SELECT 1 AS x FROM blocks WHERE account_id=? AND blocked_id=?').get(accountId, targetId);
}
function blockAccount(accountId, targetId) {
  db.prepare('INSERT OR IGNORE INTO blocks (account_id, blocked_id) VALUES (?,?)').run(accountId, targetId);
}
function unblockAccount(accountId, targetId) {
  db.prepare('DELETE FROM blocks WHERE account_id=? AND blocked_id=?').run(accountId, targetId);
}
function getBlocks(accountId) {
  return db.prepare(`SELECT b.blocked_id, a.chat_number FROM blocks b JOIN accounts a ON a.id=b.blocked_id
    WHERE b.account_id=? ORDER BY b.created_at DESC`).all(accountId);
}

function randomUid() {
  return crypto.randomBytes(8).toString('hex') + Date.now().toString(36);
}
function getChatsForAccount(accountId) {
  return db.prepare(`
    SELECT c.*,
      a1.chat_number as initiator_chat_number, CASE WHEN a1.username_public=1 THEN a1.username ELSE NULL END as initiator_username, a1.avatar_path as initiator_avatar,
      a2.chat_number as peer_chat_number, CASE WHEN a2.username_public=1 THEN a2.username ELSE NULL END as peer_username, a2.avatar_path as peer_avatar,
      (SELECT sender_id FROM messages WHERE chat_id=c.id AND deleted_for!='both' ORDER BY id DESC LIMIT 1) as last_sender_id,
      (SELECT is_read FROM messages WHERE chat_id=c.id AND deleted_for!='both' ORDER BY id DESC LIMIT 1) as last_is_read,
      (SELECT created_at FROM messages WHERE chat_id=c.id AND deleted_for!='both' ORDER BY id DESC LIMIT 1) as last_msg_time
    FROM chats c
    JOIN accounts a1 ON a1.id=c.initiator_id
    JOIN accounts a2 ON a2.id=c.peer_id
    WHERE ((c.initiator_id=? AND c.deleted_by_initiator=0) OR (c.peer_id=? AND c.deleted_by_peer=0))
    ORDER BY c.id DESC
  `).all(accountId, accountId);
}
function getChatByUid(uid) {
  return db.prepare('SELECT * FROM chats WHERE uid=?').get(uid);
}
function getChatById(id) {
  return db.prepare('SELECT * FROM chats WHERE id=?').get(id);
}
function getChatUidBetween(first, second) {
  const row = db.prepare(`
    SELECT uid FROM chats
    WHERE status='accepted' AND ((initiator_id=? AND peer_id=?) OR (initiator_id=? AND peer_id=?))
    LIMIT 1
  `).get(first, second, second, first);
  return row?.uid || null;
}
function createChat(initiatorId, peerId, label, chatNumber, burnMode, burnCustom) {
  const existing = db.prepare(`
    SELECT * FROM chats WHERE (initiator_id=? AND peer_id=?) OR (initiator_id=? AND peer_id=?) LIMIT 1
  `).get(initiatorId, peerId, peerId, initiatorId);
  if (existing) return existing;
  const uid = randomUid();
  const countA = db.prepare('SELECT COUNT(*) as c FROM chats WHERE initiator_id=? AND peer_id=?').get(initiatorId, peerId).c;
  const countB = db.prepare('SELECT COUNT(*) as c FROM chats WHERE initiator_id=? AND peer_id=?').get(peerId, initiatorId).c;
  const r = db.prepare(`
    INSERT INTO chats (uid,initiator_id,peer_id,label_initiator,chat_number_initiator,chat_number_peer,burn_mode,burn_custom_minutes,status,requested_by)
    VALUES (?,?,?,?,?,?,?,?,'pending',?)
  `).run(uid, initiatorId, peerId, label || null, chatNumber || (countA + 1), countB + 1, burnMode || 'baf', burnCustom || null, initiatorId);
  return getChatById(r.lastInsertRowid);
}
function acceptChat(chatId, accountId) {
  const chat = getChatById(chatId);
  if (!chat) return false;
  if (chat.peer_id !== accountId && chat.initiator_id !== accountId) return false;
  db.prepare("UPDATE chats SET status='accepted', accepted_at=unixepoch(), requested_by=NULL WHERE id=?").run(chatId);
  return true;
}
function isChatMember(chat, accountId) {
  return !!chat && (chat.initiator_id === accountId || chat.peer_id === accountId);
}
function setBurnMode(chatId, accountId, mode, customMin) {
  db.prepare(`UPDATE chats SET pending_burn_mode=?, pending_burn_custom=?, pending_burn_by=?, burn_confirmed=0 WHERE id=?`)
    .run(mode, customMin || null, accountId, chatId);
}
function confirmBurn(chatId, accountId) {
  const chat = getChatById(chatId);
  if (!chat || !chat.pending_burn_mode) return false;
  if (chat.pending_burn_by === accountId) return false;
  db.prepare(`UPDATE chats SET burn_mode=?, burn_custom_minutes=?, pending_burn_mode=NULL,
    pending_burn_custom=NULL, pending_burn_by=NULL, burn_confirmed=1 WHERE id=?`)
    .run(chat.pending_burn_mode, chat.pending_burn_custom, chatId);
  return true;
}
function setChatLabel(chatId, accountId, label) {
  const c = getChatById(chatId);
  if (!c) return;
  if (c.initiator_id === accountId) db.prepare('UPDATE chats SET label_initiator=? WHERE id=?').run(label, chatId);
  else db.prepare('UPDATE chats SET label_peer=? WHERE id=?').run(label, chatId);
}
function updateChatPreview(chatId, preview) {
  db.prepare('UPDATE chats SET last_message_preview=? WHERE id=?').run(preview, chatId);
}
function deleteChat(chatId, accountId, forWhom) {
  const c = getChatById(chatId);
  if (!c) return;
  const isInit = c.initiator_id === accountId;
  if (!isInit && c.peer_id !== accountId) return;
  if (forWhom === 'both') {
    hardDeleteChat(chatId);
    return;
  }
  if (isInit) db.prepare('UPDATE chats SET deleted_by_initiator=1 WHERE id=?').run(chatId);
  else db.prepare('UPDATE chats SET deleted_by_peer=1 WHERE id=?').run(chatId);
  const updated = getChatById(chatId);
  if (updated && updated.deleted_by_initiator && updated.deleted_by_peer) hardDeleteChat(chatId);
}
function hardDeleteChat(chatId) {
  const msgs = db.prepare('SELECT id, file_path FROM messages WHERE chat_id=?').all(chatId);
  const paths = msgs.map(m => m.file_path).filter(Boolean);
  db.prepare('DELETE FROM chats WHERE id=?').run(chatId);
  for (const p of paths) unlinkUploadIfUnreferenced(p, -1);
  for (const m of msgs) {
    if (m.file_path) {
      try { db.prepare('DELETE FROM uploads WHERE path=?').run(m.file_path); } catch (e) {}
    }
  }
}

function getMessages(chatId, accountId, { beforeId = null, limit = 200 } = {}) {
  const c = getChatById(chatId);
  if (!c) return [];
  const role = c.initiator_id === accountId ? 'initiator' : 'peer';
  let sql = `SELECT * FROM messages WHERE chat_id=? AND deleted_for!='both' AND deleted_for NOT LIKE ?`;
  const params = [chatId, `%${role}%`];
  if (beforeId) {
    sql += ' AND id < ?';
    params.push(beforeId);
  }
  sql += ' ORDER BY id DESC LIMIT ?';
  params.push(Math.min(Math.max(parseInt(limit) || 200, 1), 500));
  const messages = db.prepare(sql).all(...params).reverse();
  if (messages.length > 0) {
    const ids = messages.map(m => m.id);
    const placeholders = ids.map(() => '?').join(',');
    const reactions = db.prepare(`SELECT message_id, account_id, emoji FROM reactions WHERE message_id IN (${placeholders})`).all(...ids);
    const map = {};
    for (const r of reactions) {
      if (!map[r.message_id]) map[r.message_id] = [];
      map[r.message_id].push({ account_id: r.account_id, emoji: r.emoji });
    }
    return messages.map(m => ({ ...m, reactions: map[m.id] || [] }));
  }
  return messages;
}
function addMessage(chatId, senderId, content, filePath, fileType, fileName, burnSeconds, replyToId, customPreview) {
  const r = db.prepare(`
    INSERT INTO messages (chat_id,sender_id,content,file_path,file_type,file_name,burn_seconds,reply_to_id)
    VALUES (?,?,?,?,?,?,?,?)
  `).run(chatId, senderId, content || null, filePath || null, fileType || null, fileName || null, burnSeconds || null, replyToId || null);
  const preview = customPreview || (burnSeconds ? '[burns after read]' : (content ? '[encrypted]' : (fileType === 'image' ? '[image]' : '[file]')));
  updateChatPreview(chatId, preview);
  if (filePath) {
    try { db.prepare('UPDATE uploads SET message_id=? WHERE path=? AND message_id IS NULL').run(r.lastInsertRowid, filePath); } catch (e) {}
  }
  return db.prepare('SELECT * FROM messages WHERE id=?').get(r.lastInsertRowid);
}
function markRead(chatId, readerAccountId) {
  db.prepare('UPDATE messages SET is_read=1 WHERE chat_id=? AND sender_id!=? AND is_read=0').run(chatId, readerAccountId);
}
function deleteMessage(msgId, accountId, forWhom) {
  const m = db.prepare('SELECT * FROM messages WHERE id=?').get(msgId);
  if (!m) return false;
  const chat = getChatById(m.chat_id);
  if (!chat || (chat.initiator_id !== accountId && chat.peer_id !== accountId)) return false;
  if (forWhom === 'both') {
    if (m.sender_id !== accountId) return false;
    hardDeleteMessage(msgId);
    return true;
  }
  const role = chat.initiator_id === accountId ? 'initiator' : 'peer';
  let cur = m.deleted_for || '';
  if (!cur.includes(role)) cur = cur ? cur + ',' + role : role;
  if (cur.includes('both') || (cur.includes('initiator') && cur.includes('peer'))) {
    hardDeleteMessage(msgId);
  } else {
    db.prepare('UPDATE messages SET deleted_for=? WHERE id=?').run(cur, msgId);
  }
  refreshChatPreview(m.chat_id);
  return true;
}
function refreshChatPreview(chatId) {
  const last = db.prepare(`SELECT content,file_type,burn_seconds FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id DESC LIMIT 1`).get(chatId);
  const preview = last ? (last.burn_seconds ? '[burns after read]' : (last.content ? '[encrypted]' : (last.file_type === 'image' ? '[image]' : '[file]'))) : '';
  updateChatPreview(chatId, preview);
}
function hardDeleteMessage(msgId) {
  const msg = db.prepare('SELECT file_path FROM messages WHERE id=?').get(msgId);
  if (!msg) return;
  db.prepare('DELETE FROM messages WHERE id=?').run(msgId);
  if (msg.file_path) {
    unlinkUploadIfUnreferenced(msg.file_path, msgId);
    try { db.prepare('DELETE FROM uploads WHERE path=?').run(msg.file_path); } catch (e) {}
  }
  try { db.prepare('DELETE FROM uploads WHERE message_id=? AND path NOT IN (SELECT file_path FROM messages WHERE file_path IS NOT NULL)').run(msgId); } catch (e) {}
}
function applyBurnBaf(chatId) {
  const msgs = db.prepare(`SELECT id FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id ASC`).all(chatId);
  if (msgs.length <= 5) return [];
  const ids = msgs.slice(0, msgs.length - 5).map(m => m.id);
  for (const id of ids) hardDeleteMessage(id);
  refreshChatPreview(chatId);
  return ids;
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
  const msgs = db.prepare(`SELECT id FROM messages WHERE chat_id=? AND created_at<? AND deleted_for!='both'`).all(chatId, beforeUnix);
  for (const m of msgs) hardDeleteMessage(m.id);
  if (msgs.length) refreshChatPreview(chatId);
  return msgs.map(m => m.id);
}
function setMaxMessages(chatId, accountId, max) {
  db.prepare('UPDATE chats SET pending_max_messages=?, pending_max_by=? WHERE id=?').run(max, accountId, chatId);
}
function confirmMaxMessages(chatId, accountId) {
  const chat = getChatById(chatId);
  if (!chat || chat.pending_max_messages == null) return false;
  if (chat.pending_max_by === accountId) return false;
  db.prepare('UPDATE chats SET max_messages=?, pending_max_messages=NULL, pending_max_by=NULL WHERE id=?')
    .run(chat.pending_max_messages, chatId);
  return true;
}
function enforceMaxMessages(chatId) {
  const chat = db.prepare('SELECT max_messages FROM chats WHERE id=?').get(chatId);
  if (!chat || chat.max_messages < 0) return [];
  const count = db.prepare(`SELECT COUNT(*) as c FROM messages WHERE chat_id=? AND deleted_for!='both'`).get(chatId).c;
  if (count <= chat.max_messages) return [];
  const excess = count - chat.max_messages;
  const toDelete = db.prepare(`SELECT id FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id ASC LIMIT ?`).all(chatId, excess);
  for (const msg of toDelete) hardDeleteMessage(msg.id);
  refreshChatPreview(chatId);
  return toDelete.map(m => m.id);
}

function getRateLimit(key) {
  return db.prepare('SELECT * FROM rate_limits WHERE key=?').get(key);
}
function recordFailure(key) {
  const now = Math.floor(Date.now() / 1000);
  const windowSec = 15 * 60;
  const maxAttempts = 10;
  const row = getRateLimit(key) || { count: 0, blocked_until: 0, updated_at: 0 };
  let count = (now - row.updated_at > windowSec) ? 1 : row.count + 1;
  let blockedUntil = row.blocked_until;
  if (row.blocked_until > now) count = row.count;
  else if (count >= maxAttempts) blockedUntil = now + windowSec;
  db.prepare(`
    INSERT INTO rate_limits (key,count,blocked_until,updated_at) VALUES (?,?,?,?)
    ON CONFLICT(key) DO UPDATE SET count=excluded.count, blocked_until=excluded.blocked_until, updated_at=excluded.updated_at
  `).run(key, count, blockedUntil, now);
}
function isRateLimited(key) {
  const now = Math.floor(Date.now() / 1000);
  const row = getRateLimit(key);
  return !!row && row.blocked_until > now;
}
function cleanupRateLimits() {
  const cutoff = Math.floor(Date.now() / 1000) - 24 * 3600;
  db.prepare('DELETE FROM rate_limits WHERE updated_at < ?').run(cutoff);
}

function recordUpload(accountId, filePath, size) {
  const r = db.prepare('INSERT INTO uploads (account_id, path, size) VALUES (?,?,?)').run(accountId, filePath, size);
  return r.lastInsertRowid;
}
function getUploadByPath(filePath) {
  return db.prepare('SELECT * FROM uploads WHERE path=?').get(filePath);
}
function attachUpload(filePath, accountId, messageId) {
  const r = db.prepare('UPDATE uploads SET message_id=? WHERE path=? AND account_id=? AND message_id IS NULL')
    .run(messageId, filePath, accountId);
  return r.changes > 0;
}
function getUploadUsageBytes(accountId) {
  const row = db.prepare('SELECT COALESCE(SUM(size),0) AS total FROM uploads WHERE account_id=?').get(accountId);
  return Number(row.total) || 0;
}
function getGlobalUploadUsageBytes() {
  const row = db.prepare('SELECT COALESCE(SUM(size),0) AS total FROM uploads').get();
  return Number(row.total) || 0;
}
function purgeOrphanUploads(maxAgeSeconds) {
  const cutoff = Math.floor(Date.now() / 1000) - maxAgeSeconds;
  const rows = db.prepare('SELECT id, path FROM uploads WHERE message_id IS NULL AND created_at < ?').all(cutoff);
  for (const row of rows) {
    db.prepare('DELETE FROM uploads WHERE id=?').run(row.id);
    if (!uploadReferencedByOther(row.path, -1)) safeUnlinkUpload(row.path);
  }
  return rows.length;
}

const systemTypes = ['device_login', 'key_request', 'key_transfer_done', 'chat_request', 'burn_request', 'history_request'];
function parseSystemRow(r) {
  if (!r) return null;
  let payload = {};
  try { payload = JSON.parse(r.payload); } catch (e) {}
  return { ...r, payload };
}
function addSystemMessage(accountId, type, payload = {}, status = null) {
  if (!systemTypes.includes(type)) return null;
  const info = db.prepare('INSERT INTO system_messages (account_id, type, payload, status) VALUES (?, ?, ?, ?)')
    .run(accountId, type, JSON.stringify(payload), status);
  return parseSystemRow(db.prepare('SELECT * FROM system_messages WHERE id=?').get(info.lastInsertRowid));
}
function getSystemMessage(accountId, id) {
  return parseSystemRow(db.prepare('SELECT * FROM system_messages WHERE id=? AND account_id=?').get(id, accountId));
}
function getSystemMessages(accountId, limit = 200) {
  return db.prepare('SELECT * FROM system_messages WHERE account_id=? ORDER BY id DESC LIMIT ?')
    .all(accountId, limit).map(parseSystemRow);
}
function unreadSystemCount(accountId) {
  return db.prepare('SELECT COUNT(*) AS c FROM system_messages WHERE account_id=? AND read_at IS NULL').get(accountId).c;
}
function markSystemMessagesRead(accountId, id = null) {
  const now = Math.floor(Date.now() / 1000);
  if (id != null) {
    db.prepare('UPDATE system_messages SET read_at=? WHERE account_id=? AND id=? AND read_at IS NULL').run(now, accountId, id);
  } else {
    db.prepare('UPDATE system_messages SET read_at=? WHERE account_id=? AND read_at IS NULL').run(now, accountId);
  }
}
function resolveSystemMessage(accountId, id, status) {
  const row = getSystemMessage(accountId, id);
  if (!row || !['pending', 'approved'].includes(row.status)) return null;
  db.prepare('UPDATE system_messages SET status=? WHERE id=?').run(status, id);
  return { ...row, status };
}
function pendingKeyRequestsFor(accountId) {
  return db.prepare("SELECT * FROM system_messages WHERE account_id=? AND type='key_request' AND status='pending' ORDER BY id ASC")
    .all(accountId).map(parseSystemRow);
}
function completeKeyRequest(accountId, id) {
  const row = getSystemMessage(accountId, id);
  if (!row || row.type !== 'key_request' || !['pending', 'approved'].includes(row.status)) return null;
  db.prepare("UPDATE system_messages SET status='completed' WHERE id=?").run(id);
  return { ...row, status: 'completed' };
}
function expireSystemRequests() {
  const now = Math.floor(Date.now() / 1000);
  const rows = db.prepare("SELECT id, payload FROM system_messages WHERE status='pending' AND type='key_request'").all();
  for (const row of rows) {
    let payload = {};
    try { payload = JSON.parse(row.payload); } catch (e) {}
    const expiresAt = Number(payload.expiresAt) || 0;
    if (expiresAt > 0 && expiresAt <= now) {
      db.prepare("UPDATE system_messages SET status='expired' WHERE id=?").run(row.id);
    }
  }
}

function queueKeySync(deviceId, fromPublicKey, encryptedKey, requestId) {
  db.prepare('INSERT INTO key_sync_inbox (device_id, request_id, from_public_key, encrypted_key) VALUES (?, ?, ?, ?)')
    .run(deviceId, requestId || null, fromPublicKey, encryptedKey);
}
function takeKeySyncInbox(deviceId) {
  const rows = db.prepare('SELECT * FROM key_sync_inbox WHERE device_id=? ORDER BY id').all(deviceId);
  if (rows.length) db.prepare('DELETE FROM key_sync_inbox WHERE device_id=?').run(deviceId);
  return rows;
}

function purgeDeletedRows() {
  const softMessages = db.prepare("SELECT id FROM messages WHERE deleted_for='both'").all();
  for (const m of softMessages) hardDeleteMessage(m.id);
  const deadChats = db.prepare('SELECT id FROM chats WHERE deleted_by_initiator=1 AND deleted_by_peer=1').all();
  for (const c of deadChats) hardDeleteChat(c.id);
}
function checkpoint() {
  try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch (e) {}
}
function vacuum() {
  try { db.exec('VACUUM'); } catch (e) {}
}

module.exports = {
  db,
  createAccount, getAccountByNumber, getAccountByChatNumber, getAccountByUsername, getAccountById,
  setUsername, setAvatar, deleteAccount, setAccountIdentity, getAccountIdentity, setGifEnabled,
  setAlias, getAlias, getAliases, deleteAlias,
  isBlocked, blockAccount, unblockAccount, getBlocks,
  addDevice, countDevices, getDeviceByToken, getDeviceById, getDevices, getApprovedDevices,
  setDeviceKey, approveDevice, kickDevice, kickAllDevicesExcept, touchDevice, touchDeviceById,
  setPushEndpoint, getPushableDevices,
  getChatsForAccount, getChatByUid, getChatById, getChatUidBetween, createChat, acceptChat, isChatMember,
  setBurnMode, confirmBurn, setChatLabel, deleteChat, hardDeleteChat, updateChatPreview,
  getMessages, addMessage, markRead, deleteMessage, refreshChatPreview,
  applyBurnBaf, applyBurnTimed, setBurnAt, collectExpiredBurns, hardDeleteMessage,
  setMaxMessages, confirmMaxMessages, enforceMaxMessages,
  getRateLimit, recordFailure, isRateLimited, cleanupRateLimits,
  recordUpload, getUploadByPath, attachUpload, getUploadUsageBytes, getGlobalUploadUsageBytes,
  purgeOrphanUploads, safeUnlinkUpload, unlinkUploadIfUnreferenced,
  addSystemMessage, getSystemMessage, getSystemMessages, unreadSystemCount,
  markSystemMessagesRead, resolveSystemMessage, pendingKeyRequestsFor,
  completeKeyRequest, expireSystemRequests, queueKeySync, takeKeySyncInbox,
  purgeDeletedRows, checkpoint, vacuum,
};
