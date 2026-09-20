require('dotenv').config();

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const crypto = require('crypto');
const dns   = require('dns').promises;
const net   = require('net');
const express = require('express');
const { Server } = require('socket.io');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const jwt  = require('jsonwebtoken');
const multer = require('multer');
let sharp = null;
try {
  sharp = require('sharp');
} catch (e) {
  console.warn('[taupe] sharp unavailable on this platform, images will be stored without resizing/recompression (no EXIF stripping either). Avatar/file uploads still work.');
}
const selfsigned = require('selfsigned');
const DB = require('./db');

function validateFileMagic(filePath, mimetype) {
  if (!mimetype.startsWith('image/')) return true;
  try {
    const buf = Buffer.alloc(12);
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buf, 0, 12, 0);
    fs.closeSync(fd);
    const isJpg  = buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF;
    const isPng  = buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47;
    const isGif  = buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46;
    const isWebp = buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46;
    return isJpg || isPng || isGif || isWebp;
  } catch (e) {
    return false;
  }
}

const CERT_PATH = path.join(__dirname, 'cert');
if (!fs.existsSync(CERT_PATH + '/key.pem')) {
  fs.mkdirSync(CERT_PATH, { recursive: true });
  const pems = selfsigned.generate([{ name:'commonName', value:'localhost' }], { days:3650, keySize:2048 });
  fs.writeFileSync(CERT_PATH + '/key.pem', pems.private);
  fs.writeFileSync(CERT_PATH + '/cert.pem', pems.cert);
}
const tlsOptions = {
  key:  fs.readFileSync(CERT_PATH + '/key.pem'),
  cert: fs.readFileSync(CERT_PATH + '/cert.pem'),
};

const PORT      = process.env.PORT      || 3443;
const HTTP_PORT = process.env.HTTP_PORT || 3000;
const BIND_HOST = process.env.BIND_HOST || '0.0.0.0';

const SECRET_FILE = process.env.SECRET_FILE || path.join(__dirname, '.jwt_secret');
let JWT_SECRET;
if (fs.existsSync(SECRET_FILE)) {
  JWT_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
} else {
  JWT_SECRET = crypto.randomBytes(64).toString('hex');
  fs.writeFileSync(SECRET_FILE, JWT_SECRET, { mode: 0o600 });
}

const UPLOADS = path.join(__dirname, 'uploads');
const AVATARS = path.join(__dirname, 'uploads', 'avatars');
fs.mkdirSync(UPLOADS, { recursive: true });
fs.mkdirSync(AVATARS, { recursive: true });

function checkLoginRateLimit(ip) {
  const now = Math.floor(Date.now() / 1000);
  const row = DB.getRateLimit(ip);
  if (row && row.blocked_until > now) {
    const remaining = Math.ceil((row.blocked_until - now) / 60);
    return { blocked: true, remaining };
  }
  return { blocked: false };
}
function recordLoginFail(ip) { DB.recordLoginFailDb(ip); }
function recordLoginSuccess(ip) { DB.recordLoginSuccessDb(ip); }

setInterval(() => DB.cleanupRateLimits(), 15 * 60 * 1000);

const app = express();
const publicUrl = process.env.PUBLIC_URL || 'http://localhost:3000';
const cspHost = publicUrl.replace(/^https?:\/\//, '');
const extraScriptHashes = String(process.env.CSP_SCRIPT_HASHES || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", ...extraScriptHashes],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "blob:", "data:"],
      connectSrc: ["'self'", `ws://${cspHost}`, `wss://${cspHost}`, `http://${cspHost}`, `https://${cspHost}`, "blob:", "data:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    }
  }
}));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const ROOT_PUBLIC_FILES = ['index.html', 'style.css', 'client.js', 'crypto.js', 'favicon.png'];
ROOT_PUBLIC_FILES.forEach(name => {
  const abs = path.join(__dirname, name);
  app.get(name === 'index.html' ? '/' : `/${name}`, (req, res, next) => {
    res.sendFile(abs, err => { if (err) next(); });
  });
});

let twemojiPack = null;
function getTwemojiPack() {
  if (!twemojiPack) {
    try {
      twemojiPack = JSON.parse(fs.readFileSync(
        path.join(__dirname, 'public', 'vendor', 'twemoji', 'svg-pack.json'), 'utf8'));
    } catch (e) {
      console.warn('[taupe] twemoji svg-pack.json not found, emoji images disabled');
      twemojiPack = {};
    }
  }
  return twemojiPack;
}
app.get('/vendor/twemoji/svg/:name', (req, res) => {
  const name = req.params.name;
  if (!/^[0-9a-f-]+\.svg$/.test(name)) return res.status(404).end();
  const svg = getTwemojiPack()[name];
  if (!svg) return res.status(404).end();
  res.set('Content-Type', 'image/svg+xml; charset=utf-8');
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'");
  res.send(svg);
});

app.set('trust proxy', process.env.TRUST_PROXY === '1');

const rlBuckets = new Map();
function rateLimit(key, max, windowSec) {
  const now = Math.floor(Date.now() / 1000);
  let b = rlBuckets.get(key);
  if (!b || now - b.start >= windowSec) {
    b = { start: now, count: 0 };
    rlBuckets.set(key, b);
  }
  b.count++;
  return b.count <= max ? null : Math.max(1, b.start + windowSec - now);
}
setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  for (const [k, b] of rlBuckets) {
    if (now - b.start > 3600) rlBuckets.delete(k);
  }
}, 10 * 60 * 1000);

function limitMiddleware(name, max, windowSec) {
  return (req, res, next) => {
    const key = `${name}:${req.ip || req.socket?.remoteAddress || 'unknown'}`;
    const retry = rateLimit(key, max, windowSec);
    if (retry !== null) return res.status(429).json({ error: `Too many requests. Retry in ${retry}s.` });
    next();
  };
}
const registerLimiter   = limitMiddleware('register', 5, 3600);
const lookupLimiter     = limitMiddleware('lookup', 30, 60);
const loginInfoLimiter  = limitMiddleware('logininfo', 10, 60);
const gifLimiter        = limitMiddleware('gif', 30, 60);

const SAFE_UPLOAD_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp',
  '.bin', '.txt', '.pdf',
  '.mp3', '.m4a', '.ogg', '.oga', '.opus', '.wav', '.webm',
  '.zip', '.7z', '.tar', '.gz', '.apk',
]);
function sanitizeExt(originalname) {
  let ext = path.extname(originalname || '').toLowerCase();
  if (!/^\.[a-z0-9]{1,8}$/.test(ext) || !SAFE_UPLOAD_EXTS.has(ext)) ext = '';
  return ext;
}

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS),
  filename: (_, file, cb) => {
    cb(null, Date.now() + '_' + crypto.randomBytes(6).toString('hex') + sanitizeExt(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    if (file.mimetype.startsWith('video/')) return cb(new Error('Video not allowed'));
    cb(null, true);
  }
});

const avatarStorage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, AVATARS),
  filename: (_, file, cb) => {
    const ext = '.webp';
    cb(null, Date.now() + '_' + crypto.randomBytes(6).toString('hex') + ext);
  }
});
const uploadAvatar = multer({
  storage: avatarStorage,
  limits: { fileSize: 5*1024*1024 },
  fileFilter: (_, file, cb) => {
    if (!file.mimetype || !file.mimetype.startsWith('image/')) return cb(new Error('Only images allowed'));
    cb(null, true);
  }
});

function signToken(dt) { return jwt.sign({ dt }, JWT_SECRET, { expiresIn: '30d' }); }

function authMiddleware(req, res, next) {
  const raw = req.cookies?.token || req.headers.authorization?.split(' ')[1];
  if (!raw) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { dt } = jwt.verify(raw, JWT_SECRET);
    const device  = DB.getDeviceByToken(dt);
    if (!device) return res.status(401).json({ error: 'Device not found' });
    DB.touchDevice(dt);
    req.device  = device;
    req.account = DB.getAccountById(device.account_id);
    req.rawToken = dt;
    next();
  } catch { res.status(401).json({ error: 'Bad token' }); }
}

const IS_SECURE = process.env.SECURE !== 'false';
function setCookie(res, token) {
  res.cookie('token', token, {
    httpOnly: true, secure: IS_SECURE,
    sameSite: IS_SECURE ? 'strict' : 'lax',
    maxAge: 30*24*3600*1000
  });
}

const INLINE_SERVE_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp']);

app.use('/uploads', authMiddleware, (req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  const rel  = req.path.replace(/^\/+/, '');
  const safe = path.resolve(UPLOADS, '.' + (rel ? '/' + rel : ''));
  if (!safe.startsWith(UPLOADS + path.sep) && safe !== UPLOADS) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.set('X-Content-Type-Options', 'nosniff');

  if (rel.startsWith('avatars/')) {
    return res.sendFile(safe, err => { if (err && !res.headersSent) res.status(404).json({ error: 'Not found' }); });
  }

  const fileUrl = '/uploads/' + rel;
  const msg = DB.db.prepare(`
    SELECT m.id, m.file_type, c.initiator_id, c.peer_id
    FROM messages m JOIN chats c ON c.id = m.chat_id
    WHERE m.file_path = ? LIMIT 1
  `).get(fileUrl);
  if (!msg || (msg.initiator_id !== req.account.id && msg.peer_id !== req.account.id)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const ext = path.extname(safe).toLowerCase();
  if (INLINE_SERVE_EXTS.has(ext)) {
    return res.sendFile(safe, err => { if (err && !res.headersSent) res.status(404).json({ error: 'Not found' }); });
  }

  res.set('Content-Type', 'application/octet-stream');
  res.set('Content-Disposition', `attachment; filename="${path.basename(safe).replace(/[^\x20-\x7e]/g, '_')}"`);
  res.set('Content-Security-Policy', 'sandbox');
  res.sendFile(safe, err => { if (err && !res.headersSent) res.status(404).json({ error: 'Not found' }); });
});

app.post('/api/register', registerLimiter, (req, res) => {
  try {
    const acct = DB.createAccount();
    const dt = crypto.randomBytes(32).toString('hex');
    const dName = DB.addDevice(acct.id, dt);
    setCookie(res, signToken(dt));
    res.json({ accountNumber: acct.number, chatNumber: acct.chat_number, accountId: acct.id, deviceName: dName });
  } catch (e) {
    console.error('[register]', e);
    res.status(500).json({ error: 'Failed to create account' });
  }
});
app.post('/api/login', (req, res) => {
  const ip = req.ip;
  const { blocked, remaining } = checkLoginRateLimit(ip);
  if (blocked) return res.status(429).json({ error: `Too many attempts. Try in ${remaining} min.` });

  const { number } = req.body;
  const clean = (number||'').replace(/\D/g,'');
  if (clean.length !== 16) return res.status(400).json({ error: 'Enter your 16-digit private number' });

  const acct = DB.getAccountByNumber(clean);
  if (!acct) { recordLoginFail(ip); return res.status(404).json({ error: 'Account not found' }); }
  if (DB.countDevices(acct.id) >= 5) return res.status(400).json({ error: 'Max 5 devices. Kick one first.' });

  recordLoginSuccess(ip);
  const dt = crypto.randomBytes(32).toString('hex');
  const dName = DB.addDevice(acct.id, dt);
  setCookie(res, signToken(dt));
  res.json({ accountNumber: clean, chatNumber: acct.chat_number, accountId: acct.id, deviceName: dName });
});

app.post('/api/login/devices', loginInfoLimiter, (req, res) => {
  const { number } = req.body;
  const clean = (number||'').replace(/\D/g,'');
  if (clean.length !== 16) return res.status(400).json({ error: 'Invalid number' });

  const acct = DB.getAccountByNumber(clean);
  if (!acct) return res.status(404).json({ error: 'Account not found' });

  const devices = DB.getDevices(acct.id);
  res.json({ devices });
});

app.post('/api/login/kick', loginInfoLimiter, (req, res) => {
  const { number, deviceId } = req.body;
  const clean = (number||'').replace(/\D/g,'');
  if (clean.length !== 16) return res.status(400).json({ error: 'Invalid number' });

  const acct = DB.getAccountByNumber(clean);
  if (!acct) return res.status(404).json({ error: 'Account not found' });

  DB.kickDevice(parseInt(deviceId), acct.id);
  res.json({ ok: true, count: DB.countDevices(acct.id) });
});

app.post('/api/login/username', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'No username' });
  const acct = DB.getAccountByUsername(username);
  if (!acct) return res.status(404).json({ error: 'Username not found or private' });

  res.json({ chatNumber: acct.chat_number });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const devices = DB.getDevices(req.account.id);
  const aliases = DB.getAliases(req.account.id);
  res.json({
    chatNumber:    req.account.chat_number,
    accountId:     req.account.id,
    username:      req.account.username,
    usernamePublic: req.account.username_public,
    avatarPath:    req.account.avatar_path,
    showPresence:  req.account.show_presence === 0 ? false : true,
    deviceName:    req.device.device_name,
    deviceId:      req.device.id,
    devices, aliases,
  });
});

app.post('/api/logout', authMiddleware, (req, res) => {
  DB.kickDevice(req.device.id, req.account.id);
  res.clearCookie('token');
  res.json({ ok: true });
});

app.delete('/api/devices/:id', authMiddleware, (req, res) => {
  DB.kickDevice(parseInt(req.params.id), req.account.id);
  res.json({ ok: true });
});

app.post('/api/devices/kick-all', authMiddleware, (req, res) => {
  DB.kickAllDevicesExcept(req.account.id, req.rawToken);
  res.json({ ok: true });
});

app.delete('/api/account', authMiddleware, (req, res) => {
  DB.deleteAccount(req.account.id);
  res.clearCookie('token');
  res.json({ ok: true });
});

app.post('/api/me/pubkey', authMiddleware, (req, res) => {
  const { publicKey } = req.body;
  if (!publicKey) return res.status(400).json({ error: 'Missing publicKey' });
  try {
    DB.db.prepare('UPDATE devices SET public_key=? WHERE id=?').run(publicKey, req.device.id);
    DB.db.prepare('UPDATE accounts SET public_key=? WHERE id=?').run(publicKey, req.account.id);
    
    const chats = DB.getChatsForAccount(req.account.id);
    chats.forEach(c => {
      io.to(roomForChat(c.uid)).emit('peer:key_update', { chatUid: c.uid });
    });
    res.json({ ok: true });
  } catch (e) {
    console.error('[pubkey]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/me/push', authMiddleware, (req, res) => {
  const { endpoint, provider } = req.body;
  if (endpoint && typeof endpoint !== 'string') {
    return res.status(400).json({ error: 'Invalid endpoint' });
  }
  if (endpoint) {
    validatePushEndpoint(endpoint)
      .then(ok => {
        if (!ok) return res.status(400).json({ error: 'Endpoint must be a public https:// URL' });
        try {
          DB.setPushEndpoint(req.device.id, req.account.id, endpoint, provider || null);
          res.json({ ok: true });
        } catch (e) {
          console.error('[push register]', e.message);
          res.status(500).json({ error: e.message });
        }
      })
      .catch(() => res.status(400).json({ error: 'Endpoint validation failed' }));
    return;
  }
  try {
    DB.setPushEndpoint(req.device.id, req.account.id, endpoint || null, provider || null);
    res.json({ ok: true });
  } catch (e) {
    console.error('[push register]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/pubkey/:chatNumber', authMiddleware, (req, res) => {
  try {
    const acct = DB.getAccountByChatNumber(req.params.chatNumber.replace(/-/g, ''));
    if (!acct) return res.status(404).json({ error: 'Not found' });
    const devices = DB.db.prepare(
      'SELECT id, device_name, public_key FROM devices WHERE account_id=? AND public_key IS NOT NULL'
    ).all(acct.id);
    res.json({
      publicKey:  acct.public_key || null,
      publicKeys: devices.map(d => ({ deviceId: d.id, deviceName: d.device_name, key: d.public_key })),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/me/username', authMiddleware, (req, res) => {
  let { username, isPublic } = req.body;
  if (username) {
    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username))
      return res.status(400).json({ error: 'Username: 3-24 chars, letters/numbers/underscore' });
    username = username.toLowerCase();
    const existing = DB.db.prepare(
      'SELECT id FROM accounts WHERE LOWER(username)=LOWER(?) AND id!=?'
    ).get(username, req.account.id);
    if (existing) return res.status(409).json({ error: 'Username taken' });
  }
  DB.setUsername(req.account.id, username || null, isPublic);
  
  const publicUsername = isPublic ? (username || null) : null;

  const chats = DB.getChatsForAccount(req.account.id);
  chats.forEach(c => {
    io.to(roomForChat(c.uid)).emit('peer:profile_update', {
      chatUid: c.uid,
      accountId: req.account.id,
      username: publicUsername,
      isPublic: isPublic ? 1 : 0,
      avatarPath: req.account.avatar_path
    });
  });

  res.json({ ok: true, username: username || null });
});

app.patch('/api/me/presence', authMiddleware, (req, res) => {
  const { show } = req.body;
  try {
    DB.db.prepare('UPDATE accounts SET show_presence=? WHERE id=?').run(show ? 1 : 0, req.account.id);
    broadcastPresence(req.account.id);
    res.json({ ok: true, showPresence: !!show });
  } catch (e) {
    console.error('[presence setting]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/me/avatar', authMiddleware, uploadAvatar.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const outPath = req.file.path;
  
  const notifyAvatarUpdate = (accountId, rel) => {
    const chats = DB.getChatsForAccount(accountId);
    chats.forEach(c => {
      io.to(roomForChat(c.uid)).emit('peer:profile_update', {
        chatUid: c.uid,
        accountId: accountId,
        username: req.account.username,
        isPublic: req.account.username_public,
        avatarPath: rel
      });
    });
  };

  if (!validateFileMagic(outPath, req.file.mimetype)) {
    try { fs.unlinkSync(outPath); } catch {}
    return res.status(400).json({ error: 'Invalid image format' });
  }

  if (sharp) {
    try {
      let pipeline = sharp(outPath);
      if (req.body.crop) {
        try {
          const { x, y, w, h } = JSON.parse(req.body.crop);
          pipeline = pipeline.extract({ left: parseInt(x), top: parseInt(y), width: parseInt(w), height: parseInt(h) });
        } catch (e) { console.warn('[Avatar] Invalid crop data'); }
      }
      await pipeline.resize(128, 128, { fit: 'cover' }).webp({ quality: 85 }).toFile(outPath + '.webp');
      fs.unlinkSync(outPath);
      const rel = '/uploads/avatars/' + path.basename(outPath + '.webp');
      DB.setAvatar(req.account.id, rel);
      notifyAvatarUpdate(req.account.id, rel);
      return res.json({ avatarPath: rel });
    } catch (e) {
      console.error('[Avatar] Sharp processing failed:', e.message);
      try { fs.unlinkSync(outPath); } catch {}
      return res.status(500).json({ error: 'Image processing failed' });
    }
  }

  const rel = '/uploads/avatars/' + path.basename(outPath);
  DB.setAvatar(req.account.id, rel);
  notifyAvatarUpdate(req.account.id, rel);
  res.json({ avatarPath: rel });
});

app.get('/api/aliases', authMiddleware, (req, res) => {
  res.json(DB.getAliases(req.account.id));
});
app.put('/api/aliases', authMiddleware, (req, res) => {
  const { targetNumber, alias } = req.body;
  if (!targetNumber || !alias) return res.status(400).json({ error: 'Missing fields' });
  DB.setAlias(req.account.id, targetNumber.replace(/-/g,''), alias);
  res.json({ ok: true });
});
app.delete('/api/aliases/:number', authMiddleware, (req, res) => {
  DB.deleteAlias(req.account.id, req.params.number);
  res.json({ ok: true });
});

const GIPHY_API_KEY = process.env.GIPHY_KEY || '';
const GIPHY_CONFIGURED = !!process.env.GIPHY_KEY;

const GIPHY_MEDIA_RE = /^https:\/\/([a-z0-9-]+\.)*giphy\.com\/[^\s"'<>]+$/i;

app.get('/api/gifs', authMiddleware, gifLimiter, async (req, res) => {
  if (!GIPHY_CONFIGURED) return res.json({ gifs: [] });
  const q = req.query.q || 'speed';
  const offset = parseInt(req.query.offset) || 0;
  const url = `https://api.giphy.com/v1/gifs/search?api_key=${encodeURIComponent(GIPHY_API_KEY)}&q=${encodeURIComponent(q)}&limit=30&rating=pg-13&offset=${offset}`;

  try {
    const apiRes = await fetch(url, { signal: AbortSignal.timeout(8000) });
    const parsed = await apiRes.json();

    if (parsed.meta && parsed.meta.status !== 200) {
      console.error('[giphy Error]', parsed.meta.msg, 'status:', parsed.meta.status);
      return res.status(500).json({ error: parsed.meta.msg || 'giphy API error' });
    }

    const gifs = (parsed.data || [])
      .map(g => g.images?.fixed_height_small?.url)
      .filter(u => u && GIPHY_MEDIA_RE.test(u))
      .map(u => '/api/gifs/media?u=' + encodeURIComponent(u));
    res.json({ gifs });
  } catch (e) {
    console.error('[giphy request error]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/gifs/media', authMiddleware, gifLimiter, async (req, res) => {
  const u = String(req.query.u || '');
  if (!GIPHY_MEDIA_RE.test(u)) return res.status(400).json({ error: 'Invalid media URL' });
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 10000);
  try {
    const upstream = await fetch(u, { redirect: 'error', signal: abort.signal });
    if (!upstream.ok) { clearTimeout(timer); return res.status(502).json({ error: 'Upstream error' }); }
    const type = upstream.headers.get('content-type') || 'image/gif';
    if (!/^image\//.test(type)) { clearTimeout(timer); return res.status(502).json({ error: 'Not an image' }); }
    res.set('Content-Type', type);
    res.set('Cache-Control', 'public, max-age=86400');
    res.set('X-Content-Type-Options', 'nosniff');

    clearTimeout(timer);
    const reader = upstream.body.getReader();
    let aborted = false;
    res.on('close', () => {
      aborted = true;
      try { Promise.resolve(reader.cancel()).catch(() => {}); } catch {}
    });
    (async () => {
      try {
        while (!aborted && !res.destroyed && !res.writableEnded) {
          const { done, value } = await reader.read();
          if (done || aborted) break;
          if (!res.write(Buffer.from(value))) {
            await new Promise(resolve => {
              const done = () => { res.off('drain', done); res.off('close', done); resolve(); };
              res.once('drain', done);
              res.once('close', done);
            });
          }
        }
        if (!aborted && !res.destroyed && !res.writableEnded) res.end();
      } catch {
        try { if (!res.writableEnded) res.destroy(); } catch {}
      }
    })();
  } catch (e) {
    clearTimeout(timer);
    console.error('[giphy media]', e.message);
    if (!res.headersSent) res.status(502).json({ error: 'Fetch failed' });
  }
});

app.get('/api/lookup/:query', authMiddleware, lookupLimiter, (req, res) => {
  const q = req.params.query;
  let acct;
  if (q.startsWith('@')) {
    acct = DB.getAccountByUsername(q.slice(1));
  } else {
    const clean = q.replace(/-/g, '');
    acct = clean.length === 8 ? DB.getAccountByChatNumber(clean) : null;
  }
  if (!acct) return res.status(404).json({ error: 'Not found' });
  res.json({ number: acct.chat_number, username: acct.username_public ? acct.username : null, avatarPath: acct.avatar_path });
});

app.get('/api/chats', authMiddleware, (req, res) => {
  const chats = DB.getChatsForAccount(req.account.id);
  const aliases = DB.getAliases(req.account.id);
  const aliasMap = {};
  aliases.forEach(a => aliasMap[a.target_number] = a.alias);
  chats.forEach(c => {
    const myId = req.account.id;
    const peerChatNum = c.initiator_id === myId ? c.peer_chat_number : c.initiator_chat_number;
    c.peer_alias = aliasMap[peerChatNum] || null;
  });
  res.json(chats);
});

app.post('/api/chats', authMiddleware, (req, res) => {
  const { peerNumber, label, chatNumber, burnMode, burnCustom } = req.body;
  if (!peerNumber) return res.status(400).json({ error: 'peerNumber required' });
  let peer;
  if (peerNumber.startsWith('@')) {
    peer = DB.getAccountByUsername(peerNumber.slice(1));
  } else {
    const clean = peerNumber.replace(/-/g, '');
    peer = DB.getAccountByChatNumber(clean);
  }
  if (!peer) return res.status(404).json({ error: 'Peer not found' });
  if (peer.id === req.account.id) return res.status(400).json({ error: 'Cannot chat with yourself' });
  const chat = DB.createChat(req.account.id, peer.id, label, chatNumber, burnMode, burnCustom);

  const fullChat = DB.getChatsForAccount(req.account.id).find(c => c.uid === chat.uid);
  const peerChat = DB.getChatsForAccount(peer.id).find(c => c.uid === chat.uid);

  for (const [sid, sock] of io.of('/').sockets) {
    if (sock.accountId === req.account.id || sock.accountId === peer.id) {
      sock.join(roomForChat(chat.uid));
    }
  }

  io.to(`user:${peer.id}`).emit('chat:new', { chat: peerChat });
  io.to(`user:${req.account.id}`).emit('chat:new', { chat: fullChat });

  res.json(chat);
});

app.get('/api/chats/:uid/messages', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat) return res.status(404).json({ error: 'Not found' });
  const isMember = chat.initiator_id === req.account.id || chat.peer_id === req.account.id;
  if (!isMember) return res.status(403).json({ error: 'Forbidden' });

  const beforeId = req.query.beforeId ? parseInt(req.query.beforeId) : null;
  res.json(DB.getMessages(chat.id, req.account.id, { beforeId }));
});

app.get('/api/messages/:id', authMiddleware, (req, res) => {
  try {
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(parseInt(req.params.id));
    if (!msg) return res.status(404).json({ error: 'Not found' });
    
    const chat = DB.getChatById(msg.chat_id);
    if (!chat || (chat.initiator_id !== req.account.id && chat.peer_id !== req.account.id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(msg);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/chats/:uid/label', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat) return res.status(404).json({ error: 'Not found' });
  if (!isChatMember(chat, req.account.id)) return res.status(403).json({ error: 'Forbidden' });
  DB.setChatLabel(chat.id, req.account.id, req.body.label);
  res.json({ ok: true });
});

app.patch('/api/chats/:uid/burn', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat) return res.status(404).json({ error: 'Not found' });
  if (!isChatMember(chat, req.account.id)) return res.status(403).json({ error: 'Forbidden' });
  DB.setBurnMode(chat.id, req.body.mode, req.body.customMin);
  res.json({ ok: true });
});

app.post('/api/chats/:uid/burn-confirm', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat) return res.status(404).json({ error: 'Not found' });
  if (!isChatMember(chat, req.account.id)) return res.status(403).json({ error: 'Forbidden' });
  DB.confirmBurn(chat.id);
  res.json({ ok: true });
});

app.delete('/api/chats/:uid', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat) return res.status(404).json({ error: 'Not found' });
  if (!isChatMember(chat, req.account.id)) return res.status(403).json({ error: 'Forbidden' });
  DB.deleteChat(chat.id, req.account.id, req.body.forWhom || 'self');
  res.json({ ok: true });
});

app.delete('/api/messages/:id', authMiddleware, (req, res) => {
  const msgId = parseInt(req.params.id);
  if (!Number.isInteger(msgId)) return res.status(400).json({ error: 'Invalid message id' });
  const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(msgId);
  if (!msg) return res.status(404).json({ error: 'Not found' });
  const chat = DB.getChatById(msg.chat_id);
  if (!isChatMember(chat, req.account.id)) return res.status(403).json({ error: 'Forbidden' });
  DB.deleteMessage(msgId, req.account.id, req.body.forWhom || 'self');
  res.json({ ok: true });
});

app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });

  const quotaMb = parseInt(process.env.UPLOAD_QUOTA_MB) || 2048;
  if (quotaMb > 0) {
    const usage = DB.getUploadUsageBytes(req.account.id);
    if (usage + req.file.size > quotaMb * 1024 * 1024) {
      try { fs.unlinkSync(req.file.path); } catch {}
      return res.status(413).json({ error: 'Upload quota exceeded' });
    }
  }
  
  const isEncrypted = req.file.originalname.endsWith('.bin');
  const mime = isEncrypted ? 'application/octet-stream' : req.file.mimetype;
  const isImage = !isEncrypted && mime.startsWith('image/');

  if (isImage && !validateFileMagic(req.file.path, mime)) {
    try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(400).json({ error: 'Invalid image format' });
  }
  const isAnimated = !isEncrypted && (mime === 'image/gif' || mime === 'image/webp');
  let filePath = req.file.path;
  let fileName = req.file.originalname;

  if (isImage && !isAnimated && !isEncrypted && sharp) {
    const outPath = filePath.replace(/\.[^.]+$/, '.webp');
    await sharp(filePath)
      .resize({ width: 2048, height: 2048, fit: 'inside', withoutEnlargement: true })
      .webp({ quality: 82 })
      .toFile(outPath);
    fs.unlinkSync(filePath);
    filePath = outPath;
    fileName = fileName.replace(/\.[^.]+$/, '.webp');
  }

  res.json({
    url: '/uploads/' + path.basename(filePath),
    name: fileName,
    type: isImage ? 'image' : 'file',
  });
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (req.file?.path) { try { fs.unlinkSync(req.file.path); } catch {} }
    const msg = err.code === 'LIMIT_FILE_SIZE'
      ? (req.originalUrl.includes('/me/avatar') ? 'Image too large (max 5 MB)' : 'File too large (max 25 MB)')
      : err.message;
    return res.status(413).json({ error: msg });
  }
  console.error('[error]', err);
  if (res.headersSent) return;
  res.status(err.status || 500).json({ error: err.message || 'Server error' });
});

const httpsServer = https.createServer(tlsOptions, app);
const httpServer  = http.createServer(app);
const io = new Server(httpsServer, {
  pingInterval: 10000,
  pingTimeout: 10000,
});
io.attach(httpServer);

io.use((socket, next) => {
  const cookieToken = socket.handshake.headers?.cookie?.match(/(?:^|;\s*)token=([^;]*)/)?.[1];
  const raw = socket.handshake.auth?.token || cookieToken;

  if (!raw) return next(new Error('Unauthorized'));
  try {
    const { dt } = jwt.verify(raw, JWT_SECRET);
    const device = DB.getDeviceByToken(dt);
    if (!device) return next(new Error('Device not found'));
    socket.accountId = device.account_id;
    socket.deviceId  = device.id;
    next();
  } catch { next(new Error('Bad token')); }
});

const online = new Map();
const activeTimedBurns = new Set();
const presenceShown = new Map();
function roomForChat(uid) { return `chat:${uid}`; }

function isOnline(aid) {
  const set = online.get(aid);
  if (!set || !set.size) return false;
  for (const sid of set) {
    const sock = io.sockets.sockets.get(sid);
    if (sock && sock.presenceHidden !== true) return true;
  }
  return false;
}

function presenceVisibleToPeers(acct) {
  return !!acct && acct.show_presence !== 0;
}

function broadcastPresence(aid) {
  const acct = DB.getAccountById(aid);
  if (!acct) return;
  if (isOnline(aid)) {
    notifyPresence(aid, true, null);
  } else {
    notifyPresence(aid, false, acct.last_seen || null);
  }
}

function recomputePresence(aid) {
  const now = isOnline(aid);
  if (presenceShown.get(aid) === now) return;
  presenceShown.set(aid, now);
  if (!now) touchAccountLastSeen(aid, Math.floor(Date.now() / 1000));
  broadcastPresence(aid);
}

function touchAccountLastSeen(accountId, unixSec) {
  try {
    DB.db.prepare('UPDATE accounts SET last_seen=? WHERE id=?').run(unixSec, accountId);
  } catch (e) {
    console.error('[presence] last_seen update failed:', e.message);
  }
}

function notifyPresence(accountId, isOnlineNow, lastSeenSec) {
  const acct = DB.getAccountById(accountId);
  if (!acct) return;
  const visible = presenceVisibleToPeers(acct);
  const chats = DB.getChatsForAccount(accountId);
  for (const c of chats) {
    const peerId = c.initiator_id === accountId ? c.peer_id : c.initiator_id;
    io.to(`user:${peerId}`).emit('peer:presence', {
      chatUid: c.uid,
      number: acct.chat_number,
      online: visible && isOnlineNow,
      lastSeen: visible ? (lastSeenSec || null) : null,
    });
  }
}

function getChatUidBetween(a, b) {
  return DB.db.prepare(
    'SELECT uid FROM chats WHERE (initiator_id=? AND peer_id=?) OR (initiator_id=? AND peer_id=?) LIMIT 1'
  ).get(a, b, b, a)?.uid || null;
}

function isChatMember(chat, accountId) {
  return !!chat && (chat.initiator_id === accountId || chat.peer_id === accountId);
}

function isPrivateAddress(ip, family) {
  if (family === 6) {
    const v6 = ip.toLowerCase();
    if (v6 === '::1' || v6 === '::' || v6 === '::ffff:127.0.0.1') return true;
    if (v6.startsWith('fe80:') || v6.startsWith('fc') || v6.startsWith('fd')) return true;
    if (v6.startsWith('ff')) return true;
    return false;
  }
  if (!net.isIPv4(ip)) return true;
  const parts = ip.split('.').map(Number);
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

async function validatePushEndpoint(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch { return false; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return false;
  if (net.isIP(host)) {
    return !isPrivateAddress(host, net.isIP(host));
  }
  let addrs;
  try {
    addrs = await dns.lookup(host, { all: true, verbatim: true });
  } catch { return false; }
  if (!addrs || !addrs.length) return false;
  return addrs.every(a => !isPrivateAddress(a.address, a.family));
}

async function pushWakeup(accountId, chatUid, preview, burn) {
  if (online.has(accountId)) return;
  const devices = DB.getPushableDevices(accountId);
  for (const d of devices) {
    try {
      if (!d.push_endpoint || !(await validatePushEndpoint(d.push_endpoint))) continue;
      await fetch(d.push_endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: JSON.stringify({ t: 'new_message', chatUid, preview: preview || '', burn: !!burn }),
        redirect: 'manual',
        signal: AbortSignal.timeout(5000),
      });
    } catch (e) {
      console.error('[push] failed for device', d.id, e.message);
    }
  }
}

io.on('connection', socket => {
  const aid = socket.accountId;
  if (!online.has(aid)) online.set(aid, new Set());
  online.get(aid).add(socket.id);

  socket.join(`user:${aid}`);

  const chats = DB.getChatsForAccount(aid);
  chats.forEach(c => socket.join(roomForChat(c.uid)));

  recomputePresence(aid);

  for (const c of chats) {
    const peerId = c.initiator_id === aid ? c.peer_id : c.initiator_id;
    const peerAcct = DB.getAccountById(peerId);
    if (!peerAcct) continue;
    const peerOnline = isOnline(peerId);
    const peerVisible = presenceVisibleToPeers(peerAcct);
    socket.emit('peer:presence', {
      chatUid: c.uid,
      number: peerAcct.chat_number,
      online: peerVisible && peerOnline,
      lastSeen: peerVisible && !peerOnline ? (peerAcct.last_seen || null) : null,
    });
  }

  socket.on('presence:report', ({ online: reported }) => {
    socket.presenceHidden = reported === false;
    recomputePresence(aid);
  });

  socket.on('presence:get', ({ number }) => {
    if (!number) return;
    const peer = DB.getAccountByChatNumber(String(number));
    if (!peer || peer.id === aid) return;
    const sharedUid = getChatUidBetween(aid, peer.id);
    if (!sharedUid) return;
    const peerOnline = isOnline(peer.id);
    const peerVisible = presenceVisibleToPeers(peer);
    socket.emit('peer:presence', {
      chatUid: sharedUid,
      number: peer.chat_number,
      online: peerVisible && peerOnline,
      lastSeen: peerVisible && !peerOnline ? (peer.last_seen || null) : null,
    });
  });

  socket.on('disconnect', () => {
    const s = online.get(aid);
    if (s) {
      s.delete(socket.id);
      if (!s.size) online.delete(aid);
    }
    recomputePresence(aid);
  });

  const MSG_FLOOD = { count: 0, resetAt: Date.now() + 10000 };
  function floodLimited() {
    const now = Date.now();
    if (now > MSG_FLOOD.resetAt) { MSG_FLOOD.count = 0; MSG_FLOOD.resetAt = now + 10000; }
    return ++MSG_FLOOD.count > 30;
  }
  const ALLOW_PLAINTEXT = process.env.ALLOW_PLAINTEXT === 'true';
  const MSG_FILE_URL_RE = /^\/uploads\/[A-Za-z0-9][A-Za-z0-9._-]*$/;
  const MSG_FILE_TYPES = new Set(['image', 'file', 'audio']);

  socket.on('msg:send', ({ chatUid, content, fileUrl, fileType, fileName, burnSeconds, replyToId, preview }) => {
    if (typeof chatUid !== 'string' || !chatUid) return;
    if (floodLimited()) {
      socket.emit('msg:error', { chatUid, error: 'Sending too fast' });
      return;
    }
    const chat = DB.getChatByUid(chatUid);
    if (!isChatMember(chat, aid)) return;
    if (chat.initiator_id === aid && chat.deleted_by_initiator) return;
    if (chat.peer_id === aid && chat.deleted_by_peer) return;

    if (content !== undefined && content !== null && typeof content !== 'string') {
      socket.emit('msg:error', { chatUid, error: 'Invalid content' });
      return;
    }
    if (content && content.length > 65536) {
      socket.emit('msg:error', { chatUid, error: 'Message too long' });
      return;
    }
    if (content && !ALLOW_PLAINTEXT && !content.startsWith('e2e:')) {
      socket.emit('msg:error', { chatUid, error: 'Plaintext messages are rejected (must be encrypted)' });
      return;
    }
    if (fileUrl !== undefined && fileUrl !== null) {
      if (typeof fileUrl !== 'string' || !MSG_FILE_URL_RE.test(fileUrl) || fileUrl.includes('..')) {
        socket.emit('msg:error', { chatUid, error: 'Invalid fileUrl' });
        return;
      }
    }
    if (fileType !== undefined && fileType !== null && !MSG_FILE_TYPES.has(fileType)) {
      socket.emit('msg:error', { chatUid, error: 'Invalid fileType' });
      return;
    }
    if (fileName !== undefined && fileName !== null) {
      if (typeof fileName !== 'string' || fileName.length > 255) {
        socket.emit('msg:error', { chatUid, error: 'Invalid fileName' });
        return;
      }
      fileName = fileName.replace(/[\u0000-\u001f\u007f]/g, '');
    }
    if (preview !== undefined && preview !== null) {
      if (typeof preview !== 'string' || preview.length > 4096) preview = null;
    }
    if (replyToId !== undefined && replyToId !== null && replyToId !== 0) {
      const rid = parseInt(replyToId);
      if (!Number.isInteger(rid)) {
        socket.emit('msg:error', { chatUid, error: 'Invalid replyToId' });
        return;
      }
      const target = DB.db.prepare('SELECT chat_id FROM messages WHERE id=?').get(rid);
      if (!target || target.chat_id !== chat.id) {
        socket.emit('msg:error', { chatUid, error: 'Invalid replyToId' });
        return;
      }
      replyToId = rid;
    } else {
      replyToId = null;
    }

    const secs = burnSeconds > 0 ? Math.max(5, Math.min(3600, parseInt(burnSeconds) || 0)) : null;
    const finalPreview = preview || (secs ? '[burns after read]' : (content ? content.slice(0,60) : (fileType==='image'?'📷 Image':(fileType==='audio'?'ᯤ Voice':'📎 File'))));
    const msg = DB.addMessage(chat.id, aid, content, fileUrl||null, fileType||null, fileName||null, secs, replyToId, finalPreview);
    io.to(roomForChat(chatUid)).emit('msg:new', { chatUid, msg, preview: finalPreview });
    const trimmed = DB.enforceMaxMessages(chat.id);
    if (trimmed.length) {
      io.to(roomForChat(chatUid)).emit('msg:burned', { chatUid, ids: trimmed, preview: finalPreview });
    }
    const recipientId = chat.initiator_id === aid ? chat.peer_id : chat.initiator_id;
    pushWakeup(recipientId, chatUid, finalPreview, !!secs).catch(e => console.error('[push] wakeup error', e.message));
  });

  socket.on('msg:read', ({ chatUid }) => {
    const chat = DB.getChatByUid(chatUid);
    if (!isChatMember(chat, aid)) return;
    DB.markRead(chat.id, aid);
    io.to(roomForChat(chatUid)).emit('msg:read:ack', { chatUid, by: aid });
  });

  socket.on('msg:spoiler:open', ({ msgId }) => {
    const id = parseInt(msgId);
    if (!Number.isInteger(id)) return;
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(id);
    if (!msg || !msg.burn_seconds) return;
    const chat = DB.getChatById(msg.chat_id);
    if (!isChatMember(chat, aid)) return;
    const chatUid = chat.uid;
    if (msg.burn_at) {

      socket.emit('msg:burn:countdown', {
        msgId: id, chatUid,
        burnAt: msg.burn_at, burnSeconds: msg.burn_seconds,
        content: msg.content, filePath: msg.file_path,
        fileType: msg.file_type, fileName: msg.file_name,
      });
      return;
    }
    const burnAt = Math.floor(Date.now() / 1000) + msg.burn_seconds;
    DB.setBurnAt(id, burnAt);

    io.to(roomForChat(chatUid)).emit('msg:burn:countdown', {
      msgId: id, chatUid, burnAt, burnSeconds: msg.burn_seconds,
      content: msg.content, filePath: msg.file_path,
      fileType: msg.file_type, fileName: msg.file_name,
    });
  });

  socket.on('msg:burn:done', ({ msgId, chatUid }) => {
    const id = parseInt(msgId);
    if (!Number.isInteger(id) || typeof chatUid !== 'string') return;
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(id);
    if (!msg) return;
    const chat = DB.getChatByUid(chatUid);
    if (!isChatMember(chat, aid)) return;
    if (msg.chat_id !== chat.id) return;
    DB.hardDeleteMessage(id);
    
    const last = DB.db.prepare(`SELECT content,file_type,burn_seconds FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id DESC LIMIT 1`).get(chat.id);
    const preview = last ? (last.burn_seconds ? '[burns after read]' : (last.content ? last.content : (last.file_type==='image'?'[image]':'[file]'))) : '';
    DB.updateChatPreview(chat.id, preview);
    io.to(roomForChat(chatUid)).emit('msg:burned', { chatUid, ids: [id], preview });
  });

  socket.on('msg:delete', ({ msgId, forWhom }) => {
    const id = parseInt(msgId);
    if (!Number.isInteger(id)) return;
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(id);
    if (!msg) return;
    const chat = DB.getChatById(msg.chat_id);
    if (!isChatMember(chat, aid)) return;
    DB.deleteMessage(id, aid, forWhom);
    const last = DB.db.prepare(`SELECT content,file_type,burn_seconds FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id DESC LIMIT 1`).get(chat.id);
    const preview = last ? (last.burn_seconds ? '[burns after read]' : (last.content ? last.content : (last.file_type==='image'?'📷 Image':(last.file_type==='audio'?'ᯤ Voice':'📎 File')))) : '';
    io.to(roomForChat(chat.uid)).emit('msg:deleted', { msgId: id, forWhom, by: aid, chatUid: chat.uid, preview });
  });

  socket.on('msg:react', ({ msgId, emoji }) => {
    if (!emoji || emoji.length > 500) return;
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(msgId);
    if (!msg) return;
    
    const chat = DB.getChatById(msg.chat_id);
    if (!chat || (chat.initiator_id !== aid && chat.peer_id !== aid)) return;

    const existing = DB.db.prepare('SELECT 1 FROM reactions WHERE message_id=? AND account_id=? AND emoji=?').get(msgId, aid, emoji);
    
    if (existing) {
      DB.db.prepare('DELETE FROM reactions WHERE message_id=? AND account_id=? AND emoji=?').run(msgId, aid, emoji);
    } else {
      DB.db.prepare('INSERT INTO reactions (message_id, account_id, emoji) VALUES (?,?,?)').run(msgId, aid, emoji);
    }

    const reactions = DB.db.prepare('SELECT account_id, emoji FROM reactions WHERE message_id=?').all(msgId);
    io.to(roomForChat(chat.uid)).emit('msg:reaction', { msgId, reactions });
  });

  socket.on('msg:played', ({ msgId }) => {
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(msgId);
    if (!msg) return;
    const chat = DB.getChatById(msg.chat_id);
    if (!chat || (chat.initiator_id !== aid && chat.peer_id !== aid)) return;
    
    DB.db.prepare('UPDATE messages SET is_played=1 WHERE id=?').run(msgId);
    io.to(roomForChat(chat.uid)).emit('msg:played', { msgId });
  });

  socket.on('chat:join', ({ chatUid }) => {
    const chat = DB.getChatByUid(chatUid);
    if (!chat) return;
    if (chat.initiator_id === aid || chat.peer_id === aid) socket.join(roomForChat(chatUid));
  });

  socket.on('chat:delete', ({ chatUid, forWhom }) => {
    const chat = DB.getChatByUid(chatUid);
    if (!isChatMember(chat, aid)) return;
    DB.deleteChat(chat.id, aid, forWhom);
    io.to(roomForChat(chatUid)).emit('chat:deleted', { chatUid, forWhom, by: aid });
  });

  socket.on('chat:burn', ({ chatUid, mode, customMin }) => {
    const chat = DB.getChatByUid(chatUid);
    if (!chat || (chat.initiator_id !== aid && chat.peer_id !== aid)) return;
    DB.setBurnMode(chat.id, mode, customMin);
    if (mode !== 'never' && mode !== 'baf') {
      activeTimedBurns.add(chatUid);
    } else {
      activeTimedBurns.delete(chatUid);
    }
    io.to(roomForChat(chatUid)).emit('chat:burn:changed', { chatUid, mode, customMin, by: aid });
  });

  socket.on('chat:history', ({ chatUid, max }) => {
    const chat = DB.getChatByUid(chatUid);
    if (!chat || (chat.initiator_id !== aid && chat.peer_id !== aid)) return;
    const n = parseInt(max);
    if (isNaN(n) || n < -1) return;
    DB.setMaxMessages(chat.id, n);
    const label = n === -1 ? 'Unlimited' : `${n} messages max`;
    const sysMsg = { system: true, text: `History limit set to: ${label}` };
    io.to(roomForChat(chatUid)).emit('chat:history:changed', { chatUid, max: n, sysMsg });

    const trimmed = DB.enforceMaxMessages(chat.id);
    if (trimmed.length) {
      io.to(roomForChat(chatUid)).emit('msg:burned', { chatUid, ids: trimmed, preview: '' });
    }
  });

  socket.on('chat:burn:confirm', ({ chatUid }) => {
    const chat = DB.getChatByUid(chatUid);
    if (!isChatMember(chat, aid)) return;
    DB.confirmBurn(chat.id);
    io.to(roomForChat(chatUid)).emit('chat:burn:confirmed', { chatUid });
  });

  socket.on('typing:start', ({ chatUid }) => {
    socket.to(roomForChat(chatUid)).emit('typing:start', { chatUid, accountId: aid });
  });
  socket.on('typing:stop', ({ chatUid }) => {
    socket.to(roomForChat(chatUid)).emit('typing:stop', { chatUid, accountId: aid });
  });

  socket.on('key:request', ({ myPublicKey }) => {
    for (const [sid, sock] of io.of('/').sockets) {
      if (sock.accountId === aid && sock.id !== socket.id) {
        sock.emit('key:request', { fromDeviceId: socket.deviceId, fromPublicKey: myPublicKey });
      }
    }
  });

  socket.on('key:sync', async ({ targetDeviceId, encryptedKey }) => {
    const senderDevice = DB.db.prepare('SELECT public_key FROM devices WHERE id=?').get(socket.deviceId);
    if (!senderDevice || !senderDevice.public_key) return;
    
    for (const [sid, sock] of io.of('/').sockets) {
      if (sock.accountId === aid && sock.deviceId === targetDeviceId) {
        sock.emit('key:sync', { fromPublicKey: senderDevice.public_key, encryptedKey });
      }
    }
  });
});

setInterval(() => {
  const now = Math.floor(Date.now() / 1000);

  if (activeTimedBurns.size > 0) {
    const placeholders = Array.from(activeTimedBurns).map(() => '?').join(',');
    const activeChats = DB.db.prepare(`SELECT * FROM chats WHERE uid IN (${placeholders})`).all(...activeTimedBurns);

    for (const chat of activeChats) {
      let minutes = { '1min':1, '5min':5, '10min':10 }[chat.burn_mode];
      if (chat.burn_mode === 'custom' && chat.burn_custom_minutes) minutes = chat.burn_custom_minutes;
      if (!minutes) {
        activeTimedBurns.delete(chat.uid);
        continue;
      }
      const ids = DB.applyBurnTimed(chat.id, now - minutes * 60);
      if (ids.length) io.to(roomForChat(chat.uid)).emit('msg:burned', { chatUid: chat.uid, ids });
    }
  }

  const expired = DB.collectExpiredBurns();
  if (expired.length) {
    const byChat = new Map();
    for (const { id, chat_uid } of expired) {
      if (!byChat.has(chat_uid)) byChat.set(chat_uid, []);
      byChat.get(chat_uid).push(id);
    }
    for (const [chatUid, ids] of byChat) {
      const chat = DB.getChatByUid(chatUid);
      const last = DB.db.prepare(`SELECT content,file_type,burn_seconds FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id DESC LIMIT 1`).get(chat.id);
      const preview = last ? (last.burn_seconds ? '[burns after read]' : (last.content ? last.content : (last.file_type==='image'?'[image]':'[file]'))) : '';
      DB.updateChatPreview(chat.id, preview);
      io.to(roomForChat(chatUid)).emit('msg:burned', { chatUid, ids, preview });
    }
  }
}, 15_000);

process.on('uncaughtException', (err) => {
  console.error('[taupe] uncaught exception (server kept alive):', err);
});
process.on('unhandledRejection', (err) => {
  console.error('[taupe] unhandled rejection (server kept alive):', err);
});

httpsServer.listen(PORT, BIND_HOST, () => console.log(`https://localhost:${PORT} (bound to ${BIND_HOST})`));
httpServer.listen(HTTP_PORT, BIND_HOST, () => {
  console.log(`http://localhost:${HTTP_PORT} (bound to ${BIND_HOST})`);
});