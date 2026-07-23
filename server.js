const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const crypto = require('crypto');
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
  console.warn('[taupe] sharp unavailable on this platform — images will be stored without resizing/recompression (no EXIF stripping either). Avatar/file uploads still work.');
}
const selfsigned = require('selfsigned');
const DB = require('./db');
require('dotenv').config();

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
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.set('trust proxy', 1);

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '_' + crypto.randomBytes(6).toString('hex') + ext);
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
const uploadAvatar = multer({ storage: avatarStorage, limits: { fileSize: 5*1024*1024 } });

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

app.get('/uploads/*', authMiddleware, (req, res) => {
  const rel  = req.params[0] || '';
  const safe = path.resolve(UPLOADS, rel);
  if (!safe.startsWith(UPLOADS + path.sep) && safe !== UPLOADS) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  if (rel.startsWith('avatars/')) {
    return res.sendFile(safe, err => { if (err && !res.headersSent) res.status(404).json({ error: 'Not found' }); });
  }

  const fileUrl = '/uploads/' + rel;
  const msg = DB.db.prepare(`
    SELECT m.id, c.initiator_id, c.peer_id
    FROM messages m JOIN chats c ON c.id = m.chat_id
    WHERE m.file_path = ? LIMIT 1
  `).get(fileUrl);
  if (!msg || (msg.initiator_id !== req.account.id && msg.peer_id !== req.account.id)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.sendFile(safe, err => {
    if (err && !res.headersSent) res.status(404).json({ error: 'Not found' });
  });
});

app.post('/api/register', (req, res) => {
  const acct = DB.createAccount();
  const dt   = crypto.randomBytes(32).toString('hex');
  const dName = DB.addDevice(acct.id, dt);
  setCookie(res, signToken(dt));
  res.json({ accountNumber: acct.number, chatNumber: acct.chat_number, accountId: acct.id, deviceName: dName });
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
  res.json({ accountNumber: acct.number, chatNumber: acct.chat_number, accountId: acct.id, deviceName: dName });
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
    accountNumber: req.account.number,
    chatNumber:    req.account.chat_number,
    accountId:     req.account.id,
    username:      req.account.username,
    usernamePublic: req.account.username_public,
    avatarPath:    req.account.avatar_path,
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
    res.json({ ok: true });
  } catch (e) {
    console.error('[pubkey]', e.message);
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
  res.json({ ok: true, username: username || null });
});

app.post('/api/me/avatar', authMiddleware, uploadAvatar.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const outPath = req.file.path;
  
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
          pipeline = pipeline.extract({ 
            left: parseInt(x), 
            top: parseInt(y), 
            width: parseInt(w), 
            height: parseInt(h) 
          });
        } catch (e) {
          console.warn('[Avatar] Invalid crop data, falling back to center crop');
        }
      }
      
      await pipeline
        .resize(128, 128, { fit: 'cover' })
        .webp({ quality: 85 })
        .toFile(outPath + '.webp');
        
      fs.unlinkSync(outPath);
      const rel = '/uploads/avatars/' + path.basename(outPath + '.webp');
      DB.setAvatar(req.account.id, rel);
      return res.json({ avatarPath: rel });
    } catch (e) {
      console.error('[Avatar] Sharp processing failed:', e.message);
      try { fs.unlinkSync(outPath); } catch {}
      return res.status(500).json({ error: 'Image processing failed' });
    }
  }

  const rel = '/uploads/avatars/' + path.basename(outPath);
  DB.setAvatar(req.account.id, rel);
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

const GIPHY_API_KEY = process.env.GIPHY_KEY || 'api';

app.get('/api/gifs', authMiddleware, (req, res) => {
  const q = req.query.q || 'speed';
  const offset = req.query.offset || 0;
  const url = `https://api.giphy.com/v1/gifs/search?api_key=${GIPHY_API_KEY}&q=${encodeURIComponent(q)}&limit=30&rating=pg-13&offset=${offset}`;
  
  https.get(url, (apiRes) => {
    let data = '';
    apiRes.on('data', chunk => data += chunk);
    apiRes.on('end', () => {
      try {
        const parsed = JSON.parse(data);
        if (parsed.meta && parsed.meta.status !== 200) {
          console.error('[giphy Error]', parsed.meta.msg, 'status:', parsed.meta.status);
          return res.status(500).json({ error: parsed.meta.msg || 'giphy API error' });
        }
        const gifs = (parsed.data || []).map(g => g.images.fixed_height_small.url);
        res.json({ gifs });
      } catch (e) {
        console.error('[giphy parse error]', e.message, 'raw data:', data);
        res.status(500).json({ error: 'giphy parse error' });
      }
    });
  }).on('error', e => {
    console.error('[giphy request error]', e.message);
    res.status(500).json({ error: e.message });
  });
});

app.get('/api/lookup/:query', authMiddleware, (req, res) => {
  const q = req.params.query;
  let acct;
  if (q.startsWith('@')) {
    acct = DB.getAccountByUsername(q.slice(1));
  } else {
    const clean = q.replace(/-/g, '');

    acct = clean.length === 8
      ? DB.getAccountByChatNumber(clean)
      : DB.getAccountByNumber(clean);
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
  DB.setChatLabel(chat.id, req.account.id, req.body.label);
  res.json({ ok: true });
});

app.patch('/api/chats/:uid/burn', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat) return res.status(404).json({ error: 'Not found' });
  DB.setBurnMode(chat.id, req.body.mode, req.body.customMin);
  res.json({ ok: true });
});

app.post('/api/chats/:uid/burn-confirm', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat) return res.status(404).json({ error: 'Not found' });
  DB.confirmBurn(chat.id);
  res.json({ ok: true });
});

app.delete('/api/chats/:uid', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat) return res.status(404).json({ error: 'Not found' });
  DB.deleteChat(chat.id, req.account.id, req.body.forWhom || 'self');
  res.json({ ok: true });
});

app.delete('/api/messages/:id', authMiddleware, (req, res) => {
  DB.deleteMessage(parseInt(req.params.id), req.account.id, req.body.forWhom || 'self');
  res.json({ ok: true });
});

app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  
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

const httpsServer = https.createServer(tlsOptions, app);
const httpServer  = http.createServer(app);
const io = new Server(httpsServer);
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
function roomForChat(uid) { return `chat:${uid}`; }

io.on('connection', socket => {
  const aid = socket.accountId;
  if (!online.has(aid)) online.set(aid, new Set());
  online.get(aid).add(socket.id);

  socket.join(`user:${aid}`);

  const chats = DB.getChatsForAccount(aid);
  chats.forEach(c => socket.join(roomForChat(c.uid)));

  socket.on('disconnect', () => {
    const s = online.get(aid);
    if (s) { s.delete(socket.id); if (!s.size) online.delete(aid); }
  });

    socket.on('msg:send', ({ chatUid, content, fileUrl, fileType, fileName, burnSeconds, replyToId }) => {
    const chat = DB.getChatByUid(chatUid);
    if (!chat) return;
    const isInit = chat.initiator_id === aid;
    const isPeer = chat.peer_id === aid;
    if (!isInit && !isPeer) return;

    if (isInit && chat.deleted_by_initiator) return;
    if (isPeer && chat.deleted_by_peer) return;
    const secs = burnSeconds > 0 ? Math.max(5, Math.min(3600, parseInt(burnSeconds))) : null;
    const msg = DB.addMessage(chat.id, aid, content, fileUrl||null, fileType||null, fileName||null, secs, replyToId);
    const preview = secs ? '[burns after read]' : (content ? content.slice(0,60) : (fileType==='image'?'[image]':'[file]'));
    io.to(roomForChat(chatUid)).emit('msg:new', { chatUid, msg, preview });

    const trimmed = DB.enforceMaxMessages(chat.id);
    if (trimmed.length) {
      io.to(roomForChat(chatUid)).emit('msg:burned', { chatUid, ids: trimmed, preview });
    }
  });

  socket.on('msg:read', ({ chatUid }) => {
    const chat = DB.getChatByUid(chatUid);
    if (!chat) return;
    DB.markRead(chat.id, aid);
    io.to(roomForChat(chatUid)).emit('msg:read:ack', { chatUid, by: aid });
  });

  socket.on('msg:spoiler:open', ({ msgId, chatUid }) => {
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(msgId);
    if (!msg || !msg.burn_seconds) return;
    const chat = DB.getChatByUid(chatUid);
    if (!chat || (chat.initiator_id !== aid && chat.peer_id !== aid)) return;
    if (msg.burn_at) {

      socket.emit('msg:burn:countdown', {
        msgId, chatUid,
        burnAt: msg.burn_at, burnSeconds: msg.burn_seconds,
        content: msg.content, filePath: msg.file_path,
        fileType: msg.file_type, fileName: msg.file_name,
      });
      return;
    }
    const burnAt = Math.floor(Date.now() / 1000) + msg.burn_seconds;
    DB.setBurnAt(msgId, burnAt);

    io.to(roomForChat(chatUid)).emit('msg:burn:countdown', {
      msgId, chatUid, burnAt, burnSeconds: msg.burn_seconds,
      content: msg.content, filePath: msg.file_path,
      fileType: msg.file_type, fileName: msg.file_name,
    });
  });

  socket.on('msg:burn:done', ({ msgId, chatUid }) => {
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(msgId);
    if (!msg) return;
    const chat = DB.getChatByUid(chatUid);
    if (!chat || (chat.initiator_id !== aid && chat.peer_id !== aid)) return;
    DB.hardDeleteMessage(msgId);
    const last = DB.db.prepare(`SELECT content,file_type,burn_seconds FROM messages WHERE chat_id=? ORDER BY id DESC LIMIT 1`).get(chat.id);
    const preview = last ? (last.burn_seconds ? '[🔥 burns after read]' : (last.content||'').slice(0,60)||(last.file_type==='image'?'[image]':'[file]')) : '';
    io.to(roomForChat(chatUid)).emit('msg:burned', { chatUid, ids: [msgId], preview });
  });

  socket.on('msg:delete', ({ msgId, forWhom }) => {
    DB.deleteMessage(msgId, aid, forWhom);
    const m = DB.db.prepare('SELECT chat_id FROM messages WHERE id=?').get(msgId);
    if (m) {
      const chat = DB.getChatById(m.chat_id);
      if (chat) {
        const last = DB.db.prepare(`SELECT content,file_type FROM messages WHERE chat_id=? AND deleted_for!='both' ORDER BY id DESC LIMIT 1`).get(chat.id);
        const preview = last ? (last.content||'').slice(0,60)||(last.file_type==='image'?'📷 Image':'📎 File') : '';
        io.to(roomForChat(chat.uid)).emit('msg:deleted', { msgId, forWhom, by: aid, preview });
      }
    }
  });

  socket.on('msg:react', ({ msgId, emoji }) => {
    if (!emoji || emoji.length > 10) return;
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

  socket.on('chat:join', ({ chatUid }) => {
    const chat = DB.getChatByUid(chatUid);
    if (!chat) return;
    if (chat.initiator_id === aid || chat.peer_id === aid) socket.join(roomForChat(chatUid));
  });

  socket.on('chat:delete', ({ chatUid, forWhom }) => {
    const chat = DB.getChatByUid(chatUid);
    if (!chat) return;
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
    if (!chat) return;
    DB.confirmBurn(chat.id);
    io.to(roomForChat(chatUid)).emit('chat:burn:confirmed', { chatUid });
  });

  socket.on('typing:start', ({ chatUid }) => {
    socket.to(roomForChat(chatUid)).emit('typing:start', { chatUid, accountId: aid });
  });
  socket.on('typing:stop', ({ chatUid }) => {
    socket.to(roomForChat(chatUid)).emit('typing:stop', { chatUid, accountId: aid });
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
      io.to(roomForChat(chatUid)).emit('msg:burned', { chatUid, ids, preview: '' });
    }
  }
}, 15_000);

httpsServer.listen(PORT, () => console.log(`https://localhost:${PORT}`));
httpServer.listen(HTTP_PORT, () => {
  console.log(`http://localhost:${HTTP_PORT}`);
});