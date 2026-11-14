require('dotenv').config();

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const net = require('node:net');
const express = require('express');
const { Server } = require('socket.io');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const selfsigned = require('selfsigned');
const ipaddr = require('ipaddr.js');
const DB = require('./db');

let sharp = null;
try {
  sharp = require('sharp');
} catch (e) {
  console.warn('[taupe] sharp unavailable, avatar metadata stripping is disabled');
}

const port = parseInt(process.env.port || '3443', 10);
const httpPort = process.env.http_port ? parseInt(process.env.http_port, 10) : null;
const bindHost = process.env.bind_host || '127.0.0.1';
const publicUrl = process.env.public_url || 'http://localhost:' + port;
const secureCookie = process.env.secure !== 'false';
const trustProxyHops = parseInt(process.env.trust_proxy_hops || '0', 10);
const registrationInvite = process.env.registration_invite || '';
const powDifficulty = Math.min(Math.max(parseInt(process.env.pow_difficulty || '4', 10), 1), 6);
const uploadQuotaMb = parseInt(process.env.upload_quota_mb || '2048', 10);
const globalUploadGb = parseFloat(process.env.global_upload_gb || '0');
const orphanUploadHours = parseInt(process.env.orphan_upload_hours || '24', 10);
const pushAllowHosts = String(process.env.push_allow_hosts || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

const certDir = path.join(__dirname, 'cert');
if (!fs.existsSync(path.join(certDir, 'key.pem'))) {
  fs.mkdirSync(certDir, { recursive: true });
  const pems = selfsigned.generate([{ name: 'commonName', value: 'localhost' }], { days: 3650, keySize: 2048 });
  fs.writeFileSync(path.join(certDir, 'key.pem'), pems.private);
  fs.writeFileSync(path.join(certDir, 'cert.pem'), pems.cert);
  console.warn('[taupe] generated a self-signed certificate, use a real certificate behind a reverse proxy');
}
const tlsOptions = {
  key: fs.readFileSync(path.join(certDir, 'key.pem')),
  cert: fs.readFileSync(path.join(certDir, 'cert.pem')),
};

const secretFile = process.env.jwt_secret_file || path.join(__dirname, '.jwt_secret');
let jwtSecret;
if (fs.existsSync(secretFile)) {
  jwtSecret = fs.readFileSync(secretFile, 'utf8').trim();
} else {
  jwtSecret = crypto.randomBytes(64).toString('hex');
  fs.writeFileSync(secretFile, jwtSecret, { mode: 0o600 });
}

const uploadsDir = path.resolve(process.env.upload_dir || path.join(__dirname, 'uploads'));
const avatarsDir = path.join(uploadsDir, 'avatars');
fs.mkdirSync(uploadsDir, { recursive: true });
fs.mkdirSync(avatarsDir, { recursive: true });

const app = express();
app.disable('x-powered-by');
if (trustProxyHops > 0) app.set('trust proxy', trustProxyHops);

let forwardedWarningShown = false;
app.use((req, res, next) => {
  if (trustProxyHops === 0 && !forwardedWarningShown && (req.headers['x-forwarded-for'] || req.headers['x-real-ip'])) {
    forwardedWarningShown = true;
    console.warn('[taupe] forwarded headers seen but trust_proxy_hops is unset, every client shares one rate limit bucket');
  }
  next();
});

const cspHost = publicUrl.replace(/^https?:\/\//, '');
const cspConnect = ["'self'", `ws://${cspHost}`, `wss://${cspHost}`];
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'none'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      scriptSrc: ["'self'"],
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'"],
      styleSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:'],
      mediaSrc: ["'self'", 'blob:', 'data:'],
      connectSrc: cspConnect,
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: secureCookie ? { maxAge: 15552000, includeSubDomains: true } : false,
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
}));
app.use((req, res, next) => {
  res.set('Permissions-Policy', 'camera=(), microphone=(self), geolocation=(), payment=()');
  next();
});
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const rootPublicFiles = ['index.html', 'style.css', 'client.js', 'crypto.js', 'favicon.png'];
rootPublicFiles.forEach(name => {
  const abs = path.join(__dirname, name);
  app.get(name === 'index.html' ? '/' : '/' + name, (req, res, next) => {
    res.sendFile(abs, err => { if (err) next(); });
  });
});

let twemojiPack = null;
function getTwemojiPack() {
  if (!twemojiPack) {
    try {
      twemojiPack = JSON.parse(fs.readFileSync(path.join(__dirname, 'public', 'vendor', 'twemoji', 'svg-pack.json'), 'utf8'));
    } catch (e) {
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

const buckets = new Map();
function rateLimit(key, max, windowSec) {
  const now = Math.floor(Date.now() / 1000);
  let bucket = buckets.get(key);
  if (!bucket || now - bucket.start >= windowSec) {
    bucket = { start: now, count: 0 };
    buckets.set(key, bucket);
  }
  bucket.count++;
  return bucket.count <= max ? null : Math.max(1, bucket.start + windowSec - now);
}
setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  for (const [key, bucket] of buckets) {
    if (now - bucket.start > 3600) buckets.delete(key);
  }
}, 10 * 60 * 1000);
function limitByIp(name, max, windowSec) {
  return (req, res, next) => {
    const retry = rateLimit(`${name}:${req.ip || req.socket.remoteAddress || 'unknown'}`, max, windowSec);
    if (retry !== null) return res.status(429).json({ error: `Too many requests, retry in ${retry}s` });
    next();
  };
}
const registerLimiter = limitByIp('register', 5, 3600);
const lookupLimiter = limitByIp('lookup', 30, 60);
const loginLimiter = limitByIp('login', 20, 60);
const loginInfoLimiter = limitByIp('logininfo', 10, 60);
const gifLimiter = limitByIp('gif', 30, 60);
const chatLimiter = limitByIp('chat', 20, 60);
const uploadLimiter = limitByIp('upload', 60, 60);

const powChallenges = new Map();
const powChallengeTtl = 30 * 60 * 1000;
function issueChallenge() {
  const challenge = crypto.randomBytes(16).toString('hex');
  powChallenges.set(challenge, Date.now() + powChallengeTtl);
  return challenge;
}
function verifyChallenge(challenge, nonce) {
  const key = String(challenge);
  const expires = powChallenges.get(key);
  if (!expires) {
    console.warn('[pow] unknown challenge, server may have restarted');
    return false;
  }
  if (expires < Date.now()) {
    powChallenges.delete(key);
    console.warn('[pow] challenge expired');
    return false;
  }
  const hash = crypto.createHash('sha256').update(key + String(nonce)).digest('hex');
  if (!hash.startsWith('0'.repeat(powDifficulty))) {
    console.warn('[pow] invalid nonce');
    return false;
  }
  powChallenges.delete(key);
  return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [challenge, expires] of powChallenges) {
    if (expires < now) powChallenges.delete(challenge);
  }
}, 10 * 60 * 1000);

function safeUploadExt(originalname) {
  const ext = path.extname(originalname || '').toLowerCase();
  return ext === '.bin' ? '.bin' : '';
}
function makeUploadName(originalname) {
  return Date.now() + '_' + crypto.randomBytes(12).toString('hex') + safeUploadExt(originalname);
}
const chatStorage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadsDir),
  filename: (_, file, cb) => cb(null, makeUploadName(file.originalname)),
});
const chatUpload = multer({
  storage: chatStorage,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    if (!file.originalname.toLowerCase().endsWith('.bin')) return cb(new Error('Chat attachments must be encrypted .bin files'));
    if (file.mimetype.startsWith('video/')) return cb(new Error('Video not allowed'));
    cb(null, true);
  },
});
const avatarStorage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, avatarsDir),
  filename: (_, file, cb) => cb(null, Date.now() + '_' + crypto.randomBytes(8).toString('hex') + '.webp'),
});
const avatarUpload = multer({
  storage: avatarStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    if (!file.mimetype || !file.mimetype.startsWith('image/')) return cb(new Error('Only images allowed'));
    cb(null, true);
  },
});

function signToken(deviceToken) {
  return jwt.sign({ dt: deviceToken }, jwtSecret, { algorithm: 'HS256', expiresIn: '30d' });
}
function verifyToken(raw) {
  return jwt.verify(raw, jwtSecret, { algorithms: ['HS256'] });
}
function setCookie(res, token) {
  res.cookie('token', token, {
    httpOnly: true,
    secure: secureCookie,
    sameSite: secureCookie ? 'strict' : 'lax',
    maxAge: 30 * 24 * 3600 * 1000,
  });
}
function getToken(req) {
  return req.cookies?.token || req.headers.authorization?.split(' ')[1];
}

function authMiddleware(req, res, next) {
  const raw = getToken(req);
  if (!raw) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { dt } = verifyToken(raw);
    const device = DB.getDeviceByToken(dt);
    if (!device) return res.status(401).json({ error: 'Device not found' });
    const account = DB.getAccountById(device.account_id);
    if (!account) return res.status(401).json({ error: 'Account not found' });
    DB.touchDevice(dt);
    req.device = device;
    req.account = account;
    req.rawToken = dt;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Bad token' });
  }
}

function deviceName(device) {
  return device?.device_name || 'device';
}
function clientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || 'unknown');
}
function clientCountry(req) {
  const headers = req.headers || {};
  return String(headers['cf-ipcountry'] || headers['x-country-code'] || 'unknown').toUpperCase();
}

const p256SpkiPrefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
function rawEcPublicKey(rawB64) {
  const raw = Buffer.from(String(rawB64 || ''), 'base64');
  if (raw.length !== 65 || raw[0] !== 0x04) return null;
  try {
    return crypto.createPublicKey({
      key: Buffer.concat([p256SpkiPrefix, raw]),
      format: 'der',
      type: 'spki',
    });
  } catch (e) {
    return null;
  }
}
function validEcdhPublicKey(rawB64) {
  const raw = Buffer.from(String(rawB64 || ''), 'base64');
  if (raw.length !== 65 || raw[0] !== 0x04) return false;
  try {
    crypto.ECDH.convertKey(raw, 'prime256v1', null, null, 'uncompressed');
    return true;
  } catch (e) {
    return false;
  }
}
function p1363ToDer(signature) {
  if (!signature || signature.length !== 64) return signature;
  const integer = bytes => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const value = bytes.slice(start);
    const needsZero = value[0] & 0x80;
    const content = needsZero ? Buffer.concat([Buffer.from([0]), value]) : value;
    return Buffer.concat([Buffer.from([0x02, content.length]), content]);
  };
  const r = integer(signature.slice(0, 32));
  const sPart = integer(signature.slice(32));
  const body = Buffer.concat([r, sPart]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function deviceSignatureMessage(deviceId, rawB64) {
  return Buffer.concat([
    Buffer.from('taupe-device-key'),
    Buffer.from([0]),
    Buffer.from(String(deviceId)),
    Buffer.from([0]),
    Buffer.from(String(rawB64), 'base64'),
  ]);
}
function verifyDeviceSignature(identityPubB64, deviceId, publicKeyB64, signatureB64) {
  const key = rawEcPublicKey(identityPubB64);
  if (!key) return false;
  const sig = Buffer.from(String(signatureB64 || ''), 'base64');
  if (!sig.length || sig.length > 256) return false;
  const message = deviceSignatureMessage(deviceId, publicKeyB64);
  for (const encoding of ['ieee-p1363', 'der']) {
    try {
      if (crypto.verify('sha256', message, { key, dsaEncoding: encoding }, sig)) return true;
    } catch (e) {}
  }
  return false;
}
function keyRequestCode(identityPubB64, devicePubB64) {
  const first = Buffer.from(String(identityPubB64 || ''), 'base64');
  const second = Buffer.from(String(devicePubB64 || ''), 'base64');
  const sorted = Buffer.compare(first, second) <= 0
    ? Buffer.concat([first, second])
    : Buffer.concat([second, first]);
  const out = crypto.hkdfSync('sha256', sorted, Buffer.from('taupe-sync-code'), Buffer.from('taupe-sync-code'), 3);
  return Array.from(Buffer.from(out)).map(b => String(b % 100).padStart(2, '0')).join('');
}
function isPublicIp(address) {
  try {
    let parsed = ipaddr.parse(String(address));
    if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) parsed = parsed.toIPv4Address();
    return parsed.range() === 'unicast';
  } catch (e) {
    return false;
  }
}
async function resolvePushAddresses(hostname) {
  const addrs = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!addrs.length) throw new Error('No addresses');
  for (const addr of addrs) {
    if (!isPublicIp(addr.address)) throw new Error('Private address');
  }
  return addrs;
}
async function validatePushEndpoint(rawUrl) {
  let url;
  try { url = new URL(rawUrl); } catch (e) { return null; }
  if (url.protocol !== 'https:') return null;
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return null;
  if (pushAllowHosts.length && !pushAllowHosts.some(h => host === h || host.endsWith('.' + h))) return null;
  let addrs;
  if (net.isIP(host)) {
    if (!isPublicIp(host)) return null;
    addrs = [{ address: host, family: net.isIP(host) === 6 ? 6 : 4 }];
  } else {
    try { addrs = await resolvePushAddresses(host); } catch (e) { return null; }
  }
  return { url, address: addrs[0].address, family: addrs[0].family };
}
function pushRequest(endpoint, payload) {
  return new Promise(resolve => {
    const body = Buffer.from(JSON.stringify(payload));
    const req = https.request({
      protocol: 'https:',
      hostname: endpoint.url.hostname,
      port: endpoint.url.port || 443,
      path: endpoint.url.pathname + endpoint.url.search,
      method: 'POST',
      servername: endpoint.url.hostname,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': body.length,
      },
      lookup: (hostname, options, callback) => {
        callback(null, endpoint.address, endpoint.family);
      },
      timeout: 5000,
    }, res => {
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 16384) req.destroy();
      });
      res.on('end', () => resolve(true));
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
    req.end(body);
  });
}
async function pushWakeup(accountId, chatUid) {
  if (online.has(accountId)) return;
  const devices = DB.getPushableDevices(accountId);
  for (const device of devices) {
    try {
      if (!device.push_endpoint) continue;
      const endpoint = await validatePushEndpoint(device.push_endpoint);
      if (!endpoint) continue;
      await pushRequest(endpoint, { t: 'new_message', chatUid });
    } catch (e) {
      console.error('[push] failed for device', device.id, e.message);
    }
  }
}

function isValidChatAttachmentUrl(value) {
  return typeof value === 'string' && /^\/uploads\/[A-Za-z0-9][A-Za-z0-9._-]*\.bin$/.test(value) && !value.includes('..');
}
function validateChatContent(content) {
  return typeof content === 'string' && content.startsWith('e2e:') && content.length <= 65536;
}

function checkLoginBlock(ip, account) {
  const keys = [`login:ip:${ip}`];
  if (account) keys.push(`login:acct:${account.id}`);
  for (const key of keys) {
    if (DB.isRateLimited(key)) return true;
  }
  return false;
}
function recordLoginFailure(ip, account, number) {
  DB.recordFailure(`login:ip:${ip}`);
  if (account) DB.recordFailure(`login:acct:${account.id}`);
  else DB.recordFailure(`login:acct:${crypto.createHash('sha256').update(String(number)).digest('hex')}`);
}
function accountPublic(account) {
  return {
    accountId: account.id,
    chatNumber: account.chat_number,
    username: account.username,
    usernamePublic: account.username_public,
    avatarPath: account.avatar_path,
    bio: account.bio || null,
    showPresence: account.show_presence === 1,
    gifEnabled: account.gif_enabled === 1,
    identityKey: account.identity_key || null,
  };
}

function disconnectDevice(accountId, deviceId) {
  for (const [, socket] of io.of('/').sockets) {
    if (socket.accountId === accountId && socket.deviceId === deviceId) socket.disconnect(true);
  }
}
function disconnectAccount(accountId) {
  for (const [, socket] of io.of('/').sockets) {
    if (socket.accountId === accountId) socket.disconnect(true);
  }
}

app.get('/api/register/challenge', registerLimiter, (req, res) => {
  res.json({ challenge: issueChallenge(), difficulty: powDifficulty });
});

app.post('/api/register', registerLimiter, (req, res) => {
  try {
    const { challenge, nonce, invite } = req.body || {};
    if (registrationInvite && String(invite || '') !== registrationInvite) {
      return res.status(403).json({ error: 'Invite required' });
    }
    if (!verifyChallenge(challenge, nonce)) {
      return res.status(400).json({ error: 'Registration proof invalid or expired' });
    }
    const account = DB.createAccount();
    const token = crypto.randomBytes(32).toString('hex');
    const created = DB.addDevice(account.id, token);
    setCookie(res, signToken(token));
    res.json({
      accountNumber: account.number,
      chatNumber: account.chat_number,
      accountId: account.id,
      deviceId: created.id,
      deviceName: created.name,
    });
  } catch (e) {
    console.error('[register]', e);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

app.post('/api/login', loginLimiter, (req, res) => {
  const ip = clientIp(req);
  const { number } = req.body || {};
  const clean = String(number || '').replace(/\D/g, '');
  if (clean.length !== 16) return res.status(400).json({ error: 'Enter your 16-digit private number' });
  const account = DB.getAccountByNumber(clean);
  if (checkLoginBlock(ip, account)) return res.status(429).json({ error: 'Too many attempts, try later' });
  if (!account) {
    recordLoginFailure(ip, null, clean);
    return res.status(404).json({ error: 'Account not found' });
  }
  if (DB.countDevices(account.id) >= 5) return res.status(400).json({ error: 'Max 5 devices. Kick one first.' });
  const token = crypto.randomBytes(32).toString('hex');
  const created = DB.addDevice(account.id, token);
  setCookie(res, signToken(token));
  try {
    const sys = DB.addSystemMessage(account.id, 'device_login', {
      deviceName: created.name,
      ip,
      country: clientCountry(req),
      time: Math.floor(Date.now() / 1000),
    });
    if (sys) io.to(`user:${account.id}`).emit('sys:new', { message: sys });
  } catch (e) {}
  res.json({
    accountNumber: clean,
    chatNumber: account.chat_number,
    accountId: account.id,
    deviceId: created.id,
    deviceName: created.name,
    identityKey: account.identity_key || null,
  });
});

app.post('/api/login/devices', loginInfoLimiter, (req, res) => {
  const ip = clientIp(req);
  const { number } = req.body || {};
  const clean = String(number || '').replace(/\D/g, '');
  if (clean.length !== 16) return res.status(400).json({ error: 'Invalid number' });
  const account = DB.getAccountByNumber(clean);
  if (!account) {
    recordLoginFailure(ip, null, clean);
    return res.status(404).json({ error: 'Account not found' });
  }
  if (checkLoginBlock(ip, account)) return res.status(429).json({ error: 'Too many attempts, try later' });
  res.json({ devices: DB.getDevices(account.id).map(d => ({
    id: d.id, device_name: d.device_name, last_seen: d.last_seen, created_at: d.created_at,
  })) });
});

app.post('/api/login/kick', loginInfoLimiter, (req, res) => {
  const ip = clientIp(req);
  const { number, deviceId } = req.body || {};
  const clean = String(number || '').replace(/\D/g, '');
  if (clean.length !== 16) return res.status(400).json({ error: 'Invalid number' });
  const account = DB.getAccountByNumber(clean);
  if (!account) {
    recordLoginFailure(ip, null, clean);
    return res.status(404).json({ error: 'Account not found' });
  }
  if (checkLoginBlock(ip, account)) return res.status(429).json({ error: 'Too many attempts, try later' });
  const id = parseInt(deviceId, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid device' });
  DB.kickDevice(id, account.id);
  disconnectDevice(account.id, id);
  res.json({ ok: true, count: DB.countDevices(account.id) });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const devices = DB.getDevices(req.account.id).map(d => ({
    id: d.id,
    device_name: d.device_name,
    last_seen: d.last_seen,
    created_at: d.created_at,
    public_key: d.public_key,
    identity_key: d.identity_key,
    sig: d.key_sig,
    approved: d.key_approved === 1,
  }));
  res.json({
    ...accountPublic(req.account),
    deviceName: req.device.device_name,
    deviceId: req.device.id,
    deviceApproved: req.device.key_approved === 1,
    devices,
    aliases: DB.getAliases(req.account.id),
    avatars: DB.getAccountAvatars(req.account.id),
  });
});

app.post('/api/logout', authMiddleware, (req, res) => {
  DB.kickDevice(req.device.id, req.account.id);
  disconnectDevice(req.account.id, req.device.id);
  res.clearCookie('token');
  res.json({ ok: true });
});

app.delete('/api/devices/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid device' });
  DB.kickDevice(id, req.account.id);
  disconnectDevice(req.account.id, id);
  res.json({ ok: true });
});

app.post('/api/devices/kick-all', authMiddleware, (req, res) => {
  DB.kickAllDevicesExcept(req.account.id, req.rawToken);
  for (const [, socket] of io.of('/').sockets) {
    if (socket.accountId === req.account.id && socket.deviceId !== req.device.id) socket.disconnect(true);
  }
  res.json({ ok: true });
});

app.delete('/api/account', authMiddleware, (req, res) => {
  const number = String(req.body?.number || '').replace(/\D/g, '');
  if (number.length !== 16) return res.status(400).json({ error: 'Enter your 16-digit number to confirm' });
  const account = DB.getAccountByNumber(number);
  if (!account || account.id !== req.account.id) return res.status(403).json({ error: 'Invalid number' });
  disconnectAccount(req.account.id);
  DB.deleteAccount(req.account.id);
  res.clearCookie('token');
  res.json({ ok: true });
});

app.post('/api/me/pubkey', authMiddleware, (req, res) => {
  const body = req.body || {};
  const publicKey = String(body.publicKey || body.deviceKey || '');
  const identityPub = String(body.identityPub || body.identityKey || '');
  const keySig = String(body.keySig || body.signature || '');
  if (!validEcdhPublicKey(publicKey)) return res.status(400).json({ error: 'Invalid device key' });
  if (!rawEcPublicKey(identityPub)) return res.status(400).json({ error: 'Invalid identity key' });
  if (!keySig) return res.status(400).json({ error: 'Missing key signature' });
  if (!verifyDeviceSignature(identityPub, req.device.id, publicKey, keySig)) {
    return res.status(400).json({ error: 'Bad device signature' });
  }

  const storedIdentity = DB.getAccountIdentity(req.account.id);
  const identityMatches = !storedIdentity || storedIdentity === identityPub;
  if (!storedIdentity && !DB.setAccountIdentity(req.account.id, identityPub)) {
    return res.status(409).json({ error: 'Identity already set', code: 'identity_mismatch' });
  }

  const storedSignature = p1363ToDer(Buffer.from(keySig, 'base64')).toString('base64');
  DB.setDeviceKey(req.device.id, req.account.id, publicKey, identityPub, storedSignature);
  let approved = req.device.key_approved === 1;

  if (!approved && !storedIdentity) {
    DB.approveDevice(req.device.id, req.account.id, req.device.id);
    approved = true;
  }

  let request = null;
  if (!approved && identityMatches) {
    const approvedRequest = DB.getSystemMessages(req.account.id).find(m =>
      m.type === 'key_request' && m.status === 'approved' && Number(m.payload?.deviceId) === req.device.id
    );
    if (approvedRequest) {
      DB.approveDevice(req.device.id, req.account.id, approvedRequest.payload?.approvedBy || req.device.id);
      DB.completeKeyRequest(req.account.id, approvedRequest.id);
      approved = true;
    }
  }

  if (!approved) {
    request = ensureKeyRequest(req, publicKey, identityPub, storedSignature);
  } else {
    const chats = DB.getChatsForAccount(req.account.id);
    for (const chat of chats) {
      io.to(roomForChat(chat.uid)).emit('peer:key_update', { chatUid: chat.uid });
    }
  }

  res.json({
    ok: true,
    approved,
    identityKey: storedIdentity || identityPub,
    requiresIdentity: !identityMatches,
    request,
  });
});

function ensureKeyRequest(req, publicKey, identityPub, keySig) {
  const existing = DB.getSystemMessages(req.account.id).find(m =>
    m.type === 'key_request' && ['pending', 'approved'].includes(m.status) && Number(m.payload?.deviceId) === req.device.id
  );
  if (existing) return existing;
  const now = Math.floor(Date.now() / 1000);
  const accountIdentity = DB.getAccountIdentity(req.account.id) || identityPub;
  const payload = {
    deviceId: req.device.id,
    deviceName: deviceName(req.device),
    publicKey,
    identityPub,
    keySig,
    code: keyRequestCode(accountIdentity, publicKey),
    ip: clientIp(req),
    country: clientCountry(req),
    createdAt: now,
    expiresAt: now + 600,
  };
  const message = DB.addSystemMessage(req.account.id, 'key_request', payload, 'pending');
  if (message) {
    io.to(`user:${req.account.id}`).emit('sys:new', { message });
    for (const [, socket] of io.of('/').sockets) {
      if (socket.accountId === req.account.id && socket.deviceId !== req.device.id) {
        socket.emit('key:request', { request: message });
      }
    }
  }
  return message;
}

app.get('/api/pubkey/:chatNumber', authMiddleware, (req, res) => {
  const peer = DB.getAccountByChatNumber(req.params.chatNumber);
  if (!peer || peer.id === req.account.id) return res.status(404).json({ error: 'Not available' });
  if (DB.isBlocked(peer.id, req.account.id) || DB.isBlocked(req.account.id, peer.id)) {
    return res.status(404).json({ error: 'Not available' });
  }
  if (!DB.getChatUidBetween(req.account.id, peer.id)) return res.status(404).json({ error: 'Not available' });
  const devices = DB.getApprovedDevices(peer.id);
  res.json({
    identityKey: peer.identity_key || null,
    publicKeys: devices.map(d => ({
      deviceId: d.id,
      deviceName: d.device_name,
      key: d.public_key,
      sig: d.key_sig,
    })),
  });
});

app.patch('/api/me/username', authMiddleware, (req, res) => {
  let { username, isPublic } = req.body || {};
  if (username) {
    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({ error: 'Username: 3-24 chars, letters/numbers/underscore' });
    }
    username = username.toLowerCase();
    const existing = DB.db.prepare('SELECT id FROM accounts WHERE LOWER(username)=LOWER(?) AND id!=?').get(username, req.account.id);
    if (existing) return res.status(409).json({ error: 'Username taken' });
  }
  DB.setUsername(req.account.id, username || null, isPublic);
  const publicUsername = isPublic ? (username || null) : null;
  const chats = DB.getChatsForAccount(req.account.id);
  for (const chat of chats) {
    io.to(roomForChat(chat.uid)).emit('peer:profile_update', {
      chatUid: chat.uid,
      accountId: req.account.id,
      username: publicUsername,
      isPublic: isPublic ? 1 : 0,
      avatarPath: req.account.avatar_path,
    });
  }
  res.json({ ok: true, username: username || null });
});

app.patch('/api/me/bio', authMiddleware, (req, res) => {
  const bio = String(req.body?.bio || '').trim().slice(0, 120);
  DB.setBio(req.account.id, bio || null);
  for (const chat of DB.getChatsForAccount(req.account.id)) {
    io.to(roomForChat(chat.uid)).emit('peer:profile_update', {
      chatUid: chat.uid,
      accountId: req.account.id,
      bio: bio || null,
    });
  }
  res.json({ ok: true, bio: bio || null });
});

app.patch('/api/me/presence', authMiddleware, (req, res) => {
  const show = req.body?.show === true;
  DB.db.prepare('UPDATE accounts SET show_presence=? WHERE id=?').run(show ? 1 : 0, req.account.id);
  broadcastPresence(req.account.id);
  res.json({ ok: true, showPresence: show });
});

app.patch('/api/me/gif', authMiddleware, (req, res) => {
  const enabled = req.body?.enabled === true;
  DB.setGifEnabled(req.account.id, enabled);
  res.json({ ok: true, gifEnabled: enabled });
});

app.post('/api/me/avatar', authMiddleware, uploadLimiter, avatarUpload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const input = req.file.path;
  if (!sharp) {
    try { fs.unlinkSync(input); } catch (e) {}
    return res.status(503).json({ error: 'Image processing unavailable, refusing to store unstripped metadata' });
  }
  try {
    const output = input.replace(/\.webp$/, '_out.webp');
    await sharp(input).resize(512, 512, { fit: 'cover' }).webp({ quality: 90 }).toFile(output);
    try { fs.unlinkSync(input); } catch (e) {}
    const rel = '/uploads/avatars/' + path.basename(output);
    const avatars = DB.setAvatar(req.account.id, rel);
    const chats = DB.getChatsForAccount(req.account.id);
    for (const chat of chats) {
      io.to(roomForChat(chat.uid)).emit('peer:profile_update', {
        chatUid: chat.uid,
        accountId: req.account.id,
        username: req.account.username_public ? req.account.username : null,
        isPublic: req.account.username_public,
        avatarPath: rel,
      });
    }
    res.json({ avatarPath: rel, avatars });
  } catch (e) {
    try { fs.unlinkSync(input); } catch (e2) {}
    console.error('[avatar]', e.message);
    res.status(500).json({ error: 'Image processing failed' });
  }
});

app.delete('/api/me/avatars/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid avatar' });
  const result = DB.deleteAccountAvatar(req.account.id, id);
  if (!result) return res.status(404).json({ error: 'Avatar not found' });
  for (const chat of DB.getChatsForAccount(req.account.id)) {
    io.to(roomForChat(chat.uid)).emit('peer:profile_update', {
      chatUid: chat.uid,
      accountId: req.account.id,
      avatarPath: result.avatarPath,
    });
  }
  res.json(result);
});

app.get('/api/system/messages', authMiddleware, (req, res) => {
  res.json({
    messages: DB.getSystemMessages(req.account.id),
    unread: DB.unreadSystemCount(req.account.id),
  });
});

app.post('/api/system/read', authMiddleware, (req, res) => {
  const id = req.body && req.body.id != null ? parseInt(req.body.id, 10) : null;
  DB.markSystemMessagesRead(req.account.id, Number.isInteger(id) ? id : null);
  res.json({ ok: true, unread: DB.unreadSystemCount(req.account.id) });
});

app.post('/api/system/:id/resolve', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const action = req.body?.action;
  if (!Number.isInteger(id) || !['approved', 'declined'].includes(action)) {
    return res.status(400).json({ error: 'Bad request' });
  }
  const existing = DB.getSystemMessage(req.account.id, id);
  if (!existing || existing.type !== 'key_request' || existing.status !== 'pending') {
    return res.status(404).json({ error: 'Not found or already resolved' });
  }
  if (existing.payload?.expiresAt && Number(existing.payload.expiresAt) <= Math.floor(Date.now() / 1000)) {
    DB.resolveSystemMessage(req.account.id, id, 'expired');
    return res.status(410).json({ error: 'Request expired' });
  }
  const targetDeviceId = Number(existing.payload?.deviceId);
  if (!Number.isInteger(targetDeviceId)) return res.status(400).json({ error: 'Bad request' });
  if (targetDeviceId === req.device.id) {
    return res.status(403).json({ error: 'Approve this request on another device' });
  }
  if (!req.device.key_approved) return res.status(403).json({ error: 'This device is not approved' });
  const target = DB.getDeviceById(targetDeviceId);
  if (!target || target.account_id !== req.account.id) return res.status(404).json({ error: 'Device not found' });

  if (action === 'approved') {
    const identity = DB.getAccountIdentity(req.account.id);
    const code = keyRequestCode(identity, target.public_key || existing.payload?.publicKey);
    if (String(code) !== String(existing.payload?.code)) {
      return res.status(400).json({ error: 'Request code mismatch' });
    }
    const approved = DB.resolveSystemMessage(req.account.id, id, 'approved');
    if (approved) {
      DB.db.prepare("UPDATE system_messages SET payload=json_set(payload,'$.approvedBy',?) WHERE id=?")
        .run(req.device.id, id);
    }
    for (const [, socket] of io.of('/').sockets) {
      if (socket.accountId === req.account.id && socket.deviceId === target.id) {
        socket.emit('key:approved', { deviceId: target.id, requestId: id });
      }
    }
  } else {
    DB.resolveSystemMessage(req.account.id, id, 'declined');
  }
  io.to(`user:${req.account.id}`).emit('sys:updated', { id, status: action });
  res.json({ ok: true });
});

app.get('/api/aliases', authMiddleware, (req, res) => {
  res.json(DB.getAliases(req.account.id));
});
app.put('/api/aliases', authMiddleware, (req, res) => {
  const { targetNumber, alias } = req.body || {};
  if (!targetNumber || !alias || String(alias).length > 1024) return res.status(400).json({ error: 'Missing fields' });
  DB.setAlias(req.account.id, String(targetNumber).replace(/-/g, ''), alias);
  res.json({ ok: true });
});
app.delete('/api/aliases/:number', authMiddleware, (req, res) => {
  DB.deleteAlias(req.account.id, req.params.number);
  res.json({ ok: true });
});

app.get('/api/blocks', authMiddleware, (req, res) => {
  res.json(DB.getBlocks(req.account.id));
});
app.post('/api/blocks', authMiddleware, (req, res) => {
  const peer = DB.getAccountByChatNumber(req.body?.number || '');
  if (!peer) return res.status(404).json({ error: 'Not found' });
  if (peer.id === req.account.id) return res.status(400).json({ error: 'Cannot block yourself' });
  DB.blockAccount(req.account.id, peer.id);
  res.json({ ok: true });
});
app.delete('/api/blocks/:number', authMiddleware, (req, res) => {
  const peer = DB.getAccountByChatNumber(req.params.number || '');
  if (!peer) return res.status(404).json({ error: 'Not found' });
  DB.unblockAccount(req.account.id, peer.id);
  res.json({ ok: true });
});

const giphyKey = process.env.giphy_key || '';
const giphyMediaRe = /^https:\/\/([a-z0-9-]+\.)*giphy\.com\/[^\s"'<>]+$/i;
app.get('/api/gifs', authMiddleware, gifLimiter, async (req, res) => {
  if (req.account.gif_enabled !== 1) return res.status(403).json({ error: 'GIF search is opt-in in settings' });
  if (!giphyKey) return res.json({ gifs: [] });
  const q = String(req.query.q || 'speed').slice(0, 100);
  const offset = parseInt(req.query.offset, 10) || 0;
  const url = `https://api.giphy.com/v1/gifs/search?api_key=${encodeURIComponent(giphyKey)}&q=${encodeURIComponent(q)}&limit=30&rating=pg-13&offset=${offset}`;
  try {
    const apiRes = await fetch(url, { signal: AbortSignal.timeout(8000) });
    const parsed = await apiRes.json();
    if (parsed.meta && parsed.meta.status !== 200) return res.status(502).json({ error: 'GIF provider error' });
    const gifs = (parsed.data || [])
      .map(g => g.images?.fixed_height_small?.url)
      .filter(u => u && giphyMediaRe.test(u))
      .map(u => '/api/gifs/media?u=' + encodeURIComponent(u));
    res.json({ gifs });
  } catch (e) {
    console.error('[giphy]', e.message);
    res.status(502).json({ error: 'GIF provider error: ' + e.message });
  }
});

app.get('/api/gifs/media', authMiddleware, gifLimiter, async (req, res) => {
  if (req.account.gif_enabled !== 1) return res.status(403).json({ error: 'GIF search is opt-in in settings' });
  const url = String(req.query.u || '');
  if (!giphyMediaRe.test(url)) return res.status(400).json({ error: 'Invalid media URL' });
  try {
    const upstream = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(10000) });
    if (!upstream.ok) return res.status(502).json({ error: 'Upstream error' });
    const type = upstream.headers.get('content-type') || 'image/gif';
    if (!/^image\//.test(type)) return res.status(502).json({ error: 'Not an image' });
    const reader = upstream.body.getReader();
    let total = 0;
    res.set('Content-Type', type);
    res.set('Cache-Control', 'public, max-age=86400');
    res.set('X-Content-Type-Options', 'nosniff');
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > 8 * 1024 * 1024) { try { await reader.cancel(); } catch (e) {} break; }
      if (!res.write(Buffer.from(value))) {
        await new Promise(resolve => { res.once('drain', resolve); res.once('close', resolve); });
      }
      if (res.destroyed) break;
    }
    if (!res.writableEnded) res.end();
  } catch (e) {
    if (!res.headersSent) res.status(502).json({ error: 'Fetch failed' });
  }
});

app.get('/api/lookup/:query', authMiddleware, lookupLimiter, (req, res) => {
  const q = req.params.query;
  let account = null;
  if (q.startsWith('@')) account = DB.getAccountByUsername(q.slice(1));
  else {
    const clean = q.replace(/\D/g, '');
    account = clean.length >= 8 ? DB.getAccountByChatNumber(clean) : null;
  }
  if (!account || account.id === req.account.id) return res.status(404).json({ error: 'Not found' });
  if (DB.isBlocked(account.id, req.account.id) || DB.isBlocked(req.account.id, account.id)) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.json({
    number: account.chat_number,
    username: account.username_public ? account.username : null,
    avatarPath: account.avatar_path,
  });
});

app.get('/api/chats', authMiddleware, (req, res) => {
  const chats = DB.getChatsForAccount(req.account.id).filter(chat =>
    !DB.isBlocked(chat.initiator_id, chat.peer_id) && !DB.isBlocked(chat.peer_id, chat.initiator_id)
  );
  const aliases = DB.getAliases(req.account.id);
  const aliasMap = {};
  for (const alias of aliases) aliasMap[alias.target_number] = alias.alias;
  for (const chat of chats) {
    const mine = chat.initiator_id === req.account.id;
    const peerNumber = mine ? chat.peer_chat_number : chat.initiator_chat_number;
    chat.peer_alias = aliasMap[peerNumber] || null;
  }
  res.json(chats);
});

app.post('/api/chats', authMiddleware, chatLimiter, (req, res) => {
  const { peerNumber, label, chatNumber, burnMode, burnCustom } = req.body || {};
  if (!peerNumber) return res.status(400).json({ error: 'peerNumber required' });
  let peer = null;
  if (String(peerNumber).startsWith('@')) peer = DB.getAccountByUsername(String(peerNumber).slice(1));
  else peer = DB.getAccountByChatNumber(String(peerNumber).replace(/\D/g, ''));
  if (!peer || peer.id === req.account.id) return res.status(404).json({ error: 'Chat request unavailable' });
  if (DB.isBlocked(peer.id, req.account.id) || DB.isBlocked(req.account.id, peer.id)) {
    return res.status(404).json({ error: 'Chat request unavailable' });
  }
  const id = rateLimit(`chat-create:${req.account.id}`, 10, 60);
  if (id !== null) return res.status(429).json({ error: 'Too many chat requests' });
  const burn = ['baf', 'never', '1min', '5min', '10min'].includes(burnMode) ? burnMode : 'baf';
  const chat = DB.createChat(req.account.id, peer.id, label, chatNumber, burn, null);
  if (chat.status === 'pending') {
    const sys = DB.addSystemMessage(peer.id, 'chat_request', {
      chatUid: chat.uid,
      from: req.account.chat_number,
      fromId: req.account.id,
    }, 'pending');
    if (sys) io.to(`user:${peer.id}`).emit('sys:new', { message: sys });
    io.to(`user:${peer.id}`).emit('chat:request', { chatUid: chat.uid, fromNumber: req.account.chat_number });
  }
  const fullChat = DB.getChatsForAccount(req.account.id).find(c => c.uid === chat.uid);
  const peerChat = DB.getChatsForAccount(peer.id).find(c => c.uid === chat.uid);
  for (const [, socket] of io.of('/').sockets) {
    if (socket.accountId === req.account.id || socket.accountId === peer.id) socket.join(roomForChat(chat.uid));
  }
  if (peerChat) io.to(`user:${peer.id}`).emit('chat:new', { chat: peerChat });
  if (fullChat) io.to(`user:${req.account.id}`).emit('chat:new', { chat: fullChat });
  res.json(fullChat || chat);
});

app.post('/api/chats/:uid/accept', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat || chat.status !== 'pending') return res.status(404).json({ error: 'Not found' });
  if (chat.peer_id !== req.account.id) return res.status(403).json({ error: 'Forbidden' });
  if (!DB.acceptChat(chat.id, req.account.id)) return res.status(500).json({ error: 'Failed' });
  const updated = DB.getChatById(chat.id);
  for (const [, socket] of io.of('/').sockets) {
    if (socket.accountId === chat.initiator_id || socket.accountId === chat.peer_id) socket.join(roomForChat(chat.uid));
  }
  io.to(roomForChat(chat.uid)).emit('chat:accepted', { chatUid: chat.uid, by: req.account.id });
  res.json({ ok: true, chat: updated });
});

app.post('/api/chats/:uid/decline', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat || chat.status !== 'pending') return res.status(404).json({ error: 'Not found' });
  if (chat.peer_id !== req.account.id && chat.initiator_id !== req.account.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  DB.hardDeleteChat(chat.id);
  io.to(`user:${chat.initiator_id}`).emit('chat:declined', { chatUid: chat.uid });
  res.json({ ok: true });
});

app.get('/api/chats/:uid/messages', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat || !DB.isChatMember(chat, req.account.id)) return res.status(404).json({ error: 'Not found' });
  if (DB.isBlocked(chat.initiator_id, chat.peer_id) || DB.isBlocked(chat.peer_id, chat.initiator_id)) return res.status(404).json({ error: 'Not found' });
  if (chat.status !== 'accepted') return res.status(403).json({ error: 'Chat request is not accepted' });
  if ((chat.initiator_id === req.account.id && chat.deleted_by_initiator) ||
      (chat.peer_id === req.account.id && chat.deleted_by_peer)) {
    return res.status(404).json({ error: 'Not found' });
  }
  const beforeId = req.query.beforeId ? parseInt(req.query.beforeId, 10) : null;
  res.json(DB.getMessages(chat.id, req.account.id, { beforeId }));
});

app.get('/api/messages/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id' });
  const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(id);
  if (!msg) return res.status(404).json({ error: 'Not found' });
  const chat = DB.getChatById(msg.chat_id);
  if (!chat || !DB.isChatMember(chat, req.account.id)) return res.status(403).json({ error: 'Forbidden' });
  if (DB.isBlocked(chat.initiator_id, chat.peer_id) || DB.isBlocked(chat.peer_id, chat.initiator_id)) return res.status(404).json({ error: 'Not found' });
  const role = chat.initiator_id === req.account.id ? 'initiator' : 'peer';
  const deletedFor = String(msg.deleted_for || '');
  if (deletedFor === 'both' || deletedFor.includes(role)) return res.status(404).json({ error: 'Not found' });
  if ((chat.initiator_id === req.account.id && chat.deleted_by_initiator) ||
      (chat.peer_id === req.account.id && chat.deleted_by_peer)) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.json(msg);
});

app.patch('/api/chats/:uid/label', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat || !DB.isChatMember(chat, req.account.id)) return res.status(404).json({ error: 'Not found' });
  if (chat.status !== 'accepted') return res.status(403).json({ error: 'Chat not accepted' });
  const label = req.body?.label;
  if (label != null && (typeof label !== 'string' || label.length > 1024)) return res.status(400).json({ error: 'Invalid label' });
  DB.setChatLabel(chat.id, req.account.id, label || null);
  res.json({ ok: true });
});

app.patch('/api/chats/:uid/burn', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat || !DB.isChatMember(chat, req.account.id)) return res.status(404).json({ error: 'Not found' });
  if (chat.status !== 'accepted') return res.status(403).json({ error: 'Chat not accepted' });
  const mode = String(req.body?.mode || '');
  if (!['never', 'baf', '1min', '5min', '10min', 'custom'].includes(mode)) return res.status(400).json({ error: 'Invalid burn mode' });
  let custom = null;
  if (mode === 'custom') {
    custom = parseInt(req.body?.customMin, 10);
    if (!Number.isInteger(custom) || custom < 5 || custom > 1440) return res.status(400).json({ error: 'Invalid custom burn range' });
  }
  DB.setBurnMode(chat.id, req.account.id, mode, custom);
  io.to(roomForChat(chat.uid)).emit('chat:burn:pending', { chatUid: chat.uid, mode, customMin: custom, by: req.account.id });
  res.json({ ok: true });
});

app.post('/api/chats/:uid/burn-confirm', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat || !DB.isChatMember(chat, req.account.id)) return res.status(404).json({ error: 'Not found' });
  if (!DB.confirmBurn(chat.id, req.account.id)) return res.status(400).json({ error: 'Nothing to confirm' });
  const updated = DB.getChatById(chat.id);
  if (['1min', '5min', '10min', 'custom'].includes(updated.burn_mode)) activeTimedBurns.add(chat.uid);
  else activeTimedBurns.delete(chat.uid);
  io.to(roomForChat(chat.uid)).emit('chat:burn:confirmed', { chatUid: chat.uid });
  res.json({ ok: true });
});

app.post('/api/chats/:uid/history', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat || !DB.isChatMember(chat, req.account.id)) return res.status(404).json({ error: 'Not found' });
  if (chat.status !== 'accepted') return res.status(403).json({ error: 'Chat not accepted' });
  const max = parseInt(req.body?.max, 10);
  if (!Number.isInteger(max) || max === 0 || max < -1 || max > 100000) return res.status(400).json({ error: 'Invalid history limit' });
  DB.setMaxMessages(chat.id, req.account.id, max);
  io.to(roomForChat(chat.uid)).emit('chat:history:pending', { chatUid: chat.uid, max, by: req.account.id });
  res.json({ ok: true });
});

app.post('/api/chats/:uid/history-confirm', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat || !DB.isChatMember(chat, req.account.id)) return res.status(404).json({ error: 'Not found' });
  if (!DB.confirmMaxMessages(chat.id, req.account.id)) return res.status(400).json({ error: 'Nothing to confirm' });
  const trimmed = DB.enforceMaxMessages(chat.id);
  io.to(roomForChat(chat.uid)).emit('chat:history:changed', { chatUid: chat.uid, max: DB.getChatById(chat.id).max_messages });
  if (trimmed.length) io.to(roomForChat(chat.uid)).emit('msg:burned', { chatUid: chat.uid, ids: trimmed, preview: '' });
  res.json({ ok: true });
});

app.delete('/api/chats/:uid', authMiddleware, (req, res) => {
  const chat = DB.getChatByUid(req.params.uid);
  if (!chat || !DB.isChatMember(chat, req.account.id)) return res.status(404).json({ error: 'Not found' });
  const forWhom = req.body?.forWhom === 'both' ? 'both' : 'self';
  DB.deleteChat(chat.id, req.account.id, forWhom);
  io.to(roomForChat(chat.uid)).emit('chat:deleted', { chatUid: chat.uid, forWhom, by: req.account.id });
  res.json({ ok: true });
});

app.delete('/api/messages/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid message id' });
  const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(id);
  if (!msg) return res.status(404).json({ error: 'Not found' });
  const chat = DB.getChatById(msg.chat_id);
  if (!chat || !DB.isChatMember(chat, req.account.id)) return res.status(403).json({ error: 'Forbidden' });
  const forWhom = req.body?.forWhom === 'both' ? 'both' : 'self';
  if (forWhom === 'both' && msg.sender_id !== req.account.id) return res.status(403).json({ error: 'Only the sender can delete for everyone' });
  if (!DB.deleteMessage(id, req.account.id, forWhom)) return res.status(403).json({ error: 'Forbidden' });
  io.to(roomForChat(chat.uid)).emit('msg:deleted', { msgId: id, forWhom, by: req.account.id, chatUid: chat.uid });
  res.json({ ok: true });
});

app.post('/api/upload', authMiddleware, uploadLimiter, chatUpload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  if (!req.file.originalname.toLowerCase().endsWith('.bin')) {
    try { fs.unlinkSync(req.file.path); } catch (e) {}
    return res.status(400).json({ error: 'Chat attachments must be encrypted .bin files' });
  }
  if (uploadQuotaMb > 0 && DB.getUploadUsageBytes(req.account.id) + req.file.size > uploadQuotaMb * 1024 * 1024) {
    try { fs.unlinkSync(req.file.path); } catch (e) {}
    return res.status(413).json({ error: 'Upload quota exceeded' });
  }
  if (globalUploadGb > 0 && DB.getGlobalUploadUsageBytes() + req.file.size > globalUploadGb * 1024 * 1024 * 1024) {
    try { fs.unlinkSync(req.file.path); } catch (e) {}
    return res.status(507).json({ error: 'Server storage is full' });
  }
  const rel = '/uploads/' + path.basename(req.file.path);
  DB.recordUpload(req.account.id, rel, req.file.size);
  res.json({ url: rel, name: path.basename(req.file.path), type: 'file' });
});

app.use('/uploads', authMiddleware, (req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  const rel = req.path.replace(/^\/+/, '');
  const safe = path.resolve(uploadsDir, rel);
  if (!safe.startsWith(uploadsDir + path.sep)) return res.status(403).json({ error: 'Forbidden' });
  res.set('X-Content-Type-Options', 'nosniff');
  if (rel.startsWith('avatars/')) {
    return res.sendFile(safe, err => { if (err && !res.headersSent) res.status(404).json({ error: 'Not found' }); });
  }
  const fileUrl = '/uploads/' + rel;
  const msg = DB.db.prepare(`
    SELECT m.id, m.deleted_for, c.initiator_id, c.peer_id, c.status
    FROM messages m JOIN chats c ON c.id = m.chat_id
    WHERE m.file_path = ? LIMIT 1
  `).get(fileUrl);
  if (!msg || msg.status !== 'accepted' ||
      (msg.initiator_id !== req.account.id && msg.peer_id !== req.account.id)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (DB.isBlocked(msg.initiator_id, msg.peer_id) || DB.isBlocked(msg.peer_id, msg.initiator_id)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const role = msg.initiator_id === req.account.id ? 'initiator' : 'peer';
  const deletedFor = String(msg.deleted_for || '');
  if (deletedFor === 'both' || deletedFor.includes(role)) return res.status(404).json({ error: 'Not found' });
  res.set('Content-Type', 'application/octet-stream');
  res.set('Content-Disposition', 'attachment; filename="' + path.basename(safe).replace(/[^\x20-\x7e]/g, '_') + '"');
  res.set('Content-Security-Policy', 'sandbox');
  res.sendFile(safe, err => { if (err && !res.headersSent) res.status(404).json({ error: 'Not found' }); });
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (req.file?.path) { try { fs.unlinkSync(req.file.path); } catch (e) {} }
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File too large' : err.message;
    return res.status(413).json({ error: msg });
  }
  if (err) {
    if (/encrypted \.bin|Only images|Video not allowed/.test(String(err.message))) {
      if (req.file?.path) { try { fs.unlinkSync(req.file.path); } catch (e) {} }
      return res.status(400).json({ error: err.message });
    }
    console.error('[error]', err.message);
    if (!res.headersSent) res.status(err.status || 500).json({ error: 'Server error' });
  }
});

const httpsServer = https.createServer(tlsOptions, app);
const io = new Server(httpsServer, { pingInterval: 10000, pingTimeout: 10000 });
let httpServer = null;
if (httpPort) {
  httpServer = http.createServer(app);
  io.attach(httpServer);
}

function roomForChat(uid) { return `chat:${uid}`; }

io.use((socket, next) => {
  const cookieToken = socket.handshake.headers?.cookie?.match(/(?:^|;\s*)token=([^;]*)/)?.[1];
  const raw = socket.handshake.auth?.token || cookieToken;
  if (!raw) return next(new Error('Unauthorized'));
  try {
    const { dt } = verifyToken(raw);
    const device = DB.getDeviceByToken(dt);
    if (!device) return next(new Error('Device not found'));
    socket.accountId = device.account_id;
    socket.deviceId = device.id;
    next();
  } catch (e) {
    next(new Error('Bad token'));
  }
});

const online = new Map();
const activeTimedBurns = new Set();
try {
  const timed = DB.db.prepare("SELECT uid FROM chats WHERE burn_mode IN ('1min','5min','10min','custom')").all();
  for (const row of timed) activeTimedBurns.add(row.uid);
} catch (e) {}
const presenceShown = new Map();
const floodBuckets = new Map();

function floodLimited(accountId) {
  const now = Date.now();
  let bucket = floodBuckets.get(accountId);
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + 10000 };
    floodBuckets.set(accountId, bucket);
  }
  bucket.count++;
  return bucket.count > 30;
}
function isOnline(accountId) {
  const sockets = online.get(accountId);
  if (!sockets || !sockets.size) return false;
  for (const id of sockets) {
    const sock = io.sockets.sockets.get(id);
    if (sock && sock.presenceHidden !== true) return true;
  }
  return false;
}
function presenceVisibleToPeers(account) {
  return !!account && account.show_presence === 1;
}
function notifyPresence(accountId, isOnlineNow, lastSeenSec) {
  const account = DB.getAccountById(accountId);
  if (!account) return;
  const visible = presenceVisibleToPeers(account);
  const chats = DB.getChatsForAccount(accountId);
  for (const chat of chats) {
    const peerId = chat.initiator_id === accountId ? chat.peer_id : chat.initiator_id;
    io.to(`user:${peerId}`).emit('peer:presence', {
      chatUid: chat.uid,
      number: account.chat_number,
      online: visible && isOnlineNow,
      lastSeen: visible ? (lastSeenSec || null) : null,
    });
  }
}
function broadcastPresence(accountId) {
  const account = DB.getAccountById(accountId);
  if (!account) return;
  if (isOnline(accountId)) notifyPresence(accountId, true, null);
  else notifyPresence(accountId, false, account.last_seen || null);
}
function recomputePresence(accountId) {
  const now = isOnline(accountId);
  if (presenceShown.get(accountId) === now) return;
  presenceShown.set(accountId, now);
  if (!now) {
    DB.db.prepare('UPDATE accounts SET last_seen=? WHERE id=?').run(Math.floor(Date.now() / 1000), accountId);
  }
  broadcastPresence(accountId);
}
function requireChatMember(chatUid, accountId) {
  const chat = DB.getChatByUid(chatUid);
  if (!chat || !DB.isChatMember(chat, accountId)) return null;
  if (chat.status !== 'accepted') return null;
  if (DB.isBlocked(chat.initiator_id, chat.peer_id) || DB.isBlocked(chat.peer_id, chat.initiator_id)) return null;
  if ((chat.initiator_id === accountId && chat.deleted_by_initiator) ||
      (chat.peer_id === accountId && chat.deleted_by_peer)) return null;
  return chat;
}
function validString(value, max) {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

io.on('connection', socket => {
  const accountId = socket.accountId;
  if (!online.has(accountId)) online.set(accountId, new Set());
  online.get(accountId).add(socket.id);
  socket.join(`user:${accountId}`);

  const chats = DB.getChatsForAccount(accountId);
  for (const chat of chats) socket.join(roomForChat(chat.uid));

  try {
    for (const message of DB.takeKeySyncInbox(socket.deviceId)) {
      socket.emit('key:sync', { fromPublicKey: message.from_public_key, encryptedKey: message.encrypted_key });
    }
  } catch (e) {}

  recomputePresence(accountId);

  for (const chat of chats) {
    const peerId = chat.initiator_id === accountId ? chat.peer_id : chat.initiator_id;
    const peer = DB.getAccountById(peerId);
    if (!peer) continue;
    const peerOnline = isOnline(peerId);
    const visible = presenceVisibleToPeers(peer);
    socket.emit('peer:presence', {
      chatUid: chat.uid,
      number: peer.chat_number,
      online: visible && peerOnline,
      lastSeen: visible && !peerOnline ? (peer.last_seen || null) : null,
    });
  }

  const revalidate = setInterval(() => {
    const device = DB.getDeviceById(socket.deviceId);
    if (!device || device.account_id !== accountId) {
      socket.disconnect(true);
      return;
    }
    if (online.get(accountId)?.size) DB.touchDeviceById(socket.deviceId);
  }, 60000);
  if (revalidate.unref) revalidate.unref();

  socket.on('presence:report', payload => {
    if (!payload || typeof payload !== 'object') return;
    socket.presenceHidden = payload.online === false;
    recomputePresence(accountId);
  });

  socket.on('presence:get', payload => {
    if (!payload || typeof payload.number !== 'string') return;
    const peer = DB.getAccountByChatNumber(payload.number);
    if (!peer || peer.id === accountId) return;
    const uid = DB.getChatUidBetween(accountId, peer.id);
    if (!uid) return;
    const peerOnline = isOnline(peer.id);
    const visible = presenceVisibleToPeers(peer);
    socket.emit('peer:presence', {
      chatUid: uid,
      number: peer.chat_number,
      online: visible && peerOnline,
      lastSeen: visible && !peerOnline ? (peer.last_seen || null) : null,
    });
  });

  socket.on('disconnect', () => {
    const sockets = online.get(accountId);
    if (sockets) {
      sockets.delete(socket.id);
      if (!sockets.size) online.delete(accountId);
    }
    recomputePresence(accountId);
  });

  socket.on('msg:send', payload => {
    if (!payload || typeof payload !== 'object') return;
    const chatUid = payload.chatUid;
    if (!validString(chatUid, 64)) return;
    if (floodLimited(accountId)) {
      socket.emit('msg:error', { chatUid, error: 'Sending too fast' });
      return;
    }
    const chat = requireChatMember(chatUid, accountId);
    if (!chat) return;
    const content = payload.content;
    if (!content && !payload.fileUrl) return;
    if (content != null && !validateChatContent(content)) {
      socket.emit('msg:error', { chatUid, error: 'Plaintext messages are rejected' });
      return;
    }
    let fileType = payload.fileType ?? null;
    let fileUrl = payload.fileUrl ?? null;
    let fileName = payload.fileName ?? null;
    if (fileUrl != null) {
      if (!isValidChatAttachmentUrl(fileUrl)) {
        socket.emit('msg:error', { chatUid, error: 'Invalid fileUrl' });
        return;
      }
      if (!['image', 'file', 'audio'].includes(fileType)) {
        socket.emit('msg:error', { chatUid, error: 'Invalid fileType' });
        return;
      }
      const upload = DB.getUploadByPath(fileUrl);
      if (!upload || upload.account_id !== accountId || upload.message_id != null) {
        socket.emit('msg:error', { chatUid, error: 'Unknown attachment' });
        return;
      }
      if (fileName != null && (typeof fileName !== 'string' || fileName.length > 255)) fileName = null;
    } else if (fileType != null) {
      socket.emit('msg:error', { chatUid, error: 'Invalid fileType' });
      return;
    }
    let burnSeconds = null;
    if (payload.burnSeconds != null) {
      const parsed = parseInt(payload.burnSeconds, 10);
      if (Number.isInteger(parsed) && parsed > 0) burnSeconds = Math.max(5, Math.min(3600, parsed));
    }
    let replyToId = null;
    if (payload.replyToId != null) {
      const rid = parseInt(payload.replyToId, 10);
      if (!Number.isInteger(rid)) return;
      const target = DB.db.prepare('SELECT chat_id FROM messages WHERE id=?').get(rid);
      if (!target || target.chat_id !== chat.id) return;
      replyToId = rid;
    }
    const msg = DB.addMessage(chat.id, accountId, content || null, fileUrl, fileType, fileName, burnSeconds, replyToId, '[encrypted]');
    if (fileUrl) DB.attachUpload(fileUrl, accountId, msg.id);
    const safeMsg = { ...msg, content: content || null };
    io.to(roomForChat(chatUid)).emit('msg:new', { chatUid, msg: safeMsg, preview: '[encrypted]' });
    if (chat.burn_mode === 'baf') {
      const trimmed = DB.applyBurnBaf(chat.id);
      if (trimmed.length) io.to(roomForChat(chatUid)).emit('msg:burned', { chatUid, ids: trimmed, preview: '[encrypted]' });
    }
    const recipientId = chat.initiator_id === accountId ? chat.peer_id : chat.initiator_id;
    pushWakeup(recipientId, chatUid).catch(() => {});
  });

  socket.on('msg:read', payload => {
    if (!payload || typeof payload.chatUid !== 'string') return;
    const chat = requireChatMember(payload.chatUid, accountId);
    if (!chat) return;
    DB.markRead(chat.id, accountId);
    io.to(roomForChat(payload.chatUid)).emit('msg:read:ack', { chatUid: payload.chatUid, by: accountId });
  });

  socket.on('msg:spoiler:open', payload => {
    if (!payload) return;
    const id = parseInt(payload.msgId, 10);
    if (!Number.isInteger(id)) return;
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(id);
    if (!msg || !msg.burn_seconds) return;
    const chat = DB.getChatById(msg.chat_id);
    if (!chat || !DB.isChatMember(chat, accountId) || chat.status !== 'accepted') return;
    if (msg.burn_at) {
      socket.emit('msg:burn:countdown', {
        msgId: id, chatUid: chat.uid, burnAt: msg.burn_at, burnSeconds: msg.burn_seconds,
        content: msg.content, filePath: msg.file_path, fileType: msg.file_type, fileName: msg.file_name,
      });
      return;
    }
    const burnAt = Math.floor(Date.now() / 1000) + msg.burn_seconds;
    DB.setBurnAt(id, burnAt);
    io.to(roomForChat(chat.uid)).emit('msg:burn:countdown', {
      msgId: id, chatUid: chat.uid, burnAt, burnSeconds: msg.burn_seconds,
      content: msg.content, filePath: msg.file_path, fileType: msg.file_type, fileName: msg.file_name,
    });
  });

  socket.on('msg:burn:done', payload => {
    if (!payload) return;
    const id = parseInt(payload.msgId, 10);
    if (!Number.isInteger(id) || typeof payload.chatUid !== 'string') return;
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(id);
    if (!msg) return;
    const chat = DB.getChatByUid(payload.chatUid);
    if (!chat || !DB.isChatMember(chat, accountId)) return;
    if (msg.chat_id !== chat.id) return;
    DB.hardDeleteMessage(id);
    DB.refreshChatPreview(chat.id);
    io.to(roomForChat(chat.uid)).emit('msg:burned', { chatUid: chat.uid, ids: [id], preview: '' });
  });

  socket.on('msg:delete', payload => {
    if (!payload) return;
    const id = parseInt(payload.msgId, 10);
    if (!Number.isInteger(id)) return;
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(id);
    if (!msg) return;
    const chat = DB.getChatById(msg.chat_id);
    if (!chat || !DB.isChatMember(chat, accountId)) return;
    const forWhom = payload.forWhom === 'both' ? 'both' : 'self';
    if (forWhom === 'both' && msg.sender_id !== accountId) {
      socket.emit('msg:error', { chatUid: chat.uid, error: 'Only the sender can delete for everyone' });
      return;
    }
    if (!DB.deleteMessage(id, accountId, forWhom)) return;
    io.to(roomForChat(chat.uid)).emit('msg:deleted', { msgId: id, forWhom, by: accountId, chatUid: chat.uid });
  });

  socket.on('msg:react', payload => {
    if (!payload) return;
    const id = parseInt(payload.msgId, 10);
    const emoji = payload.emoji;
    if (!Number.isInteger(id) || typeof emoji !== 'string' || !emoji.length || emoji.length > 1024) return;
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(id);
    if (!msg) return;
    const chat = DB.getChatById(msg.chat_id);
    if (!chat || !DB.isChatMember(chat, accountId) || chat.status !== 'accepted') return;
    const existing = DB.db.prepare('SELECT 1 FROM reactions WHERE message_id=? AND account_id=? AND emoji=?').get(id, accountId, emoji);
    if (existing) DB.db.prepare('DELETE FROM reactions WHERE message_id=? AND account_id=? AND emoji=?').run(id, accountId, emoji);
    else DB.db.prepare('INSERT INTO reactions (message_id, account_id, emoji) VALUES (?,?,?)').run(id, accountId, emoji);
    const reactions = DB.db.prepare('SELECT account_id, emoji FROM reactions WHERE message_id=?').all(id);
    io.to(roomForChat(chat.uid)).emit('msg:reaction', { msgId: id, reactions });
  });

  socket.on('msg:played', payload => {
    if (!payload) return;
    const id = parseInt(payload.msgId, 10);
    if (!Number.isInteger(id)) return;
    const msg = DB.db.prepare('SELECT * FROM messages WHERE id=?').get(id);
    if (!msg) return;
    const chat = DB.getChatById(msg.chat_id);
    if (!chat || !DB.isChatMember(chat, accountId) || chat.status !== 'accepted') return;
    DB.db.prepare('UPDATE messages SET is_played=1 WHERE id=?').run(id);
    io.to(roomForChat(chat.uid)).emit('msg:played', { msgId: id });
  });

  socket.on('chat:join', payload => {
    if (!payload || typeof payload.chatUid !== 'string') return;
    const chat = requireChatMember(payload.chatUid, accountId);
    if (chat) socket.join(roomForChat(chat.uid));
  });

  socket.on('chat:delete', payload => {
    if (!payload || typeof payload.chatUid !== 'string') return;
    const chat = DB.getChatByUid(payload.chatUid);
    if (!chat || !DB.isChatMember(chat, accountId)) return;
    const forWhom = payload.forWhom === 'both' ? 'both' : 'self';
    DB.deleteChat(chat.id, accountId, forWhom);
    io.to(roomForChat(chat.uid)).emit('chat:deleted', { chatUid: chat.uid, forWhom, by: accountId });
  });

  socket.on('chat:burn', payload => {
    if (!payload || typeof payload.chatUid !== 'string') return;
    const chat = requireChatMember(payload.chatUid, accountId);
    if (!chat) return;
    const mode = String(payload.mode || '');
    if (!['never', 'baf', '1min', '5min', '10min', 'custom'].includes(mode)) return;
    let custom = null;
    if (mode === 'custom') {
      custom = parseInt(payload.customMin, 10);
      if (!Number.isInteger(custom) || custom < 5 || custom > 1440) return;
    }
    DB.setBurnMode(chat.id, accountId, mode, custom);
    io.to(roomForChat(chat.uid)).emit('chat:burn:pending', { chatUid: chat.uid, mode, customMin: custom, by: accountId });
  });

  socket.on('chat:history', payload => {
    if (!payload || typeof payload.chatUid !== 'string') return;
    const chat = requireChatMember(payload.chatUid, accountId);
    if (!chat) return;
    const max = parseInt(payload.max, 10);
    if (!Number.isInteger(max) || max === 0 || max < -1 || max > 100000) return;
    DB.setMaxMessages(chat.id, accountId, max);
    io.to(roomForChat(chat.uid)).emit('chat:history:pending', { chatUid: chat.uid, max, by: accountId });
  });

  socket.on('chat:burn:confirm', payload => {
    if (!payload || typeof payload.chatUid !== 'string') return;
    const chat = requireChatMember(payload.chatUid, accountId);
    if (!chat || !DB.confirmBurn(chat.id, accountId)) return;
    const updated = DB.getChatById(chat.id);
    if (['1min', '5min', '10min', 'custom'].includes(updated.burn_mode)) activeTimedBurns.add(chat.uid);
    else activeTimedBurns.delete(chat.uid);
    io.to(roomForChat(chat.uid)).emit('chat:burn:confirmed', { chatUid: chat.uid });
  });

  socket.on('chat:history:confirm', payload => {
    if (!payload || typeof payload.chatUid !== 'string') return;
    const chat = requireChatMember(payload.chatUid, accountId);
    if (!chat || !DB.confirmMaxMessages(chat.id, accountId)) return;
    const trimmed = DB.enforceMaxMessages(chat.id);
    io.to(roomForChat(chat.uid)).emit('chat:history:changed', { chatUid: chat.uid, max: DB.getChatById(chat.id).max_messages });
    if (trimmed.length) io.to(roomForChat(chat.uid)).emit('msg:burned', { chatUid: chat.uid, ids: trimmed, preview: '' });
  });

  socket.on('typing:start', payload => {
    if (!payload || typeof payload.chatUid !== 'string') return;
    const chat = requireChatMember(payload.chatUid, accountId);
    if (!chat) return;
    socket.to(roomForChat(chat.uid)).emit('typing:start', { chatUid: chat.uid, accountId });
  });
  socket.on('typing:stop', payload => {
    if (!payload || typeof payload.chatUid !== 'string') return;
    const chat = requireChatMember(payload.chatUid, accountId);
    if (!chat) return;
    socket.to(roomForChat(chat.uid)).emit('typing:stop', { chatUid: chat.uid, accountId });
  });

  socket.on('key:request', () => {
    const device = DB.getDeviceById(socket.deviceId);
    if (!device || !device.public_key || !device.identity_key || !device.key_sig) return;
    if (device.key_approved) return;
    const message = ensureKeyRequest({ account: DB.getAccountById(accountId), device, ip: socket.handshake.address, headers: socket.handshake.headers || {} }, device.public_key, device.identity_key, device.key_sig);
    if (message) socket.emit('sys:new', { message });
  });

  socket.on('key:sync', payload => {
    if (!payload) return;
    const targetDeviceId = parseInt(payload.targetDeviceId, 10);
    const requestId = parseInt(payload.requestId, 10);
    if (!Number.isInteger(targetDeviceId) || !Number.isInteger(requestId)) return;
    if (targetDeviceId === socket.deviceId) return;
    if (typeof payload.encryptedKey !== 'string' || !payload.encryptedKey.length || payload.encryptedKey.length > 262144) return;
    const request = DB.getSystemMessage(accountId, requestId);
    if (!request || request.type !== 'key_request' || !['approved'].includes(request.status)) return;
    if (Number(request.payload?.deviceId) !== targetDeviceId) return;
    const sender = DB.getDeviceById(socket.deviceId);
    const target = DB.getDeviceById(targetDeviceId);
    if (!sender || !target || target.account_id !== accountId || sender.account_id !== accountId) return;
    if (request.payload?.publicKey !== target.public_key) return;
    if (!sender.key_approved) return;
    DB.queueKeySync(target.id, sender.public_key, payload.encryptedKey, requestId);
    for (const [, sock] of io.of('/').sockets) {
      if (sock.accountId === accountId && sock.deviceId === target.id) {
        sock.emit('key:sync', { fromPublicKey: sender.public_key, encryptedKey: payload.encryptedKey });
        DB.takeKeySyncInbox(target.id);
      }
    }
  });

  socket.on('key:sync:done', payload => {
    if (!payload) return;
    const id = parseInt(payload.id, 10);
    if (!Number.isInteger(id)) return;
    const message = DB.getSystemMessage(accountId, id);
    if (!message || message.type !== 'key_request') return;
    if (!DB.completeKeyRequest(accountId, id)) return;
    const done = DB.addSystemMessage(accountId, 'key_transfer_done', {
      deviceId: message.payload.deviceId,
      deviceName: message.payload.deviceName,
    });
    io.to(`user:${accountId}`).emit('sys:updated', { id, status: 'completed' });
    if (done) io.to(`user:${accountId}`).emit('sys:new', { message: done });
  });
});

setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  if (activeTimedBurns.size > 0) {
    const placeholders = Array.from(activeTimedBurns).map(() => '?').join(',');
    const activeChats = DB.db.prepare(`SELECT * FROM chats WHERE uid IN (${placeholders})`).all(...activeTimedBurns);
    for (const chat of activeChats) {
      let minutes = { '1min': 1, '5min': 5, '10min': 10 }[chat.burn_mode];
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
    for (const item of expired) {
      if (!byChat.has(item.chat_uid)) byChat.set(item.chat_uid, []);
      byChat.get(item.chat_uid).push(item.id);
    }
    for (const [chatUid, ids] of byChat) {
      const chat = DB.getChatByUid(chatUid);
      if (!chat) continue;
      DB.refreshChatPreview(chat.id);
      io.to(roomForChat(chatUid)).emit('msg:burned', { chatUid, ids, preview: '' });
    }
  }
}, 15000);

setInterval(() => {
  DB.cleanupRateLimits();
  DB.expireSystemRequests();
  DB.purgeOrphanUploads(orphanUploadHours * 3600);
}, 10 * 60 * 1000);

setInterval(() => {
  DB.purgeDeletedRows();
  DB.checkpoint();
}, 6 * 60 * 60 * 1000);

setInterval(() => {
  DB.purgeDeletedRows();
  DB.checkpoint();
  DB.vacuum();
}, 24 * 60 * 60 * 1000);

process.on('uncaughtException', err => {
  console.error('[taupe] uncaught exception', err);
  process.exit(1);
});
process.on('unhandledRejection', err => {
  console.error('[taupe] unhandled rejection', err);
  process.exit(1);
});

httpsServer.listen(port, bindHost, () => {
  console.log(`https://localhost:${port} (bound to ${bindHost})`);
  if (bindHost === '0.0.0.0') console.warn('[taupe] binding all interfaces, prefer a reverse proxy and 127.0.0.1');
});
if (httpServer) {
  httpServer.listen(httpPort, bindHost, () => {
    console.log(`http://localhost:${httpPort} (bound to ${bindHost})`);
    if (secureCookie) console.warn('[taupe] plain HTTP is enabled while secure cookies are on');
  });
}
