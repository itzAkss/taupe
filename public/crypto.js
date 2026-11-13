const idbName = 'taupe_keys';
const idbVersion = 3;
const encPrefix = 'e2e:';
const v3Prefix = 'taupe-e2e-v3';
const v3Step = 'taupe-e2e-v3-step';
const replayWindow = 256;
const chainWindow = 1024;

function openIDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(idbName, idbVersion);
    request.onupgradeneeded = event => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains('keys')) db.createObjectStore('keys');
      if (!db.objectStoreNames.contains('session_cache')) db.createObjectStore('session_cache');
      if (!db.objectStoreNames.contains('state')) db.createObjectStore('state');
      if (!db.objectStoreNames.contains('history')) db.createObjectStore('history');
    };
    request.onsuccess = event => resolve(event.target.result);
    request.onerror = () => reject(request.error);
  });
}
async function idbGet(store, key) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const request = tx.objectStore(store).get(key);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
}
async function idbSet(store, key, value) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
async function idbDel(store, key) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function toB64(bytes) {
  let binary = '';
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i]);
  return btoa(binary);
}
function fromB64(value) {
  const normalized = String(value).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
function concat(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
function compareBytes(a, b) {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
function sortedConcat(a, b) {
  return compareBytes(a, b) <= 0 ? concat(a, b) : concat(b, a);
}
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}
async function sha512(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-512', bytes));
}
async function hkdfBytes(ikm, salt, info, length) {
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, base, length * 8);
  return new Uint8Array(bits);
}
async function hkdfAesKey(ikm, salt, info) {
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
async function ecdhBits(privateKey, publicKey) {
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256));
}
function peerRawPoint(value) {
  const text = String(value || '').trim();
  if (text.startsWith('{')) {
    const jwk = JSON.parse(text);
    const decode = part => fromB64(String(part).replace(/-/g, '+').replace(/_/g, '/'));
    const x = decode(jwk.x);
    const y = decode(jwk.y);
    if (x.length !== 32 || y.length !== 32) throw new Error('Invalid peer JWK');
    return concat(new Uint8Array([4]), x, y);
  }
  const raw = fromB64(text);
  if (raw.length === 65 && raw[0] === 4) return raw;
  if (raw.length > 65 && raw[raw.length - 65] === 4) return raw.slice(raw.length - 65);
  throw new Error('Unsupported public key format');
}
async function importPeerPublicKey(value) {
  return crypto.subtle.importKey('raw', peerRawPoint(value), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
}
function deviceSignatureMessage(deviceId, rawB64) {
  return concat(
    textEncoder.encode('taupe-device-key'),
    new Uint8Array([0]),
    textEncoder.encode(String(deviceId)),
    new Uint8Array([0]),
    fromB64(rawB64)
  );
}
function derToP1363(der) {
  let offset = 0;
  if (der[offset++] !== 0x30) return null;
  if (der[offset] & 0x80) {
    const lengthBytes = der[offset] & 0x7f;
    offset += 1 + lengthBytes;
  } else {
    offset += 1;
  }
  if (der[offset++] !== 0x02) return null;
  let rLength = der[offset++];
  if (rLength & 0x80) {
    const lengthBytes = rLength & 0x7f;
    rLength = 0;
    for (let i = 0; i < lengthBytes; i++) rLength = (rLength << 8) | der[offset++];
  }
  const r = der.slice(offset, offset + rLength);
  offset += rLength;
  if (der[offset++] !== 0x02) return null;
  let sLength = der[offset++];
  if (sLength & 0x80) {
    const lengthBytes = sLength & 0x7f;
    sLength = 0;
    for (let i = 0; i < lengthBytes; i++) sLength = (sLength << 8) | der[offset++];
  }
  const s = der.slice(offset, offset + sLength);
  const out = new Uint8Array(64);
  const rTrim = r[0] === 0 ? r.slice(1) : r;
  const sTrim = s[0] === 0 ? s.slice(1) : s;
  out.set(rTrim.slice(-32), 32 - Math.min(32, rTrim.length));
  out.set(sTrim.slice(-32), 64 - Math.min(32, sTrim.length));
  return out;
}

let deviceCache = null;
let identityCache = null;
let identityJwkCache = null;

export async function getOrCreateDeviceKeys() {
  if (deviceCache) return deviceCache;
  const existing = await idbGet('keys', 'device_ecdh_v3');
  if (existing && existing.privateKey) {
    deviceCache = existing;
    return existing;
  }
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const privateKey = await crypto.subtle.importKey(
    'jwk', privateJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
  );
  const stored = { privateKey, publicRaw: Array.from(publicRaw) };
  await idbSet('keys', 'device_ecdh_v3', stored);
  deviceCache = stored;
  return stored;
}
export async function getMyPublicKeyB64() {
  return toB64((await getOrCreateDeviceKeys()).publicRaw);
}
export async function getDeviceKeyPackage(deviceId) {
  const keys = await getOrCreateDeviceKeys();
  const identity = await getOrCreateIdentity();
  const publicKey = toB64(keys.publicRaw);
  const identityPub = toB64(identity.publicRaw);
  const keySig = await signDeviceKey(deviceId, publicKey);
  return { publicKey, identityPub, keySig };
}
async function identityWrapKey() {
  const keys = await getOrCreateDeviceKeys();
  const shared = await ecdhBits(keys.privateKey, await importPeerPublicKey(toB64(keys.publicRaw)));
  return hkdfAesKey(shared, textEncoder.encode('taupe-identity-wrap'), textEncoder.encode('taupe-identity-wrap'));
}
async function wrapIdentityJwk(jwk) {
  const publicKey = await crypto.subtle.importKey(
    'jwk', jwkToPublic(jwk), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
  );
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, await identityWrapKey(), textEncoder.encode(JSON.stringify(jwk))
  );
  return { wrapped: toB64(concat(iv, new Uint8Array(ciphertext))), publicRaw: Array.from(publicRaw) };
}
async function unwrapIdentityJwk(stored) {
  if (stored.jwk) return stored.jwk;
  if (!stored.wrapped) throw new Error('Identity key is missing');
  const combined = fromB64(stored.wrapped);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: combined.slice(0, 12) }, await identityWrapKey(), combined.slice(12)
  );
  return JSON.parse(textDecoder.decode(plaintext));
}
async function getIdentityJwk() {
  if (identityJwkCache) return identityJwkCache;
  const identity = await getOrCreateIdentity();
  identityJwkCache = identity.jwk || await unwrapIdentityJwk(identity);
  return identityJwkCache;
}
async function getOrCreateIdentity() {
  if (identityCache) return identityCache;
  let stored = await idbGet('keys', 'identity_v3');
  if (stored && stored.jwk) {
    stored = await wrapIdentityJwk(stored.jwk);
    await idbSet('keys', 'identity_v3', stored);
  }
  if (!stored || (!stored.jwk && !stored.wrapped)) {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    stored = await wrapIdentityJwk(jwk);
    await idbSet('keys', 'identity_v3', stored);
  }
  identityCache = stored;
  return stored;
}
export async function getMyIdentityPublicKeyB64() {
  return toB64((await getOrCreateIdentity()).publicRaw);
}
async function identityPrivateKey() {
  return crypto.subtle.importKey('jwk', await getIdentityJwk(), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}
export async function signDeviceKey(deviceId, publicKeyB64) {
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    await identityPrivateKey(),
    deviceSignatureMessage(deviceId, publicKeyB64)
  );
  return toB64(signature);
}
export async function verifyDeviceSignature(identityPubB64, deviceId, publicKeyB64, signatureB64) {
  try {
    const identity = await crypto.subtle.importKey(
      'raw', peerRawPoint(identityPubB64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
    );
    const message = deviceSignatureMessage(deviceId, publicKeyB64);
    const signature = fromB64(signatureB64);
    if (await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, identity, signature, message)) return true;
    const converted = derToP1363(signature);
    if (converted) {
      return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, identity, converted, message);
    }
  } catch (e) {}
  return false;
}

export async function setMyDeviceId(deviceId) {
  await idbSet('keys', 'deviceId', deviceId);
}
export async function getMyDeviceId() {
  return await idbGet('keys', 'deviceId') ?? 0;
}
export async function hasSyncedKeys() {
  const synced = await idbGet('keys', 'synced_identity');
  return !!synced;
}
export async function setOwnDeviceKeys(list) {
  await idbSet('keys', 'own_device_keys', Array.isArray(list) ? list : []);
}
export async function invalidateSession() {}
export async function clearAllSessions() {
  chainStates.clear();
}

async function getStrongPrivateKey() {
  return (await getOrCreateDeviceKeys()).privateKey;
}
async function getLegacyPrivateKeys() {
  const keys = [];
  const legacy = await idbGet('keys', 'identity');
  if (legacy && legacy.privateKeyJwk) {
    try {
      keys.push(await crypto.subtle.importKey(
        'jwk', legacy.privateKeyJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
      ));
    } catch (e) {}
  }
  const synced = await idbGet('keys', 'synced_private_keys') || [];
  for (const jwk of synced) {
    try {
      keys.push(await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']));
    } catch (e) {}
  }
  return keys;
}

async function nextCounter(chatUid) {
  const key = 'ctr:' + chatUid;
  const current = Number(await idbGet('state', key)) || 0;
  const next = current + 1;
  await idbSet('state', key, next);
  return next;
}
async function replayCheck(chatUid, senderDeviceId, counter) {
  if (!counter || counter <= 0) return false;
  const key = 'recv:' + chatUid + ':' + senderDeviceId;
  const current = await idbGet('state', key) || { max: 0, seen: [] };
  if (counter > current.max) {
    const seen = [...current.seen.filter(n => n > counter - replayWindow), counter];
    await idbSet('state', key, { max: counter, seen });
    return true;
  }
  if (current.seen.includes(counter)) return false;
  if (counter <= current.max - replayWindow) return false;
  const seen = [...current.seen.filter(n => n > current.max - replayWindow), counter];
  await idbSet('state', key, { max: current.max, seen });
  return true;
}

const chainStates = new Map();
async function chainKeyAt(cacheKey, targetIndex, rootMaker) {
  let state = chainStates.get(cacheKey);
  if (!state) {
    state = { ck: null, index: 0, window: new Map() };
    chainStates.set(cacheKey, state);
  }
  if (state.ck && targetIndex === state.index) return state.ck;
  if (state.window.has(targetIndex)) return state.window.get(targetIndex);
  let chain = state.ck;
  let index = state.index;
  if (!chain || targetIndex < index) {
    chain = await rootMaker();
    index = 1;
    state.window.clear();
    state.window.set(1, chain);
  }
  while (index < targetIndex) {
    chain = new Uint8Array(await crypto.subtle.sign({ name: 'HMAC' }, await crypto.subtle.importKey(
      'raw', chain, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    ), textEncoder.encode(v3Step)));
    index++;
    state.window.set(index, chain);
    while (state.window.size > chainWindow) {
      const first = state.window.keys().next().value;
      state.window.delete(first);
    }
  }
  state.ck = chain;
  state.index = index;
  chainStates.set(cacheKey, state);
  return chain;
}
async function v3ChainRoot(privateKey, myPub, peerPub, chatUid) {
  const shared = await ecdhBits(privateKey, await importPeerPublicKey(toB64(peerPub)));
  const salt = await sha256(textEncoder.encode(v3Prefix + chatUid));
  const info = concat(
    textEncoder.encode(v3Prefix), new Uint8Array([0]),
    textEncoder.encode(chatUid), new Uint8Array([0]),
    sortedConcat(myPub, peerPub)
  );
  return hkdfBytes(shared, salt, info, 32);
}
async function v3MessageKey(ephemeralSecret, chainKey, myPub, peerPub, chatUid) {
  const salt = await sha256(textEncoder.encode(v3Prefix + chatUid));
  const info = concat(
    textEncoder.encode(v3Prefix), new Uint8Array([0]),
    textEncoder.encode(chatUid), new Uint8Array([0]),
    sortedConcat(myPub, peerPub)
  );
  const ikm = concat(ephemeralSecret, chainKey);
  return hkdfAesKey(ikm, salt, info);
}
function v3Aad(chatUid, fromDevice, toDevice, counter) {
  return textEncoder.encode(`{"v":3,"c":${JSON.stringify(chatUid)},"f":${fromDevice},"t":${toDevice},"n":${counter}}`);
}

export async function encryptMsg(plaintext, chatUid, senderDeviceId, recipients) {
  const list = Array.isArray(recipients) ? recipients : [];
  const usable = list.filter(item => item && item.key);
  if (!usable.length) throw new Error('No usable recipient keys');
  const keys = await getOrCreateDeviceKeys();
  const myPub = new Uint8Array(keys.publicRaw);
  const counter = await nextCounter(chatUid);
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ephemeralPub = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  const slots = [];
  for (const recipient of usable) {
    try {
      const peerPub = peerRawPoint(recipient.key);
      const peerKey = await importPeerPublicKey(recipient.key);
      const ephemeralSecret = await ecdhBits(ephemeral.privateKey, peerKey);
      const cacheKey = 'v3s|' + chatUid + '|' + toB64(myPub) + '|' + toB64(peerPub);
      const chainKey = await chainKeyAt(cacheKey, counter, () => v3ChainRoot(keys.privateKey, myPub, peerPub, chatUid));
      const messageKey = await v3MessageKey(ephemeralSecret, chainKey, myPub, peerPub, chatUid);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: v3Aad(chatUid, senderDeviceId, recipient.deviceId, counter) },
        messageKey,
        textEncoder.encode(plaintext)
      );
      slots.push({ d: recipient.deviceId, p: toB64(concat(iv, new Uint8Array(ciphertext))) });
    } catch (e) {}
  }
  if (!slots.length) throw new Error('No usable recipient keys');
  const envelope = { v: 3, c: chatUid, f: senderDeviceId, n: counter, e: toB64(ephemeralPub), s: slots };
  return encPrefix + toB64(textEncoder.encode(JSON.stringify(envelope)));
}

export async function decryptMsg(payload, chatUid, peerPublicKeys, options = {}) {
  if (!isEncrypted(payload)) return payload;
  const raw = payload.slice(encPrefix.length);
  let parsed;
  try { parsed = JSON.parse(textDecoder.decode(fromB64(raw))); } catch (e) { return '[decryption failed]'; }
  if (Array.isArray(parsed)) return decryptLegacyV1(parsed, peerPublicKeys);
  if (parsed.v === 3) return decryptV3(parsed, chatUid, peerPublicKeys, options.enforceReplay !== false);
  if (parsed.v === 2) return decryptLegacyV2(parsed, peerPublicKeys);
  return '[decryption failed]';
}

async function decryptV3(envelope, chatUid, peerPublicKeys, enforceReplay = true) {
  try {
    if (chatUid && envelope.c !== chatUid) return '[decryption failed]';
    const counter = Number(envelope.n);
    if (!counter || counter <= 0) return '[decryption failed]';
    const peerKeys = Array.isArray(peerPublicKeys) ? peerPublicKeys.filter(item => item && item.key) : [];
    if (!peerKeys.length) return '[encrypted]';
    const keys = await getOrCreateDeviceKeys();
    const myPub = new Uint8Array(keys.publicRaw);
    const ownPublic = toB64(myPub);
    if (!peerKeys.some(item => item.key === ownPublic)) peerKeys.push({ deviceId: await getMyDeviceId(), key: ownPublic });
    const myDeviceId = await getMyDeviceId();
    const ephemeralPub = await crypto.subtle.importKey(
      'raw', peerRawPoint(envelope.e), { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const slots = Array.isArray(envelope.s) ? envelope.s : [];
    const ordered = [...slots].sort((a, b) => (a.d === myDeviceId ? -1 : b.d === myDeviceId ? 1 : 0));
    for (const slot of ordered) {
      if (!slot || !slot.p) continue;
      const combined = fromB64(slot.p);
      if (combined.length <= 12) continue;
      const iv = combined.slice(0, 12);
      const ciphertext = combined.slice(12);
      for (const peer of peerKeys) {
        try {
          const peerPub = peerRawPoint(peer.key);
          const staticSecret = await ecdhBits(keys.privateKey, await importPeerPublicKey(peer.key));
          const salt = await sha256(textEncoder.encode(v3Prefix + envelope.c));
          const info = concat(
            textEncoder.encode(v3Prefix), new Uint8Array([0]),
            textEncoder.encode(envelope.c), new Uint8Array([0]),
            sortedConcat(myPub, peerPub)
          );
          const cacheKey = 'v3r|' + envelope.c + '|' + toB64(myPub) + '|' + toB64(peerPub);
          const root = () => hkdfBytes(staticSecret, salt, info, 32);
          const chainKey = await chainKeyAt(cacheKey, counter, root);
          const ephemeralSecret = await ecdhBits(keys.privateKey, ephemeralPub);
          const messageKey = await hkdfAesKey(
            concat(ephemeralSecret, chainKey), salt, info
          );
          const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, additionalData: v3Aad(envelope.c, envelope.f, Number(slot.d), counter) },
            messageKey,
            ciphertext
          );
          if (enforceReplay && Number(envelope.f) !== Number(myDeviceId) && !await replayCheck(envelope.c, envelope.f, counter)) return '[replayed]';
          return textDecoder.decode(plaintext);
        } catch (e) {}
      }
    }
    const forThisDevice = slots.some(slot => Number(slot.d) === Number(myDeviceId));
    return forThisDevice ? '[decryption failed]' : '[encrypted on another device]';
  } catch (e) {
    return '[decryption failed]';
  }
}
async function decryptLegacyV2(envelope, peerPublicKeys) {
  const peerKeys = Array.isArray(peerPublicKeys) ? peerPublicKeys.filter(item => item && item.key) : [];
  const myDeviceId = await getMyDeviceId();
  const candidates = [await getStrongPrivateKey(), ...await getLegacyPrivateKeys()];
  const keys = await getOrCreateDeviceKeys();
  const myPub = new Uint8Array(keys.publicRaw);
  for (const slot of envelope.s || []) {
    const combined = fromB64(slot.p);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    for (const privateKey of candidates) {
      for (const peer of peerKeys) {
        try {
          const peerPub = peerRawPoint(peer.key);
          const shared = await ecdhBits(privateKey, await importPeerPublicKey(peer.key));
          const salt = await sha256(textEncoder.encode('taupe-e2e-v2' + envelope.c));
          const info = concat(
            textEncoder.encode('taupe-e2e-v2'), new Uint8Array([0]),
            textEncoder.encode(envelope.c), new Uint8Array([0]),
            sortedConcat(myPub, peerPub)
          );
          const aesKey = await hkdfAesKey(shared, salt, info);
          const aad = textEncoder.encode(`{"v":2,"c":${JSON.stringify(envelope.c)},"f":${envelope.f},"t":${slot.d},"n":${envelope.n}}`);
          const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, aesKey, ciphertext);
          return textDecoder.decode(plaintext);
        } catch (e) {}
      }
    }
  }
  return '[decryption failed]';
}
async function decryptLegacyV1(slots, peerPublicKeys) {
  const peerKeys = Array.isArray(peerPublicKeys) ? peerPublicKeys.filter(item => item && item.key) : [];
  const candidates = [...await getLegacyPrivateKeys(), await getStrongPrivateKey()];
  for (const slot of slots) {
    const combined = fromB64(slot.p);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    for (const privateKey of candidates) {
      for (const peer of peerKeys) {
        try {
          const shared = await ecdhBits(privateKey, await importPeerPublicKey(peer.key));
          const hash = await sha256(shared);
          const aesKey = await crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['decrypt']);
          const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
          return textDecoder.decode(plaintext);
        } catch (e) {}
      }
    }
  }
  return '[decryption failed]';
}

export async function encryptFile(blob, chatUid, senderDeviceId, recipients) {
  const keys = await getOrCreateDeviceKeys();
  const fileKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const rawFileKey = new Uint8Array(await crypto.subtle.exportKey('raw', fileKey));
  const meta = JSON.stringify({ key: toB64(rawFileKey), name: blob.name || 'file', type: blob.type || 'application/octet-stream' });
  const keyEnvelope = await encryptMsg(meta, chatUid, senderDeviceId, recipients);
  const header = textEncoder.encode(JSON.stringify({ v: 3, k: keyEnvelope }));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: header },
    fileKey,
    await blob.arrayBuffer()
  );
  const length = new Uint8Array(new Uint32Array([header.length]).buffer);
  return new Blob([length, header, iv, new Uint8Array(ciphertext)], { type: 'application/octet-stream' });
}
export async function decryptFile(blob, chatUid, peerPublicKeys, options = {}) {
  const data = new Uint8Array(await blob.arrayBuffer());
  if (data.length < 16) throw new Error('Invalid encrypted file');
  const headerLength = new DataView(data.buffer).getUint32(0, true);
  const header = data.slice(4, 4 + headerLength);
  const parsed = JSON.parse(textDecoder.decode(header));
  if (parsed.v === 3 && parsed.k) {
    const meta = JSON.parse(await decryptMsg(parsed.k, chatUid, peerPublicKeys, options));
    const iv = data.slice(4 + headerLength, 4 + headerLength + 12);
    const ciphertext = data.slice(4 + headerLength + 12);
    const key = await crypto.subtle.importKey('raw', fromB64(meta.key), { name: 'AES-GCM' }, false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: header }, key, ciphertext);
    return { blob: new Blob([plaintext], { type: meta.type || 'application/octet-stream' }), name: meta.name || 'file', type: meta.type || 'application/octet-stream' };
  }
  return decryptLegacyFile(data, headerLength, parsed, chatUid, peerPublicKeys);
}
async function decryptLegacyFile(data, headerLength, parsed, chatUid, peerPublicKeys) {
  const iv = data.slice(4 + headerLength, 4 + headerLength + 12);
  const ciphertext = data.slice(4 + headerLength + 12);
  const peerKeys = Array.isArray(peerPublicKeys) ? peerPublicKeys.filter(item => item && item.key) : [];
  const candidates = [...await getLegacyPrivateKeys(), await getStrongPrivateKey()];
  for (const slot of parsed) {
    const combined = fromB64(slot.k);
    const keyIv = combined.slice(0, 12);
    const encryptedKey = combined.slice(12);
    for (const privateKey of candidates) {
      for (const peer of peerKeys) {
        try {
          const shared = await ecdhBits(privateKey, await importPeerPublicKey(peer.key));
          const hash = await sha256(shared);
          const wrapKey = await crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['decrypt']);
          const rawFileKey = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: keyIv }, wrapKey, encryptedKey);
          const fileKey = await crypto.subtle.importKey('raw', rawFileKey, { name: 'AES-GCM' }, false, ['decrypt']);
          const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, fileKey, ciphertext);
          return { blob: new Blob([plaintext]), name: 'file', type: 'application/octet-stream' };
        } catch (e) {}
      }
    }
  }
  throw new Error('File decryption failed');
}

export function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith(encPrefix);
}

export async function getSafetyNumber(myIdentityPubB64, peerIdentityPubB64) {
  if (!myIdentityPubB64 || !peerIdentityPubB64) return null;
  try {
    const first = peerRawPoint(myIdentityPubB64);
    const second = peerRawPoint(peerIdentityPubB64);
    let hash = sortedConcat(first, second);
    hash = concat(textEncoder.encode('TAUPE-SAFETY-V2'), hash);
    for (let i = 0; i < 5200; i++) hash = await sha512(hash);
    let digits = '';
    for (let i = 0; i < 30; i++) digits += String(hash[i] % 100).padStart(2, '0');
    return digits.match(/.{5}/g).join(' ');
  } catch (e) {
    return null;
  }
}
export async function getKeySyncCode(pubA, pubB) {
  try {
    const a = peerRawPoint(pubA);
    const b = peerRawPoint(pubB);
    const out = await hkdfBytes(sortedConcat(a, b), textEncoder.encode('taupe-sync-code'), textEncoder.encode('taupe-sync-code'), 32);
    return String(out[0] % 100).padStart(2, '0') + String(out[1] % 100).padStart(2, '0') + String(out[2] % 100).padStart(2, '0');
  } catch (e) {
    return null;
  }
}

function pinKey(peerNumber) { return 'pin:' + peerNumber; }
function normalizeDevices(devices) {
  return [...(devices || [])].sort((a, b) => Number(a.d) - Number(b.d));
}
export async function getPeerPin(peerNumber) {
  return await idbGet('state', pinKey(peerNumber));
}
export async function pinPeerKeys(peerNumber, identityPub, devices) {
  const previous = await getPeerPin(peerNumber);
  const report = { identityChanged: false, added: [], changed: [], firstPin: !previous, blocking: false };
  if (previous) {
    if (previous.identityPub && identityPub && previous.identityPub !== identityPub) report.identityChanged = true;
    const previousMap = new Map((previous.devices || []).map(d => [Number(d.d), d.k]));
    for (const device of devices || []) {
      const prior = previousMap.get(Number(device.d));
      if (prior == null) report.added.push(Number(device.d));
      else if (prior !== device.k) report.changed.push(Number(device.d));
    }
  }
  report.blocking = report.identityChanged || report.changed.length > 0;
  const stored = {
    identityPub: identityPub || previous?.identityPub || '',
    devices: normalizeDevices((devices || []).map(d => ({ d: Number(d.d), k: d.k }))),
    verified: previous ? (!report.blocking && report.added.length === 0 && previous.verified === true) : false,
    blocking: report.blocking,
    updatedAt: Date.now(),
  };
  await idbSet('state', pinKey(peerNumber), stored);
  return report;
}
export async function acknowledgePeerKeys(peerNumber, keepVerified) {
  const pin = await getPeerPin(peerNumber);
  if (!pin) return;
  pin.blocking = false;
  if (!keepVerified) pin.verified = false;
  await idbSet('state', pinKey(peerNumber), pin);
}
export async function setPeerVerified(peerNumber, verified) {
  const pin = await getPeerPin(peerNumber);
  if (!pin) return;
  pin.verified = !!verified;
  if (verified) pin.blocking = false;
  await idbSet('state', pinKey(peerNumber), pin);
}
export async function isPeerBlocked(peerNumber) {
  const pin = await getPeerPin(peerNumber);
  return !!pin?.blocking;
}

export async function exportPrivateKeyForSync() {
  return getIdentityJwk();
}
export async function exportKeysForSync() {
  return [await exportPrivateKeyForSync()];
}
export async function encryptKeyForSync(keysOrJwk, theirPubB64) {
  const identityJwk = await getIdentityJwk();
  const payload = JSON.stringify({ v: 2, keys: [], identityJwk });
  const myPrivate = await getStrongPrivateKey();
  const shared = await ecdhBits(myPrivate, await importPeerPublicKey(theirPubB64));
  const aesKey = await crypto.subtle.importKey('raw', shared, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, textEncoder.encode(payload));
  return toB64(concat(iv, new Uint8Array(ciphertext)));
}
export async function decryptSyncedKey(encryptedKeyB64, theirPubB64) {
  const myPrivate = await getStrongPrivateKey();
  const shared = await ecdhBits(myPrivate, await importPeerPublicKey(theirPubB64));
  const aesKey = await crypto.subtle.importKey('raw', shared, { name: 'AES-GCM' }, false, ['decrypt']);
  const combined = fromB64(encryptedKeyB64);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: combined.slice(0, 12) }, aesKey, combined.slice(12));
  const parsed = JSON.parse(textDecoder.decode(plaintext));
  const jwk = parsed.identityJwk || (Array.isArray(parsed) ? parsed[0] : parsed);
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d) throw new Error('No identity key in sync payload');
  identityJwkCache = jwk;
  identityCache = { ...await wrapIdentityJwk(jwk), jwk };
  await idbSet('keys', 'identity_v3', { wrapped: identityCache.wrapped, publicRaw: identityCache.publicRaw });
  await idbSet('keys', 'synced_identity', true);
  return 1;
}
function jwkToPublic(jwk) {
  const copy = { ...jwk };
  delete copy.d;
  delete copy.key_ops;
  delete copy.ext;
  return copy;
}
async function metaKey() {
  const identity = await getIdentityJwk();
  const raw = fromB64(identity.d);
  return hkdfAesKey(raw, textEncoder.encode('taupe-meta-v1'), textEncoder.encode('taupe-meta-v1'));
}
export async function encryptMeta(value) {
  if (value == null || value === '') return value;
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await metaKey(), textEncoder.encode(String(value)));
    return 'm1:' + toB64(concat(iv, new Uint8Array(ciphertext)));
  } catch (e) {
    return value;
  }
}
export async function decryptMeta(value) {
  if (typeof value !== 'string' || !value.startsWith('m1:')) return value;
  try {
    const combined = fromB64(value.slice(3));
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: combined.slice(0, 12) }, await metaKey(), combined.slice(12)
    );
    return textDecoder.decode(plaintext);
  } catch (e) {
    return '[encrypted]';
  }
}

export async function saveImportedHistory(bundle) {
  if (!bundle || !Array.isArray(bundle.chats)) return 0;
  let saved = 0;
  for (const chat of bundle.chats) {
    if (!chat || !chat.uid || !Array.isArray(chat.messages)) continue;
    const existing = await idbGet('history', chat.uid) || [];
    const map = new Map(existing.map(message => [String(message.id), message]));
    for (const message of chat.messages) {
      if (!message || message.id == null || typeof message.text !== 'string') continue;
      map.set(String(message.id), {
        id: Number(message.id),
        sender_id: Number(message.sender_id),
        created_at: Number(message.created_at) || 0,
        text: message.text,
      });
      saved++;
    }
    await idbSet('history', chat.uid, [...map.values()]);
  }
  return saved;
}

export async function getHistoryForChat(chatUid) {
  if (!chatUid) return [];
  return await idbGet('history', chatUid) || [];
}

export function cryptoSupported() {
  return !!(window.crypto?.subtle && window.indexedDB);
}

export async function stripImageMetadata(file) {
  if (!file || !file.type || !file.type.startsWith('image/')) return file;
  if (file.type === 'image/gif' || file.type === 'image/svg+xml') return file;
  try {
    const bitmap = await createImageBitmap(file);
    const canvas = document.createElement('canvas');
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    canvas.getContext('2d').drawImage(bitmap, 0, 0);
    const type = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
    const blob = await new Promise(resolve => canvas.toBlob(resolve, type, 0.92));
    bitmap.close?.();
    return new File([blob], file.name.replace(/\.[^.]+$/, type === 'image/png' ? '.png' : '.jpg'), { type });
  } catch (e) {
    return file;
  }
}
