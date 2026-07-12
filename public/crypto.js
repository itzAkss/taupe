const IDB_NAME = 'taupe_keys';
const IDB_VER  = 1;

function openIDB() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(IDB_NAME, IDB_VER);
    r.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('keys'))
        db.createObjectStore('keys');
      if (!db.objectStoreNames.contains('session_cache'))
        db.createObjectStore('session_cache');
    };
    r.onsuccess = e => res(e.target.result);
    r.onerror   = () => rej(r.error);
  });
}

async function idbGet(store, key) {
  const db = await openIDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(store, 'readonly');
    const r  = tx.objectStore(store).get(key);
    r.onsuccess = () => res(r.result ?? null);
    r.onerror   = () => rej(r.error);
  });
}

async function idbSet(store, key, val) {
  const db = await openIDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(val, key);
    tx.oncomplete = () => res();
    tx.onerror    = () => rej(tx.error);
  });
}

async function idbDel(store, key) {
  const db = await openIDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => res();
    tx.onerror    = () => rej(tx.error);
  });
}

let _identityCache = null;

export async function getOrCreateIdentityKey() {
  if (_identityCache) return _identityCache;

  const existing = await idbGet('keys', 'identity');
  if (existing) { _identityCache = existing; return existing; }

  const kp = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  const pubRaw  = await crypto.subtle.exportKey('raw', kp.publicKey);
  const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);

  const stored = {
    publicKeyRaw:  Array.from(new Uint8Array(pubRaw)),
    privateKeyJwk: privJwk,
  };
  await idbSet('keys', 'identity', stored);
  _identityCache = stored;
  return stored;
}

export async function getMyPublicKeyB64() {
  const id = await getOrCreateIdentityKey();
  return btoa(String.fromCharCode(...id.publicKeyRaw));
}

export async function setMyDeviceId(deviceId) {
  await idbSet('keys', 'deviceId', deviceId);
}

export async function getMyDeviceId() {
  return await idbGet('keys', 'deviceId') ?? 0;
}

async function loadMyPrivateKey() {
  const id = await getOrCreateIdentityKey();
  return crypto.subtle.importKey(
    'jwk', id.privateKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, ['deriveKey', 'deriveBits']
  );
}

async function importPeerPublicKey(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'raw', raw,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, []
  );
}

const _sessionMem = new Map();
const MAX_SESSION_CACHE = 100;

async function getSessionKey(peerChatNumber, peerPubB64) {
  if (_sessionMem.has(peerChatNumber)) return _sessionMem.get(peerChatNumber);

  if (_sessionMem.size >= MAX_SESSION_CACHE) {
    const firstKey = _sessionMem.keys().next().value;
    _sessionMem.delete(firstKey);
  }

  const cached = await idbGet('session_cache', peerChatNumber);
  if (cached && cached.peerPub === peerPubB64) {
    const aesKey = await crypto.subtle.importKey(
      'raw', new Uint8Array(cached.keyBytes),
      { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
    _sessionMem.set(peerChatNumber, aesKey);
    return aesKey;
  }

  const myPriv   = await loadMyPrivateKey();
  const theirPub = await importPeerPublicKey(peerPubB64);

  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: theirPub },
    myPriv, 256
  );

  const hashed = await crypto.subtle.digest('SHA-256', bits);
  const aesKey = await crypto.subtle.importKey(
    'raw', hashed,
    { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
  );

  const exported = await crypto.subtle.exportKey('raw', aesKey);
  await idbSet('session_cache', peerChatNumber, {
    peerPub:  peerPubB64,
    keyBytes: Array.from(new Uint8Array(exported)),
  });

  _sessionMem.set(peerChatNumber, aesKey);
  return aesKey;
}

export async function invalidateSession(peerChatNumber) {
  _sessionMem.delete(peerChatNumber);
  await idbDel('session_cache', peerChatNumber);
}

const ENC_PREFIX = 'e2e:';

export async function encryptMsg(plaintext, peerChatNumber, peerPubB64OrKeys) {
  const keys = Array.isArray(peerPubB64OrKeys)
    ? peerPubB64OrKeys
    : [{ deviceId: 0, key: peerPubB64OrKeys }];

  const results = [];
  for (const { deviceId, key } of keys) {
    if (!key) continue;

    const sessionKey = await getSessionKey(peerChatNumber + ':' + deviceId, key);
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      sessionKey,
      new TextEncoder().encode(plaintext)
    );
    const combined = new Uint8Array(12 + ct.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ct), 12);
    results.push({ d: deviceId, p: btoa(String.fromCharCode(...combined)) });
  }

  return ENC_PREFIX + btoa(JSON.stringify(results));
}

export async function decryptMsg(payload, peerChatNumber, peerPubB64OrKeys) {
  if (!isEncrypted(payload)) return payload;
  const b64 = payload.slice(ENC_PREFIX.length);

  const keys = Array.isArray(peerPubB64OrKeys)
    ? peerPubB64OrKeys
    : (peerPubB64OrKeys ? [{ deviceId: 0, key: peerPubB64OrKeys }] : []);

  if (!keys.length) return '[encrypted — no key]';

  let slots = null;
  try {
    const parsed = JSON.parse(atob(b64));
    if (Array.isArray(parsed)) slots = parsed;
  } catch {}

  if (slots) {

    const myDeviceId = await getMyDeviceId();
    const mySlot = slots.find(s => s.d === myDeviceId);
    if (mySlot) {
      for (const { key } of keys) {
        if (!key) continue;
        try {
          const sessionKey = await getSessionKey(peerChatNumber + ':' + myDeviceId, key);
          const combined   = Uint8Array.from(atob(mySlot.p), c => c.charCodeAt(0));
          const pt = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: combined.slice(0, 12) },
            sessionKey, combined.slice(12)
          );
          return new TextDecoder().decode(pt);
        } catch {}
      }
    }

    for (const { d: deviceId, p: encB64 } of slots) {
      for (const { key } of keys) {
        if (!key) continue;
        try {
          const sessionKey = await getSessionKey(peerChatNumber + ':' + deviceId, key);
          const combined   = Uint8Array.from(atob(encB64), c => c.charCodeAt(0));
          const pt = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: combined.slice(0, 12) },
            sessionKey, combined.slice(12)
          );
          return new TextDecoder().decode(pt);
        } catch {}
      }
    }
    return '[unable to decrypt — key mismatch or corrupted]';
  }

  for (const { key } of keys) {
    if (!key) continue;
    for (const cacheKey of [peerChatNumber, peerChatNumber + ':0']) {
      try {
        const sessionKey = await getSessionKey(cacheKey, key);
        const combined   = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        const pt = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: combined.slice(0, 12) },
          sessionKey, combined.slice(12)
        );
        return new TextDecoder().decode(pt);
      } catch {}
    }
  }
  return '[unable to decrypt — key mismatch or corrupted]';
}

export async function encryptFile(blob, peerChatNumber, peerPubB64OrKeys) {
  const keys = Array.isArray(peerPubB64OrKeys) ? peerPubB64OrKeys : [{ deviceId: 0, key: peerPubB64OrKeys }];
  const { deviceId, key } = keys[0];
  if (!key) throw new Error("No key");

  const sessionKey = await getSessionKey(peerChatNumber + ':' + deviceId, key);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const buf = await blob.arrayBuffer();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sessionKey, buf);

  const combined = new Uint8Array(iv.length + ct.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ct), iv.length);

  return new Blob([combined], { type: 'application/octet-stream' });
}

export async function decryptFile(encryptedBlob, peerChatNumber, peerPubB64OrKeys) {
  const keys = Array.isArray(peerPubB64OrKeys) ? peerPubB64OrKeys : [{ deviceId: 0, key: peerPubB64OrKeys }];
  const buf = await encryptedBlob.arrayBuffer();
  const combined = new Uint8Array(buf);
  const iv = combined.slice(0, 12);
  const ct = combined.slice(12);

  for (const { deviceId, key } of keys) {
    if (!key) continue;
    try {
      const sessionKey = await getSessionKey(peerChatNumber + ':' + deviceId, key);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, sessionKey, ct);
      return new Blob([pt]);
    } catch {}
  }
  throw new Error("Decryption failed");
}

export function isEncrypted(s) {
  return typeof s === 'string' && s.startsWith(ENC_PREFIX);
}

export async function getSafetyNumber(myPubB64, peerPubB64) {
  if (!myPubB64 || !peerPubB64) return null;
  try {
    const str1 = myPubB64 < peerPubB64 ? myPubB64 : peerPubB64;
    const str2 = myPubB64 < peerPubB64 ? peerPubB64 : myPubB64;
    const raw = new TextEncoder().encode(str1 + str2);
    
    const hash = await crypto.subtle.digest('SHA-256', raw);
    const bytes = new Uint8Array(hash);
    return Array.from(bytes.slice(0, 8))
      .map(b => b.toString(16).padStart(2, '0').toUpperCase())
      .join(':');
  } catch { return null; }
}

export function cryptoSupported() {
  return !!(window.crypto?.subtle && window.indexedDB);
}