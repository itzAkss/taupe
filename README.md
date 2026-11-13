# Taupe - secure messenger

# Screenshots
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/57d6fbe5-bca7-49d2-abdd-3076392ae801" />
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/dbf7af93-483b-4f03-9ac7-593925e84964" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/f77a94f4-c47a-4f4e-84f7-715c193e16d5" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/6204d080-7fa0-4412-97ad-33334993ca6a" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/b0030330-6d6e-4ea8-80c4-b50d7a426eff" />
<img width="1919" height="1076" alt="image" src="https://github.com/user-attachments/assets/09c974ec-151f-4c86-a353-a3fba7c89762" />
<img width="1919" height="1074" alt="image" src="https://github.com/user-attachments/assets/962bb396-9538-49b1-8755-3b8dd7527452" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/ad0cee85-6bd8-4dad-abd1-a7518f012303" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/9024d38a-9567-45b8-9220-d14c95da4d17" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/897d8900-fdd4-447d-8c88-b1988841a140" />
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/34344aa6-3538-4f55-8f07-7b8041469fd0" />

## Run
```bash
npm install
cp .env-example .env
npm start
```

The server binds to `127.0.0.1` by default. Put it behind a TLS reverse proxy and set `trust_proxy_hops` when a proxy is used. A self-signed certificate is generated only for local development.

## Configuration
Create `.env` with lowercase keys:

```ini
public_url=https://messenger.example
giphy_key=
taupe_pepper=replace-with-at-least-32-random-characters
port=3443
http_port=
bind_host=127.0.0.1
secure=true
trust_proxy_hops=0
upload_quota_mb=2048
global_upload_gb=0
orphan_upload_hours=24
registration_invite=
pow_difficulty=4
push_allow_hosts=
jwt_secret_file=
```

`taupe_pepper` is required. The server refuses to start without it. The old `.pepper` file is no longer used.

## Security model
- Each device has its own P-256 ECDH key and an account identity signing key. Device keys are signed by the identity key and verified by clients.
- Messages use an ephemeral ECDH exchange, HKDF-SHA-256, a per-chat counter ratchet, and AES-256-GCM. The AEAD data binds the chat UID, sender device, recipient device, and counter.
- Clients pin peer identity and device keys on first sight. A changed or unverified key blocks sending until the user reviews the safety number and trusts the new keys.
- The safety number is computed from the peer identity keys. A verified badge is removed when keys change or a device is added.
- New devices require approval from an existing device. The approval request shows a short code derived from both public keys, plus time, IP, country, and an expiry. Key sync is accepted only for an approved request.
- Chat attachments are encrypted client-side and must be uploaded as `.bin` files. Original file names stay inside the encrypted header. Plaintext message and file fallbacks are rejected.
- Message text is never sent in plaintext. Any encryption error aborts the send.
- Device tokens are stored hashed. JWTs are pinned to HS256. Sockets are dropped when a device or account is removed and devices are rechecked periodically.
- Account numbers are stored with scrypt and a per-account salt. Lookup uses an HMAC derived from `taupe_pepper`.
- Deleted content is hard-deleted. Timed burns, burn-after-five, history limits, and chat deletion remove rows and files. SQLite runs with `secure_delete`, WAL checkpointing, periodic purge, and vacuum.
- Chat requests must be accepted. Blocked or unknown peers get the same response. Chat creation is rate limited.
- Uploads are tracked by account, orphaned uploads count toward quotas and expire, and a global disk cap is available.
- Push endpoints must be HTTPS and are resolved once, then pinned for the connection. Push wakeups contain no message preview.
- Presence is opt-in. GIF search is opt-in and sends search terms to the server and Giphy only after consent.

## What the server can still see
The server sees account chat numbers, usernames that users make public, aliases only as ciphertext, chat labels only as ciphertext, chat membership, message timestamps and sizes, presence only when opted in, device names, IP addresses, and push endpoints. It cannot read message text, attachment content, attachment names, alias values, or chat labels.

## Tests
```bash
node --check server.js
node --check db.js
```
