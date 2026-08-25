/**
 * API integration smoke test — run with: node scripts/smoke-test.mjs
 * Uses Node's Web Crypto for account-mode key operations.
 */
const BASE = "http://localhost:3080";

async function deriveAccountPasswordKey(password, salt) {
  const enc = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310_000, hash: "SHA-256" },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function b64(buf) {
  return Buffer.from(buf).toString("base64");
}
function fromB64(s) {
  const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(base64 + "=".repeat((4 - (base64.length % 4)) % 4), "base64");
}
function b64url(buf) {
  return b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function generateAccountKeyBundle(password) {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveAccountPasswordKey(password, salt);
  const encryptedPrivate = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    new TextEncoder().encode(JSON.stringify(privateJwk))
  );
  return {
    public_key: JSON.stringify(publicJwk),
    encrypted_private_key: b64(encryptedPrivate),
    key_metadata: JSON.stringify({ version: 1, salt: b64(salt), iv: b64(iv) }),
    _privateJwk: privateJwk,
  };
}

async function wrapContentKey(contentKeyRaw, recipientPublicKeyJson) {
  const recipientPublicJwk = JSON.parse(recipientPublicKeyJson);
  const recipientPublicKey = await crypto.subtle.importKey("jwk", recipientPublicJwk, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ephemeralKeyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
  const sharedSecret = await crypto.subtle.deriveBits({ name: "ECDH", public: recipientPublicKey }, ephemeralKeyPair.privateKey, 256);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  const aesWrapKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("aegisshare-wrap-v1") },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesWrapKey, contentKeyRaw);
  const ephPublicJwk = await crypto.subtle.exportKey("jwk", ephemeralKeyPair.publicKey);
  return {
    wrapped_key: b64(wrapped),
    key_metadata: JSON.stringify({ version: 1, ephPublicKey: ephPublicJwk, salt: b64(salt), iv: b64(iv) }),
  };
}

async function encryptPayload(plaintext) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  const rawKey = await crypto.subtle.exportKey("raw", key);
  return {
    payload: JSON.stringify({ ciphertext: b64(ct), iv: b64(iv), has_password: false }),
    contentKeyRaw: rawKey,
  };
}

async function decryptPayload(payloadJson, rawKey) {
  const payload = JSON.parse(payloadJson);
  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, true, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(payload.iv) },
    key,
    fromB64(payload.ciphertext)
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

function extractCookies(res) {
  const raw = res.headers.getSetCookie?.() ?? [];
  return raw.map((c) => c.split(";")[0]).join("; ");
}

async function req(path, opts = {}, cookies = "") {
  const headers = { "Content-Type": "application/json", ...(opts.headers ?? {}) };
  if (cookies) headers.Cookie = cookies;
  const res = await fetch(`${BASE}${path}`, { ...opts, headers });
  const body = res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text();
  return { status: res.status, body, cookies: extractCookies(res) || cookies };
}

let passed = 0;
let failed = 0;
function assert(name, cond) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}`); failed++; }
}

console.log("AegisShare API smoke test\n");
const suffix = `${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
const aliceName = `alice_${suffix}`;
const bobName = `bob_${suffix}`;
const carolName = `carol_${suffix}`;
const aliceEmail = `${aliceName}@test.local`;
const bobEmail = `${bobName}@test.local`;
const carolEmail = `${carolName}@test.local`;

// Guest paste
console.log("Guest mode:");
const guestEnc = await encryptPayload(JSON.stringify({ text: "hello guest", file: null }));
const guestCreate = await req("/api/paste", {
  method: "POST",
  body: JSON.stringify({ mode: "guest", payload: guestEnc.payload, burn_on_read: false, expires_at: Date.now() + 3600000 }),
});
assert("guest create 200", guestCreate.status === 200);
const guestId = guestCreate.body.id;

const guestGet = await req(`/api/paste/${guestId}`);
assert("guest get 200", guestGet.status === 200);
assert("guest mode field", guestGet.body.mode === "guest");
const guestPlain = await decryptPayload(guestGet.body.payload, guestEnc.contentKeyRaw);
assert("guest decrypts fetched payload", guestPlain.text === "hello guest");
assert("guest URL-safe key roundtrip", fromB64(b64url(guestEnc.contentKeyRaw)).byteLength === guestEnc.contentKeyRaw.byteLength);

// Duplicate register rejection
console.log("\nAuth:");
const pw = "TestPassword123!";
const keysA = await generateAccountKeyBundle(pw);
const regA = await req("/api/auth/register", {
  method: "POST",
  body: JSON.stringify({
    username: aliceName, email: aliceEmail, password: pw, confirmPassword: pw,
    public_key: keysA.public_key, encrypted_private_key: keysA.encrypted_private_key, key_metadata: keysA.key_metadata,
  }),
});
assert("register alice 200", regA.status === 200);
let cookiesA = regA.cookies;

const dupUser = await req("/api/auth/register", {
  method: "POST",
  body: JSON.stringify({
    username: aliceName, email: `dup_${bobEmail}`, password: pw, confirmPassword: pw,
    public_key: keysA.public_key, encrypted_private_key: keysA.encrypted_private_key, key_metadata: keysA.key_metadata,
  }),
});
assert("duplicate username 409", dupUser.status === 409);

const keysB = await generateAccountKeyBundle(pw);
const regB = await req("/api/auth/register", {
  method: "POST",
  body: JSON.stringify({
    username: bobName, email: bobEmail, password: pw, confirmPassword: pw,
    public_key: keysB.public_key, encrypted_private_key: keysB.encrypted_private_key, key_metadata: keysB.key_metadata,
  }),
});
assert("register bob 200", regB.status === 200);
const cookiesB = regB.cookies;

// Session
const sess = await req("/api/auth/session", {}, cookiesA);
assert("session returns user", sess.body.user?.username === aliceName);

// Resolve recipient
const resolve = await req(`/api/users/resolve?q=${encodeURIComponent(bobName)}`, {}, cookiesA);
assert("resolve bob", resolve.status === 200 && resolve.body.recipient?.username === bobName);

// Account share
console.log("\nAccount mode:");
const acctEnc = await encryptPayload(JSON.stringify({ text: "secret for bob", file: null }));
const wrap = await wrapContentKey(acctEnc.contentKeyRaw, resolve.body.recipient.public_key);
const acctCreate = await req("/api/paste", {
  method: "POST",
  body: JSON.stringify({
    mode: "account", payload: acctEnc.payload, burn_on_read: false,
    expires_at: Date.now() + 3600000, recipient: bobName,
    wrapped_key: wrap.wrapped_key, key_metadata: wrap.key_metadata,
  }),
}, cookiesA);
assert("account create 200", acctCreate.status === 200);
const acctId = acctCreate.body.id;

// Unauthorized fetch (alice can't read as recipient)
const aliceFetch = await req(`/api/paste/${acctId}`, {}, cookiesA);
assert("sender cannot read account share", aliceFetch.status === 404);

// Bob inbox
const inbox = await req("/api/inbox", {}, cookiesB);
assert("bob inbox has item", inbox.body.items?.length >= 1);

// Bob can fetch
const bobFetch = await req(`/api/paste/${acctId}`, {}, cookiesB);
assert("recipient can fetch", bobFetch.status === 200);
assert("has wrapped_key", !!bobFetch.body.wrapped_key);

// Sent list
const sent = await req("/api/sent", {}, cookiesA);
assert("alice sent has item", sent.body.items?.length >= 1);

// Revoke
const revoke = await req(`/api/paste/${acctId}/revoke`, { method: "POST" }, cookiesA);
assert("revoke 200", revoke.status === 200);

const bobAfterRevoke = await req(`/api/paste/${acctId}`, {}, cookiesB);
assert("revoked share blocked", bobAfterRevoke.status === 404);

// Wrong user can't revoke
const keysC = await generateAccountKeyBundle(pw);
await req("/api/auth/register", {
  method: "POST",
  body: JSON.stringify({
    username: carolName, email: carolEmail, password: pw, confirmPassword: pw,
    public_key: keysC.public_key, encrypted_private_key: keysC.encrypted_private_key, key_metadata: keysC.key_metadata,
  }),
});
const acct2 = await req("/api/paste", {
  method: "POST",
  body: JSON.stringify({
    mode: "account", payload: acctEnc.payload, burn_on_read: false,
    expires_at: Date.now() + 3600000, recipient: bobName,
    wrapped_key: wrap.wrapped_key, key_metadata: wrap.key_metadata,
  }),
}, cookiesA);
const acct2Id = acct2.body.id;
const carolLogin = await req("/api/auth/login", { method: "POST", body: JSON.stringify({ identifier: carolName, password: pw }) });
const carolRevoke2 = await req(`/api/paste/${acct2Id}/revoke`, { method: "POST" }, carolLogin.cookies);
assert("non-sender cannot revoke", carolRevoke2.status === 404);

// Logout
const logout = await req("/api/auth/logout", { method: "POST" }, cookiesA);
assert("logout 200", logout.status === 200);

console.log(`\nResults: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
