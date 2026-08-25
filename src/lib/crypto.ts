/**
 * Client-side only Web Crypto utilities.
 * These run exclusively in the browser — never on the server.
 */

// ---------- Buffer / Base64 ----------

export function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export function base64ToBase64Url(base64: string): string {
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlToBase64(value: string): string {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return base64 + "=".repeat((4 - (base64.length % 4)) % 4);
}

export function standardBase64ToBuffer(base64: string): ArrayBuffer {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function base64ToBuffer(base64: string): ArrayBuffer {
  const binary = window.atob(base64UrlToBase64(base64));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ---------- AES-256-GCM ----------

export async function generateAESKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}

export async function exportKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return base64ToBase64Url(bufferToBase64(raw));
}

export async function importKey(base64Key: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    base64ToBuffer(base64Key),
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptData(
  plaintext: string,
  key: CryptoKey
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    encoded
  );
  return {
    ciphertext: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv.buffer as ArrayBuffer),
  };
}

export async function decryptData(
  ciphertextB64: string,
  ivB64: string,
  key: CryptoKey
): Promise<string> {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: standardBase64ToBuffer(ivB64) as ArrayBuffer },
    key,
    standardBase64ToBuffer(ciphertextB64) as ArrayBuffer
  );
  return new TextDecoder().decode(decrypted);
}

// ---------- PBKDF2 key wrapping ----------

async function deriveWrappingKey(
  password: string,
  salt: BufferSource
): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function wrapPrimaryKey(
  primaryKey: CryptoKey,
  password: string,
  salt: Uint8Array
): Promise<{ wrapped_key: string; key_iv: string }> {
  const wrappingKey = await deriveWrappingKey(password, salt.buffer as ArrayBuffer);
  const rawKey = await crypto.subtle.exportKey("raw", primaryKey) as ArrayBuffer;
  const keyIv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedKey = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: keyIv.buffer as ArrayBuffer },
    wrappingKey,
    rawKey
  );
  return {
    wrapped_key: bufferToBase64(encryptedKey),
    key_iv: bufferToBase64(keyIv.buffer as ArrayBuffer),
  };
}

export async function unwrapPrimaryKey(
  wrappedKeyB64: string,
  keyIvB64: string,
  password: string,
  saltB64: string
): Promise<CryptoKey> {
  const wrappingKey = await deriveWrappingKey(password, standardBase64ToBuffer(saltB64) as ArrayBuffer);
  const rawKey = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: standardBase64ToBuffer(keyIvB64) as ArrayBuffer },
    wrappingKey,
    standardBase64ToBuffer(wrappedKeyB64) as ArrayBuffer
  );
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, true, [
    "encrypt",
    "decrypt",
  ]);
}

// ---------- Account mode: ECDH P-256 + HKDF + AES-GCM ----------
// Recon continuation: account shares wrap the content key with an ephemeral ECDH
// keypair against the recipient's long-term P-256 public key. HKDF derives a
// 256-bit AES-GCM wrapping key from the shared secret (ECIES-style, Web Crypto native).

const ACCOUNT_KDF_ITERATIONS = 310_000;
const WRAP_INFO = new TextEncoder().encode("aegisshare-wrap-v1");

async function deriveAccountPasswordKey(password: string, salt: BufferSource): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: ACCOUNT_KDF_ITERATIONS, hash: "SHA-256" },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function importEcdhPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey", "deriveBits"]
  );
}

async function importEcdhPublicJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
}

async function deriveAesWrapKey(sharedSecret: ArrayBuffer, salt: BufferSource): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: WRAP_INFO },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export interface AccountKeyRegistration {
  public_key: string;
  encrypted_private_key: string;
  key_metadata: string;
}

export async function generateAccountKeyBundle(password: string): Promise<AccountKeyRegistration> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveAccountPasswordKey(password, salt.buffer as ArrayBuffer);
  const encryptedPrivate = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    wrappingKey,
    new TextEncoder().encode(JSON.stringify(privateJwk))
  );
  return {
    public_key: JSON.stringify(publicJwk),
    encrypted_private_key: bufferToBase64(encryptedPrivate),
    key_metadata: JSON.stringify({
      version: 1,
      salt: bufferToBase64(salt.buffer as ArrayBuffer),
      iv: bufferToBase64(iv.buffer as ArrayBuffer),
    }),
  };
}

export async function unlockAccountPrivateKey(
  encryptedPrivateKeyB64: string,
  keyMetadataJson: string,
  password: string
): Promise<CryptoKey> {
  const meta = JSON.parse(keyMetadataJson) as { salt: string; iv: string };
  const wrappingKey = await deriveAccountPasswordKey(password, standardBase64ToBuffer(meta.salt) as ArrayBuffer);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: standardBase64ToBuffer(meta.iv) as ArrayBuffer },
    wrappingKey,
    standardBase64ToBuffer(encryptedPrivateKeyB64) as ArrayBuffer
  );
  const privateJwk = JSON.parse(new TextDecoder().decode(decrypted)) as JsonWebKey;
  return importEcdhPrivateJwk(privateJwk);
}

export async function wrapContentKeyForRecipient(
  contentKey: CryptoKey,
  recipientPublicKeyJson: string
): Promise<{ wrapped_key: string; key_metadata: string }> {
  const recipientPublicJwk = JSON.parse(recipientPublicKeyJson) as JsonWebKey;
  const recipientPublicKey = await importEcdhPublicJwk(recipientPublicJwk);
  const ephemeralKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: recipientPublicKey },
    ephemeralKeyPair.privateKey,
    256
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesWrapKey = await deriveAesWrapKey(sharedSecret, salt.buffer as ArrayBuffer);
  const rawContentKey = (await crypto.subtle.exportKey("raw", contentKey)) as ArrayBuffer;
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    aesWrapKey,
    rawContentKey
  );
  const ephPublicJwk = await crypto.subtle.exportKey("jwk", ephemeralKeyPair.publicKey);
  return {
    wrapped_key: bufferToBase64(wrapped),
    key_metadata: JSON.stringify({
      version: 1,
      ephPublicKey: ephPublicJwk,
      salt: bufferToBase64(salt.buffer as ArrayBuffer),
      iv: bufferToBase64(iv.buffer as ArrayBuffer),
    }),
  };
}

export async function unwrapContentKeyFromSender(
  wrappedKeyB64: string,
  keyMetadataJson: string,
  recipientPrivateKey: CryptoKey
): Promise<CryptoKey> {
  const meta = JSON.parse(keyMetadataJson) as {
    ephPublicKey: JsonWebKey;
    salt: string;
    iv: string;
  };
  const ephemeralPublicKey = await importEcdhPublicJwk(meta.ephPublicKey);
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeralPublicKey },
    recipientPrivateKey,
    256
  );
  const aesWrapKey = await deriveAesWrapKey(sharedSecret, standardBase64ToBuffer(meta.salt) as ArrayBuffer);
  const rawKey = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: standardBase64ToBuffer(meta.iv) as ArrayBuffer },
    aesWrapKey,
    standardBase64ToBuffer(wrappedKeyB64) as ArrayBuffer
  );
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}

export function sanitizeFilename(name: string): string {
  return name.replace(/[<>:"/\\|?*\x00-\x1f]/g, "_").slice(0, 200) || "download";
}

