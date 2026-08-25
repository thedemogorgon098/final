"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import {
  generateAESKey,
  exportKey,
  importKey,
  encryptData,
  decryptData,
  wrapPrimaryKey,
  unwrapPrimaryKey,
  bufferToBase64,
  generateAccountKeyBundle,
  unlockAccountPrivateKey,
  wrapContentKeyForRecipient,
  unwrapContentKeyFromSender,
  sanitizeFilename,
} from "@/lib/crypto";
import TraceableView from "@/components/TraceableView";

// ─── Types ────────────────────────────────────────────────────────────────────

interface AttachedFile {
  name: string;
  type: string;
  size: number;
  data: string;
}

interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  has_password: boolean;
  salt?: string;
  key_iv?: string;
  wrapped_key?: string;
}

interface PublicUser {
  id: string;
  username: string;
  email: string;
}

interface KeyBundle {
  public_key: string;
  encrypted_private_key: string;
  key_metadata: string;
}

interface ShareListItem {
  id: string;
  created_at: number;
  expires_at: number | null;
  burn_on_read: boolean;
  opened: boolean;
  revoked: boolean;
  has_attachment: boolean;
  sender?: { username: string; email: string };
  recipient?: { username: string; email: string };
}

interface DecryptedPaste {
  text: string;
  file: AttachedFile | null;
}

interface Toast {
  id: number;
  message: string;
  type: "success" | "error" | "info";
}

type NavTab = "create" | "inbox" | "sent" | "account";
type ShareMode = "guest" | "account";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function formatDate(ts: number): string {
  return new Date(ts).toLocaleString();
}

const EXPIRY_MS: Record<string, number | null> = {
  burn: null,
  "10m": 10 * 60 * 1000,
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  never: null,
};

const TEMPLATES: Record<string, string> = {
  plain: "",
  markdown: `# Title Here\n\n## Subtitle\nUse **bolding**, *italics*, or \`inline code\`.\n\n- Bullet points\n- Simple lists\n\n> This is a quote block. Securely shared.`,
  javascript: `// JavaScript Template\nconst secureMsg = "Hello AegisShare";\nconsole.log(secureMsg);`,
  python: `# Python Template\ndef handle_payload(data):\n    print(f"Size: {len(data)}")`,
  json: `{\n  "status": "secure",\n  "protocol": "AES-256-GCM"\n}`,
};

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AegisSharePage() {
  const [nav, setNav] = useState<NavTab>("create");
  const [shareMode, setShareMode] = useState<ShareMode>("guest");

  // Auth
  const [sessionUser, setSessionUser] = useState<PublicUser | null>(null);
  const [keyBundle, setKeyBundle] = useState<KeyBundle | null>(null);
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const [authTab, setAuthTab] = useState<"login" | "register">("login");
  const [authForm, setAuthForm] = useState({
    username: "", email: "", password: "", confirmPassword: "", identifier: "",
  });
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState("");
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [unlockLoading, setUnlockLoading] = useState(false);
  const [usernameAvailability, setUsernameAvailability] = useState<"idle" | "checking" | "available" | "taken">("idle");
  const [emailAvailability, setEmailAvailability] = useState<"idle" | "checking" | "available" | "taken">("idle");

  // Create form
  const [pasteText, setPasteText] = useState("");
  const [editorTab, setEditorTab] = useState<"write" | "preview">("write");
  const [mdHtml, setMdHtml] = useState("");
  const [expiry, setExpiry] = useState("24h");
  const [customExpiry, setCustomExpiry] = useState("");
  const [template, setTemplate] = useState("plain");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [pwStrength, setPwStrength] = useState(0);
  const [attachedFile, setAttachedFile] = useState<AttachedFile | null>(null);
  const [encrypting, setEncrypting] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const [recipientQuery, setRecipientQuery] = useState("");
  const [recipientValid, setRecipientValid] = useState<{ username: string; email: string; public_key: string } | null>(null);
  const [recipientError, setRecipientError] = useState("");
  const [validatingRecipient, setValidatingRecipient] = useState(false);

  // Lists
  const [inboxItems, setInboxItems] = useState<ShareListItem[]>([]);
  const [sentItems, setSentItems] = useState<ShareListItem[]>([]);
  const [listsLoading, setListsLoading] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [confirmRevokeId, setConfirmRevokeId] = useState<string | null>(null);

  // View state
  const [viewMode, setViewMode] = useState<"app" | "view" | "loading">("app");
  const [viewTab, setViewTab] = useState<"text" | "markdown">("text");
  const [decryptedPaste, setDecryptedPaste] = useState<DecryptedPaste | null>(null);
  const [viewError, setViewError] = useState<string | null>(null);
  const [isBurn, setIsBurn] = useState(false);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [countdown, setCountdown] = useState("");
  const [viewIsAccount, setViewIsAccount] = useState(false);
  const [viewPasteId, setViewPasteId] = useState("");
  const [viewSender, setViewSender] = useState<{ username: string; email: string } | null>(null);

  // Password modal (guest)
  const [showPwModal, setShowPwModal] = useState(false);
  const [modalPw, setModalPw] = useState("");
  const [showModalPw, setShowModalPw] = useState(false);
  const [pwModalError, setPwModalError] = useState("");
  const [pendingPayload, setPendingPayload] = useState<EncryptedPayload | null>(null);
  const [decryptingPw, setDecryptingPw] = useState(false);

  // Result modal
  const [showResultModal, setShowResultModal] = useState(false);
  const [shareUrl, setShareUrl] = useState("");
  const [deleteUrl, setDeleteUrl] = useState("");
  const [qrSrc, setQrSrc] = useState("");
  const [resultIsAccount, setResultIsAccount] = useState(false);
  const [resultRecipient, setResultRecipient] = useState("");

  // Server config
  const [serverConfig, setServerConfig] = useState({ localIp: "localhost", port: 3080 });

  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const handledHashRef = useRef<string | null>(null);
  const viewMdRef = useRef<HTMLDivElement>(null);

  const showToast = useCallback((message: string, type: Toast["type"] = "info") => {
    const id = ++toastId.current;
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 3500);
  }, []);

  // ─── Session bootstrap ────────────────────────────────────────────────────────

  const refreshSession = useCallback(async () => {
    try {
      const res = await fetch("/api/auth/session");
      const data = await res.json();
      if (data.user) {
        setSessionUser(data.user);
        setKeyBundle(data.keyBundle ?? null);
      } else {
        setSessionUser(null);
        setKeyBundle(null);
        privateKeyRef.current = null;
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    fetch("/api/config").then((r) => r.json()).then(setServerConfig).catch(() => {});
    refreshSession();
  }, [refreshSession]);

  const loadInbox = useCallback(async () => {
    setListsLoading(true);
    try {
      const res = await fetch("/api/inbox");
      if (res.ok) { const d = await res.json(); setInboxItems(d.items ?? []); }
    } finally { setListsLoading(false); }
  }, []);

  const loadSent = useCallback(async () => {
    setListsLoading(true);
    try {
      const res = await fetch("/api/sent");
      if (res.ok) { const d = await res.json(); setSentItems(d.items ?? []); }
    } finally { setListsLoading(false); }
  }, []);

  useEffect(() => {
    if (nav === "inbox" && sessionUser) loadInbox();
    if (nav === "sent" && sessionUser) loadSent();
  }, [nav, sessionUser, loadInbox, loadSent]);

  useEffect(() => {
    if (sessionUser) {
      loadInbox();
      loadSent();
    }
  }, [sessionUser, loadInbox, loadSent]);

  // ─── Live username/email availability check (register form) ──────────────────
  // Debounced so we're not firing a request on every keystroke — 400ms after
  // the user stops typing is enough to feel instant without spamming the API.
  useEffect(() => {
    if (authTab !== "register" || authForm.username.trim().length < 3) {
      setUsernameAvailability("idle");
      return;
    }
    setUsernameAvailability("checking");
    const handle = setTimeout(async () => {
      try {
        const res = await fetch(`/api/auth/availability?username=${encodeURIComponent(authForm.username.trim())}`);
        const data = await res.json();
        setUsernameAvailability(data.usernameTaken ? "taken" : "available");
      } catch {
        setUsernameAvailability("idle");
      }
    }, 400);
    return () => clearTimeout(handle);
  }, [authForm.username, authTab]);

  useEffect(() => {
    if (authTab !== "register" || !authForm.email.includes("@")) {
      setEmailAvailability("idle");
      return;
    }
    setEmailAvailability("checking");
    const handle = setTimeout(async () => {
      try {
        const res = await fetch(`/api/auth/availability?email=${encodeURIComponent(authForm.email.trim())}`);
        const data = await res.json();
        setEmailAvailability(data.emailTaken ? "taken" : "available");
      } catch {
        setEmailAvailability("idle");
      }
    }, 400);
    return () => clearTimeout(handle);
  }, [authForm.email, authTab]);

  // ─── Markdown preview ───────────────────────────────────────────────────────

  useEffect(() => {
    if (editorTab !== "preview") return;
    Promise.all([import("marked"), import("dompurify")]).then(([{ marked }, { default: DOMPurify }]) => {
      setMdHtml(DOMPurify.sanitize(marked.parse(pasteText || "*No text entered*") as string));
    });
  }, [editorTab, pasteText]);

  useEffect(() => {
    if (!decryptedPaste?.text || !viewMdRef.current) return;
    Promise.all([import("marked"), import("dompurify")]).then(([{ marked }, { default: DOMPurify }]) => {
      if (viewMdRef.current) viewMdRef.current.innerHTML = DOMPurify.sanitize(marked.parse(decryptedPaste.text) as string);
    });
  }, [decryptedPaste, viewTab]);

  // ─── Countdown ────────────────────────────────────────────────────────────────

  useEffect(() => {
    if (!expiresAt || isBurn) return;
    const tick = () => {
      const diff = expiresAt - Date.now();
      if (diff <= 0) { setCountdown("Expired"); return; }
      const h = Math.floor(diff / 3_600_000);
      const m = Math.floor((diff % 3_600_000) / 60_000);
      const s = Math.floor((diff % 60_000) / 1_000);
      setCountdown(h > 0 ? `${h}h ${m}m` : `${m}m ${s}s`);
    };
    tick();
    const iv = setInterval(tick, 1000);
    return () => clearInterval(iv);
  }, [expiresAt, isBurn]);

  // ─── Decrypt helpers ──────────────────────────────────────────────────────────

  async function decryptGuestPayload(payload: EncryptedPayload, primaryKeyB64: string) {
    if (payload.has_password) {
      setPendingPayload(payload);
      setModalPw("");
      setPwModalError("");
      setShowPwModal(true);
      return;
    }
    if (!primaryKeyB64) { setViewError("Missing decryption key in URL fragment."); return; }
    const key = await importKey(primaryKeyB64);
    const plain = await decryptData(payload.ciphertext, payload.iv, key);
    setDecryptedPaste(JSON.parse(plain));
  }

  async function decryptAccountPayload(
    payload: EncryptedPayload,
    wrappedKey: string,
    keyMetadata: string
  ) {
    if (!privateKeyRef.current) {
      setViewError("Sign in and unlock your encryption keys to view this share.");
      setShowUnlockModal(true);
      return;
    }
    const contentKey = await unwrapContentKeyFromSender(wrappedKey, keyMetadata, privateKeyRef.current);
    const plain = await decryptData(payload.ciphertext, payload.iv, contentKey);
    setDecryptedPaste(JSON.parse(plain));
  }

  // ─── Hash routing ─────────────────────────────────────────────────────────────

  const handleHash = useCallback(async () => {
    const hash = window.location.hash;
    if (handledHashRef.current === hash) return;
    handledHashRef.current = hash;

    if (!hash || hash === "#") {
      setViewMode("app");
      return;
    }

    if (hash.startsWith("#delete=")) {
      const parts = hash.substring(8).split(":");
      const [id, token] = parts;
      setViewMode("view");
      setViewError(null);
      try {
        const res = await fetch(`/api/paste/${id}?token=${token}`, { method: "DELETE" });
        const data = await res.json();
        if (res.ok) setDecryptedPaste({ text: "Paste deleted successfully from the server.", file: null });
        else setViewError(data.error ?? "Deletion failed.");
      } catch { setViewError("Network error during deletion."); }
      return;
    }

    const cleanHash = hash.substring(1);
    const colonIdx = cleanHash.indexOf(":");
    const id = colonIdx === -1 ? cleanHash : cleanHash.substring(0, colonIdx);
    const primaryKeyB64 = colonIdx === -1 ? "" : decodeURIComponent(cleanHash.substring(colonIdx + 1));

    setViewMode("loading");
    setViewError(null);
    setDecryptedPaste(null);
    setViewPasteId(id);
    setViewIsAccount(false);
    setViewSender(null);

    try {
      const res = await fetch(`/api/paste/${id}`);
      const data = await res.json();
      if (!res.ok) {
        setViewMode("view");
        setViewError(data.error ?? "Share not found or unavailable.");
        return;
      }

      const payload: EncryptedPayload = JSON.parse(data.payload);
      setIsBurn(data.burn_on_read);
      setExpiresAt(data.expires_at);
      setViewMode("view");

      if (data.mode === "account") {
        setViewIsAccount(true);
        setViewSender(data.sender ?? null);
        await decryptAccountPayload(payload, data.wrapped_key, data.key_metadata);
      } else {
        setViewIsAccount(false);
        await decryptGuestPayload(payload, primaryKeyB64);
      }
    } catch (err) {
      setViewMode("view");
      setViewError("Failed to load or decrypt: " + (err as Error).message);
    }
  }, []);

  useEffect(() => {
    handleHash();
    window.addEventListener("hashchange", handleHash);
    return () => window.removeEventListener("hashchange", handleHash);
  }, [handleHash]);

  // ─── Auth handlers ──────────────────────────────────────────────────────────

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    try {
      const keys = await generateAccountKeyBundle(authForm.password);
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: authForm.username,
          email: authForm.email,
          password: authForm.password,
          confirmPassword: authForm.confirmPassword,
          ...keys,
        }),
      });
      const data = await res.json();
      if (!res.ok) { setAuthError(data.error ?? "Registration failed."); return; }
      setSessionUser(data.user);
      setKeyBundle(keys);
      privateKeyRef.current = await unlockAccountPrivateKey(
        keys.encrypted_private_key, keys.key_metadata, authForm.password
      );
      showToast("Account created!", "success");
      setNav("create");
      setShareMode("account");
    } catch (err) {
      setAuthError((err as Error).message);
    } finally { setAuthLoading(false); }
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ identifier: authForm.identifier, password: authForm.password }),
      });
      const data = await res.json();
      if (!res.ok) { setAuthError(data.error ?? "Login failed."); return; }
      setSessionUser(data.user);
      setKeyBundle(data.keyBundle);
      if (data.keyBundle) {
        privateKeyRef.current = await unlockAccountPrivateKey(
          data.keyBundle.encrypted_private_key,
          data.keyBundle.key_metadata,
          authForm.password
        );
      }
      showToast("Signed in!", "success");
      setNav("create");
    } catch (err) {
      setAuthError((err as Error).message);
    } finally { setAuthLoading(false); }
  }

  async function handleLogout() {
    await fetch("/api/auth/logout", { method: "POST" });
    setSessionUser(null);
    setKeyBundle(null);
    privateKeyRef.current = null;
    setInboxItems([]);
    setSentItems([]);
    showToast("Signed out.", "info");
    setNav("create");
  }

  async function handleUnlockKeys() {
    if (!keyBundle || !unlockPassword) return;
    setUnlockLoading(true);
    setUnlockError("");
    try {
      privateKeyRef.current = await unlockAccountPrivateKey(
        keyBundle.encrypted_private_key, keyBundle.key_metadata, unlockPassword
      );
      setShowUnlockModal(false);
      setUnlockPassword("");
      showToast("Encryption keys unlocked.", "success");
      if (window.location.hash && window.location.hash !== "#") {
        handledHashRef.current = null;
        handleHash();
      }
    } catch {
      setUnlockError("Wrong password — could not unlock encryption keys.");
    } finally { setUnlockLoading(false); }
  }

  // ─── Recipient validation ─────────────────────────────────────────────────────

  async function validateRecipient() {
    if (recipientQuery.trim().length < 3) { setRecipientError("Enter at least 3 characters."); return; }
    setValidatingRecipient(true);
    setRecipientError("");
    setRecipientValid(null);
    try {
      const res = await fetch(`/api/users/resolve?q=${encodeURIComponent(recipientQuery.trim())}`);
      const data = await res.json();
      if (!res.ok) { setRecipientError(data.error ?? "Recipient not found."); return; }
      setRecipientValid(data.recipient);
    } catch { setRecipientError("Network error."); }
    finally { setValidatingRecipient(false); }
  }

  // ─── File handling ────────────────────────────────────────────────────────────

  function handleFileSelect(file: File) {
    if (file.size > 2 * 1024 * 1024) { showToast("File exceeds 2 MB limit.", "error"); return; }
    const reader = new FileReader();
    reader.onload = (e) =>
      setAttachedFile({
        name: sanitizeFilename(file.name),
        type: file.type || "application/octet-stream",
        size: file.size,
        data: e.target!.result as string,
      });
    reader.onerror = () => showToast("Failed to read file.", "error");
    reader.readAsDataURL(file);
  }

  function calcStrength(v: string): number {
    if (v.length >= 10 && /[A-Z]/.test(v) && /[^a-zA-Z0-9]/.test(v)) return 3;
    if (v.length >= 8 && /[a-zA-Z]/.test(v) && /[0-9]/.test(v)) return 2;
    if (v.length >= 6) return 1;
    return 0;
  }

  function resolveExpiresAt(): number | null {
    if (expiry === "burn" || expiry === "never") return null;
    if (expiry === "custom") {
      if (!customExpiry) return Date.now() + EXPIRY_MS["24h"]!;
      return new Date(customExpiry).getTime();
    }
    const ms = EXPIRY_MS[expiry];
    return ms ? Date.now() + ms : null;
  }

  // ─── Encrypt & Share ──────────────────────────────────────────────────────────

  async function handleEncryptShare() {
    if (!pasteText.trim() && !attachedFile) { showToast("Enter text or attach a file.", "error"); return; }

    if (shareMode === "account") {
      if (!sessionUser) { showToast("Sign in to send account shares.", "error"); setNav("account"); return; }
      if (!privateKeyRef.current) { setShowUnlockModal(true); return; }
      if (!recipientValid) { showToast("Validate a recipient first.", "error"); return; }
    }

    setEncrypting(true);
    try {
      const pasteObj = { text: pasteText, file: attachedFile };
      const primaryKey = await generateAESKey();
      const { ciphertext, iv } = await encryptData(JSON.stringify(pasteObj), primaryKey);
      const burnOnRead = expiry === "burn";
      const expiresAtVal = burnOnRead ? null : resolveExpiresAt();

      if (shareMode === "account") {
        const { wrapped_key, key_metadata } = await wrapContentKeyForRecipient(
          primaryKey, recipientValid!.public_key
        );
        const uploadPackage: EncryptedPayload = { ciphertext, iv, has_password: false };
        const res = await fetch("/api/paste", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            mode: "account",
            payload: JSON.stringify(uploadPackage),
            burn_on_read: burnOnRead,
            expires_at: expiresAtVal,
            recipient: recipientQuery.trim(),
            wrapped_key,
            key_metadata,
          }),
        });
        if (!res.ok) { const d = await res.json(); throw new Error(d.error ?? "Server error"); }
        const data = await res.json();
        setResultIsAccount(true);
        setResultRecipient(`${data.recipient.username} (${data.recipient.email})`);
        setShareUrl(`${window.location.origin}/#${data.id}`);
        setDeleteUrl("");
        setQrSrc("");
        setShowResultModal(true);
        showToast("Encrypted and sent!", "success");
        loadSent();
      } else {
        let uploadPackage: EncryptedPayload;
        let shareableFragment = "";
        if (password) {
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const { wrapped_key, key_iv } = await wrapPrimaryKey(primaryKey, password, salt);
          uploadPackage = { ciphertext, iv, has_password: true, salt: bufferToBase64(salt.buffer as ArrayBuffer), key_iv, wrapped_key };
        } else {
          uploadPackage = { ciphertext, iv, has_password: false };
          shareableFragment = `:${await exportKey(primaryKey)}`;
        }
        const res = await fetch("/api/paste", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode: "guest", payload: JSON.stringify(uploadPackage), burn_on_read: burnOnRead, expires_at: expiresAtVal }),
        });
        if (!res.ok) throw new Error("Server error " + res.status);
        const data = await res.json();
        const shareOrigin = window.location.origin;
        const fullShareUrl = `${shareOrigin}/#${data.id}${shareableFragment}`;
        setResultIsAccount(false);
        setShareUrl(fullShareUrl);
        setDeleteUrl(`${shareOrigin}/#delete=${data.id}:${data.deletion_token}`);
        setQrSrc(`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(fullShareUrl)}`);
        setShowResultModal(true);
        showToast("Secure paste created!", "success");
      }

      setPasteText(""); setPassword(""); setPwStrength(0); setAttachedFile(null);
      setRecipientQuery(""); setRecipientValid(null);
      setExpiry("24h"); setTemplate("plain"); setEditorTab("write");
    } catch (err) {
      showToast("Failed: " + (err as Error).message, "error");
    } finally { setEncrypting(false); }
  }

  async function handlePasswordDecrypt() {
    if (!modalPw || !pendingPayload) return;
    setDecryptingPw(true);
    setPwModalError("");
    try {
      const key = await unwrapPrimaryKey(pendingPayload.wrapped_key!, pendingPayload.key_iv!, modalPw, pendingPayload.salt!);
      const plain = await decryptData(pendingPayload.ciphertext, pendingPayload.iv, key);
      setDecryptedPaste(JSON.parse(plain));
      setShowPwModal(false);
      setPendingPayload(null);
      showToast("Decrypted!", "success");
    } catch { setPwModalError("Wrong password or corrupt payload."); }
    finally { setDecryptingPw(false); }
  }

  async function openInboxItem(id: string) {
    window.location.hash = id;
  }

  async function handleRevoke(id: string) {
    setRevokingId(id);
    try {
      const res = await fetch(`/api/paste/${id}/revoke`, { method: "POST" });
      if (!res.ok) { showToast("Revocation failed.", "error"); return; }
      showToast("Share revoked.", "success");
      loadSent();
    } finally {
      setRevokingId(null);
      setConfirmRevokeId(null);
    }
  }

  async function copyText(text: string, msg: string) {
    try { await navigator.clipboard.writeText(text); showToast(msg, "success"); }
    catch { showToast("Copy failed.", "error"); }
  }

  // ─── Dashboard stats ──────────────────────────────────────────────────────────

  const unreadCount = inboxItems.filter((i) => !i.opened && !i.revoked).length;
  const activeSent = sentItems.filter((i) => !i.revoked).length;
  const expiringSoon = [...inboxItems, ...sentItems].filter(
    (i) => i.expires_at && i.expires_at - Date.now() < 24 * 60 * 60 * 1000 && i.expires_at > Date.now()
  ).length;

  // ─── Render ───────────────────────────────────────────────────────────────────

  const renderCreatePanel = () => (
    <section className="glass-panel fade-in">
      <div className="panel-header">
        <div>
          <h2>Create Secure Share</h2>
          <p className="panel-subtitle">Encryption happens entirely in your browser before uploading.</p>
        </div>
        <div className="editor-modes">
          <button className={`btn-tab${editorTab === "write" ? " active" : ""}`} onClick={() => setEditorTab("write")}>
            <i className="fa-solid fa-align-left" /> Write
          </button>
          <button className={`btn-tab${editorTab === "preview" ? " active" : ""}`} onClick={() => setEditorTab("preview")}>
            <i className="fa-brands fa-markdown" /> Preview
          </button>
        </div>
      </div>

      <div className="panel-body">
        {sessionUser && (
          <div className="dashboard-grid">
            <div className="dash-card"><div className="dash-card-value">{unreadCount}</div><div className="dash-card-label">Unread Inbox</div></div>
            <div className="dash-card"><div className="dash-card-value">{activeSent}</div><div className="dash-card-label">Active Sent</div></div>
            <div className="dash-card"><div className="dash-card-value">{expiringSoon}</div><div className="dash-card-label">Expiring Soon</div></div>
          </div>
        )}

        <div className="mode-toggle">
          <button className={`mode-btn${shareMode === "guest" ? " active" : ""}`} onClick={() => setShareMode("guest")}>
            <i className="fa-solid fa-user-secret" /> Guest Share
          </button>
          <button className={`mode-btn${shareMode === "account" ? " active" : ""}`} onClick={() => setShareMode("account")}>
            <i className="fa-solid fa-envelope-circle-check" /> Account Share
          </button>
        </div>
        {shareMode === "guest" ? (
          <div className="warning-banner">
            <i className="fa-solid fa-triangle-exclamation" />
            <span>The link itself is the secret — anyone who has it (including the # key fragment) can decrypt this share. Treat it like a password.</span>
          </div>
        ) : (
          <p className="mode-desc">
            Send encrypted content directly to a registered user. The URL contains no decryption key — only the authorized recipient can decrypt after signing in.
          </p>
        )}

        {shareMode === "account" && !sessionUser && (
          <div className="info-banner">
            <i className="fa-solid fa-circle-info" />
            <span><a href="#" onClick={(e) => { e.preventDefault(); setNav("account"); }} style={{ color: "inherit" }}>Sign in</a> to send account shares.</span>
          </div>
        )}

        {shareMode === "account" && sessionUser && (
          <div className="form-group" style={{ marginBottom: 20 }}>
            <label className="form-label"><i className="fa-solid fa-user" /> Recipient (username or email)</label>
            <div className="recipient-row">
              <input type="text" placeholder="recipient@example.com" value={recipientQuery}
                onChange={(e) => { setRecipientQuery(e.target.value); setRecipientValid(null); setRecipientError(""); }} />
              <button className="btn-secondary" onClick={validateRecipient} disabled={validatingRecipient}>
                {validatingRecipient ? <i className="fa-solid fa-spinner fa-spin" /> : "Validate"}
              </button>
            </div>
            {recipientValid && <p className="recipient-valid"><i className="fa-solid fa-circle-check" /> {recipientValid.username} ({recipientValid.email})</p>}
            {recipientError && <p className="recipient-error">{recipientError}</p>}
          </div>
        )}

        <div className="editor-wrapper">
          {editorTab === "write" ? (
            <textarea className="paste-textarea" placeholder="Type sensitive text here… Markdown supported."
              value={pasteText} onChange={(e) => setPasteText(e.target.value)} />
          ) : (
            <div className="markdown-preview-area md-body" dangerouslySetInnerHTML={{ __html: mdHtml }} />
          )}
        </div>

        <div className="config-grid">
          <div className="config-card">
            <h3><i className="fa-solid fa-paperclip" /> Secure Attachment</h3>
            {!attachedFile ? (
              <div className={`drop-zone${isDragOver ? " dragover" : ""}`}
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={(e) => { e.preventDefault(); setIsDragOver(false); if (e.dataTransfer.files[0]) handleFileSelect(e.dataTransfer.files[0]); }}>
                <i className="fa-solid fa-cloud-arrow-up drop-icon" />
                <p className="drop-text">Drag & drop or <span className="text-accent-link">Browse</span></p>
                <p className="drop-subtext">Max 2 MB · Encrypted with paste</p>
                <input ref={fileInputRef} type="file" style={{ display: "none" }}
                  onChange={(e) => { if (e.target.files?.[0]) handleFileSelect(e.target.files[0]); }} />
              </div>
            ) : (
              <div className="file-info-bar">
                <div className="file-details">
                  <i className="fa-solid fa-file-shield file-details-icon" />
                  <div className="file-meta">
                    <span className="file-name-txt">{attachedFile.name}</span>
                    <span className="file-size-txt">{formatBytes(attachedFile.size)}</span>
                  </div>
                </div>
                <button className="btn-icon-danger" onClick={() => setAttachedFile(null)}><i className="fa-solid fa-trash-can" /></button>
              </div>
            )}
          </div>

          <div className="config-card">
            <h3><i className="fa-solid fa-sliders" /> Security Settings</h3>
            <div className="form-row">
              <div className="form-group">
                <label className="form-label"><i className="fa-regular fa-clock" /> Expiration</label>
                <select value={expiry} onChange={(e) => setExpiry(e.target.value)}>
                  <option value="burn">Burn on read</option>
                  <option value="10m">10 Minutes</option>
                  <option value="1h">1 Hour</option>
                  <option value="6h">6 Hours</option>
                  <option value="24h">24 Hours</option>
                  <option value="7d">7 Days</option>
                  <option value="never">Never</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label"><i className="fa-solid fa-code" /> Template</label>
                <select value={template} onChange={(e) => { setTemplate(e.target.value); if (TEMPLATES[e.target.value] !== undefined) setPasteText(TEMPLATES[e.target.value]); }}>
                  <option value="plain">Plain Text</option>
                  <option value="markdown">Markdown</option>
                  <option value="javascript">JavaScript</option>
                  <option value="python">Python</option>
                  <option value="json">JSON</option>
                </select>
              </div>
            </div>
            {expiry === "custom" && (
              <div className="form-group">
                <label className="form-label">Custom expiry (local time)</label>
                <input type="datetime-local" value={customExpiry} onChange={(e) => setCustomExpiry(e.target.value)} />
              </div>
            )}
            {shareMode === "guest" && (
              <div className="form-group">
                <label className="form-label"><i className="fa-solid fa-key" /> Password (Optional)</label>
                <div className="pw-wrapper">
                  <input type={showPw ? "text" : "password"} placeholder="PBKDF2-derived key protection"
                    value={password} onChange={(e) => { setPassword(e.target.value); setPwStrength(calcStrength(e.target.value)); }} />
                  <button className="btn-eye" onClick={() => setShowPw(!showPw)}>
                    <i className={`fa-solid fa-eye${showPw ? "-slash" : ""}`} />
                  </button>
                </div>
                <div className="strength-bar">
                  <div className="strength-fill" style={{
                    width: pwStrength === 0 ? "0" : pwStrength === 1 ? "33%" : pwStrength === 2 ? "66%" : "100%",
                    background: pwStrength <= 1 ? "var(--color-danger)" : pwStrength === 2 ? "var(--color-warning)" : "var(--color-success)",
                  }} />
                </div>
                <p className="pw-hint">Recipients need both the link and this password.</p>
              </div>
            )}
          </div>
        </div>

        <div className="security-section">
          <h3><i className="fa-solid fa-shield-halved" /> How AegisShare Protects Your Data</h3>
          <div className="security-grid">
            <div className="security-item">
              <h4>Guest Mode</h4>
              <p>Content is AES-256-GCM encrypted in your browser. The decryption key lives in the URL fragment (#) and is never sent to the server. Anyone with the full link can decrypt.</p>
            </div>
            <div className="security-item">
              <h4>Account Mode</h4>
              <p>Content keys are wrapped for a specific recipient using ECDH P-256. Only the authorized recipient can unwrap and decrypt after authenticating. Senders can revoke access anytime.</p>
            </div>
            <div className="security-item">
              <h4>Traceable View</h4>
              <p>Account shares display a watermark with your identity and timestamp to discourage unauthorized redistribution. Focus-loss blurring hides content when you switch tabs — a deterrent, not a guarantee.</p>
            </div>
            <div className="security-item">
              <h4>Zero-Knowledge</h4>
              <p>The server stores only encrypted ciphertext. Passwords are hashed with scrypt; private keys are encrypted client-side. Plaintext never reaches the database.</p>
            </div>
          </div>
          <div className="zk-status"><i className="fa-solid fa-lock" /> Zero-Knowledge Encryption Enabled</div>
        </div>
      </div>

      <div className="panel-footer">
        <button className="btn-primary btn-glow" onClick={handleEncryptShare} disabled={encrypting}>
          {encrypting ? <><i className="fa-solid fa-spinner fa-spin" /> Encrypting…</> :
            shareMode === "account" ? <><i className="fa-solid fa-paper-plane" /> Encrypt &amp; Send</> :
              <><i className="fa-solid fa-lock" /> Encrypt &amp; Create Secure Share</>}
        </button>
      </div>
    </section>
  );

  const renderShareList = (items: ShareListItem[], type: "inbox" | "sent") => (
    <section className="glass-panel fade-in">
      <div className="panel-header">
        <div>
          <h2>{type === "inbox" ? "Inbox" : "Sent"}</h2>
          <p className="panel-subtitle">{type === "inbox" ? "Encrypted shares sent to you." : "Shares you have sent."}</p>
        </div>
        <button className="btn-secondary" onClick={type === "inbox" ? loadInbox : loadSent}>
          <i className="fa-solid fa-rotate" /> Refresh
        </button>
      </div>
      <div className="panel-body">
        {listsLoading ? (
          <div className="empty-state"><i className="fa-solid fa-spinner fa-spin" /><p>Loading…</p></div>
        ) : items.length === 0 ? (
          <div className="empty-state">
            <i className={`fa-solid fa-${type === "inbox" ? "inbox" : "paper-plane"}`} />
            <p>No {type === "inbox" ? "incoming" : "sent"} shares yet.</p>
          </div>
        ) : (
          <div className="share-list">
            {items.map((item) => (
              <div key={item.id} className="share-card">
                <div className="share-card-main">
                  <div className="share-card-title">
                    {type === "inbox"
                      ? `From ${item.sender?.username ?? "unknown"}`
                      : `To ${item.recipient?.username ?? "unknown"}`}
                    {item.has_attachment && <i className="fa-solid fa-paperclip" style={{ marginLeft: 8, fontSize: 12, opacity: 0.6 }} />}
                  </div>
                  <div className="share-card-meta">
                    <span>{formatDate(item.created_at)}</span>
                    {item.expires_at && <span className="badge badge-warning">Expires {formatDate(item.expires_at)}</span>}
                    {item.burn_on_read && <span className="badge badge-danger">Burn on read</span>}
                    {item.opened ? <span className="badge badge-success">Opened</span> : <span className="badge badge-secure">Unopened</span>}
                    {item.revoked && <span className="badge badge-danger">Revoked</span>}
                  </div>
                </div>
                <div className="share-card-actions">
                  {type === "inbox" && !item.revoked && (
                    <button className="btn-primary" onClick={() => openInboxItem(item.id)}>
                      <i className="fa-solid fa-lock-open" /> Open
                    </button>
                  )}
                  {type === "sent" && !item.revoked && (
                    confirmRevokeId === item.id ? (
                      <>
                        <button className="btn-danger" onClick={() => handleRevoke(item.id)} disabled={revokingId === item.id}>
                          {revokingId === item.id ? <i className="fa-solid fa-spinner fa-spin" /> : "Confirm Revoke"}
                        </button>
                        <button className="btn-secondary" onClick={() => setConfirmRevokeId(null)}>Cancel</button>
                      </>
                    ) : (
                      <button className="btn-danger" onClick={() => setConfirmRevokeId(item.id)}>
                        <i className="fa-solid fa-ban" /> Revoke
                      </button>
                    )
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );

  const renderAccountPanel = () => (
    <section className="glass-panel fade-in">
      <div className="panel-header">
        <div>
          <h2>{sessionUser ? "Your Account" : "Sign In or Register"}</h2>
          <p className="panel-subtitle">{sessionUser ? `Signed in as ${sessionUser.username}` : "Create an account for secure direct messaging."}</p>
        </div>
      </div>
      <div className="panel-body">
        {sessionUser ? (
          <div style={{ maxWidth: 420, margin: "0 auto" }}>
            <div className="config-card" style={{ marginBottom: 20 }}>
              <p><strong>Username:</strong> {sessionUser.username}</p>
              <p><strong>Email:</strong> {sessionUser.email}</p>
              <p style={{ marginTop: 12, fontSize: 13, color: "var(--text-muted)" }}>
                Encryption keys: {privateKeyRef.current ? (
                  <span style={{ color: "var(--color-success)" }}><i className="fa-solid fa-circle-check" /> Unlocked</span>
                ) : (
                  <span style={{ color: "var(--color-warning)" }}><i className="fa-solid fa-lock" /> Locked — <a href="#" onClick={(e) => { e.preventDefault(); setShowUnlockModal(true); }} style={{ color: "var(--accent-color)" }}>unlock</a></span>
                )}
              </p>
            </div>
            <button className="btn-danger" onClick={handleLogout}><i className="fa-solid fa-right-from-bracket" /> Sign Out</button>
          </div>
        ) : (
          <>
            <div className="auth-tabs">
              <button className={`auth-tab${authTab === "login" ? " active" : ""}`} onClick={() => { setAuthTab("login"); setAuthError(""); }}>Sign In</button>
              <button className={`auth-tab${authTab === "register" ? " active" : ""}`} onClick={() => { setAuthTab("register"); setAuthError(""); }}>Register</button>
            </div>
            {authTab === "login" ? (
              <form className="auth-form" onSubmit={handleLogin}>
                <div className="form-group">
                  <label className="form-label">Email or Username</label>
                  <input type="text" value={authForm.identifier} onChange={(e) => setAuthForm({ ...authForm, identifier: e.target.value })} required />
                </div>
                <div className="form-group">
                  <label className="form-label">Password</label>
                  <input type="password" value={authForm.password} onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })} required />
                </div>
                {authError && <p className="error-text">{authError}</p>}
                <button className="btn-primary" type="submit" disabled={authLoading} style={{ width: "100%" }}>
                  {authLoading ? <i className="fa-solid fa-spinner fa-spin" /> : "Sign In"}
                </button>
              </form>
            ) : (
              <form className="auth-form" onSubmit={handleRegister}>
                <div className="form-group">
                  <label className="form-label">Username</label>
                  <input type="text" value={authForm.username} onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })} required />
                  {usernameAvailability === "checking" && <p className="pw-hint"><i className="fa-solid fa-spinner fa-spin" /> Checking availability…</p>}
                  {usernameAvailability === "taken" && <p className="error-text"><i className="fa-solid fa-circle-xmark" /> That username is already taken.</p>}
                  {usernameAvailability === "available" && <p className="recipient-valid"><i className="fa-solid fa-circle-check" /> Available</p>}
                </div>
                <div className="form-group">
                  <label className="form-label">Email</label>
                  <input type="email" value={authForm.email} onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })} required />
                  {emailAvailability === "checking" && <p className="pw-hint"><i className="fa-solid fa-spinner fa-spin" /> Checking availability…</p>}
                  {emailAvailability === "taken" && <p className="error-text"><i className="fa-solid fa-circle-xmark" /> That email is already registered.</p>}
                  {emailAvailability === "available" && <p className="recipient-valid"><i className="fa-solid fa-circle-check" /> Available</p>}
                </div>
                <div className="form-group">
                  <label className="form-label">Password (min 10 chars)</label>
                  <input type="password" value={authForm.password} onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })} required />
                </div>
                <div className="form-group">
                  <label className="form-label">Confirm Password</label>
                  <input type="password" value={authForm.confirmPassword} onChange={(e) => setAuthForm({ ...authForm, confirmPassword: e.target.value })} required />
                  {authForm.confirmPassword.length > 0 && authForm.password !== authForm.confirmPassword && (
                    <p className="error-text"><i className="fa-solid fa-circle-xmark" /> Passwords don&apos;t match.</p>
                  )}
                </div>
                {authError && <p className="error-text">{authError}</p>}
                <button
                  className="btn-primary"
                  type="submit"
                  disabled={
                    authLoading ||
                    usernameAvailability === "taken" ||
                    emailAvailability === "taken" ||
                    (authForm.confirmPassword.length > 0 && authForm.password !== authForm.confirmPassword)
                  }
                  style={{ width: "100%" }}
                >
                  {authLoading ? <i className="fa-solid fa-spinner fa-spin" /> : "Create Account"}
                </button>
                <p className="pw-hint" style={{ marginTop: 12 }}>An ECDH P-256 keypair is generated in your browser. Your private key is encrypted with your password before upload.</p>
              </form>
            )}
          </>
        )}
      </div>
    </section>
  );

  const renderViewPanel = () => (
    <section className="glass-panel fade-in">
      <div className="panel-header">
        <div>
          <div className="status-tags">
            {isBurn && <span className="badge badge-danger"><i className="fa-solid fa-fire-flame-curved" /> Burn On Read</span>}
            {expiresAt && !isBurn && <span className="badge badge-warning"><i className="fa-regular fa-clock" /> Expires: {countdown}</span>}
            {decryptedPaste && !viewError && <span className="badge badge-success"><i className="fa-solid fa-circle-check" /> Decrypted Client-Side</span>}
            {viewIsAccount && <span className="badge badge-secure"><i className="fa-solid fa-user-shield" /> Account Share</span>}
          </div>
          <h2>{viewIsAccount ? "Protected Share" : "Decrypted Secure Paste"}</h2>
          <p className="panel-subtitle">
            {viewIsAccount && viewSender ? `From ${viewSender.username} · Traceable View enabled` : "Payload decrypted in your browser. No plaintext was sent to the server."}
          </p>
        </div>
        {decryptedPaste && !viewError && (
          <div className="view-tabs">
            <button className={`btn-tab${viewTab === "text" ? " active" : ""}`} onClick={() => setViewTab("text")}><i className="fa-solid fa-code" /> Plain Text</button>
            <button className={`btn-tab${viewTab === "markdown" ? " active" : ""}`} onClick={() => setViewTab("markdown")}><i className="fa-brands fa-markdown" /> Markdown</button>
          </div>
        )}
      </div>
      <div className="panel-body">
        {viewError && <div className="alert alert-danger"><i className="fa-solid fa-triangle-exclamation" /><span>{viewError}</span></div>}
        {viewIsAccount && decryptedPaste && !viewError && (
          <div className="info-banner"><i className="fa-solid fa-fingerprint" /> Protected content is traceably displayed to discourage unauthorized sharing.</div>
        )}
        {isBurn && decryptedPaste && (
          <div className="alert alert-warning"><i className="fa-solid fa-circle-info" /><span><strong>Burn-On-Read:</strong> This share is now deleted from the server.</span></div>
        )}
        {decryptedPaste && (
          <TraceableView
            recipientLabel={sessionUser?.email ?? sessionUser?.username ?? "viewer"}
            messageId={viewPasteId}
            enabled={viewIsAccount && !viewError}
          >
            <div className="editor-wrapper">
              {viewTab === "text"
                ? <pre className="view-text-area">{decryptedPaste.text || "(empty)"}</pre>
                : <div ref={viewMdRef} className="markdown-preview-area md-body" />}
            </div>
            {decryptedPaste.file && (
              <div className="config-card file-download-card">
                <h3><i className="fa-solid fa-paperclip" /> Decrypted Attachment</h3>
                <div className="file-download-bar">
                  <div className="file-details">
                    <i className="fa-solid fa-file-shield file-details-icon" />
                    <div className="file-meta">
                      <span className="file-name-txt">{sanitizeFilename(decryptedPaste.file.name)}</span>
                      <span className="file-size-txt">{formatBytes(decryptedPaste.file.size)}</span>
                    </div>
                  </div>
                  <button className="btn-primary" onClick={() => {
                    const a = document.createElement("a");
                    a.href = decryptedPaste.file!.data;
                    a.download = sanitizeFilename(decryptedPaste.file!.name);
                    a.click();
                    showToast("Download started.", "success");
                  }}><i className="fa-solid fa-download" /> Download</button>
                </div>
              </div>
            )}
          </TraceableView>
        )}
      </div>
      <div className="panel-footer view-footer">
        <button className="btn-secondary" onClick={() => copyText(decryptedPaste?.text ?? "", "Content copied!")}>
          <i className="fa-solid fa-copy" /> Copy Content
        </button>
        <a href="/" className="btn-primary" onClick={(e) => {
          e.preventDefault(); window.location.hash = ""; setViewMode("app");
          setDecryptedPaste(null); setViewError(null);
        }}><i className="fa-solid fa-plus" /> Back to App</a>
      </div>
    </section>
  );

  const renderCinematicView = () => (
    <div className="cinematic-backdrop fade-in">
      <div className="cinematic-card">
        <div className="shimmer-effect" />
        <div className="cinematic-header">
          <div>
            <h2 className="cinematic-title">{viewIsAccount ? "Protected Share" : "Decrypted Secure Paste"}</h2>
            <div className="status-tags">
              {isBurn && <span className="badge badge-danger"><i className="fa-solid fa-fire-flame-curved" /> Burn On Read</span>}
              {expiresAt && !isBurn && <span className="badge badge-warning"><i className="fa-regular fa-clock" /> Expires: {countdown}</span>}
              {decryptedPaste && !viewError && <span className="badge badge-success"><i className="fa-solid fa-circle-check" /> Decrypted Client-Side</span>}
              {viewIsAccount && <span className="badge badge-secure"><i className="fa-solid fa-user-shield" /> Account Share</span>}
            </div>
            {viewIsAccount && viewSender && (
              <p style={{ marginTop: 8, color: "var(--text-muted)", fontSize: 14 }}>From {viewSender.username} · Traceable View enabled</p>
            )}
          </div>
          <div className="view-tabs">
            <button className={`btn-tab${viewTab === "text" ? " active" : ""}`} onClick={() => setViewTab("text")}><i className="fa-solid fa-code" /> Plain Text</button>
            <button className={`btn-tab${viewTab === "markdown" ? " active" : ""}`} onClick={() => setViewTab("markdown")}><i className="fa-brands fa-markdown" /> Markdown</button>
          </div>
        </div>

        <div className="cinematic-body">
          {viewIsAccount && !viewError && (
            <div className="info-banner"><i className="fa-solid fa-fingerprint" /> Protected content is traceably displayed to discourage unauthorized sharing.</div>
          )}
          {isBurn && (
            <div className="alert alert-warning"><i className="fa-solid fa-circle-info" /><span><strong>Burn-On-Read:</strong> This share is now deleted from the server.</span></div>
          )}
          <TraceableView
            recipientLabel={sessionUser?.email ?? sessionUser?.username ?? "viewer"}
            messageId={viewPasteId}
            enabled={viewIsAccount && !viewError}
          >
            <div className="editor-wrapper" style={{ background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.1)" }}>
              {viewTab === "text"
                ? <pre className="view-text-area" style={{ maxHeight: '50vh', overflowY: 'auto' }}>{decryptedPaste!.text || "(empty)"}</pre>
                : <div ref={viewMdRef} className="markdown-preview-area md-body" style={{ maxHeight: '50vh', overflowY: 'auto' }} />}
            </div>
            {decryptedPaste!.file && (
              <div className="config-card file-download-card">
                <h3><i className="fa-solid fa-paperclip" /> Decrypted Attachment</h3>
                <div className="file-download-bar">
                  <div className="file-details">
                    <i className="fa-solid fa-file-shield file-details-icon" />
                    <div className="file-meta">
                      <span className="file-name-txt">{sanitizeFilename(decryptedPaste!.file.name)}</span>
                      <span className="file-size-txt">{formatBytes(decryptedPaste!.file.size)}</span>
                    </div>
                  </div>
                  <button className="btn-primary" onClick={() => {
                    const a = document.createElement("a");
                    a.href = decryptedPaste!.file!.data;
                    a.download = sanitizeFilename(decryptedPaste!.file!.name);
                    a.click();
                    showToast("Download started.", "success");
                  }}><i className="fa-solid fa-download" /> Download</button>
                </div>
              </div>
            )}
          </TraceableView>
        </div>

        <div className="cinematic-footer">
          <button className="btn-secondary" onClick={() => copyText(decryptedPaste?.text ?? "", "Content copied!")}>
            <i className="fa-solid fa-copy" /> Copy Content
          </button>
          <a href="/" className="btn-primary" onClick={(e) => {
            e.preventDefault(); window.location.hash = ""; setViewMode("app");
            setDecryptedPaste(null); setViewError(null);
          }}>
            <i className="fa-solid fa-xmark" /> Close
          </a>
        </div>
      </div>
    </div>
  );

  return (
    <>
      <div className="bg-glow bg-glow-1" />
      <div className="bg-glow bg-glow-2" />
      <div className="bg-glow bg-glow-3" />

      <div className={`app-wrap ${viewMode === "view" && decryptedPaste ? "app-blurred" : ""}`}>
        <header className="app-header">
          <div className="container header-container">
            <a href="/" className="logo" onClick={(e) => { e.preventDefault(); window.location.hash = ""; setViewMode("app"); setNav("create"); }}>
              <i className="fa-solid fa-shield-halved logo-icon" />
              <span>Aegis<span className="text-accent">Share</span></span>
            </a>
            <div className="header-right">
              {(viewMode === "app" || (viewMode === "view" && decryptedPaste)) && (
                <nav className="app-nav">
                  {(["create", "inbox", "sent", "account"] as NavTab[]).map((tab) => (
                    <button key={tab} className={`nav-link${nav === tab ? " active" : ""}`}
                      onClick={() => {
                        if ((tab === "inbox" || tab === "sent") && !sessionUser) { setNav("account"); showToast("Sign in required.", "info"); return; }
                        setNav(tab);
                      }}>
                      <i className={`fa-solid fa-${tab === "create" ? "plus" : tab === "inbox" ? "inbox" : tab === "sent" ? "paper-plane" : "user"}`} />
                      {tab.charAt(0).toUpperCase() + tab.slice(1)}
                      {tab === "inbox" && unreadCount > 0 && <span className="nav-badge">{unreadCount}</span>}
                    </button>
                  ))}
                  <a className="nav-link" href="/chatrooms"><i className="fa-solid fa-comments" /> Chatrooms</a>
                </nav>
              )}
              <span className="badge badge-secure"><i className="fa-solid fa-lock" /> Zero-Knowledge AES-256</span>
            </div>
          </div>
        </header>

        <main className="container main-content">
          {viewMode === "loading" && (
            <section className="glass-panel fade-in" style={{ padding: "60px 32px", textAlign: "center" }}>
              <i className="fa-solid fa-spinner fa-spin" style={{ fontSize: 36, color: "var(--accent-color)" }} />
              <p style={{ marginTop: 16, color: "var(--text-muted)" }}>Fetching encrypted payload…</p>
            </section>
          )}
          {viewMode === "view" && !decryptedPaste && renderViewPanel()}
          {(viewMode === "app" || (viewMode === "view" && decryptedPaste)) && (
            <>
              {nav === "create" && renderCreatePanel()}
              {nav === "inbox" && renderShareList(inboxItems, "inbox")}
              {nav === "sent" && renderShareList(sentItems, "sent")}
              {nav === "account" && renderAccountPanel()}
            </>
          )}
        </main>
      </div>

      {viewMode === "view" && !!decryptedPaste && renderCinematicView()}

      {/* Unlock keys modal */}
      {showUnlockModal && (
        <div className="modal-overlay">
          <div className="glass-panel modal-box">
            <div className="modal-header"><h3><i className="fa-solid fa-key" /> Unlock Encryption Keys</h3></div>
            <div className="modal-body">
              <p>Enter your account password to decrypt your private key locally. Keys stay in memory only — never stored on the server.</p>
              <div className="form-group">
                <input type="password" placeholder="Account password" value={unlockPassword}
                  onChange={(e) => setUnlockPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleUnlockKeys()} />
                {unlockError && <p className="error-text">{unlockError}</p>}
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-primary" onClick={handleUnlockKeys} disabled={unlockLoading}>
                {unlockLoading ? <i className="fa-solid fa-spinner fa-spin" /> : <><i className="fa-solid fa-unlock" /> Unlock</>}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Guest password modal */}
      {showPwModal && (
        <div className="modal-overlay">
          <div className="glass-panel modal-box">
            <div className="modal-header"><h3><i className="fa-solid fa-key" /> Password Required</h3></div>
            <div className="modal-body">
              <p>This paste is double-encrypted. Enter the password to derive the decryption key client-side.</p>
              <div className="form-group">
                <div className="pw-wrapper">
                  <input type={showModalPw ? "text" : "password"} placeholder="Enter password" value={modalPw}
                    onChange={(e) => setModalPw(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handlePasswordDecrypt()} />
                  <button className="btn-eye" onClick={() => setShowModalPw(!showModalPw)}>
                    <i className={`fa-solid fa-eye${showModalPw ? "-slash" : ""}`} />
                  </button>
                </div>
                {pwModalError && <p className="error-text">{pwModalError}</p>}
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-primary" onClick={handlePasswordDecrypt} disabled={decryptingPw}>
                {decryptingPw ? <i className="fa-solid fa-spinner fa-spin" /> : <><i className="fa-solid fa-unlock" /> Decrypt</>}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Result modal */}
      {showResultModal && (
        <div className="modal-overlay">
          <div className="glass-panel modal-box modal-box-wide">
            <div className="modal-header">
              <h3><i className="fa-solid fa-circle-check" style={{ color: "var(--accent-color)" }} />
                {resultIsAccount ? "Share Sent Successfully" : "Paste Created Successfully"}
              </h3>
              <button className="btn-close" onClick={() => setShowResultModal(false)}>&times;</button>
            </div>
            <div className="modal-body">
              {resultIsAccount ? (
                <>
                  <p className="result-notice">Sent to <strong>{resultRecipient}</strong>. No decryption key is included in the link — only the recipient can decrypt after signing in.</p>
                  <p style={{ fontSize: 13, color: "var(--text-muted)" }}>View this share in your <a href="#" onClick={(e) => { e.preventDefault(); setShowResultModal(false); setNav("sent"); }} style={{ color: "var(--accent-color)" }}>Sent</a> list.</p>
                </>
              ) : (
                <>
                  <p className="result-notice">The decryption key is in the URL fragment (#) and was never sent to the server. Anyone with the complete link can decrypt this.</p>
                  <div className="share-row">
                    <input type="text" readOnly value={shareUrl} />
                    <button className="btn-primary" onClick={() => copyText(shareUrl, "Link copied!")}><i className="fa-solid fa-copy" /></button>
                  </div>
                  <div className="deletion-box">
                    <p className="deletion-notice"><i className="fa-solid fa-triangle-exclamation" /> Keep this deletion link safe.</p>
                    <div className="share-row">
                      <input type="text" readOnly value={deleteUrl} />
                      <button className="btn-secondary" onClick={() => copyText(deleteUrl, "Deletion link copied!")}><i className="fa-solid fa-copy" /></button>
                    </div>
                  </div>
                  {qrSrc && (
                    <div className="qr-section">
                      <h4>Scan QR Code (Mobile Access)</h4>
                      <div className="qr-bg">
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img src={qrSrc} alt="QR Code" width={150} height={150} />
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
            <div className="modal-footer">
              <button className="btn-primary" onClick={() => setShowResultModal(false)}>Done</button>
            </div>
          </div>
        </div>
      )}

      <div className="toast-container">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.type}`}>
            {t.type === "success" && <i className="fa-solid fa-circle-check" />}
            {t.type === "error" && <i className="fa-solid fa-triangle-exclamation" />}
            {t.type === "info" && <i className="fa-solid fa-circle-info" />}
            <span>{t.message}</span>
          </div>
        ))}
      </div>
    </>
  );
}
