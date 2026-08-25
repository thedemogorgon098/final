"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { decryptData, encryptData, generateAESKey, unlockAccountPrivateKey, unwrapContentKeyFromSender, wrapContentKeyForRecipient } from "@/lib/crypto";

type User = { id: string; username: string; email: string };
type KeyBundle = { public_key: string; encrypted_private_key: string; key_metadata: string };
type Candidate = User & { public_key: string };
type Room = { id: string; title: string; expires_at: number; created_at: number; creator_id: string; member_count: number };
type ChatFile = { name: string; type: string; size: number; data: string };
type WireMessage = { id: string; ciphertext: string | null; iv: string | null; created_at: number; sender_id: string; username: string; view_once?: number; viewed?: number };
type Message = WireMessage & { text?: string; unreadable?: boolean; file?: ChatFile };

export default function ChatroomsPage() {
  const [user, setUser] = useState<User | null>(null);
  const [bundle, setBundle] = useState<KeyBundle | null>(null);
  const privateKey = useRef<CryptoKey | null>(null);
  const roomKey = useRef<CryptoKey | null>(null);
  const [password, setPassword] = useState("");
  const [rooms, setRooms] = useState<Room[]>([]);
  const [active, setActive] = useState<Room | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [members, setMembers] = useState<User[]>([]);
  const [title, setTitle] = useState("");
  const [identifier, setIdentifier] = useState("");
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [draft, setDraft] = useState("");
  const [attachment, setAttachment] = useState<ChatFile | null>(null);
  const [openingFileId, setOpeningFileId] = useState<string | null>(null);
  const [previewFile, setPreviewFile] = useState<ChatFile | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [unlocking, setUnlocking] = useState(false);
  const [now, setNow] = useState(Date.now());

  const loadRooms = useCallback(async () => {
    const res = await fetch("/api/chatrooms", { cache: "no-store" });
    if (res.ok) setRooms(((await res.json()).rooms ?? []).filter((room: Room) => room.expires_at > Date.now()));
  }, []);

  useEffect(() => {
    fetch("/api/auth/session").then((r) => r.json()).then((data) => { setUser(data.user); setBundle(data.keyBundle); if (data.user) loadRooms(); });
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(clock);
  }, [loadRooms]);

  const unlock = async () => {
    if (!bundle || !password) return;
    setUnlocking(true);
    try {
      privateKey.current = await unlockAccountPrivateKey(bundle.encrypted_private_key, bundle.key_metadata, password);
      setPassword(""); setNotice("Encryption keys unlocked locally.");
    } catch { setNotice("That password could not unlock your private key."); }
    finally { setUnlocking(false); }
  };

  const addMember = async () => {
    const query = identifier.trim();
    if (!query) return;
    const res = await fetch(`/api/users/resolve?q=${encodeURIComponent(query)}`);
    const data = await res.json();
    if (!res.ok) { setNotice(data.error ?? "Member not found."); return; }
    const candidate = data.recipient as Candidate;
    if (candidates.some((m) => m.id === candidate.id)) { setNotice("That member is already included."); return; }
    setCandidates((old) => [...old, candidate]); setIdentifier(""); setNotice("");
  };

  const createRoom = async (event: FormEvent) => {
    event.preventDefault();
    if (!user || !bundle) { setNotice("Sign in before creating a room."); return; }
    if (!title.trim() || candidates.length === 0) { setNotice("Add a title and at least one other member."); return; }
    setBusy(true);
    try {
      const key = await generateAESKey();
      const all = [{ ...user, public_key: bundle.public_key }, ...candidates];
      const envelopes = await Promise.all(all.map(async (member) => ({ user_id: member.id, ...(await wrapContentKeyForRecipient(key, member.public_key)) })));
      const res = await fetch("/api/chatrooms", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title, members: envelopes }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      roomKey.current = key;
      setTitle(""); setCandidates([]); setNotice("Secret room created. It expires in 10 minutes.");
      await loadRooms();
      await openRoom(data.id, key);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not create room."); }
    finally { setBusy(false); }
  };

  const decryptMessages = async (wire: WireMessage[], key: CryptoKey) => Promise.all(wire.map(async (message) => {
    if (message.view_once) return { ...message };
    try {
      const plaintext = await decryptData(message.ciphertext!, message.iv!, key);
      const content = JSON.parse(plaintext) as { kind?: string; text?: string };
      return { ...message, text: content.kind === "text" ? content.text : plaintext };
    } catch { return { ...message, unreadable: true }; }
  }));

  const openRoom = async (id: string, knownKey?: CryptoKey) => {
    if (!privateKey.current && !knownKey) { setNotice("Unlock your encryption keys above, then press Join discussion again."); return; }
    const res = await fetch(`/api/chatrooms/${id}`, { cache: "no-store" });
    const data = await res.json();
    if (!res.ok) { setNotice(data.error ?? "Room unavailable."); setActive(null); return; }
    try {
      const key = knownKey ?? await unwrapContentKeyFromSender(data.envelope.wrapped_key, data.envelope.key_metadata, privateKey.current!);
      roomKey.current = key;
      setActive(data.room); setMembers(data.members); setMessages(await decryptMessages(data.messages, key)); setNotice("");
    } catch { setNotice("Unable to decrypt this room key."); }
  };

  useEffect(() => {
    if (!active) return;
    const poll = window.setInterval(() => openRoom(active.id, roomKey.current ?? undefined), 1000);
    return () => window.clearInterval(poll);
  // Polling is tied only to the selected room.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active?.id]);

  const send = async (event: FormEvent) => {
    event.preventDefault();
    if (!active || !roomKey.current || (!draft.trim() && !attachment)) return;
    const text = draft.trim(); const file = attachment;
    setDraft(""); setAttachment(null);
    const encrypted = await encryptData(JSON.stringify(file ? { kind: "file", file } : { kind: "text", text }), roomKey.current);
    const res = await fetch(`/api/chatrooms/${active.id}/messages`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...encrypted, view_once: !!file }) });
    const data = await res.json();
    if (!res.ok) { setDraft(text); setAttachment(file); setNotice(data.error ?? "Message was not sent."); return; }
    setMessages((old) => [...old, { ...data.message, text: file ? undefined : text, file: undefined }]);
  };

  const chooseFile = (file: File | undefined) => {
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) { setNotice("Files are limited to 2 MB in secret chatrooms."); return; }
    const reader = new FileReader();
    reader.onload = () => setAttachment({ name: file.name, type: file.type || "application/octet-stream", size: file.size, data: reader.result as string });
    reader.readAsDataURL(file);
  };

  const openOnceFile = async (message: Message) => {
    if (!active || !roomKey.current || openingFileId) return;
    setOpeningFileId(message.id);
    try {
      const res = await fetch(`/api/chatrooms/${active.id}/messages/${message.id}/open`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      const plaintext = await decryptData(data.message.ciphertext, data.message.iv, roomKey.current);
      const content = JSON.parse(plaintext) as { kind?: string; file?: ChatFile };
      if (content.kind !== "file" || !content.file) throw new Error("This view-once item is invalid.");
      setPreviewFile(content.file);
      setMessages((old) => old.map((item) => item.id === message.id ? { ...item, viewed: 1 } : item));
    } catch (error) { setNotice(error instanceof Error ? error.message : "File could not be opened."); }
    finally { setOpeningFileId(null); }
  };

  const seconds = active ? Math.max(0, Math.ceil((active.expires_at - now) / 1000)) : 0;
  const remaining = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
  if (!user) return <main className="container main-content"><section className="glass-panel" style={{ padding: 32 }}><h1>Secret chatrooms</h1><p className="panel-subtitle">Sign in from the Account area to create or join encrypted rooms.</p><a className="btn-primary" href="/">Go to Account</a></section></main>;

  return <main className="container main-content chatroom-page" onContextMenu={(event) => event.preventDefault()}>
    <section className="glass-panel chatroom-hero">
      <div className="chatroom-heading"><div><p className="chat-hero-kicker"><i className="fa-solid fa-shield-halved" /> Private by design</p><h1>Secret discussion rooms</h1><p className="panel-subtitle">Encrypted group conversations that disappear automatically after 10 minutes.</p></div><a className="btn-secondary" href="/"><i className="fa-solid fa-arrow-left" /> Back to shares</a></div>
      {!privateKey.current && <div className="warning-banner"><i className="fa-solid fa-key" /><span>Unlock your account key locally to join and read rooms.<br /><input className="chat-unlock" type="password" value={password} onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => e.key === "Enter" && unlock()} placeholder="Account password" /><button className="btn-secondary" onClick={unlock} disabled={unlocking}>{unlocking ? "Unlocking…" : "Unlock"}</button></span></div>}
      {notice && <p className="info-banner">{notice}</p>}
    </section>
    <div className="chatroom-grid">
      <aside className="glass-panel chat-sidebar">
        <div className="chat-sidebar-heading"><span><i className="fa-solid fa-plus" /></span><div><h2>Start a private room</h2><p>Create a time-limited group space.</p></div></div><form onSubmit={createRoom}><label className="chat-field-label" htmlFor="room-title">Room name</label><div className="chat-field-shell"><i className="fa-solid fa-hashtag" /><input id="room-title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Project Aurora" maxLength={80} /></div><label className="chat-field-label" htmlFor="room-member">Invite a member</label><div className="chat-add-member"><div className="chat-field-shell"><i className="fa-solid fa-at" /><input id="room-member" value={identifier} onChange={(e) => setIdentifier(e.target.value)} placeholder="username or email address" /></div><button type="button" className="btn-secondary" onClick={addMember}><i className="fa-solid fa-user-plus" /> Invite</button></div>
        <div className="chat-member-chips">{candidates.map((member) => <span key={member.id}>{member.username}<button type="button" onClick={() => setCandidates((old) => old.filter((item) => item.id !== member.id))}>×</button></span>)}</div>
        <button className="btn-primary" disabled={busy}>{busy ? "Creating…" : "Create 10-minute room"}</button></form>
        <h2 className="chat-list-title">Your active rooms</h2>{rooms.length ? rooms.map((room) => <div key={room.id} className={`chat-room-link${active?.id === room.id ? " active" : ""}`}><strong>{room.title}</strong><span>{room.member_count} members · {Math.max(0, Math.ceil((room.expires_at - now) / 60000))}m left</span><button className="btn-secondary chat-join-button" onClick={() => openRoom(room.id)}>{active?.id === room.id ? "Open" : "Join discussion"}</button></div>) : <p className="panel-subtitle">No active rooms.</p>}
      </aside>
      <section className="glass-panel chat-main">
        {!active ? <div className="empty-state"><i className="fa-solid fa-comments" /><p>Use “Join discussion” on an active invitation. Rooms do not retain plaintext on this server.</p></div> : seconds <= 0 ? <div className="empty-state"><p>This room has expired. Its encrypted messages and room keys are being removed.</p></div> : <><div className="chat-header"><div className="chat-discussion-title"><span className="chat-title-icon"><i className="fa-solid fa-comments" /></span><div><p className="chat-eyebrow">Private room</p><h2>{active.title}</h2><div className="chat-usernames">{members.map((member) => <span key={member.id}><i className="fa-solid fa-user" /> {member.username}</span>)}</div></div></div><strong className="chat-timer"><i className="fa-solid fa-clock" /> {remaining}</strong></div><div className="chat-messages">{messages.map((message) => { const isOwn = message.sender_id === user.id; return <article key={message.id} className={`chat-message${isOwn ? " own" : ""}`}><header><span className="chat-sender-name">{isOwn ? "You" : `@${message.username}`}</span><time>{new Date(message.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time></header>{message.view_once ? <div className="chat-file-message"><i className="fa-solid fa-file-shield" /><div><strong>View-once file</strong><span>{message.viewed ? "Already viewed" : "Available for one secure view"}</span></div>{!message.viewed && <button className="btn-secondary" onClick={() => openOnceFile(message)} disabled={openingFileId === message.id}>{openingFileId === message.id ? "Opening…" : "View file"}</button>}</div> : <p>{message.unreadable ? "Encrypted message could not be decrypted." : message.text}</p>}</article>; })}</div><form className="chat-compose" onSubmit={send}><span className="chat-compose-lock"><i className="fa-solid fa-lock" /></span><input value={draft} onChange={(e) => setDraft(e.target.value)} maxLength={6000} placeholder={attachment ? `Ready to send: ${attachment.name}` : "Write an encrypted message…"} aria-label="Write an encrypted message" autoComplete="off" /><label className="chat-file-button" title="Attach a view-once file"><i className="fa-solid fa-paperclip" /><input type="file" onChange={(e) => chooseFile(e.target.files?.[0])} /></label><button className="btn-primary" disabled={!draft.trim() && !attachment}><i className="fa-solid fa-paper-plane" /> Send</button></form>{attachment && <div className="chat-attachment"><i className="fa-solid fa-file-shield" /> <span>{attachment.name} · {(attachment.size / 1024).toFixed(1)} KB · view once</span><button onClick={() => setAttachment(null)} aria-label="Remove attachment">×</button></div>}<p className="chat-compose-note"><i className="fa-solid fa-shield-halved" /> Encrypted with this room’s AES-256 key before it leaves your browser.</p></>}
      </section>
    </div>
    {previewFile && <div className="chat-file-viewer" role="dialog" aria-modal="true" aria-label="View-once file">
      <div className="chat-file-viewer-card">
        <div className="chat-file-viewer-header"><div><p className="chat-eyebrow">View once</p><h2>{previewFile.name}</h2></div><button className="btn-close" onClick={() => setPreviewFile(null)} aria-label="Close file viewer"><i className="fa-solid fa-xmark" /></button></div>
        {previewFile.type.startsWith("image/") ? <img className="chat-preview-image" src={previewFile.data} alt={previewFile.name} /> : <div className="chat-preview-file"><i className="fa-solid fa-file" /><p>This file has been opened once.</p><a className="btn-primary" href={previewFile.data} download={previewFile.name}><i className="fa-solid fa-download" /> Download file</a></div>}
        <p className="chat-compose-note"><i className="fa-solid fa-circle-check" /> Closing this viewer removes the file from this chat session.</p>
      </div>
    </div>}
  </main>;
}
