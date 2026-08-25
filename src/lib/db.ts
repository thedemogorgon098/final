import { createClient, type Client, type InValue } from "@libsql/client";
import path from "path";
import fs from "fs";
import { pathToFileURL } from "url";

// Resolved relative to process.cwd() by default — this is correct as long as
// `npm run dev` / `npm start` is always launched from the project root,
// which is the standard convention. The actual bug behind "registered fine,
// login says invalid" was that this failure mode was SILENT: if the dev
// server is ever launched from a different working directory (a different
// terminal, an IDE's default shell dir, etc.), this path silently points at
// a brand-new empty database instead of the one your account is in, and
// nothing tells you that happened. DATA_DIR lets you pin an absolute path
// explicitly (recommended for production); the logging below makes the
// resolved path impossible to miss so a cwd mismatch is caught immediately
// instead of showing up as a confusing "invalid password" 20 minutes later.
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(process.cwd(), "data");
const DB_PATH = path.join(DATA_DIR, "aegisshare.db");
const DATABASE_URL = process.env.TURSO_DATABASE_URL ?? pathToFileURL(DB_PATH).href;
const DATABASE_AUTH_TOKEN = process.env.TURSO_AUTH_TOKEN;
const isRemoteDatabase = DATABASE_URL.startsWith("libsql://") || DATABASE_URL.startsWith("https://");

if (!isRemoteDatabase && !fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

let _db: Client | null = null;
let _ready: Promise<void> | null = null;

async function migratePastes(db: Client): Promise<void> {
  const result = await db.execute("PRAGMA table_info(pastes)");
  const columns = new Set((result.rows as unknown as Array<{ name: string }>).map((row) => row.name));
  const additions: Array<[string, string]> = [
    ["mode", "TEXT NOT NULL DEFAULT 'guest'"], ["sender_id", "TEXT"],
    ["recipient_id", "TEXT"], ["wrapped_key", "TEXT"], ["key_metadata", "TEXT"],
    ["opened_at", "INTEGER"], ["revoked_at", "INTEGER"], ["deleted_at", "INTEGER"],
  ];
  for (const [name, definition] of additions) {
    if (!columns.has(name)) await db.execute(`ALTER TABLE pastes ADD COLUMN ${name} ${definition}`);
  }
}

async function migrateChatMessages(db: Client): Promise<void> {
  const result = await db.execute("PRAGMA table_info(chat_messages)");
  const columns = result.rows as unknown as Array<{ name: string }>;
  if (!columns.some((row) => row.name === "view_once")) {
    await db.execute("ALTER TABLE chat_messages ADD COLUMN view_once INTEGER NOT NULL DEFAULT 0");
  }
}

/*
function legacyInitDb(): Promise<sqlite3.Database> {
  if (_db && _ready) return _ready.then(() => _db!);
  _db = new sqlite3.Database(DB_PATH);
  _ready = new Promise((resolve, reject) => {
    _db!.serialize(async () => {
      try {
        await new Promise<void>((res, rej) => _db!.run("PRAGMA foreign_keys = ON", (e) => (e ? rej(e) : res())));
        await new Promise<void>((res, rej) =>
          _db!.run(
            `CREATE TABLE IF NOT EXISTS pastes (
              id TEXT PRIMARY KEY,
              payload TEXT NOT NULL,
              burn_on_read INTEGER DEFAULT 0,
              deletion_token TEXT NOT NULL,
              expires_at INTEGER,
              created_at INTEGER NOT NULL
            )`,
            (e) => (e ? rej(e) : res())
          )
        );
        await new Promise<void>((res, rej) =>
          _db!.run(
            `CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              username TEXT NOT NULL UNIQUE COLLATE NOCASE,
              email TEXT NOT NULL UNIQUE COLLATE NOCASE,
              password_hash TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            )`,
            (e) => (e ? rej(e) : res())
          )
        );
        await new Promise<void>((res, rej) =>
          _db!.run(
            `CREATE TABLE IF NOT EXISTS user_keys (
              user_id TEXT PRIMARY KEY,
              public_key TEXT NOT NULL,
              encrypted_private_key TEXT NOT NULL,
              key_metadata TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )`,
            (e) => (e ? rej(e) : res())
          )
        );
        await new Promise<void>((res, rej) =>
          _db!.run(
            `CREATE TABLE IF NOT EXISTS sessions (
              id TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              token_hash TEXT NOT NULL UNIQUE,
              expires_at INTEGER NOT NULL,
              created_at INTEGER NOT NULL,
              revoked_at INTEGER,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )`,
            (e) => (e ? rej(e) : res())
          )
        );
        await migratePastes(_db!);
        await new Promise<void>((res, rej) => _db!.run(
          `CREATE TABLE IF NOT EXISTS chat_rooms (
            id TEXT PRIMARY KEY, creator_id TEXT NOT NULL, title TEXT NOT NULL,
            expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, disabled_at INTEGER,
            FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
          )`, (e) => e ? rej(e) : res()
        ));
        await new Promise<void>((res, rej) => _db!.run(
          `CREATE TABLE IF NOT EXISTS chat_room_members (
            room_id TEXT NOT NULL, user_id TEXT NOT NULL, wrapped_key TEXT NOT NULL,
            key_metadata TEXT NOT NULL, joined_at INTEGER NOT NULL, PRIMARY KEY (room_id, user_id),
            FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
          )`, (e) => e ? rej(e) : res()
        ));
        await new Promise<void>((res, rej) => _db!.run(
          `CREATE TABLE IF NOT EXISTS chat_messages (
            id TEXT PRIMARY KEY, room_id TEXT NOT NULL, sender_id TEXT NOT NULL,
            ciphertext TEXT NOT NULL, iv TEXT NOT NULL, created_at INTEGER NOT NULL,
            FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
          )`, (e) => e ? rej(e) : res()
        ));
        await migrateChatMessages(_db!);
        await new Promise<void>((res, rej) => _db!.run(
          `CREATE TABLE IF NOT EXISTS chat_message_views (
            message_id TEXT NOT NULL, user_id TEXT NOT NULL, viewed_at INTEGER NOT NULL,
            PRIMARY KEY (message_id, user_id),
            FOREIGN KEY (message_id) REFERENCES chat_messages(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
          )`, (e) => e ? rej(e) : res()
        ));
        await new Promise<void>((res, rej) =>
          _db!.run("CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)", (e) => (e ? rej(e) : res()))
        );
        await new Promise<void>((res, rej) =>
          _db!.run("CREATE INDEX IF NOT EXISTS idx_pastes_recipient ON pastes(recipient_id, created_at)", (e) => (e ? rej(e) : res()))
        );
        await new Promise<void>((res, rej) =>
          _db!.run("CREATE INDEX IF NOT EXISTS idx_pastes_sender ON pastes(sender_id, created_at)", (e) => (e ? rej(e) : res()))
        );
        await new Promise<void>((res, rej) =>
          _db!.run("CREATE INDEX IF NOT EXISTS idx_pastes_expiry ON pastes(expires_at)", (e) => (e ? rej(e) : res()))
        );
        await new Promise<void>((res, rej) =>
          _db!.run("CREATE INDEX IF NOT EXISTS idx_chat_messages_room ON chat_messages(room_id, created_at)", (e) => (e ? rej(e) : res()))
        );
        await new Promise<void>((res, rej) =>
          _db!.run("CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_room_members(user_id)", (e) => (e ? rej(e) : res()))
        );
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
  return _ready.then(() => _db!);
}
*/

async function initializeDb(db: Client): Promise<void> {
  const statements = [
    "PRAGMA foreign_keys = ON",
    `CREATE TABLE IF NOT EXISTS pastes (id TEXT PRIMARY KEY, payload TEXT NOT NULL, burn_on_read INTEGER DEFAULT 0, deletion_token TEXT NOT NULL, expires_at INTEGER, created_at INTEGER NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS user_keys (user_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, encrypted_private_key TEXT NOT NULL, key_metadata TEXT NOT NULL, created_at INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`,
    `CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`,
    `CREATE TABLE IF NOT EXISTS chat_rooms (id TEXT PRIMARY KEY, creator_id TEXT NOT NULL, title TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, disabled_at INTEGER, FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE)`,
    `CREATE TABLE IF NOT EXISTS chat_room_members (room_id TEXT NOT NULL, user_id TEXT NOT NULL, wrapped_key TEXT NOT NULL, key_metadata TEXT NOT NULL, joined_at INTEGER NOT NULL, PRIMARY KEY (room_id, user_id), FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`,
    `CREATE TABLE IF NOT EXISTS chat_messages (id TEXT PRIMARY KEY, room_id TEXT NOT NULL, sender_id TEXT NOT NULL, ciphertext TEXT NOT NULL, iv TEXT NOT NULL, created_at INTEGER NOT NULL, FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE, FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE)`,
    `CREATE TABLE IF NOT EXISTS chat_message_views (message_id TEXT NOT NULL, user_id TEXT NOT NULL, viewed_at INTEGER NOT NULL, PRIMARY KEY (message_id, user_id), FOREIGN KEY (message_id) REFERENCES chat_messages(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`,
    "CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)",
    "CREATE INDEX IF NOT EXISTS idx_pastes_recipient ON pastes(recipient_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_pastes_sender ON pastes(sender_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_pastes_expiry ON pastes(expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_chat_messages_room ON chat_messages(room_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_room_members(user_id)",
  ];
  for (const statement of statements) await db.execute(statement);
  await migratePastes(db);
  await migrateChatMessages(db);
}

function getDb(): Client {
  if (!_db) {
    if ((DATABASE_URL.startsWith("libsql://") || DATABASE_URL.startsWith("https://")) && !DATABASE_AUTH_TOKEN) {
      throw new Error("TURSO_AUTH_TOKEN is required for a remote database.");
    }
    _db = createClient({ url: DATABASE_URL, authToken: DATABASE_AUTH_TOKEN });
  }
  return _db;
}

function initDb(): Promise<Client> {
  if (_db && _ready) return _ready.then(() => _db!);
  _db = getDb();
  _ready = initializeDb(_db);
  return _ready.then(() => _db!);
}

async function ensureDb(): Promise<Client> {
  return initDb();
}

export interface PasteRow {
  id: string;
  payload: string;
  burn_on_read: number;
  deletion_token: string;
  expires_at: number | null;
  created_at: number;
  mode: "guest" | "account";
  sender_id: string | null;
  recipient_id: string | null;
  wrapped_key: string | null;
  key_metadata: string | null;
  opened_at: number | null;
  revoked_at: number | null;
  deleted_at: number | null;
}

export interface UserRow {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  created_at: number;
  updated_at: number;
}

export interface UserKeyRow {
  user_id: string;
  public_key: string;
  encrypted_private_key: string;
  key_metadata: string;
  created_at: number;
}

export interface SessionRow {
  id: string;
  user_id: string;
  token_hash: string;
  expires_at: number;
  created_at: number;
  revoked_at: number | null;
}

export function dbGet<T>(sql: string, params: unknown[] = []): Promise<T | undefined> {
  return ensureDb().then(async (db) => {
    const result = await db.execute({ sql, args: params as InValue[] });
    return result.rows[0] as T | undefined;
  });
}

export function dbAll<T>(sql: string, params: unknown[] = []): Promise<T[]> {
  return ensureDb().then(async (db) => {
    const result = await db.execute({ sql, args: params as InValue[] });
    return result.rows as unknown as T[];
  });
}

export function dbRun(sql: string, params: unknown[] = []): Promise<void> {
  return ensureDb().then(async (db) => {
    await db.execute({ sql, args: params as InValue[] });
  });
}

export function dbRunResult(sql: string, params: unknown[] = []): Promise<{ changes: number; lastID: number }> {
  return ensureDb().then(async (db) => {
    const result = await db.execute({ sql, args: params as InValue[] });
    return { changes: result.rowsAffected, lastID: Number(result.lastInsertRowid ?? 0) };
  });
}

export async function purgeExpired(): Promise<void> {
  const now = Date.now();
  // Lazy cleanup fits this self-hosted app: every API request marks expired shares inaccessible.
  await dbRun(
    "UPDATE pastes SET deleted_at = ? WHERE expires_at IS NOT NULL AND expires_at < ? AND deleted_at IS NULL",
    [now, now]
  );
  await dbRun("DELETE FROM sessions WHERE expires_at < ? OR revoked_at IS NOT NULL", [now]);
  await dbRun("UPDATE chat_rooms SET disabled_at = ? WHERE expires_at <= ? AND disabled_at IS NULL", [now, now]);
  await dbRun("DELETE FROM chat_messages WHERE room_id IN (SELECT id FROM chat_rooms WHERE disabled_at IS NOT NULL)");
  await dbRun("DELETE FROM chat_room_members WHERE room_id IN (SELECT id FROM chat_rooms WHERE disabled_at IS NOT NULL)");
}
