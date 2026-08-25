import { randomBytes, scrypt as scryptCallback, createHash, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { cookies } from "next/headers";
import { dbGet, dbRun, purgeExpired, SessionRow, UserRow } from "@/lib/db";

const scrypt = promisify(scryptCallback);
const SESSION_COOKIE = "aegisshare_session";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface PublicUser {
  id: string;
  username: string;
  email: string;
}

export function publicUser(user: UserRow): PublicUser {
  return { id: user.id, username: user.username, email: user.email };
}

export function normalizeIdentifier(value: string): string {
  return value.trim().toLowerCase();
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("base64");
  const derived = (await scrypt(password, salt, 64)) as Buffer;
  return `scrypt$${salt}$${derived.toString("base64")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, salt, expectedB64] = stored.split("$");
  if (scheme !== "scrypt" || !salt || !expectedB64) return false;
  const actual = (await scrypt(password, salt, 64)) as Buffer;
  const expected = Buffer.from(expectedB64, "base64");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function hashSessionToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export async function createSession(userId: string): Promise<string> {
  const token = randomBytes(32).toString("base64url");
  const now = Date.now();
  await dbRun(
    `INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?)`,
    [randomBytes(12).toString("hex"), userId, hashSessionToken(token), now + SESSION_TTL_MS, now]
  );
  return token;
}

export async function setSessionCookie(token: string): Promise<void> {
  const jar = await cookies();
  jar.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: Math.floor(SESSION_TTL_MS / 1000),
  });
}

export async function clearSessionCookie(): Promise<void> {
  const jar = await cookies();
  const token = jar.get(SESSION_COOKIE)?.value;
  if (token) {
    await dbRun("UPDATE sessions SET revoked_at = ? WHERE token_hash = ?", [Date.now(), hashSessionToken(token)]);
  }
  jar.delete(SESSION_COOKIE);
}

export async function getCurrentUser(): Promise<UserRow | null> {
  await purgeExpired();
  const jar = await cookies();
  const token = jar.get(SESSION_COOKIE)?.value;
  if (!token) return null;

  const session = await dbGet<SessionRow>(
    "SELECT * FROM sessions WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
    [hashSessionToken(token), Date.now()]
  );
  if (!session) return null;

  return (
    (await dbGet<UserRow>("SELECT * FROM users WHERE id = ?", [session.user_id])) ?? null
  );
}

export async function requireUser(): Promise<UserRow> {
  const user = await getCurrentUser();
  if (!user) {
    throw new Error("Unauthorized");
  }
  return user;
}
