import { randomBytes } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { createSession, hashPassword, normalizeIdentifier, publicUser, setSessionCookie } from "@/lib/auth";
import { dbGet, dbRun, UserRow } from "@/lib/db";
import { rateLimit } from "@/lib/rateLimit";

export async function POST(req: NextRequest) {
  const limited = rateLimit(req, { capacity: 5, refillPeriodSeconds: 300, keyPrefix: "register" });
  if (limited) return limited;

  try {
    const body = (await req.json()) as {
      username?: string;
      email?: string;
      password?: string;
      confirmPassword?: string;
      public_key?: string;
      encrypted_private_key?: string;
      key_metadata?: string;
    };

    const username = body.username?.trim() ?? "";
    const email = normalizeIdentifier(body.email ?? "");
    const password = body.password ?? "";

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return NextResponse.json({ error: "Username must be 3-24 letters, numbers, or underscores." }, { status: 400 });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json({ error: "Enter a valid email address." }, { status: 400 });
    }
    if (password.length < 10) {
      return NextResponse.json({ error: "Password must be at least 10 characters." }, { status: 400 });
    }
    if (password !== body.confirmPassword) {
      return NextResponse.json({ error: "Passwords do not match." }, { status: 400 });
    }
    if (!body.public_key || !body.encrypted_private_key || !body.key_metadata) {
      return NextResponse.json({ error: "Encrypted key material is required." }, { status: 400 });
    }

    const duplicate = await dbGet<UserRow>(
      "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
      [username, email]
    );
    if (duplicate?.username.toLowerCase() === username.toLowerCase()) {
      return NextResponse.json({ error: "That username is already registered." }, { status: 409 });
    }
    if (duplicate?.email.toLowerCase() === email) {
      return NextResponse.json({ error: "That email is already registered." }, { status: 409 });
    }

    const now = Date.now();
    const userId = randomBytes(12).toString("hex");
    const passwordHash = await hashPassword(password);

    // Wrapped in a transaction so a failure partway through (e.g. the
    // user_keys insert failing) can't leave an orphaned user row with no
    // key material — which would silently break that account's login forever
    // since account-mode share features all assume user_keys exists.
    try {
      await dbRun("BEGIN TRANSACTION");
      await dbRun(
        `INSERT INTO users (id, username, email, password_hash, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [userId, username, email, passwordHash, now, now]
      );
      await dbRun(
        `INSERT INTO user_keys (user_id, public_key, encrypted_private_key, key_metadata, created_at)
         VALUES (?, ?, ?, ?, ?)`,
        [userId, body.public_key, body.encrypted_private_key, body.key_metadata, now]
      );
      await dbRun("COMMIT");
    } catch (txErr) {
      await dbRun("ROLLBACK").catch(() => {});
      // Two requests can both pass the duplicate-check SELECT above before
      // either INSERT completes (classic check-then-act race). The SELECT
      // is a fast-path for a friendly error in the common case; this catch
      // is the actual guarantee, enforced by the UNIQUE constraint in the
      // schema — without it, the loser of the race got a raw 500 instead
      // of "username taken."
      const message = txErr instanceof Error ? txErr.message : String(txErr);
      if (message.includes("UNIQUE constraint failed")) {
        return NextResponse.json({ error: "That username or email was just taken — try another." }, { status: 409 });
      }
      throw txErr;
    }

    const token = await createSession(userId);
    await setSessionCookie(token);
    const user = await dbGet<UserRow>("SELECT * FROM users WHERE id = ?", [userId]);
    return NextResponse.json({ user: publicUser(user!) });
  } catch (err) {
    console.error("POST /api/auth/register error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}