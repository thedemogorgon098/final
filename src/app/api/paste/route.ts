import { NextRequest, NextResponse } from "next/server";
import { randomBytes } from "crypto";
import { getCurrentUser } from "@/lib/auth";
import { dbGet, dbRun, purgeExpired, UserRow } from "@/lib/db";

export async function POST(req: NextRequest) {
  try {
    await purgeExpired();

    const body = (await req.json()) as {
      mode?: "guest" | "account";
      payload?: string;
      burn_on_read?: boolean;
      expires_at?: number | null;
      recipient?: string;
      wrapped_key?: string;
      key_metadata?: string;
    };

    if (!body.payload) {
      return NextResponse.json({ error: "Payload is required." }, { status: 400 });
    }

    const mode = body.mode ?? "guest";
    const id = randomBytes(8).toString("hex");
    const deletionToken = randomBytes(16).toString("hex");
    const now = Date.now();
    const expiresAt = typeof body.expires_at === "number" ? body.expires_at : null;
    const burnOnRead = body.burn_on_read ? 1 : 0;

    if (mode === "account") {
      const sender = await getCurrentUser();
      if (!sender) {
        return NextResponse.json({ error: "Sign in required." }, { status: 401 });
      }
      const recipientQuery = body.recipient?.trim() ?? "";
      const recipient = await dbGet<UserRow>(
        "SELECT * FROM users WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE",
        [recipientQuery.toLowerCase(), recipientQuery]
      );
      if (!recipient || recipient.id === sender.id) {
        return NextResponse.json({ error: "Recipient is not available." }, { status: 400 });
      }
      if (!body.wrapped_key || !body.key_metadata) {
        return NextResponse.json({ error: "Wrapped key material is required." }, { status: 400 });
      }

      await dbRun(
        `INSERT INTO pastes
          (id, payload, burn_on_read, deletion_token, expires_at, created_at, mode, sender_id, recipient_id, wrapped_key, key_metadata)
         VALUES (?, ?, ?, ?, ?, ?, 'account', ?, ?, ?, ?)`,
        [id, body.payload, burnOnRead, deletionToken, expiresAt, now, sender.id, recipient.id, body.wrapped_key, body.key_metadata]
      );
      return NextResponse.json({
        id,
        expires_at: expiresAt,
        burn_on_read: !!burnOnRead,
        recipient: { username: recipient.username, email: recipient.email },
      });
    }

    await dbRun(
      `INSERT INTO pastes (id, payload, burn_on_read, deletion_token, expires_at, created_at, mode)
       VALUES (?, ?, ?, ?, ?, ?, 'guest')`,
      [id, body.payload, burnOnRead, deletionToken, expiresAt, now]
    );

    return NextResponse.json({ id, deletion_token: deletionToken, expires_at: expiresAt, burn_on_read: !!burnOnRead });
  } catch (err) {
    console.error("POST /api/paste error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({ error: "Use GET /api/paste/:id" }, { status: 400 });
}
