import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { dbAll, purgeExpired } from "@/lib/db";

interface SentRow {
  id: string;
  created_at: number;
  expires_at: number | null;
  burn_on_read: number;
  opened_at: number | null;
  revoked_at: number | null;
  deleted_at: number | null;
  payload: string;
  recipient_username: string;
  recipient_email: string;
}

export async function GET() {
  await purgeExpired();
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ error: "Sign in required." }, { status: 401 });

  const rows = await dbAll<SentRow>(
    `SELECT p.id, p.created_at, p.expires_at, p.burn_on_read, p.opened_at, p.revoked_at, p.deleted_at, p.payload,
            u.username AS recipient_username, u.email AS recipient_email
       FROM pastes p
       JOIN users u ON u.id = p.recipient_id
      WHERE p.mode = 'account' AND p.sender_id = ? AND p.deleted_at IS NULL
      ORDER BY p.created_at DESC`,
    [user.id]
  );

  return NextResponse.json({
    items: rows.map((row) => ({
      id: row.id,
      recipient: { username: row.recipient_username, email: row.recipient_email },
      created_at: row.created_at,
      expires_at: row.expires_at,
      burn_on_read: !!row.burn_on_read,
      opened: !!row.opened_at,
      revoked: !!row.revoked_at,
      has_attachment: row.payload.includes('"file":') && !row.payload.includes('"file":null'),
    })),
  });
}
