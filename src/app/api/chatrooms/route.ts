import { randomBytes } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { dbAll, dbRun, purgeExpired, UserKeyRow, UserRow } from "@/lib/db";
import { rateLimit } from "@/lib/rateLimit";

type MemberInput = { user_id?: string; wrapped_key?: string; key_metadata?: string };

export async function POST(req: NextRequest) {
  const limited = rateLimit(req, { capacity: 12, refillPeriodSeconds: 60, keyPrefix: "chat-create" });
  if (limited) return limited;
  try {
    await purgeExpired();
    const creator = await getCurrentUser();
    if (!creator) return NextResponse.json({ error: "Sign in required." }, { status: 401 });
    const body = await req.json() as { title?: string; members?: MemberInput[] };
    const title = body.title?.trim() ?? "";
    const members = body.members ?? [];
    if (!title || title.length > 80) return NextResponse.json({ error: "Give the room a title of up to 80 characters." }, { status: 400 });
    if (members.length < 2 || members.length > 20) return NextResponse.json({ error: "A room needs 2–20 members, including you." }, { status: 400 });
    const ids = members.map((member) => member.user_id ?? "");
    if (!ids.includes(creator.id) || new Set(ids).size !== ids.length || members.some((m) => !m.wrapped_key || !m.key_metadata)) {
      return NextResponse.json({ error: "Invalid member key envelopes." }, { status: 400 });
    }
    const placeholders = ids.map(() => "?").join(",");
    const users = await dbAll<UserRow>(`SELECT * FROM users WHERE id IN (${placeholders})`, ids);
    const keys = await dbAll<UserKeyRow>(`SELECT * FROM user_keys WHERE user_id IN (${placeholders})`, ids);
    if (users.length !== ids.length || keys.length !== ids.length) return NextResponse.json({ error: "One or more members are unavailable." }, { status: 400 });

    const now = Date.now();
    const id = randomBytes(12).toString("hex");
    const expiresAt = now + 10 * 60 * 1000;
    await dbRun("BEGIN TRANSACTION");
    try {
      await dbRun("INSERT INTO chat_rooms (id, creator_id, title, expires_at, created_at) VALUES (?, ?, ?, ?, ?)", [id, creator.id, title, expiresAt, now]);
      for (const member of members) {
        await dbRun("INSERT INTO chat_room_members (room_id, user_id, wrapped_key, key_metadata, joined_at) VALUES (?, ?, ?, ?, ?)", [id, member.user_id!, member.wrapped_key!, member.key_metadata!, now]);
      }
      await dbRun("COMMIT");
    } catch (error) {
      await dbRun("ROLLBACK").catch(() => {});
      throw error;
    }
    return NextResponse.json({ id, title, expires_at: expiresAt });
  } catch (error) {
    console.error("POST /api/chatrooms error:", error);
    return NextResponse.json({ error: "Unable to create the chatroom." }, { status: 500 });
  }
}

export async function GET() {
  await purgeExpired();
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ error: "Sign in required." }, { status: 401 });
  const rooms = await dbAll<{ id: string; title: string; expires_at: number; created_at: number; creator_id: string; member_count: number }>(
    `SELECT r.id, r.title, r.expires_at, r.created_at, r.creator_id, COUNT(m2.user_id) AS member_count
       FROM chat_rooms r JOIN chat_room_members m ON m.room_id = r.id
       JOIN chat_room_members m2 ON m2.room_id = r.id
      WHERE m.user_id = ? AND r.disabled_at IS NULL AND r.expires_at > ?
      GROUP BY r.id ORDER BY r.created_at DESC`, [user.id, Date.now()]
  );
  return NextResponse.json({ rooms });
}
