import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { dbAll, dbGet, purgeExpired } from "@/lib/db";

export async function GET(_req: NextRequest, ctx: RouteContext<"/api/chatrooms/[id]">) {
  await purgeExpired();
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ error: "Sign in required." }, { status: 401 });
  const { id } = await ctx.params;
  const room = await dbGet<{ id: string; title: string; expires_at: number; created_at: number; creator_id: string }>(
    `SELECT r.id, r.title, r.expires_at, r.created_at, r.creator_id FROM chat_rooms r
      JOIN chat_room_members m ON m.room_id = r.id WHERE r.id = ? AND m.user_id = ? AND r.disabled_at IS NULL AND r.expires_at > ?`, [id, user.id, Date.now()]
  );
  if (!room) return NextResponse.json({ error: "This room has expired or is unavailable." }, { status: 404 });
  const envelope = await dbGet<{ wrapped_key: string; key_metadata: string }>("SELECT wrapped_key, key_metadata FROM chat_room_members WHERE room_id = ? AND user_id = ?", [id, user.id]);
  const members = await dbAll<{ id: string; username: string }>("SELECT u.id, u.username FROM users u JOIN chat_room_members m ON m.user_id = u.id WHERE m.room_id = ? ORDER BY u.username", [id]);
  const messages = await dbAll<{ id: string; ciphertext: string | null; iv: string | null; created_at: number; sender_id: string; username: string; view_once: number; viewed: number }>(
    `SELECT cm.id,
            CASE WHEN cm.view_once = 1 THEN NULL ELSE cm.ciphertext END AS ciphertext,
            CASE WHEN cm.view_once = 1 THEN NULL ELSE cm.iv END AS iv,
            cm.created_at, cm.sender_id, u.username, cm.view_once,
            EXISTS(SELECT 1 FROM chat_message_views v WHERE v.message_id = cm.id AND v.user_id = ?) AS viewed
       FROM chat_messages cm JOIN users u ON u.id = cm.sender_id
      WHERE cm.room_id = ? ORDER BY cm.created_at ASC LIMIT 500`, [user.id, id]
  );
  return NextResponse.json({ room, envelope, members, messages });
}
