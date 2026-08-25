import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { dbGet, dbRun, dbRunResult, purgeExpired } from "@/lib/db";

export async function POST(_req: NextRequest, ctx: RouteContext<"/api/chatrooms/[id]/messages/[messageId]/open">) {
  await purgeExpired();
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ error: "Sign in required." }, { status: 401 });
  const { id, messageId } = await ctx.params;
  const message = await dbGet<{ id: string; ciphertext: string; iv: string; created_at: number; sender_id: string; view_once: number; username: string }>(
    `SELECT cm.id, cm.ciphertext, cm.iv, cm.created_at, cm.sender_id, cm.view_once, u.username
       FROM chat_messages cm JOIN users u ON u.id = cm.sender_id
       JOIN chat_rooms r ON r.id = cm.room_id JOIN chat_room_members m ON m.room_id = r.id
      WHERE cm.id = ? AND cm.room_id = ? AND m.user_id = ? AND r.disabled_at IS NULL AND r.expires_at > ?`, [messageId, id, user.id, Date.now()]
  );
  if (!message || !message.view_once) return NextResponse.json({ error: "This file is unavailable." }, { status: 404 });
  const result = await dbRunResult("INSERT OR IGNORE INTO chat_message_views (message_id, user_id, viewed_at) VALUES (?, ?, ?)", [messageId, user.id, Date.now()]);
  if (result.changes !== 1) return NextResponse.json({ error: "This file was already viewed." }, { status: 410 });
  return NextResponse.json({ message: { ...message, view_once: 1, viewed: 1 } });
}
