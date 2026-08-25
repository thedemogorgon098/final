import { randomBytes } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { dbGet, dbRun, purgeExpired } from "@/lib/db";
import { rateLimit } from "@/lib/rateLimit";

export async function POST(req: NextRequest, ctx: RouteContext<"/api/chatrooms/[id]/messages">) {
  const limited = rateLimit(req, { capacity: 40, refillPeriodSeconds: 60, keyPrefix: "chat-message" });
  if (limited) return limited;
  await purgeExpired();
  const user = await getCurrentUser();
  if (!user) return NextResponse.json({ error: "Sign in required." }, { status: 401 });
  const { id } = await ctx.params;
  const allowed = await dbGet<{ id: string }>("SELECT r.id FROM chat_rooms r JOIN chat_room_members m ON m.room_id = r.id WHERE r.id = ? AND m.user_id = ? AND r.disabled_at IS NULL AND r.expires_at > ?", [id, user.id, Date.now()]);
  if (!allowed) return NextResponse.json({ error: "This room has expired or is unavailable." }, { status: 404 });
  const body = await req.json() as { ciphertext?: string; iv?: string; view_once?: boolean };
  if (!body.ciphertext || !body.iv || body.ciphertext.length > 3_000_000 || body.iv.length > 100) return NextResponse.json({ error: "Invalid encrypted message or file is too large (2 MB max)." }, { status: 400 });
  const message = { id: randomBytes(12).toString("hex"), ciphertext: body.ciphertext, iv: body.iv, view_once: body.view_once ? 1 : 0, viewed: 0, created_at: Date.now(), sender_id: user.id, username: user.username };
  await dbRun("INSERT INTO chat_messages (id, room_id, sender_id, ciphertext, iv, view_once, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", [message.id, id, user.id, message.ciphertext, message.iv, message.view_once, message.created_at]);
  return NextResponse.json({ message });
}
