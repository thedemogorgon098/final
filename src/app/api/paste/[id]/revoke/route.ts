import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { dbGet, dbRun, PasteRow } from "@/lib/db";

interface RouteContext {
  params: Promise<{ id: string }>;
}

export async function POST(_req: NextRequest, context: RouteContext) {
  try {
    const { id } = await context.params;
    const user = await getCurrentUser();
    if (!user) {
      return NextResponse.json({ error: "Sign in required." }, { status: 401 });
    }

    const row = await dbGet<Pick<PasteRow, "sender_id" | "mode" | "revoked_at" | "deleted_at">>(
      "SELECT sender_id, mode, revoked_at, deleted_at FROM pastes WHERE id = ?",
      [id]
    );
    if (!row || row.mode !== "account" || row.deleted_at || row.revoked_at) {
      return NextResponse.json({ error: "Share not found or unavailable." }, { status: 404 });
    }
    if (row.sender_id !== user.id) {
      return NextResponse.json({ error: "Share not found or unavailable." }, { status: 404 });
    }

    await dbRun("UPDATE pastes SET revoked_at = ? WHERE id = ? AND sender_id = ?", [
      Date.now(),
      id,
      user.id,
    ]);
    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("POST /api/paste/[id]/revoke error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
