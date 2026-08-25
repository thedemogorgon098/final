import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { dbGet, dbRun, dbRunResult, purgeExpired, PasteRow, UserRow } from "@/lib/db";

interface RouteContext {
  params: Promise<{ id: string }>;
}

function genericMissing() {
  return NextResponse.json({ error: "Share not found or unavailable." }, { status: 404 });
}

async function loadActivePaste(id: string): Promise<PasteRow | null> {
  await purgeExpired();
  const row = await dbGet<PasteRow>("SELECT * FROM pastes WHERE id = ? AND deleted_at IS NULL", [id]);
  if (!row || row.revoked_at) return null;
  if (row.expires_at && Date.now() > row.expires_at) {
    await dbRun("UPDATE pastes SET deleted_at = ? WHERE id = ?", [Date.now(), id]);
    return null;
  }
  if (row.burn_on_read && row.opened_at) return null;
  return row;
}

export async function GET(_req: NextRequest, context: RouteContext) {
  try {
    const { id } = await context.params;
    const row = await loadActivePaste(id);
    if (!row) return genericMissing();

    if (row.mode === "account") {
      const user = await getCurrentUser();
      if (!user || user.id !== row.recipient_id) return genericMissing();
      if (row.burn_on_read) {
        const claimed = await dbRunResult(
          "UPDATE pastes SET opened_at = ? WHERE id = ? AND burn_on_read = 1 AND opened_at IS NULL AND deleted_at IS NULL AND revoked_at IS NULL",
          [Date.now(), id]
        );
        if (claimed.changes !== 1) return genericMissing();
      } else if (!row.opened_at) {
        await dbRun("UPDATE pastes SET opened_at = ? WHERE id = ? AND opened_at IS NULL", [Date.now(), id]);
      }
      const sender = await dbGet<Pick<UserRow, "username" | "email">>("SELECT username, email FROM users WHERE id = ?", [row.sender_id]);
      return NextResponse.json({
        mode: "account",
        payload: row.payload,
        wrapped_key: row.wrapped_key,
        key_metadata: row.key_metadata,
        created_at: row.created_at,
        expires_at: row.expires_at,
        burn_on_read: !!row.burn_on_read,
        sender,
      });
    }

    if (row.burn_on_read) {
      const claimed = await dbRunResult(
        "UPDATE pastes SET opened_at = ?, deleted_at = ? WHERE id = ? AND burn_on_read = 1 AND opened_at IS NULL AND deleted_at IS NULL",
        [Date.now(), Date.now(), id]
      );
      if (claimed.changes !== 1) return genericMissing();
    }

    return NextResponse.json({
      mode: "guest",
      payload: row.payload,
      created_at: row.created_at,
      expires_at: row.expires_at,
      burn_on_read: !!row.burn_on_read,
    });
  } catch (err) {
    console.error("GET /api/paste/[id] error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest, context: RouteContext) {
  try {
    const { id } = await context.params;
    const token = req.headers.get("x-deletion-token") ?? new URL(req.url).searchParams.get("token");
    if (!token) return NextResponse.json({ error: "Deletion token is required." }, { status: 400 });

    const row = await dbGet<Pick<PasteRow, "deletion_token" | "mode">>(
      "SELECT deletion_token, mode FROM pastes WHERE id = ? AND deleted_at IS NULL",
      [id]
    );
    if (!row || row.mode !== "guest" || row.deletion_token !== token) return genericMissing();

    await dbRun("UPDATE pastes SET deleted_at = ? WHERE id = ?", [Date.now(), id]);
    return NextResponse.json({ success: true, message: "Share deleted." });
  } catch (err) {
    console.error("DELETE /api/paste/[id] error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
