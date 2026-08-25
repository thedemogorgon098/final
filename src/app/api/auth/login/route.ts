import { NextRequest, NextResponse } from "next/server";
import { createSession, normalizeIdentifier, publicUser, setSessionCookie, verifyPassword } from "@/lib/auth";
import { dbGet, UserKeyRow, UserRow } from "@/lib/db";
import { rateLimit } from "@/lib/rateLimit";

export async function POST(req: NextRequest) {
  const limited = rateLimit(req, { capacity: 8, refillPeriodSeconds: 300, keyPrefix: "login" });
  if (limited) return limited;

  try {
    const body = (await req.json()) as { identifier?: string; password?: string };
    const identifier = normalizeIdentifier(body.identifier ?? "");
    const password = body.password ?? "";
    const user = await dbGet<UserRow>(
      "SELECT * FROM users WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE",
      [identifier, identifier]
    );
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return NextResponse.json({ error: "Invalid username/email or password." }, { status: 401 });
    }
    const keys = await dbGet<UserKeyRow>("SELECT * FROM user_keys WHERE user_id = ?", [user.id]);
    const token = await createSession(user.id);
    await setSessionCookie(token);
    return NextResponse.json({
      user: publicUser(user),
      keyBundle: keys
        ? {
            public_key: keys.public_key,
            encrypted_private_key: keys.encrypted_private_key,
            key_metadata: keys.key_metadata,
          }
        : null,
    });
  } catch (err) {
    console.error("POST /api/auth/login error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}