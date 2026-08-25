import { NextRequest, NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { dbGet, UserKeyRow, UserRow } from "@/lib/db";

export async function GET(req: NextRequest) {
  const current = await getCurrentUser();
  if (!current) {
    return NextResponse.json({ error: "Sign in required." }, { status: 401 });
  }

  const query = new URL(req.url).searchParams.get("q")?.trim() ?? "";
  if (query.length < 3) {
    return NextResponse.json({ error: "Enter at least 3 characters." }, { status: 400 });
  }

  const user = await dbGet<UserRow>(
    "SELECT * FROM users WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE",
    [query.toLowerCase(), query]
  );
  if (!user) {
    return NextResponse.json({ error: "No registered recipient found." }, { status: 404 });
  }
  if (user.id === current.id) {
    return NextResponse.json({ error: "Choose another registered user as the recipient." }, { status: 400 });
  }

  const keys = await dbGet<UserKeyRow>("SELECT * FROM user_keys WHERE user_id = ?", [user.id]);
  if (!keys) {
    return NextResponse.json({ error: "Recipient key material is unavailable." }, { status: 404 });
  }

  return NextResponse.json({
    recipient: { id: user.id, username: user.username, email: user.email, public_key: keys.public_key },
  });
}
