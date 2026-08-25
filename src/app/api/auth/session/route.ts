import { NextResponse } from "next/server";
import { getCurrentUser, publicUser } from "@/lib/auth";
import { dbGet, UserKeyRow } from "@/lib/db";

export async function GET() {
  const user = await getCurrentUser();
  if (!user) {
    return NextResponse.json({ user: null });
  }
  const keys = await dbGet<UserKeyRow>("SELECT * FROM user_keys WHERE user_id = ?", [user.id]);
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
}
