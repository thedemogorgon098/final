import { NextRequest, NextResponse } from "next/server";
import { dbGet, UserRow } from "@/lib/db";
import { rateLimit } from "@/lib/rateLimit";

export async function GET(req: NextRequest) {
  const limited = rateLimit(req, { capacity: 20, refillPeriodSeconds: 60, keyPrefix: "availability" });
  if (limited) return limited;

  const url = new URL(req.url);
  const username = url.searchParams.get("username")?.trim() ?? "";
  const email = url.searchParams.get("email")?.trim().toLowerCase() ?? "";

  const result: { usernameTaken?: boolean; emailTaken?: boolean } = {};

  if (username.length >= 3) {
    const match = await dbGet<Pick<UserRow, "username">>(
      "SELECT username FROM users WHERE username = ? COLLATE NOCASE",
      [username]
    );
    result.usernameTaken = !!match;
  }

  if (email.includes("@")) {
    const match = await dbGet<Pick<UserRow, "email">>(
      "SELECT email FROM users WHERE email = ? COLLATE NOCASE",
      [email]
    );
    result.emailTaken = !!match;
  }

  return NextResponse.json(result);
}