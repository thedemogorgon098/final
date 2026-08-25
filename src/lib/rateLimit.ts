/**
 * In-memory per-IP token bucket rate limiter for API routes.
 * No auth endpoint in this app had any throttling before this — meaning
 * /api/auth/login was brute-forceable and /api/auth/register was spammable.
 * Good enough for a single-instance hackathon deploy; swap for a
 * Redis-backed bucket if you ever run multiple instances behind a
 * load balancer (in-memory state won't be shared across them).
 */
import { NextRequest, NextResponse } from "next/server";

interface Bucket {
  tokens: number;
  lastCheck: number;
}

const buckets = new Map<string, Bucket>();

function clientIp(req: NextRequest): string {
  const fwd = req.headers.get("x-forwarded-for");
  return fwd ? fwd.split(",")[0].trim() : "unknown";
}

/**
 * Returns null if the request is allowed, or a 429 NextResponse to return
 * immediately if the caller has exceeded the limit.
 */
export function rateLimit(
  req: NextRequest,
  opts: { capacity: number; refillPeriodSeconds: number; keyPrefix: string }
): NextResponse | null {
  const key = `${opts.keyPrefix}:${clientIp(req)}`;
  const now = Date.now();
  const existing = buckets.get(key) ?? { tokens: opts.capacity, lastCheck: now };

  const elapsedSeconds = (now - existing.lastCheck) / 1000;
  const refilled = Math.min(
    opts.capacity,
    existing.tokens + elapsedSeconds * (opts.capacity / opts.refillPeriodSeconds)
  );

  if (refilled < 1) {
    buckets.set(key, { tokens: refilled, lastCheck: now });
    return NextResponse.json({ error: "Too many requests — slow down and try again shortly." }, { status: 429 });
  }

  buckets.set(key, { tokens: refilled - 1, lastCheck: now });
  return null;
}