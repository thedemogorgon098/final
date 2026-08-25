import { NextResponse } from "next/server";
import os from "os";

function getLocalIpAddress(): string {
  const interfaces = os.networkInterfaces();
  const candidates: string[] = [];

  for (const name of Object.keys(interfaces)) {
    for (const net of interfaces[name] ?? []) {
      if (net.family === "IPv4" && !net.internal) {
        candidates.push(net.address);
      }
    }
  }

  return candidates.find((address) =>
    address.startsWith("192.168.") ||
    address.startsWith("10.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(address)
  ) ?? candidates[0] ?? "localhost";
}

export async function GET() {
  return NextResponse.json({
    localIp: getLocalIpAddress(),
    port: process.env.PORT ?? 3080,
  });
}
