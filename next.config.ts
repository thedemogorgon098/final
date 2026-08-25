import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: [
    "localhost",
    "127.0.0.1",
    "192.168.29.235",
    "192.168.0.100",
    "192.168.1.100",
  ],
};

export default nextConfig;
