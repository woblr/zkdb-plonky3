import path from "path";
import type { NextConfig } from "next";

// The Rust zkDB backend runs on port 3000 (Next.js dev server uses port 3002 when running alongside).
const BACKEND = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:3001";

const nextConfig: NextConfig = {
  output: "standalone",
  // Tailwind v4 emits `@import "tailwindcss"` which both Turbopack and webpack must
  // resolve as a package.  When the Next.js project is nested inside a non-npm parent
  // directory (the Rust workspace) the resolver walks up past frontend/ and can't find
  // node_modules.  Pin resolution explicitly for both bundlers.
  turbopack: {
    // Pin workspace root so Next.js doesn't pick up the lockfile at ~/Desktop
    root: __dirname,
    resolveAlias: {
      tailwindcss: path.resolve(__dirname, "node_modules/tailwindcss"),
    },
  },
  webpack(config) {
    config.resolve.modules = [
      path.resolve(__dirname, "node_modules"),
      "node_modules",
    ];
    return config;
  },
  async rewrites() {
    return [
      { source: "/health", destination: `${BACKEND}/health` },
      { source: "/v1/:path*", destination: `${BACKEND}/v1/:path*` },
      // Legacy proxy path kept for backward compat
      { source: "/api-proxy/:path*", destination: `${BACKEND}/:path*` },
    ];
  },
};

export default nextConfig;
