import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // A self-contained server for the Docker image (dashboard/Dockerfile).
  output: "standalone",
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    root: __dirname,
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
