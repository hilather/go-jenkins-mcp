import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Admin BFF default (UI-002 / ADR 0014): loopback 8787.
const adminBffTarget = "http://127.0.0.1:8787";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      // Dev: SPA at Vite; /admin/* → local admin BFF.
      "/admin": {
        target: adminBffTarget,
        changeOrigin: false,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
  },
});
