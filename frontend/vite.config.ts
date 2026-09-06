import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
    },
  },
  build: {
    // Single-page app, single vendor+app bundle (~200KB gzipped) — well under
    // what actually costs load time. Raised rather than forcing a code-split
    // that would add complexity without a real performance problem to fix.
    chunkSizeWarningLimit: 750,
  },
});
