import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The production build is embedded into the Go binary (internal/ui/dist/app).
// In development the API of a running "photofinish serve" is proxied; set
// PHOTOFINISH_API to point at another address.
const api = process.env.PHOTOFINISH_API || "http://127.0.0.1:7340";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "../internal/ui/dist/app", emptyOutDir: true, chunkSizeWarningLimit: 900 },
  server: {
    // Loopback only, on the address CONTRIBUTING.md gives: localhost may
    // resolve to ::1 alone, where 127.0.0.1 would not answer.
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    // The API checks Host and rejects cross-origin writes, so present the
    // proxied requests as coming from the API's own origin.
    proxy: { "/api": { target: api, changeOrigin: true, headers: { Origin: api } } },
  },
});
