import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy /api tới daemon FastAPI (127.0.0.1:8787) trong lúc phát triển.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8787", changeOrigin: true },
    },
  },
  build: { outDir: "dist", sourcemap: true },
});
