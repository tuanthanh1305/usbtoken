import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy các route của daemon FastAPI (127.0.0.1:8787) trong lúc phát triển.
// Daemon CHỈ bind loopback + kiểm Host/Origin; changeOrigin để qua các kiểm tra đó.
const target = "http://127.0.0.1:8787";
const routes = ["/health", "/diagnose", "/tokens", "/login", "/logout", "/validate", "/sign", "/api"];

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      ...Object.fromEntries(routes.map((r) => [r, { target, changeOrigin: true }])),
      "/events": { target, changeOrigin: true, ws: true },
    },
  },
  build: { outDir: "dist", sourcemap: true },
});
