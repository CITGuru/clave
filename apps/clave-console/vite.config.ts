import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const gateway = process.env.VITE_GATEWAY_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    proxy: {
      "/auth": { target: gateway, changeOrigin: true },
      "/admin": { target: gateway, changeOrigin: true },
      "/enroll": { target: gateway, changeOrigin: true },
    },
  },
});
