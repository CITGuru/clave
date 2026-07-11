import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// Tauri expects a fixed dev port; keep the console clear so Rust logs are visible.
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  clearScreen: false,
  server: { port: 1430, strictPort: true },
});
