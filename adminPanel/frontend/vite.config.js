import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Vite config with dev proxy to Django backend on localhost:8000
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Proxy all /api requests to Django dev server
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
