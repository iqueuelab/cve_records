Frontend (React + Vite)

Quick start

1. Install dependencies

```bash
cd adminPanel/frontend
npm install
```

2. Start dev server

```bash
npm run dev
```

By default the UI expects the Django API to be available at `/api/cve-history/` on the same host. During development you can:

- Run the Django server on port 8000 and the frontend Vite dev server on port 5173 and configure a proxy in `vite.config.js` (not included) or enable CORS in Django.

Notes

- If you see CORS errors, either enable `django-cors-headers` in Django or set up a Vite dev proxy to forward `/api` to your Django backend.

Suggested dev proxy (vite.config.js):

```js
// vite.config.js
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
```

This UI is intentionally minimal — it provides pagination, sorting (click headers), and simple filters. You can extend filters component to expose all backend filter features (date ranges, json search, multi-value IN filters, etc.).
