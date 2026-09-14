import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Polling, not native inotify (Slice 16, found live): this dev
    // server runs against a bind-mounted volume inside Docker — native
    // filesystem-change events from a Windows host don't reliably
    // reach a Linux container's inotify watches through that mount, so
    // HMR silently kept serving stale file content after an edit with
    // no error of any kind. Polling costs a little CPU but actually
    // works across the bind mount.
    watch: {
      usePolling: true,
    },
    proxy: {
      '/api': {
        // VITE_BACKEND_URL (Slice 16, found live): inside the Docker
        // network this dev server itself runs in, "localhost:8000"
        // refers to the frontend container's OWN loopback, not the
        // separate aiiam_backend container — every proxied request was
        // failing with ECONNREFUSED, surfaced to the browser as a
        // generic 500 with no indication why. docker-compose.yml sets
        // this to "http://backend:8000" (the compose service's DNS
        // name on the shared network); the localhost fallback is for
        // running `npm run dev` directly on a host machine instead.
        target: process.env.VITE_BACKEND_URL || 'http://localhost:8000',
        changeOrigin: true,
      }
    }
  }
})
