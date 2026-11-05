import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// In development the Flask API runs on :8000 (see dev/mock_api.py).
// In production nginx serves dist/ and proxies these same paths to gunicorn.
const api = { target: 'http://127.0.0.1:8000', changeOrigin: false }

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { '/api': api, '/files': api, '/health': api } },
  preview: { proxy: { '/api': api, '/files': api, '/health': api } },
  build: { sourcemap: false, assetsInlineLimit: 0 },
})
