import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// Inside docker-compose the API is reachable as `backend`. For a frontend run
// directly on the host, set VITE_API_TARGET=http://localhost:8000.
const apiTarget = process.env.VITE_API_TARGET || 'http://backend:8000'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: apiTarget,
        // keep the browser's Host so API redirects stay on this origin
        changeOrigin: false,
      },
      '/ws': {
        target: apiTarget.replace(/^http/, 'ws'),
        ws: true,
      },
    },
  },
})
