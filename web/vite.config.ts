import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The build output is embedded into the Go server binary (internal/server/webdist).
export default defineConfig({
  plugins: [react()],
  build: { outDir: '../internal/server/webdist/app', emptyOutDir: true },
  server: {
    // `npm run dev` proxies API calls to a locally running proxbackup-server.
    proxy: { '/api': { target: process.env.PROXBACKUP_DEV_API ?? 'https://localhost:8077', changeOrigin: true, secure: false } },
  },
})
