import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/v1': 'http://localhost:8200',
      '/api': 'http://localhost:8200',
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  }
})
