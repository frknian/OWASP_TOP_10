import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const isVercel = process.env.VERCEL === '1'

// base: '/app/' → build, control-panel'in /app mount'u altında servis edilir.
// Vercel deploy'larında kök dizine bağlanacak şekilde '/' kullanırız.
// server.proxy: dev sırasında /api istekleri control-panel'e (9000) yönlenir.
export default defineConfig({
  base: isVercel ? '/' : '/app/',
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:9000',
    },
  },
})
