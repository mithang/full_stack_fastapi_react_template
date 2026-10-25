import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from "@tailwindcss/vite"
import path from "path"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/api': {
        // Override with VITE_BACKEND_URL for another machine / port.
        // Default matches the backend's local API base (localhost:8000).
        target: process.env.VITE_BACKEND_URL || 'http://localhost:8000',
      }

    },
    allowedHosts: ['demo.dev.xyz', 'netflix.demo.dev.xyz', 'fsrapp.netflix.com', 'localhost']
  },
  build: {
    outDir: "../../backend/api/ui",
    emptyOutDir: true,
  },
})
