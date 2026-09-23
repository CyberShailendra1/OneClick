import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/health': 'http://localhost:8000',
      '/scan': 'http://localhost:8000',
      '/history': 'http://localhost:8000',
      '/scan-url': 'http://localhost:8000',
      '/investigate-url': 'http://localhost:8000',
      '/scan-message': 'http://localhost:8000',
      '/url-history': 'http://localhost:8000',
      '/redact-message': 'http://localhost:8000',
      '/scam-lookup': 'http://localhost:8000',
      '/breach': 'http://localhost:8000',
      '/tools': 'http://localhost:8000',
    },
  },
  build: {
    outDir: 'dist',
  },
});

