import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// `npm run dev` proxies the API to a running `sessionlens start` / `sessionlens view`.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { '/api': { target: 'http://localhost:47831', ws: true } },
  },
  test: { environment: 'node' },
});
