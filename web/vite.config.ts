import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// `npm run dev` proxies the API to a running `sessionlens start` / `sessionlens view`.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { '/api': { target: 'http://localhost:47831', ws: true } },
  },
  // Inline the small icon so the offline report (export/index.html) only has to embed one JS and one CSS file.
  build: { assetsInlineLimit: 8192 },
  test: { environment: 'node' },
});
