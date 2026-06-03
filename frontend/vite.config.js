import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  base: './',
  build: {
    outDir: '../migate/panel/static/spa',
    emptyOutDir: true,
    assetsDir: 'assets',
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8787',
      '/login': 'http://127.0.0.1:8787',
      '/sub': 'http://127.0.0.1:8787',
    },
  },
})
