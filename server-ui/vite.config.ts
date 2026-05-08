import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      // WebSocket 专用代理（必须在通用 /api/v1 之前，路径更精确优先匹配）
      '/api/v1/ws': {
        target: 'http://localhost:8085',
        changeOrigin: true,
        ws: true,
        // 后端未启动时静默忽略，不抛 EPIPE
        configure: (proxy) => {
          proxy.on('error', (err) => {
            console.warn('[Vite WS Proxy] Backend unavailable:', err.message);
          });
        },
      },
      // REST API 代理（不代理 WS）
      '/api/v1': {
        target: 'http://localhost:8085',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          antd: ['antd', '@ant-design/icons', '@ant-design/pro-components'],
          echarts: ['echarts', 'echarts-for-react'],
          monaco: ['@monaco-editor/react'],
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    globals: true,
  },
});
