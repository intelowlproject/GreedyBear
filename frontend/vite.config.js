import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
    plugins: [
        react(),
    ],
    define: {
        'process.env.REACT_APP_GREEDYBEAR_VERSION': JSON.stringify(process.env.REACT_APP_GREEDYBEAR_VERSION || 'dev'),
        'process.env.PUBLIC_URL': JSON.stringify(process.env.PUBLIC_URL || ''),
    },
    resolve: {
        alias: {
            '~bootstrap': path.resolve(__dirname, 'node_modules/bootstrap'),
        },
    },
    server: {
        port: 3001,
        open: true,
        proxy: {
            '/api': {
                target: 'http://localhost:80',
                changeOrigin: true,
                secure: false,
            },
        },
    },
    build: {
        outDir: 'build',
    },
});
