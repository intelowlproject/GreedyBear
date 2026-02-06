import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import EnvironmentPlugin from 'vite-plugin-environment';
import path from 'path';

export default defineConfig({
    plugins: [
        react(),
        EnvironmentPlugin('all', { prefix: 'REACT_APP_' }),
    ],
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
