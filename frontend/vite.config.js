import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
    plugins: [react()],
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: './vitest.setup.js',
        css: true,
    },
    base: process.env.VITE_BASE_URL || '/',

    resolve: {
        alias: {
            '~bootstrap': path.resolve(__dirname, 'node_modules/bootstrap'),
            '~': path.resolve(__dirname, 'node_modules'),
        }
    },

    server: {
        port: 3001,
        proxy: {
            '/api': {
                target: 'http://localhost:80',
                changeOrigin: true,
                secure: false
            }
        }
    },

    build: {
        outDir: 'build',
        sourcemap: false,
        rollupOptions: {
            output: {
                // Split large dependencies into separate chunks for better caching and smaller initial load
                manualChunks: {
                    recharts: ['recharts'],
                    vendor: ['react', 'react-dom', 'react-router-dom'],
                    certego: ['@certego/certego-ui'],
                    reactstrap: ['reactstrap'],
                },
            },
        },
    }
});
