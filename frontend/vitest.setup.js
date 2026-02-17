import '@testing-library/jest-dom';
import { vi } from 'vitest';

if (typeof globalThis.localStorage !== 'undefined' && typeof globalThis.localStorage.getItem !== 'function') {
    const store = {};
    globalThis.localStorage = {
        getItem: (key) => store[key] ?? null,
        setItem: (key, value) => { store[key] = String(value); },
        removeItem: (key) => { delete store[key]; },
        clear: () => { Object.keys(store).forEach(k => delete store[k]); },
        get length() { return Object.keys(store).length; },
        key: (i) => Object.keys(store)[i] ?? null,
    };
}




