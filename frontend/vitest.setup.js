import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Polyfill for legacy Jest tests using jest.fn(), jest.mock(), etc.
global.jest = vi;

// Mock zustand to handle version mismatch in @certego/certego-ui
vi.mock('zustand', async (importOriginal) => {
    const actual = await importOriginal();
    const create = actual.create || actual.default;
    return {
        ...actual,
        create: create,
        default: create,
    };
});
