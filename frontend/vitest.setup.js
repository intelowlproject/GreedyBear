import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Polyfill for legacy Jest tests using jest.fn(), jest.mock(), etc.
global.jest = vi;
