// Mock for src/constants/environment.js to fix Jest compatibility with Vite's import.meta.env
// This is a temporary workaround until we migrate to Vitest

export const GREEDYBEAR_DOCS_URL =
  "https://intelowlproject.github.io/docs/GreedyBear/Introduction/";
export const VERSION = process.env.VITE_GREEDYBEAR_VERSION || "3.1.0";

// Add any other exports from environment.js that tests might need
export default {
  GREEDYBEAR_DOCS_URL,
  VERSION,
};
