// Mock for src/constants/environment.js to fix Jest compatibility with Vite's import.meta.env
// This is a temporary workaround until we migrate to Vitest

export const API_BASE_URI = process.env.REACT_APP_API_BASE_URI || "/api";
export const GREEDYBEAR_DOCS_URL =
  "https://greedybear.readthedocs.io/en/latest/";
export const VERSION = process.env.REACT_APP_GREEDYBEAR_VERSION || "3.1.0";

// Add any other exports from environment.js that tests might need
export default {
  API_BASE_URI,
  GREEDYBEAR_DOCS_URL,
  VERSION,
};
