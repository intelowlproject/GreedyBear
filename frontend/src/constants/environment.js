export const GREEDYBEAR_DOCS_URL =
  "https://intelowlproject.github.io/docs/GreedyBear/Introduction/";

// env variables
// Vite uses import.meta.env, Jest uses process.env
const isTest =
  typeof process !== "undefined" && process.env.NODE_ENV === "test";

export const VERSION = isTest
  ? process.env.VITE_GREEDYBEAR_VERSION || "3.0.1"
  : import.meta.env.VITE_GREEDYBEAR_VERSION;

export const PUBLIC_URL = isTest
  ? (process.env.PUBLIC_URL || "/").replace(/\/$/, "")
  : import.meta.env.BASE_URL.replace(/\/$/, "");
