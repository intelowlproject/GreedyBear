// Vite environment variables for Jest
global.import = global.import || {};
global.import.meta = global.import.meta || {};
global.import.meta.env = {
  MODE: "test",
  VITE_GREEDYBEAR_VERSION: "3.0.1",
  BASE_URL: "/",
};

// suppression of the logs for the frontend tests in the CI or in case the flag is set
if (process.env.STAGE_CI || process.env.SUPPRESS_JEST_LOG) {
  global.console = {
    ...console,
    log: jest.fn(),
    debug: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  };
}
