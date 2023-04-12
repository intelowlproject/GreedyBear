export const GREEDYBEAR_DOCS_URL = "https://greedybear.readthedocs.io/";

// env variables
export const VERSION = process.env.REACT_APP_GREEDYBEAR_VERSION;
export const { PUBLIC_URL } = process.env;

// runtime env config
export const RECAPTCHA_SITEKEY = window.$env
  ? window.$env.RECAPTCHA_SITEKEY
  : "";
