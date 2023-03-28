// api/ auth
export const API_BASE_URI = "/api";

// statistics
export const FEEDS_STATISTICS_SOURCES_URI = `${API_BASE_URI}/statistics/sources/feeds`;
export const FEEDS_STATISTICS_DOWNLOADS_URI = `${API_BASE_URI}/statistics/downloads/feeds`;
export const FEEDS_STATISTICS_TYPES_URI = `${API_BASE_URI}/statistics/feeds_types`;
export const ENRICHMENT_STATISTICS_SOURCES_URI = `${API_BASE_URI}/statistics/sources/enrichment`;
export const ENRICHMENT_STATISTICS_REQUESTS_URI = `${API_BASE_URI}/statistics/requests/enrichment`;

// user
export const USERACCESS_URI = `${API_BASE_URI}/me/access`;

// auth
export const AUTH_BASE_URI = `${API_BASE_URI}/auth`;
export const CHECK_AUTHENTICATION_URI = `${AUTH_BASE_URI}/authentication`;
export const LOGIN_URI = `${AUTH_BASE_URI}/login`;
export const LOGOUT_URI = `${AUTH_BASE_URI}/logout`;
export const SESSIONS_BASE_URI = `${AUTH_BASE_URI}/sessions`;
export const APIACCESS_BASE_URI = `${AUTH_BASE_URI}/apiaccess`;
