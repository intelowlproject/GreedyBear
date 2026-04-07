/**
 * Normalise country names from T-Pot geoip to match Natural Earth names used by world-atlas@2.
 * (https://github.com/topojson/world-atlas)
 */
export const COUNTRY_NAME_FIXES = {
  "United States": "United States of America",
  "Czech Republic": "Czechia",
  "Ivory Coast": "Côte d'Ivoire",
  "Democratic Republic of the Congo": "Dem. Rep. Congo",
  "Republic of the Congo": "Congo",
  "Bosnia and Herzegovina": "Bosnia and Herz.",
  "Central African Republic": "Central African Rep.",
  "Dominican Republic": "Dominican Rep.",
  "Equatorial Guinea": "Eq. Guinea",
  "South Sudan": "S. Sudan",
  "North Macedonia": "Macedonia",
  Eswatini: "eSwatini",
  "State of Palestine": "Palestine",
  "Western Sahara": "W. Sahara",
  "Solomon Islands": "Solomon Is.",
  "Falkland Islands": "Falkland Is.",
  "French Southern Territories": "Fr. S. Antarctic Lands",
};

/**
 * Returns a normalised country name if a fix is available, otherwise returns the original name.
 *
 * @param {string|null|undefined} name - Raw country name (e.g., from T-Pot GeoIP)
 * @returns {string|null|undefined} - Normalised country name (matching Natural Earth standards)
 */
export function normalizeCountryName(name) {
  return COUNTRY_NAME_FIXES[name] ?? name;
}
