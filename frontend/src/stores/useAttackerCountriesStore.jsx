import axios from "axios";
import { create } from "zustand";
import { IOC_ATTACKER_COUNTRIES_URI } from "../constants/api";

const NAME_FIXES = {
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

function normalise(name) {
  return NAME_FIXES[name] ?? name;
}

const useAttackerCountriesStore = create((set, get) => ({
  rawData: [],
  countryDataMap: {},
  maxCount: 0,
  loading: false,
  error: null,
  lastRange: null,
  currentController: null,

  fetchData: async (range) => {
    const rangeStr = JSON.stringify(range);
    if (get().lastRange === rangeStr && !get().error) return;

    if (get().loading && get().lastRange === rangeStr) return;

    if (get().currentController) {
      get().currentController.abort();
    }

    const controller = new AbortController();
    set({
      loading: true,
      error: null,
      lastRange: rangeStr,
      currentController: controller,
    });

    try {
      const resp = await axios.get(IOC_ATTACKER_COUNTRIES_URI, {
        params: { range },
        signal: controller.signal,
      });

      const rawData = Array.isArray(resp?.data) ? resp.data : [];
      const countryDataMap = {};
      let maxCount = 0;

      rawData.forEach((item) => {
        if (item && typeof item === "object") {
          const { country, count } = item;
          if (typeof country === "string") {
            const key = normalise(country);
            const countNum = Number(count) || 0;
            countryDataMap[key] = countNum;
            if (countNum > maxCount) maxCount = countNum;
          }
        }
      });

      set({
        rawData,
        countryDataMap,
        maxCount: maxCount || 1,
        loading: false,
        currentController: null,
      });
    } catch (err) {
      if (axios.isCancel(err)) {
        return;
      }
      console.error("useAttackerCountriesStore error:", err);
      set({
        error: "Failed to load attacker countries data.",
        loading: false,
        currentController: null,
      });
    }
  },
}));

export default useAttackerCountriesStore;
