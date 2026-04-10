import axios from "axios";
import { create } from "zustand";
import { IOC_ATTACKER_COUNTRIES_URI } from "../constants/api";
import { getStandardMapName } from "../utils/isoMapping";

const useAttackerCountriesStore = create((set, get) => ({
  normalizedData: [],
  countryDataMap: {},
  maxCount: 0,
  loading: false,
  error: null,
  lastRange: null,
  currentController: null,

  fetchData: async (range) => {
    const rangeStr = JSON.stringify(range);
    if (get().lastRange === rangeStr && !get().error) return;

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
      const countryCodeMap = {}; // representative code for the label
      let maxCount = 0;

      rawData.forEach((item) => {
        if (item && typeof item === "object") {
          const standardName = getStandardMapName(item.code, item.country);
          const countNum = Number(item.count) || 0;

          // Aggregate count by standard name
          countryDataMap[standardName] =
            (countryDataMap[standardName] || 0) + countNum;
          countryCodeMap[standardName] =
            item.code || countryCodeMap[standardName];

          if (countryDataMap[standardName] > maxCount) {
            maxCount = countryDataMap[standardName];
          }
        }
      });

      // Create unique aggregated list for charts
      const normalizedData = Object.entries(countryDataMap)
        .map(([country, count]) => ({
          country,
          count,
          code: countryCodeMap[country],
        }))
        .sort((a, b) => b.count - a.count);

      if (get().currentController === controller) {
        set({
          normalizedData,
          countryDataMap,
          maxCount,
          loading: false,
          currentController: null,
        });
      }
    } catch (err) {
      if (axios.isCancel(err)) {
        return;
      }
      console.error("useAttackerCountriesStore error:", err);
      if (get().currentController === controller) {
        set({
          error: "Failed to load attacker countries data.",
          loading: false,
          currentController: null,
        });
      }
    }
  },
}));

export default useAttackerCountriesStore;
