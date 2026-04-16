import axios from "axios";
import { create } from "zustand";
import { IOC_ATTACKER_COUNTRIES_URI } from "../constants/api";

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
      const countryNameMap = {}; // alpha-2 code → first-seen display name
      let maxCount = 0;

      rawData.forEach((item) => {
        if (item && typeof item === "object") {
          const code =
            typeof item.code === "string" ? item.code.toUpperCase() : null;
          if (!code) return; // skip items without an ISO-A2 code

          const countNum = Number(item.count) || 0;

          // Aggregate count by alpha-2 code
          countryDataMap[code] = (countryDataMap[code] || 0) + countNum;

          // Keep the first-seen display name for this code
          if (!countryNameMap[code]) {
            countryNameMap[code] = item.country || code;
          }

          if (countryDataMap[code] > maxCount) {
            maxCount = countryDataMap[code];
          }
        }
      });

      // Build unique aggregated list for charts
      const normalizedData = Object.entries(countryDataMap)
        .map(([code, count]) => ({
          country: countryNameMap[code],
          count,
          code,
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
