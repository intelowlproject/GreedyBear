import axios from "axios";
import { create } from "zustand";
import { IOC_ATTACKER_COUNTRIES_URI } from "../constants/api";
import { normalizeCountryName } from "../utils/country";

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

      const rawData = (Array.isArray(resp?.data) ? resp.data : []).map(
        (item) => {
          if (
            item &&
            typeof item === "object" &&
            typeof item.country === "string"
          ) {
            return { ...item, country: normalizeCountryName(item.country) };
          }
          return item;
        },
      );
      const countryDataMap = {};
      let maxCount = 0;

      rawData.forEach((item) => {
        if (item && typeof item === "object") {
          const { country, count } = item;
          if (typeof country === "string") {
            const countNum = Number(count) || 0;
            countryDataMap[country] = countNum;
            if (countNum > maxCount) maxCount = countNum;
          }
        }
      });

      if (get().currentController === controller) {
        set({
          rawData,
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
