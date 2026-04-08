import { describe, it, expect } from "vitest";
import { getStandardMapName } from "../../src/utils/isoMapping";

describe("isoMapping utility", () => {
  it("should return the standard map name for a valid ISO code", () => {
    expect(getStandardMapName("US", "United States")).toBe(
      "United States of America",
    );
    expect(getStandardMapName("CN", "China")).toBe("China");
    expect(getStandardMapName("CZ", "Czech Republic")).toBe("Czechia");
  });

  it("should return the fallback name if the ISO code is not in the mapping", () => {
    expect(getStandardMapName("XX", "Unknown Country")).toBe("Unknown Country");
  });

  it("should return the fallback name if the ISO code is missing or null", () => {
    expect(getStandardMapName(null, "United States")).toBe("United States");
    expect(getStandardMapName(undefined, "China")).toBe("China");
    expect(getStandardMapName("", "Italy")).toBe("Italy");
  });

  it("should handle mixed case ISO codes (case-insensitive)", () => {
    expect(getStandardMapName("us", "United States")).toBe(
      "United States of America",
    );
    expect(getStandardMapName("uS", "United States")).toBe(
      "United States of America",
    );
  });
});
