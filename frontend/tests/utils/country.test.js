import { describe, it, expect } from "vitest";
import { normalizeCountryName } from "../../src/utils/country";

describe("normalizeCountryName", () => {
  it("should normalize known mismatched names", () => {
    expect(normalizeCountryName("United States")).toBe(
      "United States of America",
    );
    expect(normalizeCountryName("Czech Republic")).toBe("Czechia");
    expect(normalizeCountryName("Ivory Coast")).toBe("Côte d'Ivoire");
    expect(normalizeCountryName("South Sudan")).toBe("S. Sudan");
  });

  it("should return the same name if no mismatch is known", () => {
    expect(normalizeCountryName("Italy")).toBe("Italy");
    expect(normalizeCountryName("Brazil")).toBe("Brazil");
    expect(normalizeCountryName("France")).toBe("France");
  });

  it("should handle edge cases like empty strings or nulls", () => {
    expect(normalizeCountryName("")).toBe("");
    expect(normalizeCountryName(null)).toBe(null);
    expect(normalizeCountryName(undefined)).toBe(undefined);
  });
});
