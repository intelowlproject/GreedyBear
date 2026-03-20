import React from "react";
import { render } from "@testing-library/react";
import { vi, describe, it, expect } from "vitest";

const { mockAnyChartWidget } = vi.hoisted(() => ({
  mockAnyChartWidget: vi.fn(),
}));

vi.mock("@certego/certego-ui", () => ({
  AnyChartWidget: mockAnyChartWidget,
  getRandomColorsArray: () => Array(30).fill("#aabbcc"),
}));

vi.mock("../../../../constants/api", () => ({
  FEEDS_STATISTICS_SOURCES_URI: "/api/statistics/sources/feeds",
  FEEDS_STATISTICS_DOWNLOADS_URI: "/api/statistics/downloads/feeds",
  FEEDS_STATISTICS_TYPES_URI: "/api/statistics/feeds_types",
  ENRICHMENT_STATISTICS_SOURCES_URI: "/api/statistics/sources/enrichment",
  ENRICHMENT_STATISTICS_REQUESTS_URI: "/api/statistics/requests/enrichment",
}));

vi.mock("../../../../constants", () => ({
  FEED_COLOR_MAP: { Sources: "#82ca9d", Downloads: "#8884d8" },
  ENRICHMENT_COLOR_MAP: { Sources: "#82ca9d", Requests: "#8884d8" },
}));

import {
  FeedsSourcesChart,
  FeedsDownloadsChart,
  EnrichmentSourcesChart,
  EnrichmentRequestsChart,
  FeedsTypesChart,
} from "../../../../src/components/dashboard/utils/charts";

function captureProps(Component) {
  let captured = null;
  mockAnyChartWidget.mockImplementationOnce((props) => {
    captured = props;
    return <div data-testid="chart-widget" />;
  });
  render(<Component />);
  return captured;
}

describe("Chart URLs", () => {
  it.each([
    [FeedsSourcesChart, "/api/statistics/sources/feeds"],
    [FeedsDownloadsChart, "/api/statistics/downloads/feeds"],
    [EnrichmentSourcesChart, "/api/statistics/sources/enrichment"],
    [EnrichmentRequestsChart, "/api/statistics/requests/enrichment"],
    [FeedsTypesChart, "/api/statistics/feeds_types"],
  ])("%s passes correct URL", (Component, expectedUrl) => {
    const props = captureProps(Component);
    expect(props.url).toBe(expectedUrl);
  });
});

describe("accessorFnAggregation", () => {
  it.each([
    [FeedsSourcesChart, "FeedsSourcesChart"],
    [FeedsDownloadsChart, "FeedsDownloadsChart"],
    [EnrichmentSourcesChart, "EnrichmentSourcesChart"],
    [EnrichmentRequestsChart, "EnrichmentRequestsChart"],
    [FeedsTypesChart, "FeedsTypesChart"],
  ])("%s uses identity function", (Component) => {
    const props = captureProps(Component);
    const testData = { foo: 1 };
    expect(props.accessorFnAggregation(testData)).toBe(testData);
  });
});

describe("FeedsSourcesChart componentsFn", () => {
  it("returns one Area with dataKey Sources and correct fill and stroke", () => {
    const { componentsFn } = captureProps(FeedsSourcesChart);
    const result = componentsFn();
    expect(result).toHaveLength(1);
    expect(result[0].props.dataKey).toBe("Sources");
    expect(result[0].props.fill).toBe("#82ca9d");
    expect(result[0].props.stroke).toBe("#82ca9d");
  });
});

describe("FeedsDownloadsChart componentsFn", () => {
  it("returns one Area with dataKey Downloads and correct fill and stroke", () => {
    const { componentsFn } = captureProps(FeedsDownloadsChart);
    const result = componentsFn();
    expect(result).toHaveLength(1);
    expect(result[0].props.dataKey).toBe("Downloads");
    expect(result[0].props.fill).toBe("#8884d8");
    expect(result[0].props.stroke).toBe("#8884d8");
  });
});

describe("EnrichmentSourcesChart componentsFn", () => {
  it("returns one Area with dataKey Sources and correct fill and stroke", () => {
    const { componentsFn } = captureProps(EnrichmentSourcesChart);
    const result = componentsFn();
    expect(result).toHaveLength(1);
    expect(result[0].props.dataKey).toBe("Sources");
    expect(result[0].props.fill).toBe("#82ca9d");
    expect(result[0].props.stroke).toBe("#82ca9d");
  });
});

describe("EnrichmentRequestsChart componentsFn", () => {
  it("returns one Area with dataKey Requests and correct fill and stroke", () => {
    const { componentsFn } = captureProps(EnrichmentRequestsChart);
    const result = componentsFn();
    expect(result).toHaveLength(1);
    expect(result[0].props.dataKey).toBe("Requests");
    expect(result[0].props.fill).toBe("#8884d8");
    expect(result[0].props.stroke).toBe("#8884d8");
  });
});

describe("FeedsTypesChart componentsFn", () => {
  it("returns null for empty array", () => {
    const { componentsFn } = captureProps(FeedsTypesChart);
    expect(componentsFn([])).toBeNull();
  });

  it("returns null for undefined", () => {
    const { componentsFn } = captureProps(FeedsTypesChart);
    expect(componentsFn(undefined)).toBeNull();
  });

  it("extracts feed type keys from respData skipping date field", () => {
    const { componentsFn } = captureProps(FeedsTypesChart);
    const respData = [
      { date: "2024-01-01", honeypot: 10, cowrie: 5, dionaea: 3 },
      { date: "2024-01-02", honeypot: 8, cowrie: 6, dionaea: 4 },
    ];
    const result = componentsFn(respData);
    expect(result).toHaveLength(3);
    expect(result[0].props.dataKey).toBe("honeypot");
    expect(result[1].props.dataKey).toBe("cowrie");
    expect(result[2].props.dataKey).toBe("dionaea");
  });

  it("all Bar components have stackId feedtype", () => {
    const { componentsFn } = captureProps(FeedsTypesChart);
    const respData = [{ date: "2024-01-01", ssh: 5, telnet: 3 }];
    const result = componentsFn(respData);
    result.forEach((bar) => {
      expect(bar.props.stackId).toBe("feedtype");
    });
  });

  it("assigns colors from getRandomColorsArray by index", () => {
    const { componentsFn } = captureProps(FeedsTypesChart);
    const respData = [{ date: "2024-01-01", ssh: 5, telnet: 3 }];
    const result = componentsFn(respData);
    expect(result[0].props.fill).toBe("#aabbcc");
    expect(result[1].props.fill).toBe("#aabbcc");
  });
});