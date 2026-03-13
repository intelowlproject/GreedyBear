import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { vi } from "vitest";

import {
  FeedsSourcesChart,
  FeedsDownloadsChart,
  EnrichmentSourcesChart,
  EnrichmentRequestsChart,
  FeedsTypesChart,
} from "../../../src/components/dashboard/utils/charts";

import {
  FEEDS_STATISTICS_SOURCES_URI,
  FEEDS_STATISTICS_TYPES_URI,
} from "../../../src/constants/api";

import { AnyChartWidget } from "@certego/certego-ui";

// Mock recharts
vi.mock("recharts", () => ({
  Bar: ({ dataKey }) => <div data-testid={`bar-${dataKey}`} />,
  Area: ({ dataKey }) => <div data-testid={`area-${dataKey}`} />,
}));

// Mock certego-ui
vi.mock("@certego/certego-ui", () => ({
  AnyChartWidget: vi.fn(({ url, componentsFn }) => {
    const mockData = [{ date: "2024-01-01", feed1: 10, feed2: 20 }];

    return (
      <div data-testid="chart-widget" data-url={url}>
        {componentsFn && componentsFn(mockData)}
      </div>
    );
  }),
  getRandomColorsArray: vi.fn(() => ["#111111", "#222222", "#333333"]),
}));

describe("Charts Components", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("createAreaChart sets correct displayName", () => {
    expect(FeedsSourcesChart.displayName).toBe("FeedsSourcesChart");
    expect(FeedsDownloadsChart.displayName).toBe("FeedsDownloadsChart");
    expect(EnrichmentSourcesChart.displayName).toBe("EnrichmentSourcesChart");
    expect(EnrichmentRequestsChart.displayName).toBe("EnrichmentRequestsChart");
  });

  test("charts pass correct props to AnyChartWidget", () => {
    render(<FeedsSourcesChart />);

    expect(AnyChartWidget).toHaveBeenCalled();

    const props = AnyChartWidget.mock.calls[0][0];

    expect(props).toEqual(
      expect.objectContaining({
        url: FEEDS_STATISTICS_SOURCES_URI,
        accessorFnAggregation: expect.any(Function),
        componentsFn: expect.any(Function),
      }),
    );
  });

  test("charts render Area components", () => {
    render(<FeedsSourcesChart />);

    const areas = screen.getAllByTestId(/^area-/);
    expect(areas.length).toBeGreaterThan(0);
  });

  test("FeedsTypesChart passes correct props to AnyChartWidget", () => {
    render(<FeedsTypesChart />);

    expect(AnyChartWidget).toHaveBeenCalled();

    const props = AnyChartWidget.mock.calls[0][0];

    expect(props).toEqual(
      expect.objectContaining({
        url: FEEDS_STATISTICS_TYPES_URI,
        accessorFnAggregation: expect.any(Function),
        componentsFn: expect.any(Function),
      }),
    );
  });

  test("FeedsTypesChart renders Bar components from response data", () => {
    render(<FeedsTypesChart />);

    const bars = screen.getAllByTestId(/^bar-/);
    expect(bars.length).toBeGreaterThan(0);
  });
});
