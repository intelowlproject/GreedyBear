import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";

import {
  FeedsSourcesChart,
  FeedsDownloadsChart,
  EnrichmentSourcesChart,
  EnrichmentRequestsChart,
  FeedsTypesChart,
} from "../../../src/components/dashboard/utils/charts";

import { AnyChartWidget } from "@certego/certego-ui";


// Mock recharts
jest.mock("recharts", () => ({
  Bar: ({ dataKey }) => <div data-testid={`bar-${dataKey}`} />,
  Area: ({ dataKey }) => <div data-testid={`area-${dataKey}`} />,
}));


// Mock certego-ui
jest.mock("@certego/certego-ui", () => ({
  AnyChartWidget: jest.fn(({ url, componentsFn }) => {
    const mockData = [
      { date: "2024-01-01", feed1: 10, feed2: 20 },
    ];

    return (
      <div data-testid="chart-widget" data-url={url}>
        {componentsFn && componentsFn(mockData)}
      </div>
    );
  }),
  getRandomColorsArray: jest.fn(() => ["#111111", "#222222", "#333333"]),
}));


describe("Charts Components", () => {

  test("createAreaChart factory sets correct displayName", () => {
    expect(FeedsSourcesChart.displayName).toBe("FeedsSourcesChart");
    expect(FeedsDownloadsChart.displayName).toBe("FeedsDownloadsChart");
    expect(EnrichmentSourcesChart.displayName).toBe("EnrichmentSourcesChart");
    expect(EnrichmentRequestsChart.displayName).toBe("EnrichmentRequestsChart");
  });


  test("factory charts pass correct props to AnyChartWidget", () => {
    render(<FeedsSourcesChart />);

    expect(AnyChartWidget).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "/api/statistics/sources/feeds",
        accessorFnAggregation: expect.any(Function),
        componentsFn: expect.any(Function),
      }),
      {}
    );
  });


  test("factory charts render Area components", () => {
    render(<FeedsSourcesChart />);

    const areas = screen.getAllByTestId(/^area-/);
    expect(areas.length).toBeGreaterThan(0);
  });


  test("FeedsTypesChart passes correct props to AnyChartWidget", () => {
    render(<FeedsTypesChart />);

    expect(AnyChartWidget).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "/api/statistics/feeds_types",
        accessorFnAggregation: expect.any(Function),
        componentsFn: expect.any(Function),
      }),
      {}
    );
  });


  test("FeedsTypesChart renders Bar components from response data", () => {
    render(<FeedsTypesChart />);

    const bars = screen.getAllByTestId(/^bar-/);
    expect(bars.length).toBeGreaterThan(0);
  });

});
