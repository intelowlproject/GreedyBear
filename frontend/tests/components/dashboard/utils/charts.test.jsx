import React from "react";
import { render, screen } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";

const { mockAnyChartWidget } = vi.hoisted(() => ({
  mockAnyChartWidget: vi.fn(({ url }) => (
    <div data-testid="chart-widget" data-url={url} />
  )),
}));

vi.mock("@certego/certego-ui", () => ({
  AnyChartWidget: mockAnyChartWidget,
  getRandomColorsArray: () => Array(30).fill("#000000"),
}));

vi.mock("../../../../constants/api", () => ({
  FEEDS_STATISTICS_SOURCES_URI: "/api/statistics/sources/feeds",
  FEEDS_STATISTICS_DOWNLOADS_URI: "/api/statistics/downloads/feeds",
  FEEDS_STATISTICS_TYPES_URI: "/api/statistics/feeds_types",
  ENRICHMENT_STATISTICS_SOURCES_URI: "/api/statistics/sources/enrichment",
  ENRICHMENT_STATISTICS_REQUESTS_URI: "/api/statistics/requests/enrichment",
}));

vi.mock("../../../../constants", () => ({
  FEED_COLOR_MAP: { total: "#ff0000", downloaded: "#00ff00" },
  ENRICHMENT_COLOR_MAP: { sources: "#0000ff", requests: "#ffff00" },
}));

import {
  FeedsSourcesChart,
  FeedsDownloadsChart,
  EnrichmentSourcesChart,
  EnrichmentRequestsChart,
  FeedsTypesChart,
} from "../../../../src/components/dashboard/utils/charts";

beforeEach(() => {
  mockAnyChartWidget.mockImplementation(({ url }) => (
    <div data-testid="chart-widget" data-url={url} />
  ));
});

describe("Dashboard Chart Components", () => {
  it("FeedsSourcesChart renders with correct URL", () => {
    render(<FeedsSourcesChart />);
    expect(screen.getByTestId("chart-widget")).toHaveAttribute(
      "data-url",
      "/api/statistics/sources/feeds",
    );
  });

  it("FeedsDownloadsChart renders with correct URL", () => {
    render(<FeedsDownloadsChart />);
    expect(screen.getByTestId("chart-widget")).toHaveAttribute(
      "data-url",
      "/api/statistics/downloads/feeds",
    );
  });

  it("EnrichmentSourcesChart renders with correct URL", () => {
    render(<EnrichmentSourcesChart />);
    expect(screen.getByTestId("chart-widget")).toHaveAttribute(
      "data-url",
      "/api/statistics/sources/enrichment",
    );
  });

  it("EnrichmentRequestsChart renders with correct URL", () => {
    render(<EnrichmentRequestsChart />);
    expect(screen.getByTestId("chart-widget")).toHaveAttribute(
      "data-url",
      "/api/statistics/requests/enrichment",
    );
  });

  it("FeedsTypesChart renders with correct URL", () => {
    render(<FeedsTypesChart />);
    expect(screen.getByTestId("chart-widget")).toHaveAttribute(
      "data-url",
      "/api/statistics/feeds_types",
    );
  });
});

describe("FeedsTypesChart - componentsFn behavior", () => {
  it("componentsFn returns null when respData is empty array", () => {
    let capturedComponentsFn;
    mockAnyChartWidget.mockImplementationOnce(({ componentsFn }) => {
      capturedComponentsFn = componentsFn;
      return <div data-testid="chart-widget" />;
    });
    render(<FeedsTypesChart />);
    const result = capturedComponentsFn([]);
    expect(result).toBeNull();
  });

  it("componentsFn returns null when respData is undefined", () => {
    let capturedComponentsFn;
    mockAnyChartWidget.mockImplementationOnce(({ componentsFn }) => {
      capturedComponentsFn = componentsFn;
      return <div data-testid="chart-widget" />;
    });
    render(<FeedsTypesChart />);
    const result = capturedComponentsFn(undefined);
    expect(result).toBeNull();
  });
});