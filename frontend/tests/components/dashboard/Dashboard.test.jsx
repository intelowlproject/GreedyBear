import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import Dashboard from "../../../src/components/dashboard/Dashboard";

jest.mock("axios");
// mock charts module
jest.mock("../../../src/components/dashboard/utils/charts", () => {
  const originalChartModule = jest.requireActual(
    "../../../src/components/dashboard/utils/charts"
  );
  const FeedsSourcesChart = () => <div />;
  const FeedsDownloadsChart = () => <div />;
  const EnrichmentSourcesChart = () => <div />;
  const EnrichmentRequestsChart = () => <div />;
  const FeedsTypesChart = () => <div />;

  return {
    __esModule: true,
    ...originalChartModule,
    FeedsSourcesChart,
    FeedsDownloadsChart,
    EnrichmentSourcesChart,
    EnrichmentRequestsChart,
    FeedsTypesChart,
  };
});

describe("Dashboard component", () => {
  test("Dashboard", () => {
    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>
    );

    const FeedsSourcesChart = screen.getByText("Feeds: Sources");
    expect(FeedsSourcesChart).toBeInTheDocument();
    const FeedsDownloadsChart = screen.getByText("Feeds: Downloads");
    expect(FeedsDownloadsChart).toBeInTheDocument();
    const FeedsTypesChart = screen.getByText("Feeds: Types");
    expect(FeedsTypesChart).toBeInTheDocument();
    const EnrichmentSourcesChart = screen.getByText(
      "Enrichment Service: Sources"
    );
    expect(EnrichmentSourcesChart).toBeInTheDocument();
    const EnrichmentRequestsChart = screen.getByText(
      "Enrichment Service: Requests"
    );
    expect(EnrichmentRequestsChart).toBeInTheDocument();
  });
});
