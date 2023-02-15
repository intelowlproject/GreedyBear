import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
// import axios from "axios";
// import { mockCancelToken } from "axios-hooks";
import Dashboard from "../../../src/components/dashboard/Dashboard";

jest.mock("axios");
jest.mock("axios-hooks");

describe("Dashboard component", () => {

  // beforeEach(() => {
  //   const cancel = jest.fn()
  //   const token = {
  //     promise: Promise.resolve({ message: 'none' }),
  //     reason: { message: 'none' },
  //     throwIfRequested() {}
  //   }
  //   axios.isCancel= jest.fn();
  //   axios.CancelToken = Object.assign(jest.fn(), {
  //     source: () => ({
  //       cancel,
  //       token
  //     })
  //   });
  // })

  // beforeEach(() => {
  //   const {cancel, token} = mockCancelToken(axios);
  // })

  test("Dashboard", async () => {

    render(
      <BrowserRouter >
        <Dashboard />
      </BrowserRouter>
    );

    const FeedsSourcesChart = screen.getByText("Feeds: Sources");
    expect(FeedsSourcesChart).toBeInTheDocument();
    const FeedsDownloadsChart = screen.getByText("Feeds: Downloads");
    expect(FeedsDownloadsChart).toBeInTheDocument();
    const FeedsTypesChart = screen.getByText("Feeds: Types");
    expect(FeedsTypesChart).toBeInTheDocument();
    const EnrichmentSourcesChart = screen.getByText("Enrichment Service: Sources");
    expect(EnrichmentSourcesChart).toBeInTheDocument();
    const EnrichmentRequestsChart = screen.getByText("Enrichment Service: Requests");
    expect(EnrichmentRequestsChart).toBeInTheDocument();
    
  });
});
