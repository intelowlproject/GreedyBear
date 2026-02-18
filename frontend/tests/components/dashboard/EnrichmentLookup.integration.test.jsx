import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import Dashboard from "../../../src/components/dashboard/Dashboard";
import { ENRICHMENT_URI } from "../../../src/constants/api";
import { AUTHENTICATION_STATUSES } from "../../../src/constants";

vi.mock("axios");

// Mock charts module
vi.mock(
  "../../../src/components/dashboard/utils/charts",
  async (importOriginal) => {
    const originalChartModule = await importOriginal();
    const FeedsSourcesChart = () => <div />;
    const FeedsDownloadsChart = () => <div />;
    const EnrichmentSourcesChart = () => <div />;
    const EnrichmentRequestsChart = () => <div />;
    const FeedsTypesChart = () => <div />;

    return {
      ...originalChartModule,
      FeedsSourcesChart,
      FeedsDownloadsChart,
      EnrichmentSourcesChart,
      EnrichmentRequestsChart,
      FeedsTypesChart,
    };
  }
);

// Mock useAuthStore
const mockUseAuthStore = vi.fn();
vi.mock("../../../src/stores", () => ({
  useAuthStore: (selector) => mockUseAuthStore(selector),
}));

describe("Enrichment Lookup Integration Tests", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("enrichment lookup section is visible on dashboard page", () => {
    // Mock authenticated state to see the enrichment section
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE })
    );

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>
    );

    // Verify the Enrichment Lookup section header is present
    expect(screen.getByText("Enrichment Lookup")).toBeInTheDocument();

    // Verify the form elements are present
    expect(screen.getByLabelText("IP Address or Domain:")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Search/i })).toBeInTheDocument();
  });

  test("try looking up an IP without authentication", async () => {
    const user = userEvent.setup();

    // Mock unauthenticated state
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.FALSE })
    );

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>
    );

    // Verify enrichment lookup section is still visible (publicly visible)
    expect(screen.getByText("Enrichment Lookup")).toBeInTheDocument();

    // Get form elements
    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    // Attempt to search for an IP without authentication
    await user.type(inputElement, "192.168.1.100");
    await user.click(submitButton);

    // Should show authentication error without calling the API
    await waitFor(() => {
      expect(
        screen.getByText(
          /You must be authenticated to use the enrichment feature/i
        )
      ).toBeInTheDocument();
    });

    // Verify API was NOT called
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("look up an IP with authentication - found scenario", async () => {
    const user = userEvent.setup();

    // Mock authenticated state
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE })
    );

    // Mock successful API response with IOC data
    const mockIocData = {
      name: "192.168.1.100",
      type: "ip",
      attack_count: 42,
      interaction_count: 150,
      login_attempts: 25,
      first_seen: "2024-01-01",
      last_seen: "2024-01-15",
      scanner: true,
      payload_request: true,
      ip_reputation: "malicious",
      asn: "12345",
      destination_ports: [22, 80, 443],
      firehol_categories: ["abuse"],
      general_honeypot: ["Cowrie", "Heralding"],
      recurrence_probability: 0.85,
      expected_interactions: 120.5,
    };

    axios.get.mockResolvedValue({
      data: {
        found: true,
        query: "192.168.1.100",
        ioc: mockIocData,
      },
    });

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>
    );

    // Get form elements
    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    // Search for an IP with authentication
    await user.type(inputElement, "192.168.1.100");
    await user.click(submitButton);

    // Verify API was called with correct parameters
    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(ENRICHMENT_URI, {
        params: { query: "192.168.1.100" },
        headers: { "Content-Type": "application/json" },
      });
    });

    // Verify IOC details are displayed
    await waitFor(() => {
      expect(
        screen.getByText(/IOC Details for: 192.168.1.100/i)
      ).toBeInTheDocument();
      expect(screen.getByText("42")).toBeInTheDocument(); // attack_count
      expect(screen.getByText("150")).toBeInTheDocument(); // interaction_count
      expect(screen.getByText("malicious")).toBeInTheDocument(); // ip_reputation
      expect(screen.getByText("Cowrie")).toBeInTheDocument(); // honeypot
    });
  });

  test("look up an IP with authentication - not found scenario", async () => {
    const user = userEvent.setup();

    // Mock authenticated state
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE })
    );

    // Mock API response - IP not found in database
    axios.get.mockResolvedValue({
      data: {
        found: false,
        query: "1.2.3.4",
        ioc: null,
      },
    });

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>
    );

    // Get form elements
    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    // Search for an IP that doesn't exist in the database
    await user.type(inputElement, "1.2.3.4");
    await user.click(submitButton);

    // Verify API was called
    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(ENRICHMENT_URI, {
        params: { query: "1.2.3.4" },
        headers: { "Content-Type": "application/json" },
      });
    });

    // Verify "not found" message is displayed
    await waitFor(() => {
      expect(
        screen.getByText(/No data available for "1.2.3.4" in our database/i)
      ).toBeInTheDocument();
    });
  });

  test("look up an IP with authentication - validation error", async () => {
    const user = userEvent.setup();

    // Mock authenticated state
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE })
    );

    // Mock API validation error
    const errorMessage = "Observable is not a valid IP";
    axios.get.mockRejectedValue({
      response: {
        data: {
          non_field_errors: [errorMessage],
        },
      },
    });

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>
    );

    // Get form elements
    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    // Search for an invalid IP
    await user.type(inputElement, "invalid-ip-address");
    await user.click(submitButton);

    // Verify API was called
    await waitFor(() => {
      expect(axios.get).toHaveBeenCalled();
    });

    // Verify validation error message is displayed
    await waitFor(() => {
      expect(screen.getByText(errorMessage)).toBeInTheDocument();
    });
  });
});
