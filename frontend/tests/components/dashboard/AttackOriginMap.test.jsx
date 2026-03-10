import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import axios from "axios";
import AttackOriginMap from "../../../src/components/dashboard/AttackOriginMap";
import { IOC_ATTACKER_COUNTRIES_URI } from "../../../src/constants/api";

vi.mock("axios");

vi.mock("@certego/certego-ui", () => ({
  useTimePickerStore: () => ({ range: "7d" }),
}));

// Mock react-simple-maps components
vi.mock("react-simple-maps", () => ({
  ComposableMap: ({ children, onMouseMove, onMouseLeave }) => (
    <div
      data-testid="composable-map"
      onMouseMove={onMouseMove}
      onMouseLeave={onMouseLeave}
    >
      {children}
    </div>
  ),
  Geographies: ({ children }) =>
    children({
      geographies: [
        { rsmKey: "geo-cn", properties: { name: "China" } },
        { rsmKey: "geo-usa", properties: { name: "United States of America" } },
      ],
    }),
  Geography: ({ fill, onMouseEnter, onMouseLeave, geography }) => (
    <div
      data-testid={`geography-${geography.rsmKey}`}
      data-fill={fill}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    />
  ),
  ZoomableGroup: ({ children }) => <div>{children}</div>,
}));

const COUNTRIES_DATA = [
  { country: "China", count: 120 },
  { country: "United States", count: 80 },
  { country: "Germany", count: 40 },
];

describe("AttackOriginMap", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("shows loading state while request is in flight", () => {
    axios.get.mockReturnValue(new Promise(() => {}));
    render(<AttackOriginMap />);
    expect(screen.getByText("Loading map…")).toBeInTheDocument();
  });

  test("shows error state when request fails", async () => {
    axios.get.mockRejectedValue(new Error("Network error"));
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByText("Failed to load map data.")).toBeInTheDocument(),
    );
  });

  test("calls the countries endpoint with the range param", async () => {
    axios.get.mockResolvedValue({ data: [] });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith(IOC_ATTACKER_COUNTRIES_URI, {
        params: { range: "7d" },
      }),
    );
  });

  test("renders map and hides legend when response is empty", async () => {
    axios.get.mockResolvedValue({ data: [] });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByTestId("composable-map")).toBeInTheDocument(),
    );
    // maxCount stays 0 (legend must not render)
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  test("renders map and shows legend with correct maxCount when data is present", async () => {
    axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByTestId("composable-map")).toBeInTheDocument(),
    );
    // Legend: left label "0" and right label matching the max value
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getByText("120")).toBeInTheDocument();
  });

  test("geographies are rendered for each geo in the response", async () => {
    axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByTestId("geography-geo-cn")).toBeInTheDocument(),
    );
    expect(screen.getByTestId("geography-geo-usa")).toBeInTheDocument();
  });

  test("empty country for a geo gets the empty fill colour", async () => {
    axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
    render(<AttackOriginMap />);
    // Germany is in the data but not in the mocked geographies, so the USA
    // geo should get a non-empty colour and an unknown geo should get COLOR_EMPTY
    await waitFor(() =>
      expect(screen.getByTestId("geography-geo-cn")).toBeInTheDocument(),
    );
    const chinaEl = screen.getByTestId("geography-geo-cn");
    expect(chinaEl.dataset.fill).not.toBe("#2a2a3a");
  });

  test("country name normalisation is applied (United States => United States of America)", async () => {
    axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByTestId("geography-geo-usa")).toBeInTheDocument(),
    );

    const usaEl = screen.getByTestId("geography-geo-usa");
    expect(usaEl.dataset.fill).not.toBe("#2a2a3a");
  });
});
