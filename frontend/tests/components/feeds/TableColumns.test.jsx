import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { feedsTableColumns } from "../../../src/components/feeds/tableColumns";

describe("IntelOwl Analyze column", () => {
  const row = { original: { value: "1.2.3.4" } };

  beforeEach(() => {
    vi.resetModules();
  });

  test("column is present when INTELOWL_URL is set", async () => {
    vi.doMock("../../../src/constants/environment", () => ({
      INTELOWL_URL: "https://intelowl.example.com",
      PUBLIC_URL: "",
    }));
    const { feedsTableColumns: columns } =
      await import("../../../src/components/feeds/tableColumns");
    const col = columns.find((c) => c.id === "intelowl");
    expect(col).toBeDefined();
    render(<col.Cell row={row} />);
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute(
      "href",
      "https://intelowl.example.com/scan?observable_name=1.2.3.4",
    );
  });

  test("column is absent when INTELOWL_URL is not set", async () => {
    vi.doMock("../../../src/constants/environment", () => ({
      INTELOWL_URL: "",
      PUBLIC_URL: "",
    }));
    const { feedsTableColumns: columns } =
      await import("../../../src/components/feeds/tableColumns");
    const col = columns.find((c) => c.id === "intelowl");
    expect(col).toBeUndefined();
  });

  test("column URL-encodes the IOC value", async () => {
    vi.doMock("../../../src/constants/environment", () => ({
      INTELOWL_URL: "https://intelowl.example.com",
      PUBLIC_URL: "",
    }));
    const { feedsTableColumns: columns } =
      await import("../../../src/components/feeds/tableColumns");
    const col = columns.find((c) => c.id === "intelowl");
    const specialRow = { original: { value: "evil domain.com/path?q=1&x=2" } };
    render(<col.Cell row={specialRow} />);
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute(
      "href",
      "https://intelowl.example.com/scan?observable_name=evil%20domain.com%2Fpath%3Fq%3D1%26x%3D2",
    );
  });
});

describe("Feeds table details popover", () => {
  test("shows details button and popover content on click", async () => {
    const user = userEvent.setup();
    const detailsColumn = feedsTableColumns.find(
      (column) => column.accessor === "details",
    );
    expect(detailsColumn).toBeDefined();

    const row = {
      id: "0",
      original: {
        recurrence_probability: 0.25,
        expected_interactions: 12.7,
        interaction_count: 10,
        destination_port_count: 2,
        login_attempts: 3,
        asn: "AS123",
        ip_reputation: "benign",
      },
    };

    const DetailsCell = detailsColumn.Cell;

    render(<DetailsCell row={row} />);

    const detailsButton = screen.getByLabelText(/view details/i);
    expect(detailsButton).toBeInTheDocument();
    expect(screen.queryByText(/Recurrence:/i)).not.toBeInTheDocument();

    await user.click(detailsButton);

    expect(
      await screen.findByText(/Recurrence:\s*25\.0%/i),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(/Expected Interactions:\s*13/i),
    ).toBeInTheDocument();
  });

  test("shows country in popover details when country is provided", async () => {
    const user = userEvent.setup();
    const detailsColumn = feedsTableColumns.find(
      (column) => column.accessor === "details",
    );

    const row = {
      id: "1",
      original: {
        recurrence_probability: 0.5,
        expected_interactions: 5,
        interaction_count: 4,
        destination_port_count: 1,
        login_attempts: 0,
        asn: "AS456",
        ip_reputation: "malicious",
        attacker_country: "United States",
      },
    };

    const DetailsCell = detailsColumn.Cell;
    render(<DetailsCell row={row} />);

    const detailsButton = screen.getByLabelText(/view details/i);
    await user.click(detailsButton);

    expect(
      await screen.findByText(/Country:\s*United States/i),
    ).toBeInTheDocument();
  });

  test("shows dash for country in popover when country is not provided", async () => {
    const user = userEvent.setup();
    const detailsColumn = feedsTableColumns.find(
      (column) => column.accessor === "details",
    );

    const row = {
      id: "2",
      original: {
        recurrence_probability: null,
        expected_interactions: null,
        interaction_count: null,
        destination_port_count: null,
        login_attempts: null,
        asn: null,
        ip_reputation: null,
        attacker_country: null,
      },
    };

    const DetailsCell = detailsColumn.Cell;
    render(<DetailsCell row={row} />);

    const detailsButton = screen.getByLabelText(/view details/i);
    await user.click(detailsButton);

    expect(await screen.findByText(/Country:\s*-/i)).toBeInTheDocument();
  });

  test("shows sensors in popover details when sensors are provided", async () => {
    const user = userEvent.setup();
    const detailsColumn = feedsTableColumns.find(
      (column) => column.accessor === "details",
    );

    const row = {
      id: "3",
      original: {
        sensors: [
          { address: "10.0.0.1", label: "AWS-West" },
          { address: "10.0.0.2", label: "" },
        ],
      },
    };

    const DetailsCell = detailsColumn.Cell;
    render(<DetailsCell row={row} />);

    const detailsButton = screen.getByLabelText(/view details/i);
    await user.click(detailsButton);

    expect(await screen.findByText(/Sensors/i)).toBeInTheDocument();
    expect(await screen.findByText(/10\.0\.0\.1/i)).toBeInTheDocument();
    expect(await screen.findByText(/\(AWS-West\)/i)).toBeInTheDocument();
    expect(await screen.findByText(/10\.0\.0\.2/i)).toBeInTheDocument();
  });
});
