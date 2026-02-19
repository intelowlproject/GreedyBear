import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { feedsTableColumns } from "../../../src/components/feeds/tableColumns";

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
});
