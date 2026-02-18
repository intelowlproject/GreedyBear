import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import Feeds from "../../../src/components/feeds/Feeds";

vi.mock("@certego/certego-ui", async (importOriginal) => {
  const originalModule = await importOriginal();

  const feeds = {
    count: 1,
    total_pages: 1,
    results: {
      license: "licenseTest",
      iocs: [
        {
          value: "test",
          SCANNER: true,
          PAYLOAD_REQUEST: true,
          first_seen: "2023-03-15",
          last_seen: "2023-03-15",
          attack_count: 1,
          feed_type: "cowrie",
        },
      ],
    },
  };

  const MockTableComponent = () => <div>table</div>;
  const loader = (props) => {
    return <originalModule.Loader loading={false} {...props} />;
  };

  // Mock the Select component to render a real select for testing
  const Select = ({ id, choices, value, onChange, name }) => (
    <select
      id={id}
      data-testid={id}
      value={value}
      onChange={onChange}
      name={name}
    >
      {choices.map((c) => (
        <option key={c.value} value={c.value}>
          {c.label}
        </option>
      ))}
    </select>
  );

  return {
    ...originalModule,
    Select,
    useAxiosComponentLoader: vi.fn(() => [
      ["Honeytrap", "Glutton", "CitrixHoneypot", "Cowrie"],
      loader,
    ]),

    useDataTable: vi.fn(() => [
      feeds,
      <MockTableComponent />,
      vi.fn(),
      vi.fn(),
    ]),
  };
});

describe("Feeds component", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  test("Feeds", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <Feeds />
      </BrowserRouter>
    );

    const buttonFeedsLicense = screen.getByRole("link", {
      name: /Feeds license/i,
    });
    expect(buttonFeedsLicense).toHaveAttribute(
      "href",
      "https://github.com/intelowlproject/GreedyBear/blob/main/FEEDS_LICENSE.md"
    );

    const feedTypeSelectElement = screen.getByLabelText("Feed type:");
    expect(feedTypeSelectElement).toBeInTheDocument();
    const attackTypeSelectElement = screen.getByLabelText("Attack type:");
    expect(attackTypeSelectElement).toBeInTheDocument();
    const iocTypeSelectElement = screen.getByLabelText("IOC type:");
    expect(iocTypeSelectElement).toBeInTheDocument();
    const prioritizationSelectElement = screen.getByLabelText("Prioritize:");
    expect(prioritizationSelectElement).toBeInTheDocument();

    const buttonRawData = screen.getByRole("link", { name: /Raw data/i });
    expect(buttonRawData).toHaveAttribute(
      "href",
      "/api/feeds/all/all/recent.json"
    );

    await user.selectOptions(feedTypeSelectElement, "cowrie");
    await user.selectOptions(attackTypeSelectElement, "scanner");
    await user.selectOptions(iocTypeSelectElement, "ip");
    await user.selectOptions(prioritizationSelectElement, "persistent");

    await waitFor(() => {
      // check link has been changed including ioc_type parameter
      expect(buttonRawData).toHaveAttribute(
        "href",
        "/api/feeds/cowrie/scanner/persistent.json?ioc_type=ip"
      );
    });

    // Test selecting domain IOC type
    await user.selectOptions(iocTypeSelectElement, "domain");
    await waitFor(() => {
      expect(buttonRawData).toHaveAttribute(
        "href",
        "/api/feeds/cowrie/scanner/persistent.json?ioc_type=domain"
      );
    });
  });
});
