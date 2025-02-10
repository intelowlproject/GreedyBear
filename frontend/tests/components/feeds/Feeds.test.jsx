import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import Feeds from "../../../src/components/feeds/Feeds";

jest.mock("@certego/certego-ui", () => {
  const originalModule = jest.requireActual("@certego/certego-ui");

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
          feed_type: "log4j",
        },
      ],
    },
  };

  const MockTableComponent = () => <div>table</div>;
  const loader = (props) => {
    return <originalModule.Loader loading={false} {...props} />;
  };

  //Mock the useAxiosComponentLoader and useDataTable
  return {
    __esModule: true,
    ...originalModule,

    useAxiosComponentLoader: jest.fn(() => [
      ["Honeytrap", "Glutton", "CitrixHoneypot"],
      loader,
    ]),

    useDataTable: jest.fn(() => [feeds, <MockTableComponent />, jest.fn()]),
  };
});

describe("Feeds component", () => {
  afterEach(() => {
    jest.restoreAllMocks();
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
    const ageSelectElement = screen.getByLabelText("Age:");
    expect(ageSelectElement).toBeInTheDocument();

    const buttonRawData = screen.getByRole("link", { name: /Raw data/i });
    expect(buttonRawData).toHaveAttribute(
      "href",
      "/api/feeds/all/all/recent.json"
    );

    await user.selectOptions(feedTypeSelectElement, "log4j");
    await user.selectOptions(attackTypeSelectElement, "scanner");
    await user.selectOptions(ageSelectElement, "persistent");

    await waitFor(() => {
      // check link has been changed
      expect(buttonRawData).toHaveAttribute(
        "href",
        "/api/feeds/log4j/scanner/persistent.json"
      );
    });
  });
});
