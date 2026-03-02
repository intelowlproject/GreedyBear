import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import { AUTH_BASE_URI } from "../../../src/constants/api";
import ResetPassword from "../../../src/components/auth/ResetPassword";

vi.mock("axios");

describe("ResetPassword component", () => {
  test("Valid key", async () => {
    // mock user interaction: reccomanded to put this at the start of the test
    const user = userEvent.setup();

    render(
      <MemoryRouter
        initialEntries={[
          "/reset-password?key=c0236120-c905-4534-b8ba-aca5e94aa5da",
        ]}
      >
        <ResetPassword />
      </MemoryRouter>,
    );

    // page before reset password
    const passwordInputElement = screen.getByLabelText("New Password");
    expect(passwordInputElement).toBeInTheDocument();
    const confirmPasswordInputElement = screen.getByLabelText(
      "Confirm New Password",
    );
    expect(confirmPasswordInputElement).toBeInTheDocument();
    const submitButtonElement = screen.getByRole("button", { name: /Submit/i });
    expect(submitButtonElement).toBeInTheDocument();

    // user populates the reset password form and submit
    await user.type(passwordInputElement, "NewPassword1234");
    await user.type(confirmPasswordInputElement, "NewPassword1234");
    await user.click(submitButtonElement);

    await waitFor(() => {
      // check request has been performed
      expect(axios.post).toHaveBeenCalledWith(
        `${AUTH_BASE_URI}/reset-password`,
        {
          key: "c0236120-c905-4534-b8ba-aca5e94aa5da",
          password: "NewPassword1234",
        },
      );
    });
  });

  test("Invalid key", () => {
    render(
      <MemoryRouter
        initialEntries={["/reset-password?key=c0236120-c905-4534-b8ba"]}
      >
        <ResetPassword />
      </MemoryRouter>,
    );

    const element = screen.getByText("Error: Invalid key.");
    expect(element).toBeInTheDocument();
  });

  test("Double-clicking submit while submitting does not trigger duplicate requests", async () => {
    const user = userEvent.setup();

    // Clearing and creating a mock promise
    axios.post.mockClear();
    let resolvePost;
    axios.post.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolvePost = resolve;
        }),
    );

    // Rendering the component with a valid key
    render(
      <MemoryRouter
        initialEntries={[
          "/reset-password?key=c0236120-c905-4534-b8ba-aca5e94aa5da",
        ]}
      >
        <ResetPassword />
      </MemoryRouter>,
    );

    const passwordInputElement = screen.getByLabelText("New Password");
    const confirmPasswordInputElement = screen.getByLabelText(
      "Confirm New Password",
    );
    const submitButtonElement = screen.getByRole("button", { name: /Submit/i });

    // Populating and submitting
    await user.type(passwordInputElement, "NewPassword1234");
    await user.type(confirmPasswordInputElement, "NewPassword1234");

    // First submit
    await user.click(submitButtonElement);

    // Checking that the button is disabled
    await waitFor(() => {
      expect(submitButtonElement).toBeDisabled();
    });

    // Second submit
    await user.click(submitButtonElement);

    // only one api was called?
    expect(axios.post).toHaveBeenCalledTimes(1);

    resolvePost({ data: {} });

    // Waiting for submission to fully settle by checking the button re-enables
    await waitFor(() => {
      expect(submitButtonElement).not.toBeDisabled();
    });
  });
});
