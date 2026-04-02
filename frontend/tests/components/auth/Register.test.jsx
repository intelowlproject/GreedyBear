import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import Register from "../../../src/components/auth/Register";
import { AUTH_BASE_URI } from "../../../src/constants/api";

vi.mock("axios");

function fillRegistrationForm() {
  fireEvent.change(screen.getByLabelText("First Name"), {
    target: { value: "firstname" },
  });
  fireEvent.change(screen.getByLabelText("Last Name"), {
    target: { value: "lastname" },
  });
  fireEvent.change(screen.getByLabelText("Email"), {
    target: { value: "test@test.com" },
  });
  fireEvent.change(screen.getByLabelText("Username"), {
    target: { value: "test_user" },
  });
  fireEvent.change(screen.getByLabelText("Password"), {
    target: { value: "GreedyBearPassword" },
  });
  fireEvent.change(screen.getByLabelText("Confirm Password"), {
    target: { value: "GreedyBearPassword" },
  });
  fireEvent.change(screen.getByLabelText("Company/ Organization"), {
    target: { value: "companyname" },
  });
  fireEvent.change(screen.getByLabelText("Role"), {
    target: { value: "companyrole" },
  });
}

describe("Registration component", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  test("User registration", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <Register />
      </BrowserRouter>,
    );

    // page before registration
    const firstNameInputElement = screen.getByLabelText("First Name");
    expect(firstNameInputElement).toBeInTheDocument();
    const lastNameInputElement = screen.getByLabelText("Last Name");
    expect(lastNameInputElement).toBeInTheDocument();
    const emailInputElement = screen.getByLabelText("Email");
    expect(emailInputElement).toBeInTheDocument();
    const usernameInputElement = screen.getByLabelText("Username");
    expect(usernameInputElement).toBeInTheDocument();
    const passwordInputElement = screen.getByLabelText("Password");
    expect(passwordInputElement).toBeInTheDocument();
    const confirmPasswordInputElement =
      screen.getByLabelText("Confirm Password");
    expect(confirmPasswordInputElement).toBeInTheDocument();
    const companyNameInputElement = screen.getByLabelText(
      "Company/ Organization",
    );
    expect(companyNameInputElement).toBeInTheDocument();
    const companyRoleInputElement = screen.getByLabelText("Role");
    expect(companyRoleInputElement).toBeInTheDocument();
    const submitButtonElement = screen.getByRole("button", {
      name: /Register/i,
    });
    expect(submitButtonElement).toBeInTheDocument();

    // user populates the registration form and submit
    fillRegistrationForm();

    await waitFor(() => {
      expect(submitButtonElement).not.toBeDisabled();
    });
    await user.click(submitButtonElement);

    await waitFor(() => {
      // check request has been performed
      expect(axios.post).toHaveBeenCalledWith(`${AUTH_BASE_URI}/register`, {
        first_name: "firstname",
        last_name: "lastname",
        username: "test_user",
        email: "test@test.com",
        password: "GreedyBearPassword",
        profile: {
          company_name: "companyname",
          company_role: "companyrole",
          twitter_handle: "",
          discover_from: "other",
        },
      });
    });
  });

  test("Show password checkbox", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <Register />
      </BrowserRouter>,
    );

    const checkBoxElement = screen.getByRole("checkbox");
    expect(checkBoxElement).toBeInTheDocument();
    expect(checkBoxElement).not.toBeChecked();

    await user.click(checkBoxElement);

    await waitFor(() => {
      expect(checkBoxElement).toBeChecked();
    });
  });

  test("Double-clicking Register while submitting does not trigger duplicate requests", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <Register />
      </BrowserRouter>,
    );

    // Populating the form
    fillRegistrationForm();

    const submitButtonElement = screen.getByRole("button", {
      name: /Register/i,
    });

    await waitFor(() => {
      expect(submitButtonElement).not.toBeDisabled();
    });

    // setting up the mock and clearing previous calls
    axios.post.mockClear();
    let resolvePost;
    axios.post.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolvePost = resolve;
        }),
    );

    // First submit
    await user.click(submitButtonElement);

    // Testing that the button is disabled
    await waitFor(() => {
      expect(submitButtonElement).toBeDisabled();
    });

    // Second Submit
    await user.click(submitButtonElement);

    // Only one call was made?
    expect(axios.post).toHaveBeenCalledTimes(1);

    resolvePost({ data: {} });

    // Waiting for submission to fully settle by checking the button re-enables
    await waitFor(() => {
      expect(submitButtonElement).not.toBeDisabled();
    });
  });
});
