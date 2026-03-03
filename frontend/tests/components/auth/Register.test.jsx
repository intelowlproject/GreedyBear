import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import Register from "../../../src/components/auth/Register";
import { AUTH_BASE_URI } from "../../../src/constants/api";

vi.mock("axios");

describe("Registration component", () => {
  test("User registration", async () => {
    // mock user interaction: reccomanded to put this at the start of the test
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
    await user.type(firstNameInputElement, "firstname");
    await user.type(lastNameInputElement, "lastname");
    await user.type(emailInputElement, "test@test.com");
    await user.type(usernameInputElement, "test_user");
    await user.type(passwordInputElement, "GreedyBearPassword");
    await user.type(confirmPasswordInputElement, "GreedyBearPassword");
    await user.type(companyNameInputElement, "companyname");
    await user.type(companyRoleInputElement, "companyrole");
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

    // Clear the storage to prevent state pollution from previous calls
    localStorage.clear();
    vi.resetModules();

    // Then reimporting to get a fresh state
    const { default: Register } =
      await import("../../../src/components/auth/Register");

    render(
      <BrowserRouter>
        <Register />
      </BrowserRouter>,
    );

    const firstNameInputElement = screen.getByLabelText("First Name");
    const lastNameInputElement = screen.getByLabelText("Last Name");
    const emailInputElement = screen.getByLabelText("Email");
    const usernameInputElement = screen.getByLabelText("Username");
    const passwordInputElement = screen.getByLabelText("Password");
    const confirmPasswordInputElement =
      screen.getByLabelText("Confirm Password");
    const companyNameInputElement = screen.getByLabelText(
      "Company/ Organization",
    );
    const companyRoleInputElement = screen.getByLabelText("Role");
    const submitButtonElement = screen.getByRole("button", {
      name: /Register/i,
    });

    // Populating the form
    await user.type(firstNameInputElement, "firstname");
    await user.type(lastNameInputElement, "lastname");
    await user.type(emailInputElement, "test@test.com");
    await user.type(usernameInputElement, "test_user");
    await user.type(passwordInputElement, "GreedyBearPassword");
    await user.type(confirmPasswordInputElement, "GreedyBearPassword");
    await user.type(companyNameInputElement, "companyname");
    await user.type(companyRoleInputElement, "companyrole");

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
