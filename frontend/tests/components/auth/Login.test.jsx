import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import Login from "../../../src/components/auth/Login";
import { LOGIN_URI } from "../../../src/constants/api";

vi.mock("axios");

describe("Login component", () => {
  // mock login request
  axios.post.mockImplementation({
    data: {
      expiry: "2023-02-09T14:52:04.877168Z",
      token: "12345a6680364c7bf58b54b8c3d59b93",
      user: {
        email: "test@test.com",
        first_name: "test",
        full_name: "test user",
        last_name: "user",
        username: "test_user",
      },
    },
    headers: { "Content-Type": "application/json" },
  });

  test("User login", async () => {
    // mock user interaction: reccomanded to put this at the start of the test
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>,
    );

    // page before login
    const usernameInputElement = screen.getByLabelText("Username");
    expect(usernameInputElement).toBeInTheDocument();
    const passwordInputElement = screen.getByLabelText("Password");
    expect(passwordInputElement).toBeInTheDocument();
    const submitButtonElement = screen.getByRole("button", { name: /Login/i });
    expect(submitButtonElement).toBeInTheDocument();

    // user populates the login form and submit
    await user.type(usernameInputElement, "test_user");
    await user.type(passwordInputElement, "dummyPwd1");
    await user.click(submitButtonElement);

    await waitFor(() => {
      // check request has been performed
      expect(axios.post).toHaveBeenCalledWith(
        LOGIN_URI,
        { password: "dummyPwd1", username: "test_user" },
        {
          headers: { "Content-Type": "application/json" },
          certegoUIenableProgressBar: false,
        },
      );
    });
  });

  test("Double-clicking Login while submitting does not trigger duplicate requests", async () => {
    const user = userEvent.setup();

    // Clearing any previous mock calls and creating a promise
    axios.post.mockClear();
    let resolvePost;
    axios.post.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolvePost = resolve;
        }),
    );

    render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>,
    );

    const usernameInputElement = screen.getByLabelText("Username");
    const passwordInputElement = screen.getByLabelText("Password");
    const submitButtonElement = screen.getByRole("button", { name: /Login/i });

    // Populating the form
    await user.type(usernameInputElement, "test_user");
    await user.type(passwordInputElement, "dummyPwd1");

    // First Submit
    await user.click(submitButtonElement);

    // Checking that the button is disabled while submitting
    expect(submitButtonElement).toBeDisabled();

    // Second Submit
    await user.click(submitButtonElement);

    // Only one call was made?
    expect(axios.post).toHaveBeenCalledTimes(1);

    resolvePost({ data: { token: "test-token" } });

    // Waiting for submission to fully settle by checking the button re-enables
    await waitFor(() => {
      expect(submitButtonElement).not.toBeDisabled();
    });
  });
});
