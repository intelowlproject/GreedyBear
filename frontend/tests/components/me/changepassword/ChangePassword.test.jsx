import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import ChangePassword from "../../../../src/components/me/changepassword/ChangePassword";
import { CHANGE_PASSWORD_URI } from "../../../../src/constants/api";

vi.mock("axios");
vi.mock("@certego/certego-ui", async () => {
  const actual = await vi.importActual("@certego/certego-ui");
  return {
    ...actual,
    addToast: vi.fn(),
  };
});

describe("ChangePassword component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    axios.post.mockResolvedValue({
      data: { message: "Password changed successfully" },
    });
  });

  test("renders change password form fields", () => {
    render(
      <BrowserRouter>
        <ChangePassword />
      </BrowserRouter>,
    );

    expect(screen.getByLabelText("Old Password")).toBeInTheDocument();
    expect(screen.getByLabelText("New Password")).toBeInTheDocument();
    expect(screen.getByLabelText("Confirm New Password")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Change Password/i }),
    ).toBeInTheDocument();
  });

  test("successful password change calls API", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ChangePassword />
      </BrowserRouter>,
    );

    await user.type(screen.getByLabelText("Old Password"), "oldPassword123!");
    await user.type(
      screen.getByLabelText("New Password"),
      "newValidPassword123!",
    );
    await user.type(
      screen.getByLabelText("Confirm New Password"),
      "newValidPassword123!",
    );
    await user.click(screen.getByRole("button", { name: /Change Password/i }));

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        CHANGE_PASSWORD_URI,
        expect.objectContaining({
          old_password: "oldPassword123!",
          new_password: "newValidPassword123!",
        }),
        {
          headers: { "Content-Type": "application/json" },
          certegoUIenableProgressBar: false,
        },
      );
    });
  });

  test("does not call API when new password matches old password", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ChangePassword />
      </BrowserRouter>,
    );

    const samePassword = "samePassword123!";
    await user.type(screen.getByLabelText("Old Password"), samePassword);
    await user.type(screen.getByLabelText("New Password"), samePassword);
    await user.type(
      screen.getByLabelText("Confirm New Password"),
      samePassword,
    );
    await user.click(screen.getByRole("button", { name: /Change Password/i }));

    // The component shows a toast and returns early without calling the API
    await waitFor(() => {
      expect(axios.post).not.toHaveBeenCalled();
    });
  });

  test("does not call API when new password fails regex policy", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ChangePassword />
      </BrowserRouter>,
    );

    await user.type(screen.getByLabelText("Old Password"), "oldPassword123!");
    await user.type(screen.getByLabelText("New Password"), "short"); // < 12 chars
    await user.type(screen.getByLabelText("Confirm New Password"), "short");
    await user.click(screen.getByRole("button", { name: /Change Password/i }));

    // The component shows a toast and returns early without calling the API
    await waitFor(() => {
      expect(axios.post).not.toHaveBeenCalled();
    });
  });
});
