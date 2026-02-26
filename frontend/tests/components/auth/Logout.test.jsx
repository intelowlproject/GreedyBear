import React from "react";
import axios from "axios";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { LOGOUT_URI } from "../../../src/constants/api";
import Logout from "../../../src/components/auth/Logout";
import { useAuthStore } from "../../../src/stores";

vi.mock("axios");

describe("Logout component", () => {
  // mock login request
  axios.post.mockImplementation(() => Promise.resolve());

  test("User logout", async () => {
    await useAuthStore.getState().service.loginUser();
    expect(useAuthStore.getState().isAuthenticated).toBeTruthy();

    render(
      <BrowserRouter>
        <Logout />
      </BrowserRouter>,
    );

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(LOGOUT_URI, null, {
        certegoUIenableProgressBar: false,
      });
    });
    expect(await screen.findByText("Logging you out...")).toBeInTheDocument();
  });
});
