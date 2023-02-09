import React from "react";
import axios from "axios";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { renderHook } from "@testing-library/react-hooks";
import { LOGOUT_URI } from "../../../src/constants/api";
import Logout from "../../../src/components/auth/Logout";
import { useAuthStore } from "../../../src/stores";

jest.mock("axios");

describe("Logout component", () => {
  // mock login request
  axios.post.mockImplementation(() => Promise.resolve());

  test("User logout", async () => {
    // user logged in before the logout action:
    // Another option is to mock zustand and useAuthStore, but this solution is easier
    const { result } = renderHook(() =>
      useAuthStore((s) => [s.isAuthenticated, s.service.loginUser])
    );
    // we need to do this because the class to mock the hook return a tuple
    const isAuthenticatedPos = 0;
    const loginUserPos = 1;
    result.current[loginUserPos]();
    expect(result.current[isAuthenticatedPos]).toBeTruthy();

    render(
      <BrowserRouter>
        <Logout />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(LOGOUT_URI, null, {
        certegoUIenableProgressBar: false,
      });
    });
    expect(await screen.findByText("Logging you out...")).toBeInTheDocument();
  });
});
