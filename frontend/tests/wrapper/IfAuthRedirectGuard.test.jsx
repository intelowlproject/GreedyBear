import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AUTHENTICATION_STATUSES } from "../../src/constants";
import IfAuthRedirectGuard from "../../src/wrappers/ifAuthRedirectGuard";

const mockUseAuthStore = vi.fn();
vi.mock("../../src/stores", () => ({
  useAuthStore: (selector) => mockUseAuthStore(selector),
}));

const mockUseSearchParam = vi.fn();
vi.mock("react-use/esm/useSearchParam", () => ({
  default: () => mockUseSearchParam(),
}));

describe("IfAuthRedirectGuard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseSearchParam.mockReturnValue(null);
  });

  test("renders children when user is not authenticated", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.FALSE }),
    );

    render(
      <MemoryRouter initialEntries={["/login"]}>
        <Routes>
          <Route
            path="/login"
            element={
              <IfAuthRedirectGuard>
                <div>Login Page</div>
              </IfAuthRedirectGuard>
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Login Page")).toBeInTheDocument();
  });

  test("redirects authenticated user from /login to / when no next param", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE }),
    );
    mockUseSearchParam.mockReturnValue(null);

    render(
      <MemoryRouter initialEntries={["/login"]}>
        <Routes>
          <Route
            path="/login"
            element={
              <IfAuthRedirectGuard>
                <div>Login Page</div>
              </IfAuthRedirectGuard>
            }
          />
          <Route path="/" element={<div>Home Page</div>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Home Page")).toBeInTheDocument();
    expect(screen.queryByText("Login Page")).not.toBeInTheDocument();
  });

  test("redirects authenticated user to ?next param when provided", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE }),
    );
    mockUseSearchParam.mockReturnValue("/dashboard");

    render(
      <MemoryRouter initialEntries={["/login?next=/dashboard"]}>
        <Routes>
          <Route
            path="/login"
            element={
              <IfAuthRedirectGuard>
                <div>Login Page</div>
              </IfAuthRedirectGuard>
            }
          />
          <Route path="/dashboard" element={<div>Dashboard Page</div>} />
          <Route path="/" element={<div>Home Page</div>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Dashboard Page")).toBeInTheDocument();
    expect(screen.queryByText("Login Page")).not.toBeInTheDocument();
  });
});
