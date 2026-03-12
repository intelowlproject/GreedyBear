import { describe, test, expect, vi, beforeEach } from "vitest";
import axios from "axios";
import useAuthStore from "../../src/stores/useAuthStore";
import { AUTHENTICATION_STATUSES } from "../../src/constants";

vi.mock("axios");

describe("useAuthStore", () => {
  // Reset store before every test
  beforeEach(() => {
    useAuthStore.setState({
      user: { full_name: "", first_name: "", last_name: "", email: "" },
      isSuperuser: false,
      isAuthenticated: AUTHENTICATION_STATUSES.FALSE,
    });

    vi.clearAllMocks();
  });

  //initial state test

  describe("Initial State", () => {
    test("initial state is correct", () => {
      const state = useAuthStore.getState();

      expect(state.user).toEqual({
        full_name: "",
        first_name: "",
        last_name: "",
        email: "",
      });

      expect(state.isSuperuser).toBe(false);

      expect(state.isAuthenticated).toBe(AUTHENTICATION_STATUSES.FALSE);
    });
  });

  //login tests

  describe("loginUser", () => {
    test("sets authentication FALSE on failure", async () => {
      axios.post.mockRejectedValue(new Error("login failure"));

      const { loginUser } = useAuthStore.getState().service;

      await expect(
        loginUser({ username: "test", password: "123" }),
      ).rejects.toThrow();

      expect(useAuthStore.getState().isAuthenticated).toBe(
        AUTHENTICATION_STATUSES.FALSE,
      );
    });

    test("sets authentication TRUE on success", async () => {
      axios.post.mockResolvedValue({ data: {} });

      const { loginUser } = useAuthStore.getState().service;

      await loginUser({ username: "test", password: "123" });

      expect(axios.post).toHaveBeenCalled();

      expect(useAuthStore.getState().isAuthenticated).toBe(
        AUTHENTICATION_STATUSES.TRUE,
      );
    });
  });

  //logout tests

  describe("logoutUser", () => {
    test("clears user and auth state", async () => {
      axios.post.mockResolvedValue({});

      useAuthStore.setState({
        isAuthenticated: AUTHENTICATION_STATUSES.TRUE,
        user: {
          full_name: "Test",
          first_name: "Test",
          last_name: "User",
          email: "test@test.com",
        },
        isSuperuser: true,
      });

      const { logoutUser } = useAuthStore.getState().service;

      await logoutUser();

      const state = useAuthStore.getState();

      expect(state.isAuthenticated).toBe(AUTHENTICATION_STATUSES.FALSE);

      expect(state.isSuperuser).toBe(false);

      expect(state.user).toEqual({
        full_name: "",
        first_name: "",
        last_name: "",
        email: "",
      });
    });
  });

  //fetch user access test

  describe("fetchUserAccess", () => {
    test("stores user data", async () => {
      axios.get.mockResolvedValue({
        data: {
          user: {
            full_name: "user1",
            first_name: "user",
            last_name: "1",
            email: "user1@test.com",
          },
        },
      });

      const { fetchUserAccess } = useAuthStore.getState().service;

      await fetchUserAccess();

      expect(useAuthStore.getState().user.email).toBe("user1@test.com");
    });
  });

  //check Authentication test

  describe("checkAuthentication", () => {
    test("sets auth TRUE", async () => {
      axios.get.mockResolvedValue({
        data: { is_superuser: true },
      });

      const { checkAuthentication } = useAuthStore.getState();

      await checkAuthentication();

      expect(useAuthStore.getState().isAuthenticated).toBe(
        AUTHENTICATION_STATUSES.TRUE,
      );

      expect(useAuthStore.getState().isSuperuser).toBe(true);
    });
  });

  //change password test

  describe("changePassword", () => {
    test("resolves on success", async () => {
      axios.post.mockResolvedValue({ data: {} });

      const { changePassword } = useAuthStore.getState().service;

      await expect(
        changePassword({ old: "a", new: "b" }),
      ).resolves.toBeDefined();
    });
  });
});
