import axios from "axios";
import create from "zustand";

import { addToast } from "@certego/certego-ui";

import {
  USERACCESS_URI,
  CHECK_AUTHENTICATION_URI,
  LOGIN_URI,
  LOGOUT_URI,
} from "../constants/api";
import { AUTHENTICATION_STATUSES } from "../constants";

// hook/ store see: https://github.com/pmndrs/zustand
const useAuthStore = create((set, get) => ({
  user: { full_name: "", first_name: "", last_name: "", email: "" },
  isSuperuser: false,
  isAuthenticated: AUTHENTICATION_STATUSES.FALSE,
  checkAuthentication: async () => {
    try {
      const resp = await axios.get(CHECK_AUTHENTICATION_URI, {headers: {'Content-Type': 'application/json'}});
      if (get().isSuperuser !== resp.data.is_superuser) {
        set({
          isSuperuser: resp.data.is_superuser,
        });
      }
      if (get().isAuthenticated === AUTHENTICATION_STATUSES.FALSE) {
        set({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE });
      }
    } catch (err) {
      if (get().isAuthenticated === AUTHENTICATION_STATUSES.TRUE) {
        set({ isAuthenticated: AUTHENTICATION_STATUSES.FALSE });
      }
    }
  },
  service: {
    fetchUserAccess: async () => {
      try {
        const resp = await axios.get(USERACCESS_URI, {
          certegoUIenableProgressBar: false,
          headers: {'Content-Type': 'application/json'},
        });
        set({
          user: resp.data.user,
        });
      } catch (err) {
        addToast(
          "Error fetching user access information!",
          err.parsedMsg,
          "danger"
        );
      }
    },
    loginUser: async (body) => {
      try {
        set({ isAuthenticated: AUTHENTICATION_STATUSES.PENDING });
        const resp = await axios.post(LOGIN_URI, body, {headers: {'Content-Type': 'application/json'}}, {
          certegoUIenableProgressBar: false,
        });
        set({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE });
        addToast("You've been logged in!", null, "success");
        return Promise.resolve(resp);
      } catch (err) {
        set({ isAuthenticated: AUTHENTICATION_STATUSES.FALSE });
        addToast("Login failed!", err.parsedMsg, "danger", true);
        return Promise.reject(err);
      }
    },
    logoutUser: async () => {
      set({ isAuthenticated: AUTHENTICATION_STATUSES.PENDING });
      const onLogoutCb = () => {
        set({ isAuthenticated: AUTHENTICATION_STATUSES.FALSE });
        addToast("Logged out!", null, "info");
      };
      return axios
        .post(LOGOUT_URI, null, {
          certegoUIenableProgressBar: false,
        })
        .then(onLogoutCb)
        .catch(onLogoutCb);
    },
  },
}));

export default useAuthStore;
