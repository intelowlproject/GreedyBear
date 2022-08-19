import axios from "axios";
import create from "zustand";

import { addToast } from "@certego/certego-ui";

import { USERACCESS_URI, AUTH_BASE_URI, IS_AUTH_URI } from "../constants/api";

// hook/ store see: https://github.com/pmndrs/zustand
const useAuthStore = create((set, get) => ({
    loading: false,
    user: { full_name: "", first_name: "", last_name: "", email: "" },
    isAuthenticated: false,
    isAuth: async () => {
      try {
        const resp = await axios.get(IS_AUTH_URI);
        if (resp.status === 200) {
          set({ isAuthenticated: true });
        }
      } catch (err) {
        //set({ isAuthenticated: false });
      }
    },
    service: {
        fetchUserAccess: async () => {
          try {
            const resp = await axios.get(USERACCESS_URI, {
              certegoUIenableProgressBar: false,
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
            set({ loading: true });
            const resp = await axios.post(`${AUTH_BASE_URI}/login`, body, {
              certegoUIenableProgressBar: false,
            });
            set({ isAuthenticated: true });
            addToast("You've been logged in!", null, "success");
            return Promise.resolve(resp);
          } catch (err) {
            addToast("Login failed!", err.parsedMsg, "danger", true);
            return Promise.reject(err);
          } finally {
            set({ loading: false });
          }
        },
        logoutUser: async () => {
          set({ loading: true });
          const onLogoutCb = () => {
            set({ loading: false });
            set({ isAuthenticated: false });
            addToast("Logged out!", null, "info");
          };
          return axios
            .post(`${AUTH_BASE_URI}/logout`, null, {
              certegoUIenableProgressBar: false,
            })
            .then(onLogoutCb)
            .catch(onLogoutCb);
        },
    },
}));

export default useAuthStore;
