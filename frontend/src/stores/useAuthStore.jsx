import axios from "axios";
import create from "zustand";

import { addToast } from "@certego/certego-ui";

import { USERACCESS_URI, AUTH_BASE_URI } from "../constants/api";

// constants
const TOKEN_STORAGE_KEY = "GREEDYBEAR_AUTH_TOKEN";

// hook/ store see: https://github.com/pmndrs/zustand
const useAuthStore = create((set, get) => ({
    loading: false,
    // extract the user from the response from the API that we will use to get the isAuthenticated boolean value
    user: { full_name: "", first_name: "", last_name: "", email: "" },
    // todo change this to use axios and get if it is authenticated
    isAuthenticated: () => !!get().token,
    service: {
        loginUser: async (body) => {
          try {
            set({ loading: true });
            const resp = await axios.post(`${AUTH_BASE_URI}/login`, body, {
              certegoUIenableProgressBar: false,
            });
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
            addToast("Logged out!", null, "info");
          };
          return axios
            .post(`${AUTH_BASE_URI}/logout`, null, {
              certegoUIenableProgressBar: false,
            })
            .then(onLogoutCb)
            .catch(onLogoutCb);
        }
    },
}));

export default useAuthStore;
