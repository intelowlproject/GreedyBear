import axios from "axios";
import create from "zustand";

import { addToast } from "@certego/certego-ui";

import { USERACCESS_URI, AUTH_BASE_URI, CHECK_AUTHENTICATION_URI } from "../constants/api";

// hook/ store see: https://github.com/pmndrs/zustand
const useAuthStore = create((set, get) => ({
    loading: false,
    user: { full_name: "", first_name: "", last_name: "", email: "" },
    isAuthenticated: false,
    checkAuthentication: async () => {
      try {
        await axios.get(CHECK_AUTHENTICATION_URI);
        if( !get().isAuthenticated) {
          set({isAuthenticated: true});
        }
      } catch (err) {
        if( get().isAuthenticated) {
          set({ isAuthenticated: false });
        }
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
            if( !get().isAuthenticated) {
              set({ isAuthenticated: true });
            }
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
            set({ 
              isAuthenticated: false, 
              loading: false
            });
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
