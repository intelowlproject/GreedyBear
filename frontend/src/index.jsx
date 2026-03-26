import "./styles/App.scss";

import React from "react";
import ReactDOM from "react-dom";
import axios from "axios";
import App from "./App";
import useAuthStore from "./stores/useAuthStore";

// axios interceptor to handle session expiration (401/403)
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && [401, 403].includes(error.response.status)) {
      useAuthStore.getState().reset();
    }
    return Promise.reject(error);
  },
);

function noop() {}

// Vite uses import.meta.env.MODE, but Jest uses process.env.NODE_ENV
const isProduction =
  typeof process !== "undefined" && process.env.NODE_ENV === "test"
    ? false
    : import.meta.env.MODE !== "development";

if (isProduction) {
  console.debug = noop;
}

ReactDOM.render(<App />, document.getElementById("root"));
