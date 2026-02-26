import "./styles/App.scss";

import React from "react";
import ReactDOM from "react-dom";
import App from "./App";

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
