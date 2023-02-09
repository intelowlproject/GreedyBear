import "./styles/App.scss";

import React from "react";
import ReactDOM from "react-dom";
import App from "./App";

function noop() {}
// hack to disable console.debug statements in production build
if (process.env.NODE_ENV !== "development") {
  console.debug = noop;
}

ReactDOM.render(<App />, document.getElementById("root"));
