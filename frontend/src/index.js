import "bootstrap/dist/css/bootstrap.min.css";
import React from 'react';
import ReactDOM from 'react-dom';
import App from "./App";
import { BrowserRouter as Router } from "react-router-dom";

const render = ReactDOM.render;

render( 
  <Router>
    <App />
  </Router>, 
  document.getElementById("root")
);  