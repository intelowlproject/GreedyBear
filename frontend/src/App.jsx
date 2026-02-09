import React from "react";
import { BrowserRouter } from "react-router-dom";

import { PUBLIC_URL } from "./constants/environment";

// layout
import AppMain from "./layouts/AppMain";
import AppFooter from "./layouts/AppFooter";

function App() {
  return (
    <BrowserRouter basename={PUBLIC_URL}>
      <AppMain />
      <AppFooter />
    </BrowserRouter>
  );
}

export default App;
