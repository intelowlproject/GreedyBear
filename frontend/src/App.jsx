import React from "react";
import { BrowserRouter } from "react-router-dom";

//layout
import AppHeader from "./layouts/AppHeader";
import AppMain from "./layouts/AppMain";
import AppFooter from "./layouts/AppFooter";

function App() {
    return (
        <BrowserRouter>
            <AppHeader />
            <AppMain />
            <AppFooter />
        </BrowserRouter>
    );     
}

export default App;