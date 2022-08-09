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
            <main role="main" className="px-1 px-md-5 mx-auto">
                <AppMain />
            </main>
            <AppFooter />
        </BrowserRouter>
    );     
}

export default App;