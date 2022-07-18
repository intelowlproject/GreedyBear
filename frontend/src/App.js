import React from "react";
import Home from "./components/Home";
import NotFoundPage from "./components/NotFoundPage";
import { Route, Routes } from "react-router-dom";

function App() {
    return (
        <div>
            <Routes>
                <Route path="/" exact element={<Home />}/> 
                <Route path="*" element={<NotFoundPage />}/> 
            </Routes>
        </div>
    );     
}

export default App;