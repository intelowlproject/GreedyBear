import React from "react";
import Home from "./components/Home";
import NotFoundPage from "./components/NotFoundPage";
import { Route, Switch } from "react-router-dom";

function App() {
    return (
        <div>
            <Switch>
                <Route path="/" exact component={Home}/> 
                <Route component={NotFoundPage}/> 
            </Switch>
        </div>
    );     
}

export default App;