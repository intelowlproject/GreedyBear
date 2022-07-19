import React from "react";
import { useRoutes } from "react-router-dom";

import NotFoundPage from "./NotFoundPage";
import Home from "../components/home/Home";
import Login from "../components/auth/Login";

function AppMain() {
    const routes = useRoutes([
      {
        path: "/",
        element: <Home />,
      },
      {
        path: "/login",
        element: <Login />,
      },
      {
        path: "*",
        element: <NotFoundPage />,
      },
    ]);
  
    return routes;
  }
  
  export default AppMain;