import React from "react";
import { useRoutes } from "react-router-dom";

import NotFoundPage from "./NotFoundPage";
import Home from "../components/home/Home";
import Login from "../components/auth/Login";
import Dashboard from "../components/dashboard/Dashboard"

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
        path: "/dashboard",
        element: <Dashboard />,
      },
      {
        path: "*",
        element: <NotFoundPage />,
      },
    ]);
  
    return routes;
  }
  
  export default AppMain;