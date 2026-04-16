import React, { Suspense } from "react";
import { useRoutes, Outlet } from "react-router-dom";



// wrapper
import withAuth from "../wrappers/withAuth";

// layout
import {
  publicRoutesLazy,
  noAuthRoutesLazy,
  authRoutesLazy,
} from "../components/Routes";
import AppHeader from "./AppHeader";

const NotFoundPage = React.lazy(() => import("./NotFoundPage"));

function Layout() {
  return (
    <>
      <AppHeader />
      <main role="main" className="px-1 px-md-5 mx-auto">
        <Outlet />
      </main>
    </>
  );
}

function AppMain() {
  const AuthLayout = withAuth(Layout);
  const routes = useRoutes([
    {
      path: "/",
      element: <AuthLayout />,
      children: [...publicRoutesLazy, ...noAuthRoutesLazy, ...authRoutesLazy],
    },
    {
      path: "*",
      element: (
       <Suspense fallback={<div>Loading...</div>}>
          <NotFoundPage />
        </Suspense>
      ),
    },
  ]);

  return routes;
}

export default AppMain;
