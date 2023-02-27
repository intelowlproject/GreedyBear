import React, { Suspense } from "react";
import { FallBackLoading } from "@certego/certego-ui";

import IfAuthRedirectGuard from "../wrappers/ifAuthRedirectGuard";
import AuthGuard from "../wrappers/AuthGuard";
import { Feeds } from "./feeds/Feeds";

const Home = React.lazy(() => import("./home/Home"));
const Login = React.lazy(() => import("./auth/Login"));
const Logout = React.lazy(() => import("./auth/Logout"));
const Dashboard = React.lazy(() => import("./dashboard/Dashboard"));
const Sessions = React.lazy(() => import("./me/sessions/Sessions"));

// public components
const publicRoutesLazy = [
  /* Home */
  {
    index: true,
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Home />
      </Suspense>
    ),
  },
  /* Dashboard */
  {
    path: "/dashboard",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Dashboard />
      </Suspense>
    ),
  },
  /* Feeds */
  {
    path: "/feeds",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Feeds />
      </Suspense>
    ),
  },
].map((r) => ({
  ...r,
  element: <Suspense fallback={<FallBackLoading />}>{r.element}</Suspense>,
}));

// no auth public components
const noAuthRoutesLazy = [
  {
    path: "/login",
    element: <Login />,
  },
].map((r) => ({
  ...r,
  element: (
    <IfAuthRedirectGuard>
      <Suspense fallback={<FallBackLoading />}>{r.element}</Suspense>
    </IfAuthRedirectGuard>
  ),
}));

// auth components
const authRoutesLazy = [
  /* auth */
  {
    path: "/logout",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Logout />
      </Suspense>
    ),
  },
  /* API Access/Sessions Management */
  {
    path: "/me/sessions",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <Sessions />
      </Suspense>
    ),
  },
].map((r) => ({
  ...r,
  element: (
    <AuthGuard>
      <Suspense fallback={<FallBackLoading />}>{r.element}</Suspense>
    </AuthGuard>
  ),
}));

export { publicRoutesLazy, noAuthRoutesLazy, authRoutesLazy };
