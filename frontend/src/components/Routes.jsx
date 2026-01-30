import React, { Suspense } from "react";
import { FallBackLoading } from "@certego/certego-ui";

import IfAuthRedirectGuard from "../wrappers/ifAuthRedirectGuard";
import AuthGuard from "../wrappers/AuthGuard";

const Home = React.lazy(() => import("./home/Home"));
const Login = React.lazy(() => import("./auth/Login"));
const Logout = React.lazy(() => import("./auth/Logout"));
const Register = React.lazy(() => import("./auth/Register"));
const EmailVerification = React.lazy(() => import("./auth/EmailVerification"));
const ResetPassword = React.lazy(() => import("./auth/ResetPassword"));
const ChangePassword = React.lazy(() => import("./auth/ChangePassword"));
const Dashboard = React.lazy(() => import("./dashboard/Dashboard"));
const Sessions = React.lazy(() => import("./me/sessions/Sessions"));
const Feeds = React.lazy(() => import("./feeds/Feeds"));

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
  {
    path: "/register",
    element: <Register />,
  },
  {
    path: "/verify-email",
    element: <EmailVerification />,
  },
  {
    path: "/reset-password",
    element: <ResetPassword />,
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
  /* Change Password */
  {
    path: "/me/change-password",
    element: (
      <Suspense fallback={<FallBackLoading />}>
        <ChangePassword />
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
