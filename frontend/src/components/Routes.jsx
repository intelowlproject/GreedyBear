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
const Dashboard = React.lazy(() => import("./dashboard/Dashboard"));
const Sessions = React.lazy(() => import("./me/sessions/Sessions"));
const Feeds = React.lazy(() => import("./feeds/Feeds"));
const ChangePassword = React.lazy(
  () => import("./me/changepassword/ChangePassword"),
);

// public components
const publicRoutesLazy = [
  /* Home */
  {
    index: true,
    element: <Home />,
  },
  /* Dashboard */
  {
    path: "/dashboard",
    element: <Dashboard />,
  },
  /* Feeds */
  {
    path: "/feeds",
    element: <Feeds />,
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
    element: <Logout />,
  },
  /* API Access/Sessions Management */
  {
    path: "/me/sessions",
    element: <Sessions />,
  },
  /* Change Password */
  {
    path: "/me/change-password",
    element: <ChangePassword />,
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
