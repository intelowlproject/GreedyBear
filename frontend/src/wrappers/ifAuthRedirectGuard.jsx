import React from "react";
import PropTypes from "prop-types";
import { Navigate } from "react-router-dom";
import useSearchParam from "react-use/lib/useSearchParam";

import { useAuthStore } from "../stores";
import { AUTHENTICATION_STATUSES } from "../constants";

/*
Wrapper for Routes which should be accessible only to a non-authenticated user
*/
export default function IfAuthRedirectGuard({ children }) {
  // store
  const isAuthenticated = useAuthStore(
    React.useCallback((s) => s.isAuthenticated, []),
  );

  const next = useSearchParam("next") || "/";

  if (isAuthenticated === AUTHENTICATION_STATUSES.TRUE) {
    return <Navigate replace to={next} />;
  }
  return children;
}

IfAuthRedirectGuard.propTypes = {
  children: PropTypes.node.isRequired,
};
