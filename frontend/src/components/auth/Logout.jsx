import React from "react";



import { useAuthStore } from "../../stores";
import { AUTHENTICATION_STATUSES } from "../../constants";

export default function Logout() {
  // auth store
  const [isAuthenticated, logoutUser] = useAuthStore(
    React.useCallback((s) => [s.isAuthenticated, s.service.logoutUser], []),
  );

  React.useEffect(() => {
    if (isAuthenticated === AUTHENTICATION_STATUSES.TRUE) {
      logoutUser();
    }
  }, [isAuthenticated, logoutUser]);

  return <div>Logging you out...</div>;
}
