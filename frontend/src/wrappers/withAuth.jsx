import React from "react";

import { useAuthStore } from "../stores";

/**
 * Higher Order Component (HoC)
 */
 function withAuth(WrappedComponent) {
    function AuthenticatedComponent(props) {
      // stores
      const [isAuthenticated, isAuth, fetchUserAccess] = useAuthStore(
        React.useCallback(
          (s) => [s.isAuthenticated, s.isAuth, s.service.fetchUserAccess],
          []
        )
      );
    
      React.useEffect(isAuth, [isAuth]);

      React.useEffect(() => {
        if (isAuthenticated) {
          fetchUserAccess();
        }
      }, [isAuthenticated, fetchUserAccess]); // onAuthStateChange
  
      return <WrappedComponent {...props} />;
    }
    return AuthenticatedComponent;
  }
  
  export default withAuth;
  