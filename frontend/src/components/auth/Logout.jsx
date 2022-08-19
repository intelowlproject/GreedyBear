import React from "react";

import { FallBackLoading } from "@certego/certego-ui";

import { useAuthStore } from "../../stores";

export default function Logout() {

  // auth store
  const [loading, logoutUser] = useAuthStore(
    React.useCallback((s) => [s.loading, s.service.logoutUser], [])
  );

  console.log(loading)

  React.useEffect(() => {

    console.log(loading)
    
    if (!loading) {
      logoutUser();
    }
  }, [loading, logoutUser]);

  return <FallBackLoading text="Logging you out..." />;
}
