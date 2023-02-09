import React from "react";
import {
  UncontrolledDropdown,
  DropdownToggle,
  DropdownMenu,
  DropdownItem,
} from "reactstrap";
import { FiLogOut } from "react-icons/fi";
import { IoMdKey, IoMdSettings } from "react-icons/io";

import { UserBubble, DropdownNavLink } from "@certego/certego-ui";

import { useAuthStore } from "../../stores";

function UserMenu(props) {
  // auth store
  const [user, isSuperuser] = useAuthStore(
    React.useCallback((s) => [s.user, s.isSuperuser], [])
  );

  return (
    <UncontrolledDropdown nav inNavbar {...props}>
      <DropdownToggle nav className="text-center">
        <UserBubble size="sm" userInfo={user} />
      </DropdownToggle>
      <DropdownMenu end className="bg-dark" data-bs-popper>
        <DropdownItem text>
          logged in as <b>{`${user?.username}`}</b>
        </DropdownItem>
        <DropdownItem divider />
        {/* Django Admin Interface */}
        {isSuperuser && (
          <DropdownNavLink to="/admin/" target="_blank">
            <IoMdSettings className="me-2" /> Django Admin Interface
          </DropdownNavLink>
        )}
        {/* API Access/Sessions */}
        <DropdownNavLink to="/me/sessions">
          <IoMdKey className="me-2" /> API Access / Sessions
        </DropdownNavLink>
        <DropdownItem divider />
        {/* Logout */}
        <DropdownNavLink to="/logout">
          <FiLogOut className="me-2" /> Logout
        </DropdownNavLink>
      </DropdownMenu>
    </UncontrolledDropdown>
  );
}

export default UserMenu;
