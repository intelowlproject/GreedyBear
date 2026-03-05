import React from "react";
import { FormGroup, Input, Label } from "reactstrap";

export function usePasswordVisibility() {
  const [passwordShown, setPasswordShown] = React.useState(false);
  const toggleVisibility = React.useCallback(
    () => setPasswordShown((prev) => !prev),
    [],
  );
  const inputType = passwordShown ? "text" : "password";
  return { passwordShown, toggleVisibility, inputType };
}

export function ShowPasswordToggle({ id, passwordShown, onChange }) {
  return (
    <FormGroup check>
      <Input
        id={id}
        type="checkbox"
        checked={passwordShown}
        onChange={onChange}
      />
      <Label check htmlFor={id}>
        Show password
      </Label>
    </FormGroup>
  );
}
