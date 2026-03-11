import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  ShowPasswordToggle,
  usePasswordVisibility,
} from "../../../src/components/common/ShowPasswordToggle";

// Helper component to test the hook
function TestHookConsumer() {
  const { passwordShown, toggleVisibility, inputType } =
    usePasswordVisibility();
  return (
    <div>
      <input data-testid="pw-input" type={inputType} />
      <ShowPasswordToggle
        id="test-toggle"
        passwordShown={passwordShown}
        onChange={toggleVisibility}
      />
      <span data-testid="shown-state">{String(passwordShown)}</span>
    </div>
  );
}

describe("ShowPasswordToggle", () => {
  test("renders checkbox with 'Show password' label", () => {
    render(
      <ShowPasswordToggle
        id="test-toggle"
        passwordShown={false}
        onChange={() => {}}
      />,
    );

    const checkbox = screen.getByLabelText("Show password");
    expect(checkbox).toBeInTheDocument();
    expect(checkbox).toHaveAttribute("type", "checkbox");
    expect(checkbox).not.toBeChecked();
  });

  test("renders as checked when passwordShown is true", () => {
    render(
      <ShowPasswordToggle
        id="test-toggle"
        passwordShown={true}
        onChange={() => {}}
      />,
    );

    expect(screen.getByLabelText("Show password")).toBeChecked();
  });

  test("calls onChange when clicked", async () => {
    const handleChange = vi.fn();
    const user = userEvent.setup();

    render(
      <ShowPasswordToggle
        id="test-toggle"
        passwordShown={false}
        onChange={handleChange}
      />,
    );

    await user.click(screen.getByLabelText("Show password"));
    expect(handleChange).toHaveBeenCalledTimes(1);
  });

  test("links label to checkbox via htmlFor/id", () => {
    render(
      <ShowPasswordToggle
        id="my-toggle"
        passwordShown={false}
        onChange={() => {}}
      />,
    );

    const checkbox = screen.getByLabelText("Show password");
    expect(checkbox).toHaveAttribute("id", "my-toggle");
  });
});

describe("usePasswordVisibility", () => {
  test("starts with password hidden", () => {
    render(<TestHookConsumer />);

    expect(screen.getByTestId("shown-state")).toHaveTextContent("false");
    expect(screen.getByTestId("pw-input")).toHaveAttribute("type", "password");
  });

  test("toggles to text on click, back to password on second click", async () => {
    const user = userEvent.setup();
    render(<TestHookConsumer />);

    const toggle = screen.getByLabelText("Show password");

    await user.click(toggle);
    expect(screen.getByTestId("shown-state")).toHaveTextContent("true");
    expect(screen.getByTestId("pw-input")).toHaveAttribute("type", "text");

    await user.click(toggle);
    expect(screen.getByTestId("shown-state")).toHaveTextContent("false");
    expect(screen.getByTestId("pw-input")).toHaveAttribute("type", "password");
  });
});
