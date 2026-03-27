import React from "react";
import {
  Dropdown,
  DropdownToggle,
  DropdownMenu,
  DropdownItem,
} from "reactstrap";

export function MultiSelectDropdown({
  options,
  value = [],
  onChange,
  placeholder = "All",
  id,
}) {
  const [isOpen, setIsOpen] = React.useState(false);

  const displayLabel =
    value.length === 0
      ? placeholder
      : value.length === 1
        ? value[0].label
        : `${value.length} selected`;

  return (
    <Dropdown
      isOpen={isOpen}
      toggle={() => setIsOpen((o) => !o)}
      className="w-100"
    >
      <DropdownToggle
        id={id}
        tag="button"
        type="button"
        className="form-select text-start w-100"
      >
        <span className={value.length === 0 ? "text-muted" : ""}>
          {displayLabel}
        </span>
      </DropdownToggle>
      <DropdownMenu className="w-100 bg-dark">
        {options.map((opt) => {
          const isSelected = value.some((v) => v.value === opt.value);
          return (
            <DropdownItem
              key={opt.value}
              toggle={false}
              onClick={() =>
                onChange(
                  isSelected
                    ? value.filter((v) => v.value !== opt.value)
                    : [...value, opt],
                )
              }
            >
              <input
                type="checkbox"
                checked={isSelected}
                readOnly
                className="me-2"
                aria-label={opt.label}
              />
              {opt.label}
            </DropdownItem>
          );
        })}
      </DropdownMenu>
    </Dropdown>
  );
}
