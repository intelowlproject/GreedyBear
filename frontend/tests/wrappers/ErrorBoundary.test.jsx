import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import ErrorBoundary from "../../src/wrappers/ErrorBoundary";

// A component that throws an error
const ThrowError = ({ shouldThrow }) => {
    if (shouldThrow) {
        throw new Error("Test error");
    }
    return <div>Component rendered successfully</div>;
};

describe("ErrorBoundary", () => {
    // Prevent console.error from cluttering the test output
    const originalError = console.error;
    beforeAll(() => {
        console.error = vi.fn();
    });
    afterAll(() => {
        console.error = originalError;
    });

    it("renders children when there is no error", () => {
        render(
            <ErrorBoundary>
                <ThrowError shouldThrow={false} />
            </ErrorBoundary>,
        );
        expect(screen.getByText("Component rendered successfully")).toBeInTheDocument();
    });

    it("renders fallback UI when there is an error", () => {
        render(
            <ErrorBoundary>
                <ThrowError shouldThrow={true} />
            </ErrorBoundary>,
        );
        expect(screen.getByText("Something went wrong.")).toBeInTheDocument();
        expect(
            screen.getByText(
                "An unexpected error occurred in this section of the application.",
            ),
        ).toBeInTheDocument();
        expect(screen.getByText("Reload Page")).toBeInTheDocument();
        expect(screen.getByText("Go to Home")).toBeInTheDocument();
    });

    it("calls console.error when an error is caught", () => {
        render(
            <ErrorBoundary>
                <ThrowError shouldThrow={true} />
            </ErrorBoundary>,
        );
        expect(console.error).toHaveBeenCalled();
    });
});
