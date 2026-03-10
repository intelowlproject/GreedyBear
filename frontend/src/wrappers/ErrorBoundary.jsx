import React from "react";
import PropTypes from "prop-types";
import { Container, Button } from "reactstrap";

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    // Update state so the next render will show the fallback UI.
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    // You can also log the error to an error reporting service
    console.error("ErrorBoundary caught an error", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      // You can render any custom fallback UI
      return (
        <Container className="d-flex flex-column align-items-center mt-5 text-center">
          <h2 className="mb-4">Something went wrong.</h2>
          <p className="text-muted">
            An unexpected error occurred in this section of the application.
          </p>
          <div className="mt-3">
            <Button
              color="primary"
              onClick={() => window.location.reload()}
              className="me-2"
            >
              Reload Page
            </Button>
            <Button
              color="secondary"
              outline
              onClick={() => (window.location.href = "/")}
            >
              Go to Home
            </Button>
          </div>
        </Container>
      );
    }

    return this.props.children;
  }
}

ErrorBoundary.propTypes = {
  children: PropTypes.node.isRequired,
};

export default ErrorBoundary;
