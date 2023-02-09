import React from "react";
import { Link } from "react-router-dom";
import { Container } from "reactstrap";

function NotFoundPage() {
  console.debug("NotFoundPage rendered!");

  return (
    <Container className="d-flex flex-column center">
      <h2> Page not found </h2>
      <br />
      <Link to="/" className="standout">
        Go back to Home Page?
      </Link>
      <br />
    </Container>
  );
}

export default NotFoundPage;
