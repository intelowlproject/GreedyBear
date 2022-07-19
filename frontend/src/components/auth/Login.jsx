import React from "react";
import {
  FormGroup,
  Label,
  Container,
  Input,
  Button,
} from "reactstrap";

import { ContentSection } from "@certego/certego-ui";

function Login() {

  return (
    <ContentSection className="bg-body">
      <Container className="col-12 col-lg-8 col-xl-4">
        <ContentSection>
          <h3 className="fw-bold">Log In</h3>
          <hr />
            {/* Form */}
            <form>
                {/* username */}
                <FormGroup>
                  <Label for="LoginForm__username">Username</Label>
                  <Input
                    id="LoginForm__username"
                    type="text"
                    name="username"
                    placeholder="Enter username"
                    autoComplete="username"
                  />
                </FormGroup>
                {/* password */}
                <FormGroup>
                  <Label for="LoginForm__password">Password</Label>
                  <Input
                    id="LoginForm__password"
                    type="password"
                    name="password"
                    placeholder="Enter password"
                    autoComplete="current-password"
                  />
                </FormGroup>
                <div className="text-muted mb-3">
                  Don&apos;t have an account? Contact the administrator for
                  access.
                </div>
                {/* Submit */}
                <FormGroup className="d-flex-center">
                  <Button
                    type="submit"
                    color="primary"
                    outline
                   >
                    Login
                  </Button>
                </FormGroup>
            </form>
        </ContentSection>
      </Container>
    </ContentSection>
  );
}

export default Login;