import React from "react";
import {
  FormGroup,
  Label,
  Container,
  Input,
  Spinner,
  Button,
  Row,
} from "reactstrap";
import { Form, Formik } from "formik";

import { ContentSection } from "@certego/certego-ui";

import { useAuthStore } from "../../stores";
import {
  ResendVerificationEmailButton,
  ForgotPasswordButton,
} from "./utils/registration-buttons";

// constants
const initialValues = {
  username: "",
  password: "",
};

// methods
const onValidate = (values) => {
  const errors = {};
  if (!values.username) {
    errors.username = "Required";
  }
  if (!values.password) {
    errors.password = "Required";
  }
  return errors;
};

// Component
function Login() {
  console.debug("Login rendered!");

  // local state
  const [passwordShown, setPasswordShown] = React.useState(false);

  // auth store
  const loginUser = useAuthStore(
    React.useCallback((s) => s.service.loginUser, [])
  );

  // callbacks
  const onSubmit = React.useCallback(
    async (values, _formik) => {
      try {
        await loginUser(values);
      } catch (e) {
        // handled inside loginUser
      }
    },
    [loginUser]
  );

  return (
    <ContentSection className="bg-body">
      <Container className="col-12 col-lg-8 col-xl-4">
        <ContentSection>
          <h3 className="fw-bold">Log In</h3>
          <hr />
          {/* Form */}
          <Formik
            initialValues={initialValues}
            validate={onValidate}
            onSubmit={onSubmit}
            validateOnChange
          >
            {(formik) => (
              <Form>
                {/* username */}
                <FormGroup>
                  <Label for="LoginForm__username">Username</Label>
                  <Input
                    id="LoginForm__username"
                    type="text"
                    name="username"
                    placeholder="Enter username"
                    autoComplete="username"
                    onChange={formik.handleChange}
                  />
                </FormGroup>
                {/* password */}
                <FormGroup>
                  <Label for="LoginForm__password">Password</Label>
                  <Input
                    id="LoginForm__password"
                    type={passwordShown ? "text" : "password"}
                    name="password"
                    placeholder="Enter password"
                    autoComplete="current-password"
                    onChange={formik.handleChange}
                  />
                </FormGroup>
                <FormGroup check>
                  <Input
                    id="LoginForm__showPassword"
                    type="checkbox"
                    defaultChecked={passwordShown}
                    onChange={() => setPasswordShown(!passwordShown)}
                  />
                  <Label check>Show password</Label>
                </FormGroup>
                {/* Submit */}
                <FormGroup className="d-flex-center">
                  <Button
                    type="submit"
                    disabled={!(formik.isValid || formik.isSubmitting)}
                    color="primary"
                    outline
                  >
                    {formik.isSubmitting && <Spinner size="sm" />} Login
                  </Button>
                </FormGroup>
              </Form>
            )}
          </Formik>
        </ContentSection>
        {/* popover buttons */}
        <Row className="d-flex flex-column align-items-end g-0">
          <ForgotPasswordButton />
          <ResendVerificationEmailButton />
        </Row>
      </Container>
    </ContentSection>
  );
}

export default Login;
