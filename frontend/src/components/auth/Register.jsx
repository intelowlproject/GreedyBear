import React from "react";
import {
  Container,
  Row,
  Col,
  FormGroup,
  Label,
  Spinner,
  Input,
  InputGroup,
  Button,
  InputGroupText,
} from "reactstrap";
import { Form, Formik } from "formik";
import useTitle from "react-use/lib/useTitle";

import { ContentSection, Select } from "@certego/certego-ui";

import {
  AfterRegistrationModalAlert,
  InviteOnlyAlert,
  ConfigurationModalAlert,
} from "./utils/registration-alert";
import { registerUser, checkConfiguration } from "./api";
import {
  EmailValidator,
  PasswordValidator,
  UserFieldsValidator,
  ProfileValidator,
  UsernameValidator,
  ComparePassword,
} from "./utils/validator";

// constants
const hearAboutUsChoices = [
  {
    label: "Other",
    value: "other",
  },
  {
    label: "Search Engine (Google, DuckDuckGo, etc.)",
    value: "search_engine",
  },
  {
    label: "Recommended by friend or colleague",
    value: "was_recommended",
  },
  {
    label: "Social media",
    value: "social_media",
  },
  {
    label: "Blog or Publication",
    value: "blog_or_publication",
  },
];

const INITIAL_VALUES = {
  first_name: "",
  last_name: "",
  email: "",
  username: "",
  password: "",
  confirmPassword: "",
  company_name: "",
  company_role: "",
  twitter_handle: "",
  discover_from: "other",
};

const REGISTRATION_FORM_STORAGE_KEY = "registrationForm";
const initialValues =
  JSON.parse(localStorage.getItem(REGISTRATION_FORM_STORAGE_KEY, "{}")) ||
  INITIAL_VALUES;

console.debug("initialValues", initialValues);

const onValidate = (values) => {
  const errors = {};

  // static text fields
  ["first_name", "last_name"].forEach((field) => {
    const userErrors = UserFieldsValidator(field, values[field]);
    if (userErrors[field]) {
      errors[field] = userErrors[field];
    }
  });

  // username
  const usernameErrors = UsernameValidator(values.username);
  if (usernameErrors.username) {
    errors.username = usernameErrors.username;
  }

  // email
  const emailErrors = EmailValidator(values.email);
  if (emailErrors.email) {
    errors.email = emailErrors.email;
  }

  // profile
  ["company_name", "company_role"].forEach((field) => {
    const profileErrors = ProfileValidator(field, values[field]);
    if (profileErrors[field]) {
      errors[field] = profileErrors[field];
    }
  });

  // store in localStorage so user doesn't have to fill all fields again
  localStorage.setItem(
    REGISTRATION_FORM_STORAGE_KEY,
    JSON.stringify({
      ...values,
      password: "",
      confirmPassword: "",
    })
  );
  Object.keys(initialValues).forEach((key) => {
    initialValues[key] = values[key];
  });

  // password fields
  const passwordErrors = PasswordValidator(values.password);
  if (passwordErrors.password) {
    errors.password = passwordErrors.password;
  }
  const confirmPasswordErrors = PasswordValidator(values.confirmPassword);
  if (confirmPasswordErrors.password) {
    errors.confirmPassword = confirmPasswordErrors.password;
  }
  const comparePasswordErrors = ComparePassword(
    values.password,
    values.confirmPassword
  );
  if (comparePasswordErrors.password) {
    errors.password = comparePasswordErrors.password;
  }
  if (comparePasswordErrors.confirmPassword) {
    errors.confirmPassword = comparePasswordErrors.confirmPassword;
  }

  // console.debug("Errors", errors);
  return errors;
};

// Component
export default function Register() {
  /* ATTENTION! The Register page has been temporarily disabled due to not proper Terms of Service */
  console.debug("Register rendered!");

  // page title
  useTitle("GreedyBear | Sign up", { restoreOnUnmount: true });

  // local state
  const [showAfterRegistrationModal, setShowAfterRegistrationModal] =
    React.useState(false);
  const [showConfigurationModal, setShowConfigurationModal] =
    React.useState(false);
  const [passwordShown, setPasswordShown] = React.useState(false);

  console.debug("showAfterRegistrationModal:", showAfterRegistrationModal);

  React.useEffect(() => {
    checkConfiguration({
      params: {
        page: "register",
      },
    }).catch((e) => {
      console.debug(e);
      setShowConfigurationModal(true);
    });
  }, []);

  console.debug("showConfigurationModal:", showConfigurationModal);

  // callbacks
  const onSubmit = React.useCallback(
    async (values) => {
      const reqBody = {
        first_name: values.first_name,
        last_name: values.last_name,
        username: values.username,
        email: values.email,
        password: values.password,
        profile: {
          company_name: values.company_name,
          company_role: values.company_role,
          twitter_handle: values.twitter_handle,
          discover_from: values.discover_from,
        },
      };
      try {
        await registerUser(reqBody);

        // deleted user data after successful registration
        localStorage.removeItem(REGISTRATION_FORM_STORAGE_KEY);
        Object.keys(INITIAL_VALUES).forEach((key) => {
          initialValues[key] = INITIAL_VALUES[key];
        });

        setShowAfterRegistrationModal(true);
      } catch (e) {
        // handled inside registerUser
      }
    },
    [setShowAfterRegistrationModal]
  );

  return (
    <ContentSection className="bg-body">
      {showConfigurationModal && (
        <ConfigurationModalAlert
          isOpen={showConfigurationModal}
          setIsOpen={setShowConfigurationModal}
          title="The Registration Feature has not been configured!"
        />
      )}
      {showAfterRegistrationModal && (
        <AfterRegistrationModalAlert
          isOpen={showAfterRegistrationModal}
          setIsOpen={setShowAfterRegistrationModal}
        />
      )}
      <Container fluid className="col-12">
        <Row className="g-0">
          <InviteOnlyAlert />
        </Row>
        <ContentSection className="col-12 col-lg-10 col-xl-5 mx-auto">
          <Row>
            <h3 className="font-weight-bold">Register</h3>
          </Row>
          <hr />
          {/* Form */}
          <Formik
            initialValues={initialValues}
            validate={onValidate}
            onSubmit={onSubmit}
            validateOnMount
          >
            {(formik) => (
              <Form>
                {/* Name */}
                <FormGroup row>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="RegisterForm__first_name"
                    >
                      First Name
                    </Label>
                    <Input
                      id="RegisterForm__first_name"
                      name="first_name"
                      type="text"
                      className="form-control"
                      placeholder="Jane"
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      value={formik.values.first_name}
                      valid={!formik.errors.first_name}
                      invalid={
                        formik.errors.first_name && formik.touched.first_name
                      }
                    />
                    {formik.touched.first_name && (
                      <small>{formik.errors.first_name}</small>
                    )}
                  </Col>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="RegisterForm__last_name"
                    >
                      Last Name
                    </Label>
                    <Input
                      id="RegisterForm__last_name"
                      name="last_name"
                      type="text"
                      className="form-control"
                      placeholder="Doe"
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      value={formik.values.last_name}
                      valid={!formik.errors.last_name}
                      invalid={
                        formik.errors.last_name && formik.touched.last_name
                      }
                    />
                    {formik.touched.last_name && (
                      <small>{formik.errors.last_name}</small>
                    )}
                  </Col>
                </FormGroup>
                {/* Email/Username */}
                <FormGroup row>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="RegisterForm__email"
                    >
                      Email
                    </Label>
                    <Input
                      id="RegisterForm__email"
                      name="email"
                      type="email"
                      className="form-control"
                      placeholder="jane@example.com"
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      value={formik.values.email}
                      valid={!formik.errors.email}
                      invalid={formik.errors.email && formik.touched.email}
                    />
                    {formik.touched.email && (
                      <small>{formik.errors.email}</small>
                    )}
                  </Col>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="RegisterForm__username"
                    >
                      Username
                    </Label>
                    <Input
                      id="RegisterForm__username"
                      name="username"
                      type="text"
                      className="form-control"
                      placeholder="janedoe"
                      autoComplete="username"
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      value={formik.values.username}
                      valid={!formik.errors.username}
                      invalid={
                        formik.errors.username && formik.touched.username
                      }
                    />
                    {formik.touched.username && (
                      <small>{formik.errors.username}</small>
                    )}
                  </Col>
                </FormGroup>
                {/* Password */}
                <FormGroup row>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="RegisterForm__password"
                    >
                      Password
                    </Label>
                    <Input
                      id="RegisterForm__password"
                      name="password"
                      type={passwordShown ? "text" : "password"}
                      className="form-control"
                      placeholder="Create a strong password..."
                      autoComplete="new-password"
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      valid={!formik.errors.password}
                      invalid={
                        formik.errors.password && formik.touched.password
                      }
                    />
                    {formik.touched.password && (
                      <small>{formik.errors.password}</small>
                    )}
                  </Col>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="RegisterForm__confirmPassword"
                    >
                      Confirm Password
                    </Label>
                    <Input
                      id="RegisterForm__confirmPassword"
                      name="confirmPassword"
                      type={passwordShown ? "text" : "password"}
                      className="form-control"
                      placeholder="Re-enter password"
                      autoComplete="new-password"
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      valid={!formik.errors.confirmPassword}
                      invalid={
                        formik.errors.confirmPassword &&
                        formik.touched.confirmPassword
                      }
                    />
                    {formik.touched.confirmPassword && (
                      <small>{formik.errors.confirmPassword}</small>
                    )}
                  </Col>
                </FormGroup>
                <FormGroup check>
                  <Input
                    id="RegisterForm__showPassword"
                    type="checkbox"
                    defaultChecked={passwordShown}
                    onChange={() => setPasswordShown(!passwordShown)}
                  />
                  <Label check>Show password</Label>
                </FormGroup>
                <Col sm={12} md={12} className="text-center standout alert">
                  We ask you to provide the following information to better
                  understand what you intend to use GreedyBear for
                </Col>
                {/* Extra fields */}
                <FormGroup row>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="RegisterForm__company_name"
                    >
                      Company/ Organization
                    </Label>
                    <Input
                      id="RegisterForm__company_name"
                      name="company_name"
                      type="text"
                      className="form-control"
                      placeholder="E Corp"
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      value={formik.values.company_name}
                      valid={!formik.errors.company_name}
                      invalid={
                        formik.errors.company_name &&
                        formik.touched.company_name
                      }
                    />
                    {formik.touched.company_name && (
                      <small>{formik.errors.company_name}</small>
                    )}
                  </Col>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="RegisterForm__company_role"
                    >
                      Role
                    </Label>
                    <Input
                      id="RegisterForm__company_role"
                      name="company_role"
                      type="text"
                      className="form-control"
                      placeholder="Researcher"
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      value={formik.values.company_role}
                      valid={!formik.errors.company_role}
                      invalid={
                        formik.errors.company_role &&
                        formik.touched.company_role
                      }
                    />
                    {formik.touched.company_role && (
                      <small>{formik.errors.company_role}</small>
                    )}
                  </Col>
                </FormGroup>
                <FormGroup row>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label"
                      htmlFor="RegisterForm__twitter_handle"
                    >
                      Twitter Handle (optional)
                    </Label>
                    <InputGroup>
                      <InputGroupText>@</InputGroupText>
                      <Input
                        id="RegisterForm__twitter_handle"
                        name="twitter_handle"
                        type="text"
                        className="form-control"
                        placeholder="greedybear"
                        onChange={formik.handleChange}
                        onBlur={formik.handleBlur}
                        value={formik.values.twitter_handle}
                        valid={
                          !formik.errors.twitter_handle &&
                          formik.touched.twitter_handle
                        }
                      />
                    </InputGroup>
                  </Col>
                  <Col sm={12} md={6}>
                    <Label
                      className="form-control-label required"
                      htmlFor="RegisterForm__discover_from"
                    >
                      How did you discover GreedyBear ?
                    </Label>
                    <Select
                      id="RegisterForm__discover_from"
                      name="discover_from"
                      choices={hearAboutUsChoices}
                      onChange={formik.handleChange}
                      onBlur={formik.handleBlur}
                      value={formik.values.discover_from}
                      valid={
                        !formik.errors.discover_from &&
                        formik.touched.discover_from
                      }
                    />
                  </Col>
                </FormGroup>
                {/* Submit */}
                <FormGroup className="mt-3 d-flex">
                  <Button
                    type="submit"
                    disabled={!(formik.isValid || formik.isSubmitting)}
                    color="primary"
                    outline
                    className="mx-auto"
                  >
                    {formik.isSubmitting && <Spinner size="sm" />} Register
                  </Button>
                </FormGroup>
              </Form>
            )}
          </Formik>
        </ContentSection>
      </Container>
    </ContentSection>
  );
}
