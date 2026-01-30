import React from "react";
import { FormGroup, Label, Input, Button, Spinner } from "reactstrap";
import { Form, Formik } from "formik";
import { ContentSection } from "@certego/certego-ui";
import { changePassword } from "./api";
import { PasswordValidator, ComparePassword } from "./utils/validator";

const initialValues = {
    old_password: "",
    new_password: "",
    confirmNewPassword: "",
};

const onValidate = (values) => {
    const errors = {};
    if (!values.old_password) {
        errors.old_password = "Required";
    }
    const passwordErrors = PasswordValidator(values.new_password);
    if (passwordErrors.password) {
        errors.new_password = passwordErrors.password;
    }
    const comparePasswordErrors = ComparePassword(
        values.new_password,
        values.confirmNewPassword
    );
    if (comparePasswordErrors.password) {
        errors.new_password = comparePasswordErrors.password;
    }
    if (comparePasswordErrors.confirmPassword) {
        errors.confirmNewPassword = comparePasswordErrors.confirmPassword;
    }
    return errors;
};

export default function ChangePassword() {
    const [passwordShown, setPasswordShown] = React.useState(false);

    const onSubmit = React.useCallback(async (values, { setSubmitting, resetForm, setErrors }) => {
        try {
            await changePassword(values);
            resetForm();
        } catch (err) {
            if (err.error) {
                // Backend sent a specific error message
                setErrors({ submit: err.error });
            } else if (err.new_password) {
                setErrors({ new_password: err.new_password });
            } else if (err.confirmNewPassword) {
                setErrors({ confirmNewPassword: err.confirmNewPassword });
            } else if (err.old_password) {
                setErrors({ old_password: err.old_password });
            }
            else {
                // Fallback
                setErrors({ submit: "Password change failed. Please check your inputs." });
            }
        } finally {
            setSubmitting(false);
        }
    }, []);

    return (
        <ContentSection className="bg-body">
            <ContentSection className="col-lg-6 mx-auto">
                <h3 className="font-weight-bold">Change Password</h3>
                <hr />
                <Formik
                    initialValues={initialValues}
                    validate={onValidate}
                    onSubmit={onSubmit}
                >
                    {(formik) => (
                        <Form>
                            {formik.errors.submit && (
                                <div className="alert alert-danger" role="alert">
                                    {formik.errors.submit}
                                </div>
                            )}
                            <FormGroup>
                                <Label className="required">Old Password</Label>
                                <Input
                                    name="old_password"
                                    type={passwordShown ? "text" : "password"}
                                    onChange={formik.handleChange}
                                    onBlur={formik.handleBlur}
                                    value={formik.values.old_password}
                                    valid={formik.touched.old_password && !formik.errors.old_password}
                                    invalid={formik.touched.old_password && !!formik.errors.old_password}
                                />
                                {formik.touched.old_password && <small className="text-danger">{formik.errors.old_password}</small>}
                            </FormGroup>

                            <FormGroup>
                                <Label className="required">New Password</Label>
                                <Input
                                    name="new_password"
                                    type={passwordShown ? "text" : "password"}
                                    onChange={formik.handleChange}
                                    onBlur={formik.handleBlur}
                                    value={formik.values.new_password}
                                    valid={formik.touched.new_password && !formik.errors.new_password}
                                    invalid={formik.touched.new_password && !!formik.errors.new_password}
                                />
                                {formik.touched.new_password && <small className="text-danger">{formik.errors.new_password}</small>}
                            </FormGroup>

                            <FormGroup>
                                <Label className="required">Confirm New Password</Label>
                                <Input
                                    name="confirmNewPassword"
                                    type={passwordShown ? "text" : "password"}
                                    onChange={formik.handleChange}
                                    onBlur={formik.handleBlur}
                                    value={formik.values.confirmNewPassword}
                                    valid={formik.touched.confirmNewPassword && !formik.errors.confirmNewPassword}
                                    invalid={formik.touched.confirmNewPassword && !!formik.errors.confirmNewPassword}
                                />
                                {formik.touched.confirmNewPassword && <small className="text-danger">{formik.errors.confirmNewPassword}</small>}
                            </FormGroup>

                            <FormGroup check>
                                <Input
                                    type="checkbox"
                                    checked={passwordShown}
                                    onChange={() => setPasswordShown(!passwordShown)}
                                />
                                <Label check>Show password</Label>
                            </FormGroup>

                            <Button
                                type="submit"
                                color="primary"
                                disabled={formik.isSubmitting || !formik.isValid}
                                className="mt-3"
                            >
                                {formik.isSubmitting && <Spinner size="sm" />} Change Password
                            </Button>
                        </Form>
                    )}
                </Formik>
            </ContentSection>
        </ContentSection>
    );
}
