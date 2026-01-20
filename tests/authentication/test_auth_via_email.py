# tests/authentication/test_authviaemail.py
from django.contrib.auth import get_user_model
from django.test import tag
from rest_framework import status
from rest_framework.reverse import reverse

from . import CustomOAuthTestCase  # Use the same base class as the reference test

User = get_user_model()


@tag("api", "user")
class TestLoginSerializer(CustomOAuthTestCase):
    def setUp(self):
        super().setUp()  # Call parent setUp if it exists

        # Generic test credentials
        self.username = "testuser"
        self.email = "testuser@example.com"
        self.password = "TestPass123!"

        # Create a user with email verified and approved
        self.user = User.objects.create_user(
            username=self.username,
            email=self.email,
            password=self.password,
            is_active=True,
        )

        # Handle email verification properly
        # Based on the reference test, this uses rest_email_auth
        if hasattr(self.user, "email_addresses"):
            email_obj = self.user.email_addresses.first()
            if email_obj:
                email_obj.is_verified = True
                email_obj.save()

        # Set approved if it's a field (not a property)
        if hasattr(User, "approved") and hasattr(self.user, "approved"):
            # Check if it's a field descriptor, not a property
            if not isinstance(getattr(User, "approved"), property):
                self.user.approved = True
                self.user.save()

        self.login_url = reverse("auth_login")  # Use reverse like the reference test

    def test_login_with_username(self):
        """Login works with username"""
        response = self.client.post(
            self.login_url,
            {"username": self.username, "password": self.password},
            format="json",
        )

        cookies_data = response.cookies
        msg = (response, cookies_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK, msg=msg)
        # Check for cookie-based auth like the reference test
        self.assertIn("CERTEGO_SAAS_AUTH_TOKEN", cookies_data, msg=msg)

    def test_login_with_email(self):
        """Login works with email"""
        response = self.client.post(
            self.login_url,
            {
                "username": self.email,  # The reference test shows username field accepts email
                "password": self.password,
            },
            format="json",
        )

        cookies_data = response.cookies
        msg = (response, cookies_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK, msg=msg)
        self.assertIn("CERTEGO_SAAS_AUTH_TOKEN", cookies_data, msg=msg)

    def test_login_wrong_password(self):
        """Login fails with wrong password"""
        response = self.client.post(
            self.login_url,
            {"username": self.username, "password": "WrongPassword"},
            format="json",
        )

        # Your application might return 200 with an error message instead of 400
        # Check what the actual behavior is and adjust accordingly
        self.assertNotEqual(response.status_code, status.HTTP_200_OK)

    def test_login_nonexistent_user(self):
        """Login fails for nonexistent username/email"""
        response = self.client.post(
            self.login_url,
            {"username": "nonexistent", "password": "password"},
            format="json",
        )

        # Your application might return 200 with an error message instead of 400
        # Check what the actual behavior is and adjust accordingly
        self.assertNotEqual(response.status_code, status.HTTP_200_OK)
