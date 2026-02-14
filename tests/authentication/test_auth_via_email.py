from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import tag
from durin.models import AuthToken, Client
from rest_framework.reverse import reverse

from . import CustomOAuthTestCase

User = get_user_model()
login_uri = reverse("auth_login")
logout_uri = reverse("auth_logout")
register_uri = reverse("auth_register")
verify_email_uri = reverse("auth_verify-email")


@tag("api", "user")
class TestUserAuth(CustomOAuthTestCase):
    def __register_user(self, body: dict):
        response = self.client.post(register_uri, {**body}, format="json")
        content = response.json()
        msg = (response, content)

        # response assertions
        self.assertEqual(201, response.status_code, msg=msg)
        self.assertEqual(content["username"], body["username"], msg=msg)
        self.assertEqual(content["email"], body["email"], msg=msg)
        self.assertFalse(
            content["is_active"], msg="newly registered user must have is_active=False"
        )

    def setUp(self):
        # test data
        self.testregisteruser = {
            "email": "testregisteruser@test.com",
            "username": "testregisteruser",
            "first_name": "testregisteruser",
            "last_name": "testregisteruser",
            "password": "testregisteruser",
            "profile": {
                "company_name": "companytest",
                "company_role": "greedybear test",
                "twitter_handle": "@fake",
                "discover_from": "other",
            },
        }
        mail.outbox = []
        self.__register_user(body=self.testregisteruser)
        self.user = User.objects.get(username=self.testregisteruser["username"])

    def tearDown(self):  # skipcq: PYL-R0201
        # cache clear (for throttling)
        cache.clear()
        # db clean
        AuthToken.objects.all().delete()
        Client.objects.all().delete()

    def verify_user(self):
        # Verify user and mail
        email = self.user.email_addresses.first()
        email.is_verified = True
        self.user.is_active = True
        self.user.save()
        email.save()

    def test_login_via_mail(self):
        # Using email for login
        self.verify_user()
        password = self.testregisteruser["password"]
        body = {"username": self.user.email, "password": password}
        response = self.client.post(login_uri, body)
        cookies_data = response.cookies
        msg = (response, cookies_data)
        self.assertEqual(response.status_code, 200, msg=msg)
        self.assertIn("CERTEGO_SAAS_AUTH_TOKEN", cookies_data, msg=msg)

        self.assertEqual(AuthToken.objects.count(), 1)

    def test_unverified_login_via_email(self):
        # User unverified should fail
        password = self.testregisteruser["password"]
        body = {"username": self.user.email, "password": password}
        response = self.client.post(login_uri, body)
        cookies_data = response.cookies
        msg = (response, cookies_data)
        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertNotIn("CERTEGO_SAAS_AUTH_TOKEN", cookies_data, msg=msg)

        self.assertEqual(AuthToken.objects.count(), 0)

    def test_login_via_username(self):
        # Testing login via username
        self.verify_user()
        password = self.testregisteruser["password"]
        body = {"username": self.user.username, "password": password}
        response = self.client.post(login_uri, body)
        cookies_data = response.cookies
        msg = (response, cookies_data)
        self.assertEqual(response.status_code, 200, msg=msg)
        self.assertIn("CERTEGO_SAAS_AUTH_TOKEN", cookies_data, msg=msg)

        self.assertEqual(AuthToken.objects.count(), 1)
