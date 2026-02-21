from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from greedybear.models import IOC, GeneralHoneypot
from tests import CustomTestCase

User = get_user_model()


class HealthViewTestCase(CustomTestCase):
    """Tests for admin health/overview API"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        IOC.objects.all().delete()
        GeneralHoneypot.objects.all().delete()

        cls.testpot1, _ = GeneralHoneypot.objects.get_or_create(name="testpot1", active=True)
        cls.testpot2, _ = GeneralHoneypot.objects.get_or_create(name="testpot2", active=True)

        cls.ioc1 = IOC.objects.create(
            name="ioc1.example.com",
            type="ip",
            attack_count=5,
            interaction_count=10,
            login_attempts=2,
            first_seen=timezone.now() - timezone.timedelta(days=2),
        )
        cls.ioc1.general_honeypot.add(cls.testpot1, cls.testpot2)
        cls.ioc1.save()

        cls.ioc2 = IOC.objects.create(
            name="ioc2.example.com",
            type="ip",
            attack_count=2,
            interaction_count=5,
            login_attempts=1,
            first_seen=timezone.now() - timezone.timedelta(days=1),
        )
        cls.ioc2.general_honeypot.add(cls.testpot1)
        cls.ioc2.save()

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        self.url = "/api/health/overview/"

    def _get_payload(self, response):
        payload = response.json()
        self.assertIsInstance(payload, dict)
        return payload

    def test_admin_can_access_health_endpoint(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        payload = self._get_payload(response)

        self.assertIn("system", payload)
        self.assertIn("overview", payload)
        self.assertIn("database", payload["system"])
        self.assertIn("qcluster", payload["system"])
        self.assertIn("elasticsearch", payload["system"])
        self.assertIn("uptime_seconds", payload["system"])

    def test_non_admin_cannot_access(self):
        user = User.objects.create_user(username="user", password="123")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_cannot_access(self):
        self.client.force_authenticate(user=None)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 401)

    def test_overview_contains_ioc_and_honeypot_counts(self):
        response = self.client.get(self.url)
        payload = self._get_payload(response)

        overview = payload["overview"]
        self.assertEqual(overview["iocs"]["total"], 2)
        self.assertEqual(overview["honeypots"]["total"], 2)
        self.assertEqual(overview["honeypots"]["active"], 2)
