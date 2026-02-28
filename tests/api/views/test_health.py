from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework.test import APIClient

from greedybear.models import IOC, GeneralHoneypot
from tests import CustomTestCase

User = get_user_model()


class HealthViewTestCase(CustomTestCase):
    """Comprehensive tests for admin health/overview API"""

    @classmethod
    def setUpTestData(cls):
        # deleting all existing objects to have predictable test counts
        GeneralHoneypot.objects.all().delete()
        IOC.objects.all().delete()

        cls.superuser = User.objects.create_superuser(
            username="admin",
            email="admin@test.com",
            password="adminpass",
        )

        cls.testpot1 = GeneralHoneypot.objects.create(name="testpot1", active=True)
        cls.testpot2 = GeneralHoneypot.objects.create(name="testpot2", active=True)

        cls.ioc1 = IOC.objects.create(
            name="ioc1.example.com",
            type="ip",
            attack_count=5,
            interaction_count=10,
            login_attempts=2,
            first_seen=datetime.now() - timedelta(days=2),
        )
        cls.ioc1.general_honeypot.add(cls.testpot1, cls.testpot2)

        cls.ioc2 = IOC.objects.create(
            name="ioc2.example.com",
            type="ip",
            attack_count=2,
            interaction_count=5,
            login_attempts=1,
            first_seen=datetime.now() - timedelta(hours=5),
        )
        cls.ioc2.general_honeypot.add(cls.testpot1)

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        self.url = "/api/health/"

    def _get_payload(self, response):
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIsInstance(payload, dict)
        return payload

    # permission test
    def test_admin_can_access(self):
        response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertIn("system", payload)
        self.assertIn("overview", payload)

    def test_non_admin_cannot_access(self):
        user = User.objects.create_user(username="user", password="123")
        self.client.force_authenticate(user=user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_cannot_access(self):
        self.client.force_authenticate(user=None)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 401)

    # tetsing overview count
    def test_overview_counts_correct(self):
        response = self.client.get(self.url)
        payload = self._get_payload(response)
        overview = payload["overview"]

        self.assertEqual(overview["iocs"]["total"], 2)
        self.assertEqual(overview["iocs"]["new_last_24h"], 1)
        self.assertEqual(overview["honeypots"]["total"], 2)
        self.assertEqual(overview["honeypots"]["active"], 2)

    # db status checkup
    @patch("api.views.health.get_db_status", return_value="down")
    def test_database_down(self, mock_db):
        response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertEqual(payload["system"]["database"], "down")
        self.assertEqual(payload["overview"], {})

    @patch("api.views.health.get_observables_overview")
    def test_database_degraded(self, mock_observables):
        mock_observables.side_effect = Exception("Aggregation failed")
        response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertEqual(payload["system"]["database"], "degraded")

    @patch("api.views.health.get_observables_overview")
    @patch("api.views.health.get_db_status", return_value="up")
    def test_database_degraded_when_observables_fail(self, mock_db, mock_observables):
        """DB is up but aggregation fails → database should be 'degraded'."""
        mock_observables.side_effect = Exception("Aggregation failed")
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("system", payload)
        self.assertEqual(payload["system"]["database"], "degraded")
        self.assertEqual(payload["overview"], {})

    # elasticsearch status test
    @override_settings(ELASTIC_CLIENT=None)
    def test_elasticsearch_not_configured(self):
        response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertEqual(payload["system"]["elasticsearch"], "not configured")

    def test_elasticsearch_green(self):
        mock_client = MagicMock()
        mock_client.cluster.health.return_value = {"status": "green"}
        with override_settings(ELASTIC_CLIENT=mock_client):
            response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertEqual(payload["system"]["elasticsearch"], "up")

    def test_elasticsearch_yellow(self):
        mock_client = MagicMock()
        mock_client.cluster.health.return_value = {"status": "yellow"}
        with override_settings(ELASTIC_CLIENT=mock_client):
            response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertEqual(payload["system"]["elasticsearch"], "up")

    def test_elasticsearch_red(self):
        mock_client = MagicMock()
        mock_client.cluster.health.return_value = {"status": "red"}
        with override_settings(ELASTIC_CLIENT=mock_client):
            response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertEqual(payload["system"]["elasticsearch"], "down")

    def test_elasticsearch_exception(self):
        mock_client = MagicMock()
        mock_client.cluster.health.side_effect = Exception("ES failure")
        with override_settings(ELASTIC_CLIENT=mock_client):
            response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertEqual(payload["system"]["elasticsearch"], "down")

    # qcluster test
    @patch("api.views.health.get_job_stats")
    def test_qcluster_up(self, mock_jobs):
        mock_jobs.return_value = {
            "q_status": "up",
            "scheduled": 0,
            "failed_last_24h": 0,
            "successful_last_24h": 0,
        }
        response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertEqual(payload["system"]["qcluster"], "up")

    @patch("api.views.health.get_job_stats")
    def test_qcluster_idle(self, mock_jobs):
        mock_jobs.return_value = {
            "q_status": "idle",
            "scheduled": 5,
            "failed_last_24h": 0,
            "successful_last_24h": 0,
        }
        response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertEqual(payload["system"]["qcluster"], "idle")

    @patch("api.views.health.get_job_stats")
    def test_qcluster_down(self, mock_jobs):
        mock_jobs.return_value = {
            "q_status": "down",
            "scheduled": 0,
            "failed_last_24h": 0,
            "successful_last_24h": 0,
        }
        response = self.client.get(self.url)
        payload = self._get_payload(response)
        self.assertEqual(payload["system"]["qcluster"], "down")
