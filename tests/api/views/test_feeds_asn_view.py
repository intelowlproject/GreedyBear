from django.utils import timezone
from rest_framework.test import APIClient

from greedybear.models import IOC, GeneralHoneypot
from tests import CustomTestCase


class FeedsASNViewTestCase(CustomTestCase):
    """Tests for ASN aggregated feeds API"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        IOC.objects.all().delete()
        cls.testpot1, _ = GeneralHoneypot.objects.get_or_create(name="testpot1", active=True)
        cls.testpot2, _ = GeneralHoneypot.objects.get_or_create(name="testpot2", active=True)

        cls.high_asn = "13335"
        cls.low_asn = "16276"

        cls.ioc_high1 = IOC.objects.create(
            name="high1.example.com",
            type="ip",
            asn=cls.high_asn,
            attack_count=15,
            interaction_count=30,
            login_attempts=5,
            first_seen=timezone.now() - timezone.timedelta(days=10),
            recurrence_probability=0.8,
            expected_interactions=20.0,
        )
        cls.ioc_high1.general_honeypot.add(cls.testpot1, cls.testpot2)
        cls.ioc_high1.save()

        cls.ioc_high2 = IOC.objects.create(
            name="high2.example.com",
            type="ip",
            asn=cls.high_asn,
            attack_count=5,
            interaction_count=10,
            login_attempts=2,
            first_seen=timezone.now() - timezone.timedelta(days=5),
            recurrence_probability=0.3,
            expected_interactions=8.0,
        )
        cls.ioc_high2.general_honeypot.add(cls.testpot1, cls.testpot2)
        cls.ioc_high2.save()

        cls.ioc_low = IOC.objects.create(
            name="low.example.com",
            type="ip",
            asn=cls.low_asn,
            attack_count=2,
            interaction_count=5,
            login_attempts=1,
            first_seen=timezone.now(),
            recurrence_probability=0.1,
            expected_interactions=3.0,
        )
        cls.ioc_low.general_honeypot.add(cls.testpot1, cls.testpot2)
        cls.ioc_low.save()

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        self.url = "/api/feeds/asn/"

    def _get_results(self, response):
        payload = response.json()
        self.assertIsInstance(payload, list)
        return payload

    def test_200_asn_feed_aggregated_fields(self):
        """Ensure aggregated fields are computed correctly per ASN using dynamic sums"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)

        # filtering high ASN
        high_item = next((item for item in results if str(item["asn"]) == self.high_asn), None)
        self.assertIsNotNone(high_item)

        # getting all IOCs for high ASN from the DB
        high_iocs = IOC.objects.filter(asn=self.high_asn)

        self.assertEqual(high_item["ioc_count"], high_iocs.count())
        self.assertEqual(high_item["total_attack_count"], sum(i.attack_count for i in high_iocs))
        self.assertEqual(high_item["total_interaction_count"], sum(i.interaction_count for i in high_iocs))
        self.assertEqual(high_item["total_login_attempts"], sum(i.login_attempts for i in high_iocs))
        self.assertAlmostEqual(high_item["expected_ioc_count"], sum(i.recurrence_probability for i in high_iocs))
        self.assertAlmostEqual(high_item["expected_interactions"], sum(i.expected_interactions for i in high_iocs))

        # validating first_seen / last_seen dynamically
        self.assertEqual(high_item["first_seen"], min(i.first_seen for i in high_iocs).isoformat())
        self.assertEqual(high_item["last_seen"], max(i.last_seen for i in high_iocs).isoformat())

        # validating honeypots dynamically
        expected_honeypots = sorted({hp.name for i in high_iocs for hp in i.general_honeypot.all()})
        self.assertEqual(sorted(high_item["honeypots"]), expected_honeypots)

    def test_200_asn_feed_default_ordering(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)

        # high_asn has ioc_count=2 > low_asn ioc_count=1
        self.assertEqual(str(results[0]["asn"]), self.high_asn)
        self.assertEqual(str(results[1]["asn"]), self.low_asn)

    def test_200_asn_feed_ordering_desc_ioc_count(self):
        response = self.client.get(self.url + "?ordering=-ioc_count")
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)

        self.assertEqual(str(results[0]["asn"]), self.high_asn)

    def test_200_asn_feed_ordering_asc_ioc_count(self):
        response = self.client.get(self.url + "?ordering=ioc_count")
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)
        self.assertEqual(str(results[0]["asn"]), self.low_asn)

    def test_200_asn_feed_ordering_desc_interaction_count(self):
        response = self.client.get(self.url + "?ordering=-total_interaction_count")
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)
        self.assertEqual(str(results[0]["asn"]), self.high_asn)

    def test_200_asn_feed_with_asn_filter(self):
        response = self.client.get(self.url + f"?asn={self.high_asn}")
        self.assertEqual(response.status_code, 200)

        results = self._get_results(response)
        self.assertEqual(len(results), 1)
        self.assertEqual(str(results[0]["asn"]), self.high_asn)

    def test_400_asn_feed_invalid_ordering_honeypots(self):
        response = self.client.get(self.url + "?ordering=honeypots")
        self.assertEqual(response.status_code, 400)
        data = response.json()
        errors_container = data.get("errors", data)
        error_list = errors_container.get("ordering", [])
        self.assertTrue(error_list)
        error_msg = error_list[0].lower()
        self.assertIn("honeypots", error_msg)
        self.assertIn("invalid", error_msg)

    def test_400_asn_feed_invalid_ordering_random(self):
        response = self.client.get(self.url + "?ordering=xyz123")
        self.assertEqual(response.status_code, 400)
        data = response.json()
        errors_container = data.get("errors", data)
        error_list = errors_container.get("ordering", [])
        self.assertTrue(error_list)
        error_msg = error_list[0].lower()
        self.assertIn("xyz123", error_msg)
        self.assertIn("invalid", error_msg)

    def test_400_asn_feed_invalid_ordering_model_field_not_in_agg(self):
        response = self.client.get(self.url + "?ordering=attack_count")
        self.assertEqual(response.status_code, 400)
        data = response.json()
        errors_container = data.get("errors", data)
        error_list = errors_container.get("ordering", [])
        self.assertTrue(error_list)
        error_msg = error_list[0].lower()
        self.assertIn("attack_count", error_msg)
        self.assertIn("invalid", error_msg)

    def test_400_asn_feed_ordering_empty_param(self):
        response = self.client.get(self.url + "?ordering=")
        self.assertEqual(response.status_code, 400)
        data = response.json()
        errors_container = data.get("errors", data)
        error_list = errors_container.get("ordering", [])
        self.assertTrue(error_list)
        error_msg = error_list[0].lower()
        self.assertIn("blank", error_msg)

    def test_asn_feed_ignores_feed_size(self):
        response = self.client.get(self.url + "?feed_size=1")
        results = response.json()
        # aggregation should return all ASNs regardless of feed_size
        self.assertEqual(len(results), 2)
