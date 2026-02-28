from datetime import datetime, timedelta

from rest_framework.test import APIClient

from greedybear.models import IOC, IocType
from tests import CustomTestCase


class FeedsEnhancementsTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

        # Use unique values to avoid collision with CustomTestCase defaults
        self.ioc.asn = 11111
        self.ioc.destination_ports = [9001, 9002]
        self.ioc.recurrence_probability = 0.8
        self.ioc.save()

        # Create a second IOC for filtering contrast
        self.ioc2 = IOC.objects.create(
            name="10.0.0.50",
            type=IocType.IP.value,
            days_seen=[datetime.now()],
            number_of_days_seen=1,
            scanner=True,
            payload_request=True,
            related_urls=[],
            first_seen=datetime.now() - timedelta(days=1),
            last_seen=datetime.now(),
            recurrence_probability=0.2,
            asn=22222,
            destination_ports=[9003],
            attack_count=1,
            interaction_count=1,
            login_attempts=0,
        )
        self.ioc2.general_honeypot.add(self.cowrie_hp)
        self.ioc2.save()

    def test_filter_by_asn(self):
        """Test filtering feeds by ASN."""
        response = self.client.get("/api/feeds/advanced/?asn=11111")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["value"], self.ioc.name)
        self.assertEqual(iocs[0]["asn"], 11111)

    def test_filter_by_min_score(self):
        """Test filtering by minimum recurrence_probability (score)."""
        # Should return only the high-score IOC (0.8 >= 0.5)
        # Note: Filtering also implicitly includes CustomTestCase IOCs if they match,
        # but we look for our specific ones.
        # But we can combine filters to be safe, or just check inclusion.
        response = self.client.get("/api/feeds/advanced/?min_score=0.5")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        # self.ioc (0.8) should be there. ioc2 (0.2) should not.
        values = [i["value"] for i in iocs]
        self.assertIn(self.ioc.name, values)
        self.assertNotIn(self.ioc2.name, values)

    def test_filter_by_port(self):
        """Test filtering by destination port."""
        # Port 9001 -> Only IOC 1
        response = self.client.get("/api/feeds/advanced/?port=9001")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["value"], self.ioc.name)

        # Port 9003 -> Only IOC 2
        response = self.client.get("/api/feeds/advanced/?port=9003")
        self.assertEqual(len(response.json()["iocs"]), 1)
        self.assertEqual(response.json()["iocs"][0]["value"], self.ioc2.name)

    def test_filter_by_date_range(self):
        """Test filtering by date range."""
        today = datetime.now().strftime("%Y-%m-%d")
        tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")

        # Range covering today (inclusive of time) requires end_date to be tomorrow
        # because defaults interpretation might exclude current time if end_date=today (00:00).
        response = self.client.get(f"/api/feeds/advanced/?start_date={today}&end_date={tomorrow}")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.json()["iocs"]), 1, f"Response: {response.json()}")

        # Future range -> Should return nothing
        future_start = (datetime.now() + timedelta(days=2)).strftime("%Y-%m-%d")
        response = self.client.get(f"/api/feeds/advanced/?start_date={future_start}")
        self.assertEqual(response.json()["iocs"], [])

    def test_stix_21_export(self):
        """Test STIX 2.1 export format."""
        response = self.client.get("/api/feeds/advanced/?format_=stix21")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["type"], "bundle")
        self.assertEqual(data["objects"][0]["type"], "indicator")
        self.assertEqual(data["objects"][0]["spec_version"], "2.1")
        # Check if patterns are correct
        patterns = [obj["pattern"] for obj in data["objects"]]
        self.assertIn(f"[ipv4-addr:value = '{self.ioc.name}']", patterns)

    def test_shareable_feeds_flow(self):
        """Test the full flow of generating and consuming a shareable feed."""
        # 1. Generate Link
        share_response = self.client.get("/api/feeds/share?asn=11111&port=9001")
        self.assertEqual(share_response.status_code, 200)
        share_url = share_response.json()["url"]
        self.assertIn("/api/feeds/consume/", share_url)

        token = share_url.split("/")[-1]

        # 2. Consume Link (Unauthenticated)
        self.client.logout()
        consume_response = self.client.get(f"/api/feeds/consume/{token}")
        self.assertEqual(consume_response.status_code, 200)

        iocs = consume_response.json()["iocs"]
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["value"], self.ioc.name)
        self.assertEqual(iocs[0]["asn"], 11111)

    def test_shareable_feed_invalid_token(self):
        """Test consuming with an invalid token."""
        self.client.logout()
        response = self.client.get("/api/feeds/consume/invalid-token-123")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "Invalid or expired token")
