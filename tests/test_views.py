from api.views.utils import is_ip_address, is_sha256hash
from greedybear.consts import FEEDS_LICENSE
from greedybear.models import GeneralHoneypot, Statistics, viewType
from rest_framework.test import APIClient

from . import CustomTestCase


class EnrichmentViewTestCase(CustomTestCase):
    def setUp(self):
        # setup client
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_for_vaild_unregistered_ip(self):
        """Check for a valid IP that is unavaliable in DB"""
        response = self.client.get("/api/enrichment?query=192.168.0.1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], False)

    def test_for_invaild_unregistered_ip(self):
        """Check for a IP that Fails Regex Checks and is unavaliable in DB"""
        response = self.client.get("/api/enrichment?query=30.168.1.255.1")
        self.assertEqual(response.status_code, 400)

    def test_for_vaild_registered_ip(self):
        """Check for a valid IP that is avaliable in DB"""
        response = self.client.get("/api/enrichment?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], True)
        self.assertEqual(response.json()["ioc"]["name"], self.ioc.name)
        self.assertEqual(response.json()["ioc"]["type"], self.ioc.type)
        self.assertEqual(
            response.json()["ioc"]["first_seen"],
            self.ioc.first_seen.isoformat(sep="T", timespec="microseconds"),
        )
        self.assertEqual(
            response.json()["ioc"]["last_seen"],
            self.ioc.last_seen.isoformat(sep="T", timespec="microseconds"),
        )
        self.assertEqual(response.json()["ioc"]["number_of_days_seen"], self.ioc.number_of_days_seen)
        self.assertEqual(response.json()["ioc"]["attack_count"], self.ioc.attack_count)
        self.assertEqual(response.json()["ioc"]["log4j"], self.ioc.log4j)
        self.assertEqual(response.json()["ioc"]["cowrie"], self.ioc.cowrie)
        self.assertEqual(response.json()["ioc"]["general_honeypot"][0], self.heralding.name)  # FEEDS
        self.assertEqual(response.json()["ioc"]["general_honeypot"][1], self.ciscoasa.name)  # FEEDS
        self.assertEqual(response.json()["ioc"]["scanner"], self.ioc.scanner)
        self.assertEqual(response.json()["ioc"]["payload_request"], self.ioc.payload_request)
        self.assertEqual(response.json()["ioc"]["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(response.json()["ioc"]["expected_interactions"], self.ioc.expected_interactions)

    def test_for_invalid_authentication(self):
        """Check for a invalid authentication"""
        self.client.logout()
        response = self.client.get("/api/enrichment?query=140.246.171.141")
        self.assertEqual(response.status_code, 401)


class FeedsViewTestCase(CustomTestCase):
    def test_200_all_feeds(self):
        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["license"], FEEDS_LICENSE)
        self.assertEqual(response.json()["iocs"][0]["feed_type"], "log4j")
        self.assertEqual(response.json()["iocs"][0]["attack_count"], 1)
        self.assertEqual(response.json()["iocs"][0]["scanner"], True)
        self.assertEqual(response.json()["iocs"][0]["payload_request"], True)
        self.assertEqual(response.json()["iocs"][0]["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(response.json()["iocs"][0]["expected_interactions"], self.ioc.expected_interactions)

    def test_200_general_feeds(self):
        response = self.client.get("/api/feeds/heralding/all/recent.json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["license"], FEEDS_LICENSE)
        self.assertEqual(response.json()["iocs"][0]["feed_type"], "heralding")
        self.assertEqual(response.json()["iocs"][0]["attack_count"], 1)
        self.assertEqual(response.json()["iocs"][0]["scanner"], True)
        self.assertEqual(response.json()["iocs"][0]["payload_request"], True)
        self.assertEqual(response.json()["iocs"][0]["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(response.json()["iocs"][0]["expected_interactions"], self.ioc.expected_interactions)

    def test_200_feeds_scanner_exclusion(self):
        response = self.client.get("/api/feeds/heralding/all/recent.json?exclude_mass_scanners")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["license"], FEEDS_LICENSE)
        self.assertEqual(len(response.json()["iocs"]), 0)

    def test_400_feeds(self):
        response = self.client.get("/api/feeds/test/all/recent.json")
        self.assertEqual(response.status_code, 400)

    def test_200_feeds_pagination(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_scanner_exclusion(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&exclude_mass_scanners")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 0)

    def test_400_feeds_pagination(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=test&age=recent")
        self.assertEqual(response.status_code, 400)


class FeedsAdvancedViewTestCase(CustomTestCase):
    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_200_all_feeds(self):
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["license"], FEEDS_LICENSE)
        self.assertEqual(response.json()["iocs"][0]["feed_type"], "log4j")
        self.assertEqual(response.json()["iocs"][0]["attack_count"], 1)
        self.assertEqual(response.json()["iocs"][0]["scanner"], True)
        self.assertEqual(response.json()["iocs"][0]["payload_request"], True)
        self.assertEqual(response.json()["iocs"][0]["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(response.json()["iocs"][0]["expected_interactions"], self.ioc.expected_interactions)

    def test_200_general_feeds(self):
        response = self.client.get("/api/feeds/advanced/?feed_type=heralding")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["license"], FEEDS_LICENSE)
        self.assertEqual(response.json()["iocs"][0]["feed_type"], "heralding")
        self.assertEqual(response.json()["iocs"][0]["attack_count"], 1)
        self.assertEqual(response.json()["iocs"][0]["scanner"], True)
        self.assertEqual(response.json()["iocs"][0]["payload_request"], True)
        self.assertEqual(response.json()["iocs"][0]["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(response.json()["iocs"][0]["expected_interactions"], self.ioc.expected_interactions)

    def test_400_feeds(self):
        response = self.client.get("/api/feeds/advanced/?attack_type=test")
        self.assertEqual(response.status_code, 400)

    def test_200_feeds_pagination(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_400_feeds_pagination(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&attack_type=test")
        self.assertEqual(response.status_code, 400)


class StatisticsViewTestCase(CustomTestCase):
    @classmethod
    def setUpClass(self):
        super(StatisticsViewTestCase, self).setUpClass()
        Statistics.objects.all().delete()
        Statistics.objects.create(source="140.246.171.141", view=viewType.FEEDS_VIEW.value)
        Statistics.objects.create(source="140.246.171.141", view=viewType.ENRICHMENT_VIEW.value)

    @classmethod
    def tearDownClass(self):
        super(StatisticsViewTestCase, self).tearDownClass()
        Statistics.objects.all().delete()

    def test_200_feeds_sources(self):
        response = self.client.get("/api/statistics/sources/feeds")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Sources"], 1)

    def test_200_feeds_downloads(self):
        response = self.client.get("/api/statistics/downloads/feeds")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Downloads"], 1)

    def test_200_enrichment_sources(self):
        response = self.client.get("/api/statistics/sources/enrichment")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Sources"], 1)

    def test_200_enrichment_requests(self):
        response = self.client.get("/api/statistics/requests/enrichment")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Requests"], 1)

    def test_200_feed_types(self):
        self.assertEqual(GeneralHoneypot.objects.count(), 2)
        # add a general honeypot without associated ioc
        GeneralHoneypot(name="Tanner", active=True).save()
        self.assertEqual(GeneralHoneypot.objects.count(), 3)

        response = self.client.get("/api/statistics/feeds_types")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Heralding"], 1)
        self.assertEqual(response.json()[0]["Ciscoasa"], 1)
        self.assertEqual(response.json()[0]["Log4j"], 1)
        self.assertEqual(response.json()[0]["Cowrie"], 1)
        self.assertEqual(response.json()[0]["Tanner"], 0)


class GeneralHoneypotViewTestCase(CustomTestCase):
    def test_200_all_general_honeypots(self):
        self.assertEqual(GeneralHoneypot.objects.count(), 2)
        # add a general honeypot not active
        GeneralHoneypot(name="Adbhoney", active=False).save()
        self.assertEqual(GeneralHoneypot.objects.count(), 3)

        response = self.client.get("/api/general_honeypot")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), ["Heralding", "Ciscoasa", "Adbhoney"])

    def test_200_active_general_honeypots(self):
        self.assertEqual(GeneralHoneypot.objects.count(), 2)
        response = self.client.get("/api/general_honeypot?onlyActive=true")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), ["Heralding", "Ciscoasa"])


class CommandSequenceViewTestCase(CustomTestCase):
    """Test cases for the command_sequence_view."""

    def setUp(self):
        # setup client
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_missing_query_parameter(self):
        """Test that view returns BadRequest when query parameter is missing."""
        response = self.client.get("/api/command_sequence")
        self.assertEqual(response.status_code, 400)

    def test_invalid_query_parameter(self):
        """Test that view returns BadRequest when query parameter is invalid."""
        response = self.client.get("/api/command_sequence?query=invalid-input}")
        self.assertEqual(response.status_code, 400)

    def test_ip_address_query(self):
        """Test view with a valid IP address query."""
        response = self.client.get("/api/command_sequence?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("executed_commands", response.data)
        self.assertIn("executed_by", response.data)

    def test_ip_address_query_with_similar(self):
        """Test view with a valid IP address query including similar sequences."""
        response = self.client.get("/api/command_sequence?query=140.246.171.141&include_similar")
        self.assertEqual(response.status_code, 200)
        self.assertIn("executed_commands", response.data)
        self.assertIn("executed_by", response.data)

    def test_nonexistent_ip_address(self):
        """Test that view returns 404 for IP with no sequences."""
        response = self.client.get("/api/command_sequence?query=10.0.0.1")
        self.assertEqual(response.status_code, 404)

    def test_hash_query(self):
        """Test view with a valid hash query."""
        response = self.client.get(f"/api/command_sequence?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("commands", response.data)
        self.assertIn("iocs", response.data)

    def test_hash_query_with_similar(self):
        """Test view with a valid hash query including similar sequences."""
        response = self.client.get(f"/api/command_sequence?query={self.hash}&include_similar")
        self.assertEqual(response.status_code, 200)
        self.assertIn("commands", response.data)
        self.assertIn("iocs", response.data)

    def test_nonexistent_hash(self):
        """Test that view returns 404 for nonexistent hash."""
        response = self.client.get(f"/api/command_sequence?query={'f' * 64}")
        self.assertEqual(response.status_code, 404)


class ValidationHelpersTestCase(CustomTestCase):
    """Test cases for the validation helper functions."""

    def test_is_ip_address_valid_ipv4(self):
        """Test that is_ip_address returns True for valid IPv4 addresses."""
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("10.0.0.1"))
        self.assertTrue(is_ip_address("127.0.0.1"))

    def test_is_ip_address_valid_ipv6(self):
        """Test that is_ip_address returns True for valid IPv6 addresses."""
        self.assertTrue(is_ip_address("::1"))
        self.assertTrue(is_ip_address("2001:db8::1"))
        self.assertTrue(is_ip_address("fe80::1ff:fe23:4567:890a"))

    def test_is_ip_address_invalid(self):
        """Test that is_ip_address returns False for invalid IP addresses."""
        self.assertFalse(is_ip_address("not-an-ip"))
        self.assertFalse(is_ip_address("256.256.256.256"))
        self.assertFalse(is_ip_address("192.168.0"))
        self.assertFalse(is_ip_address("2001:xyz::1"))

    def test_is_sha256hash_valid(self):
        """Test that is_sha256hash returns True for valid SHA-256 hashes."""
        self.assertTrue(is_sha256hash("a" * 64))
        self.assertTrue(is_sha256hash("1234567890abcdef" * 4))
        self.assertTrue(is_sha256hash("A" * 64))

    def test_is_sha256hash_invalid(self):
        """Test that is_sha256hash returns False for invalid SHA-256 hashes."""
        self.assertFalse(is_sha256hash("a" * 63))  # Too short
        self.assertFalse(is_sha256hash("a" * 65))  # Too long
        self.assertFalse(is_sha256hash("z" * 64))  # Invalid chars
        self.assertFalse(is_sha256hash("not-a-hash"))
