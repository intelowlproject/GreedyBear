from unittest.mock import MagicMock, patch

import requests
from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from api.views.utils import BLOG_BASE_URL, CACHE_KEY_GREEDYBEAR_NEWS, MAX_FILES_TO_CHECK, is_ip_address, is_sha256hash
from greedybear.models import IOC, GeneralHoneypot, Statistics, ViewType

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
        # Honeypots are now via M2M relationship (serialized as list of strings)
        honeypot_names = response.json()["ioc"]["general_honeypot"]
        self.assertIn(self.heralding.name, honeypot_names)
        self.assertIn(self.ciscoasa.name, honeypot_names)
        self.assertIn(self.cowrie_hp.name, honeypot_names)
        self.assertIn(self.log4pot_hp.name, honeypot_names)
        self.assertEqual(response.json()["ioc"]["scanner"], self.ioc.scanner)
        self.assertEqual(response.json()["ioc"]["payload_request"], self.ioc.payload_request)
        self.assertEqual(
            response.json()["ioc"]["recurrence_probability"],
            self.ioc.recurrence_probability,
        )
        self.assertEqual(
            response.json()["ioc"]["expected_interactions"],
            self.ioc.expected_interactions,
        )

    def test_for_invalid_authentication(self):
        """Check for a invalid authentication"""
        self.client.logout()
        response = self.client.get("/api/enrichment?query=140.246.171.141")
        self.assertEqual(response.status_code, 401)


class FeedsViewTestCase(CustomTestCase):
    def test_200_log4pot_feeds(self):
        response = self.client.get("/api/feeds/log4pot/all/recent.json")
        self.assertEqual(response.status_code, 200)
        if settings.FEEDS_LICENSE:
            self.assertEqual(response.json()["license"], settings.FEEDS_LICENSE)
        else:
            self.assertNotIn("license", response.json())

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        # feed_type now derived from general_honeypot M2M
        self.assertIn("log4pot", target_ioc["feed_type"])
        self.assertIn("cowrie", target_ioc["feed_type"])
        self.assertIn("heralding", target_ioc["feed_type"])
        self.assertIn("ciscoasa", target_ioc["feed_type"])
        self.assertEqual(target_ioc["attack_count"], 1)
        self.assertEqual(target_ioc["scanner"], True)
        self.assertEqual(target_ioc["payload_request"], True)
        self.assertEqual(target_ioc["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(target_ioc["expected_interactions"], self.ioc.expected_interactions)

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_200_all_feeds_with_license(self):
        """Test feeds endpoint when FEEDS_LICENSE is populated"""
        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.json())
        self.assertEqual(response.json()["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_200_all_feeds_without_license(self):
        """Test feeds endpoint when FEEDS_LICENSE is empty"""
        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.json())

    def test_200_general_feeds(self):
        response = self.client.get("/api/feeds/heralding/all/recent.json")
        self.assertEqual(response.status_code, 200)
        if settings.FEEDS_LICENSE:
            self.assertEqual(response.json()["license"], settings.FEEDS_LICENSE)
        else:
            self.assertNotIn("license", response.json())

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        self.assertEqual(set(target_ioc["feed_type"]), {"log4pot", "cowrie", "heralding", "ciscoasa"})
        self.assertEqual(target_ioc["attack_count"], 1)
        self.assertEqual(target_ioc["scanner"], True)
        self.assertEqual(target_ioc["payload_request"], True)
        self.assertEqual(target_ioc["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(target_ioc["expected_interactions"], self.ioc.expected_interactions)

    def test_200_feeds_scanner_inclusion(self):
        response = self.client.get("/api/feeds/heralding/all/recent.json?include_mass_scanners")
        self.assertEqual(response.status_code, 200)
        if settings.FEEDS_LICENSE:
            self.assertEqual(response.json()["license"], settings.FEEDS_LICENSE)
        else:
            self.assertNotIn("license", response.json())
        # Expecting 3 because setupTestData creates 3 IOCs (ioc, ioc_2, ioc_domain) associated with Heralding
        self.assertEqual(len(response.json()["iocs"]), 3)

    def test_400_feeds(self):
        response = self.client.get("/api/feeds/test/all/recent.json")
        self.assertEqual(response.status_code, 400)

    def test_200_feeds_pagination(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_inclusion_mass(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&include_mass_scanners")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)

    def test_200_feeds_pagination_inclusion_tor(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&include_tor_exit_nodes")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)

    def test_200_feeds_pagination_inclusion_mass_and_tor(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&include_mass_scanners&include_tor_exit_nodes")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 4)

    def test_200_feeds_filter_ip_only(self):
        response = self.client.get("/api/feeds/all/all/recent.json?ioc_type=ip")
        self.assertEqual(response.status_code, 200)
        # Should only return IP addresses, not domains
        for ioc in response.json()["iocs"]:
            # Verify all returned values are IPs (contain dots and numbers pattern)
            self.assertRegex(ioc["value"], r"^\d+\.\d+\.\d+\.\d+$")

    def test_200_feeds_filter_domain_only(self):
        response = self.client.get("/api/feeds/all/all/recent.json?ioc_type=domain")
        self.assertEqual(response.status_code, 200)
        # Should only return domains, not IPs
        self.assertGreater(len(response.json()["iocs"]), 0)
        for ioc in response.json()["iocs"]:
            # Verify all returned values are domains (contain alphabetic characters)
            self.assertRegex(ioc["value"], r"[a-zA-Z]")

    def test_200_feeds_pagination_filter_ip(self):
        response = self.client.get(
            "/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&ioc_type=ip&include_mass_scanners&include_tor_exit_nodes"
        )
        self.assertEqual(response.status_code, 200)
        # Should return only IPs (3 in test data)
        self.assertEqual(response.json()["count"], 3)

    def test_200_feeds_pagination_filter_domain(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&ioc_type=domain")
        self.assertEqual(response.status_code, 200)
        # Should return only domains (1 in test data)
        self.assertEqual(response.json()["count"], 1)

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
        if settings.FEEDS_LICENSE:
            self.assertEqual(response.json()["license"], settings.FEEDS_LICENSE)
        else:
            self.assertNotIn("license", response.json())

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        self.assertEqual(set(target_ioc["feed_type"]), {"log4pot", "cowrie", "heralding", "ciscoasa"})
        self.assertEqual(target_ioc["attack_count"], 1)
        self.assertEqual(target_ioc["scanner"], True)
        self.assertEqual(target_ioc["payload_request"], True)
        self.assertEqual(target_ioc["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(target_ioc["expected_interactions"], self.ioc.expected_interactions)

    def test_200_general_feeds(self):
        response = self.client.get("/api/feeds/advanced/?feed_type=heralding")
        self.assertEqual(response.status_code, 200)
        if settings.FEEDS_LICENSE:
            self.assertEqual(response.json()["license"], settings.FEEDS_LICENSE)
        else:
            self.assertNotIn("license", response.json())

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        self.assertEqual(set(target_ioc["feed_type"]), {"log4pot", "cowrie", "heralding", "ciscoasa"})
        self.assertEqual(target_ioc["attack_count"], 1)
        self.assertEqual(target_ioc["scanner"], True)
        self.assertEqual(target_ioc["payload_request"], True)
        self.assertEqual(target_ioc["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(target_ioc["expected_interactions"], self.ioc.expected_interactions)

    def test_400_feeds(self):
        response = self.client.get("/api/feeds/advanced/?attack_type=test")
        self.assertEqual(response.status_code, 400)

    def test_200_feeds_pagination(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 4)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_include(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&include_reputation=mass%20scanner")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_exclude_mass(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&exclude_reputation=mass%20scanner")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_exclude_tor(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&exclude_reputation=tor%20exit%20node")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_400_feeds_pagination(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&attack_type=test")
        self.assertEqual(response.status_code, 400)


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


class StatisticsViewTestCase(CustomTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        Statistics.objects.all().delete()
        Statistics.objects.create(source="140.246.171.141", view=ViewType.FEEDS_VIEW.value)
        Statistics.objects.create(source="140.246.171.141", view=ViewType.ENRICHMENT_VIEW.value)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
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
        # Count honeypots before adding new one
        initial_count = GeneralHoneypot.objects.count()
        # add a general honeypot without associated ioc
        GeneralHoneypot(name="Tanner", active=True).save()
        self.assertEqual(GeneralHoneypot.objects.count(), initial_count + 1)

        response = self.client.get("/api/statistics/feeds_types")
        self.assertEqual(response.status_code, 200)
        # Expecting 3 because setupTestData creates 3 IOCs (ioc, ioc_2, ioc_domain) associated with Heralding
        self.assertEqual(response.json()[0]["Heralding"], 3)
        self.assertEqual(response.json()[0]["Ciscoasa"], 2)
        self.assertEqual(response.json()[0]["Log4pot"], 3)
        self.assertEqual(response.json()[0]["Cowrie"], 3)
        self.assertEqual(response.json()[0]["Tanner"], 0)


class GeneralHoneypotViewTestCase(CustomTestCase):
    def test_200_all_general_honeypots(self):
        initial_count = GeneralHoneypot.objects.count()
        # add a general honeypot not active
        GeneralHoneypot(name="Adbhoney", active=False).save()
        self.assertEqual(GeneralHoneypot.objects.count(), initial_count + 1)

        response = self.client.get("/api/general_honeypot")
        self.assertEqual(response.status_code, 200)
        # Verify the newly created honeypot is in the response
        self.assertIn("Adbhoney", response.json())

    def test_200_active_general_honeypots(self):
        response = self.client.get("/api/general_honeypot?onlyActive=true")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        # Should include active honeypots from CustomTestCase
        self.assertIn("Heralding", result)
        self.assertIn("Ciscoasa", result)
        # Should NOT include inactive honeypot
        self.assertNotIn("Ddospot", result)


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

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_ip_address_query_with_license(self):
        """Test that license is included when FEEDS_LICENSE is populated."""
        response = self.client.get("/api/command_sequence?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.data)
        self.assertEqual(response.data["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_ip_address_query_without_license(self):
        """Test that license is not included when FEEDS_LICENSE is empty."""
        response = self.client.get("/api/command_sequence?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.data)

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_hash_query_with_license(self):
        """Test that license is included when FEEDS_LICENSE is populated."""
        response = self.client.get(f"/api/command_sequence?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.data)
        self.assertEqual(response.data["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_hash_query_without_license(self):
        """Test that license is not included when FEEDS_LICENSE is empty."""
        response = self.client.get(f"/api/command_sequence?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.data)


class CowrieSessionViewTestCase(CustomTestCase):
    """Test cases for the cowrie_session_view."""

    def setUp(self):
        # setup client
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    # # # # # Basic IP Query Test # # # # #
    def test_ip_address_query(self):
        """Test view with a valid IP address query."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)

    def test_ip_address_query_with_similar(self):
        """Test view with a valid IP address query including similar sequences."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_similar=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)
        self.assertEqual(len(response.data["sources"]), 2)

    def test_ip_address_query_with_credentials(self):
        """Test view with a valid IP address query including credentials."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)
        self.assertEqual(len(response.data["credentials"]), 1)
        self.assertEqual(response.data["credentials"][0], "root | root")

    def test_ip_address_query_with_sessions(self):
        """Test view with a valid IP address query including session data."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertIn("sessions", response.data)
        self.assertEqual(len(response.data["sessions"]), 1)
        self.assertIn("time", response.data["sessions"][0])
        self.assertEqual(response.data["sessions"][0]["duration"], 1.234)
        self.assertEqual(response.data["sessions"][0]["source"], "140.246.171.141")
        self.assertEqual(response.data["sessions"][0]["interactions"], 5)
        self.assertEqual(response.data["sessions"][0]["credentials"][0], "root | root")
        self.assertEqual(response.data["sessions"][0]["commands"], "cd foo\nls -la")

    def test_ip_address_query_with_all(self):
        """Test view with a valid IP address query including everything."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_similar=true&include_credentials=true&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertIn("credentials", response.data)
        self.assertIn("sessions", response.data)

    # # # # # Basic Hash Query Test # # # # #
    def test_hash_query(self):
        """Test view with a valid hash query."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)

    def test_hash_query_with_all(self):
        """Test view with a valid hash query including everything."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}&include_similar=true&include_credentials=true&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertIn("credentials", response.data)
        self.assertIn("sessions", response.data)
        self.assertEqual(len(response.data["sources"]), 2)

    # # # # # IP Address Validation Tests # # # # #
    def test_nonexistent_ip_address(self):
        """Test that view returns 404 for IP with no sequences."""
        response = self.client.get("/api/cowrie_session?query=10.0.0.1")
        self.assertEqual(response.status_code, 404)

    def test_ipv6_address_query(self):
        """Test view with a valid IPv6 address query."""
        response = self.client.get("/api/cowrie_session?query=2001:db8::1")
        self.assertEqual(response.status_code, 404)

    def test_invalid_ip_format(self):
        """Test that malformed IP addresses are rejected."""
        response = self.client.get("/api/cowrie_session?query=999.999.999.999")
        self.assertEqual(response.status_code, 400)

    def test_ip_with_cidr_notation(self):
        """Test that CIDR notation is rejected."""
        response = self.client.get("/api/cowrie_session?query=192.168.1.0/24")
        self.assertEqual(response.status_code, 400)

    # # # # # Parameter Validation Tests # # # # #
    def test_missing_query_parameter(self):
        """Test that view returns BadRequest when query parameter is missing."""
        response = self.client.get("/api/cowrie_session")
        self.assertEqual(response.status_code, 400)

    def test_invalid_query_parameter(self):
        """Test that view returns BadRequest when query parameter is invalid."""
        response = self.client.get("/api/cowrie_session?query=invalid-input}")
        self.assertEqual(response.status_code, 400)

    def test_include_credentials_invalid_value(self):
        """Test that invalid boolean values default to false."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=maybe")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("credentials", response.data)

    def test_case_insensitive_boolean_parameters(self):
        """Test that boolean parameters accept various case formats."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=TRUE")
        self.assertEqual(response.status_code, 200)
        self.assertIn("credentials", response.data)

        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=True")
        self.assertEqual(response.status_code, 200)
        self.assertIn("credentials", response.data)

    # # # # # Hash Validation Tests # # # # #
    def test_nonexistent_hash(self):
        """Test that view returns 404 for nonexistent hash."""
        response = self.client.get(f"/api/cowrie_session?query={'f' * 64}")
        self.assertEqual(response.status_code, 404)

    def test_hash_wrong_length(self):
        """Test that hashes with incorrect length are rejected."""
        response = self.client.get("/api/cowrie_session?query=" + "a" * 32)  # 32 chars instead of 64
        self.assertEqual(response.status_code, 400)

    def test_hash_invalid_characters(self):
        """Test that hashes with invalid characters are rejected."""
        invalid_hash = "g" * 64  # 'g' is not a valid hex character
        response = self.client.get(f"/api/cowrie_session?query={invalid_hash}")
        self.assertEqual(response.status_code, 400)

    def test_hash_case_insensitive(self):
        """Test that hash queries are case-insensitive."""
        response_lower = self.client.get(f"/api/cowrie_session?query={self.hash.lower()}")
        response_upper = self.client.get(f"/api/cowrie_session?query={self.hash.upper()}")
        self.assertEqual(response_lower.status_code, response_upper.status_code)

    # # # # # Special Characters & Encoding Tests # # # # #
    def test_query_with_url_encoding(self):
        """Test that URL-encoded queries work correctly."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141%20")
        # Should either work or return 400, not crash
        self.assertIn(response.status_code, [200, 400, 404])

    # # # # # License Tests # # # # #
    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_ip_query_with_license(self):
        """Test that license is included when FEEDS_LICENSE is populated."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.data)
        self.assertEqual(response.data["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_ip_query_without_license(self):
        """Test that license is not included when FEEDS_LICENSE is empty."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.data)

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_hash_query_with_license(self):
        """Test that license is included when FEEDS_LICENSE is populated."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.data)
        self.assertEqual(response.data["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_hash_query_without_license(self):
        """Test that license is not included when FEEDS_LICENSE is empty."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.data)

    def test_query_with_special_characters(self):
        """Test handling of queries with special characters."""
        response = self.client.get("/api/cowrie_session?query=<script>alert('xss')</script>")
        self.assertEqual(response.status_code, 400)

    # # # # # Authentication & Authorization Tests # # # # #
    def test_unauthenticated_request(self):
        """Test that unauthenticated requests are rejected."""
        client = APIClient()  # No authentication
        response = client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 401)

    def test_regular_user_access(self):
        """Test that regular (non-superuser) authenticated users can access."""
        client = APIClient()
        client.force_authenticate(user=self.regular_user)
        response = client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)


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


class NewsViewTestCase(CustomTestCase):
    def setUp(self):
        """Set up test client and clear cache before each test."""
        self.client = APIClient()
        cache.clear()

    def tearDown(self):
        """Clear cache after each test."""
        cache.clear()

    @patch("api.views.utils.requests.get")
    def test_news_view_returns_cached_data(self, mock_get):
        """Should return cached news data without making API calls."""
        cached_data = [{"title": "Cached GreedyBear Post", "date": "2024-01-01", "link": "https://example.com", "subtext": "Cached content"}]
        cache.set(CACHE_KEY_GREEDYBEAR_NEWS, cached_data, 300)

        response = self.client.get("/api/news/")  # Adjust URL to match your urls.py

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, cached_data)
        mock_get.assert_not_called()

    @patch("api.views.utils.requests.get")
    @patch("api.views.utils.loads")
    def test_news_view_fetches_and_returns_greedybear_posts(self, mock_loads, mock_get):
        """Should fetch, filter, and return GreedyBear posts via API."""
        # Mock file list response
        mock_list_response = MagicMock()
        mock_list_response.json.return_value = [
            {"type": "file", "name": "greedybear-post.md", "download_url": "https://example.com/greedybear-post.md"},
            {"type": "file", "name": "other-post.md", "download_url": "https://example.com/other-post.md"},
        ]

        # Mock markdown content responses
        mock_md_response1 = MagicMock()
        mock_md_response1.text = "markdown content 1"

        mock_md_response2 = MagicMock()
        mock_md_response2.text = "markdown content 2"

        mock_get.side_effect = [mock_list_response, mock_md_response1, mock_md_response2]

        # Mock parsed post data
        mock_loads.side_effect = [
            MagicMock(
                get=lambda k: {"title": "GreedyBear Security Update", "date": "2024-02-01"}.get(k),
                content="This is a GreedyBear related post with important security updates",
            ),
            MagicMock(get=lambda k: {"title": "IntelOwl Release", "date": "2024-01-15"}.get(k), content="This is about IntelOwl"),
        ]

        response = self.client.get("/api/news/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["title"], "GreedyBear Security Update")
        self.assertEqual(response.data[0]["date"], "2024-02-01")
        self.assertEqual(response.data[0]["link"], f"{BLOG_BASE_URL}/greedybear-post")
        self.assertIn("GreedyBear related post", response.data[0]["subtext"])

    @patch("api.views.utils.requests.get")
    @patch("api.views.utils.loads")
    def test_news_view_returns_posts_sorted_by_date(self, mock_loads, mock_get):
        """Should return posts sorted with newest first."""
        mock_list_response = MagicMock()
        mock_list_response.json.return_value = [
            {"type": "file", "name": "old.md", "download_url": "https://example.com/old.md"},
            {"type": "file", "name": "new.md", "download_url": "https://example.com/new.md"},
        ]

        mock_md_old = MagicMock()
        mock_md_new = MagicMock()

        mock_get.side_effect = [mock_list_response, mock_md_old, mock_md_new]

        mock_loads.side_effect = [
            MagicMock(get=lambda k: {"title": "GreedyBear Old Post", "date": "2024-01-01"}.get(k), content="Old content"),
            MagicMock(get=lambda k: {"title": "GreedyBear New Post", "date": "2024-02-01"}.get(k), content="New content"),
        ]

        response = self.client.get("/api/news/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
        self.assertEqual(response.data[0]["title"], "GreedyBear New Post")
        self.assertEqual(response.data[0]["date"], "2024-02-01")
        self.assertEqual(response.data[1]["title"], "GreedyBear Old Post")
        self.assertEqual(response.data[1]["date"], "2024-01-01")

    @patch("api.views.utils.requests.get")
    def test_news_view_returns_empty_list_when_no_markdown_files(self, mock_get):
        """Should return empty list when no markdown files exist."""
        mock_list_response = MagicMock()
        mock_list_response.json.return_value = [
            {"type": "file", "name": "readme.txt", "download_url": "https://example.com/readme.txt"},
            {"type": "directory", "name": "posts"},
        ]

        mock_get.return_value = mock_list_response

        response = self.client.get("/api/news/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])

    @patch("api.views.utils.requests.get")
    @patch("api.views.utils.loads")
    def test_news_view_filters_posts_without_required_fields(self, mock_loads, mock_get):
        """Should skip posts missing title or date."""
        mock_list_response = MagicMock()
        mock_list_response.json.return_value = [
            {"type": "file", "name": "incomplete1.md", "download_url": "https://example.com/incomplete1.md"},
            {"type": "file", "name": "incomplete2.md", "download_url": "https://example.com/incomplete2.md"},
            {"type": "file", "name": "complete.md", "download_url": "https://example.com/complete.md"},
        ]

        mock_md1 = MagicMock()
        mock_md2 = MagicMock()
        mock_md3 = MagicMock()

        mock_get.side_effect = [mock_list_response, mock_md1, mock_md2, mock_md3]

        mock_loads.side_effect = [
            # Missing date
            MagicMock(get=lambda k: {"title": "GreedyBear Post"}.get(k), content="Content"),
            # Missing title
            MagicMock(get=lambda k: {"date": "2024-01-01"}.get(k), content="Content"),
            # Complete
            MagicMock(get=lambda k: {"title": "GreedyBear Complete", "date": "2024-01-01"}.get(k), content="Complete content"),
        ]

        response = self.client.get("/api/news/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["title"], "GreedyBear Complete")

    @patch("api.views.utils.requests.get")
    @patch("api.views.utils.loads")
    def test_news_view_filters_non_greedybear_posts(self, mock_loads, mock_get):
        """Should only return posts with 'greedybear' in title."""
        mock_list_response = MagicMock()
        mock_list_response.json.return_value = [
            {"type": "file", "name": "post1.md", "download_url": "https://example.com/post1.md"},
            {"type": "file", "name": "post2.md", "download_url": "https://example.com/post2.md"},
        ]

        mock_md1 = MagicMock()
        mock_md2 = MagicMock()

        mock_get.side_effect = [mock_list_response, mock_md1, mock_md2]

        mock_loads.side_effect = [
            MagicMock(get=lambda k: {"title": "IntelOwl Update", "date": "2024-01-01"}.get(k), content="IntelOwl content"),
            MagicMock(get=lambda k: {"title": "GreedyBear Feature", "date": "2024-01-15"}.get(k), content="GreedyBear content"),
        ]

        response = self.client.get("/api/news/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["title"], "GreedyBear Feature")

    @patch("api.views.utils.requests.get")
    @patch("api.views.utils.loads")
    def test_news_view_truncates_long_subtext(self, mock_loads, mock_get):
        """Should truncate subtext to 180 characters."""
        mock_list_response = MagicMock()
        mock_list_response.json.return_value = [{"type": "file", "name": "long.md", "download_url": "https://example.com/long.md"}]

        mock_md = MagicMock()
        mock_get.side_effect = [mock_list_response, mock_md]

        long_content = "word " * 100  # Very long content
        mock_loads.return_value = MagicMock(get=lambda k: {"title": "GreedyBear Long Post", "date": "2024-01-01"}.get(k), content=long_content)

        response = self.client.get("/api/news/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertLessEqual(len(response.data[0]["subtext"]), 184)  # 180 + "..."
        self.assertTrue(response.data[0]["subtext"].endswith("..."))

    @patch("api.views.utils.requests.get")
    def test_news_view_handles_api_failure_gracefully(self, mock_get):
        """Should return empty list on API failure."""
        mock_get.side_effect = requests.RequestException("Connection error")

        response = self.client.get("/api/news/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])

    @patch("api.views.utils.requests.get")
    @patch("api.views.utils.loads")
    def test_news_view_caches_results(self, mock_loads, mock_get):
        """Should cache results after first request."""
        mock_list_response = MagicMock()
        mock_list_response.json.return_value = [{"type": "file", "name": "post.md", "download_url": "https://example.com/post.md"}]

        mock_md = MagicMock()
        mock_get.side_effect = [mock_list_response, mock_md]

        mock_loads.return_value = MagicMock(get=lambda k: {"title": "GreedyBear Post", "date": "2024-01-01"}.get(k), content="Content here")

        # First request - should hit API
        response1 = self.client.get("/api/news/")
        self.assertEqual(response1.status_code, status.HTTP_200_OK)

        # Reset mock to verify cache is used
        mock_get.reset_mock()

        # Second request - should use cache
        response2 = self.client.get("/api/news/")
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertEqual(response1.data, response2.data)
        mock_get.assert_not_called()

    @patch("api.views.utils.requests.get")
    @patch("api.views.utils.loads")
    def test_news_view_respects_max_files_limit(self, mock_loads, mock_get):
        """Should only process up to MAX_FILES_TO_CHECK files."""
        many_files = [{"type": "file", "name": f"post{i}.md", "download_url": f"https://example.com/post{i}.md"} for i in range(MAX_FILES_TO_CHECK + 10)]

        mock_list_response = MagicMock()
        mock_list_response.json.return_value = many_files

        mock_get.return_value = mock_list_response

        response = self.client.get("/api/news/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify we don't process more than MAX_FILES_TO_CHECK
        self.assertLessEqual(mock_get.call_count, MAX_FILES_TO_CHECK + 1)

    def test_news_view_only_accepts_get_method(self):
        """Should only accept GET requests."""
        post_response = self.client.post("/api/news/")
        put_response = self.client.put("/api/news/")
        delete_response = self.client.delete("/api/news/")

        self.assertEqual(post_response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(put_response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(delete_response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
