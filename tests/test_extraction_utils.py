from datetime import datetime
from unittest.mock import Mock, patch

from greedybear.consts import DOMAIN, IP
from greedybear.cronjobs.extraction.utils import (
    correct_ip_reputation,
    get_ioc_type,
    iocs_from_hits,
    is_valid_cidr,
    is_valid_ipv4,
    is_whatsmyip_domain,
    threatfox_submission,
)
from greedybear.models import FireHolList, MassScanner, WhatsMyIPDomain

from . import CustomTestCase, ExtractionTestCase


class TestGetIocType(CustomTestCase):
    def test_ipv4_returns_ip(self):
        self.assertEqual(get_ioc_type("1.2.3.4"), IP)

    def test_ipv4_edge_cases(self):
        self.assertEqual(get_ioc_type("0.0.0.0"), IP)
        self.assertEqual(get_ioc_type("255.255.255.255"), IP)
        self.assertEqual(get_ioc_type("192.168.1.1"), IP)

    def test_domain_returns_domain(self):
        self.assertEqual(get_ioc_type("example.com"), DOMAIN)

    def test_subdomain_returns_domain(self):
        self.assertEqual(get_ioc_type("sub.example.com"), DOMAIN)

    def test_invalid_ip_returns_domain(self):
        self.assertEqual(get_ioc_type("256.1.1.1"), DOMAIN)
        self.assertEqual(get_ioc_type("1.2.3"), DOMAIN)


class TestIsValidIpv4(CustomTestCase):
    def test_valid_ipv4_returns_true_and_cleaned_ip(self):
        is_valid, ip = is_valid_ipv4("1.2.3.4")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "1.2.3.4")

    def test_valid_ipv4_edge_cases(self):
        # Test boundary values
        is_valid, ip = is_valid_ipv4("0.0.0.0")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "0.0.0.0")

        is_valid, ip = is_valid_ipv4("255.255.255.255")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "255.255.255.255")

        is_valid, ip = is_valid_ipv4("192.168.1.1")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "192.168.1.1")

    def test_ipv4_with_whitespace_strips_and_validates(self):
        # Test leading whitespace
        is_valid, ip = is_valid_ipv4("  1.2.3.4")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "1.2.3.4")

        # Test trailing whitespace
        is_valid, ip = is_valid_ipv4("1.2.3.4  ")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "1.2.3.4")

        # Test both
        is_valid, ip = is_valid_ipv4("  1.2.3.4  ")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "1.2.3.4")

    def test_invalid_ipv4_out_of_range_octets(self):
        # Test octets > 255
        is_valid, ip = is_valid_ipv4("256.1.1.1")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.256.1.1")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.1.256.1")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.1.1.256")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("999.999.999.999")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_incomplete_format(self):
        # Too few octets
        is_valid, ip = is_valid_ipv4("1.2.3")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.2")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_too_many_octets(self):
        is_valid, ip = is_valid_ipv4("1.2.3.4.5")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_domains(self):
        is_valid, ip = is_valid_ipv4("example.com")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("sub.example.com")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_ipv6_addresses(self):
        # IPv6 should not be valid for IPv4 validation
        is_valid, ip = is_valid_ipv4("2001:0db8:85a3::8a2e:0370:7334")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("::1")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_random_strings(self):
        is_valid, ip = is_valid_ipv4("/w00tw00t.at.ISC.SANS.DFind:)")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("not an ip")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_special_characters(self):
        is_valid, ip = is_valid_ipv4("1.2.3.4#comment")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.2.3.4 # comment")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_negative_numbers(self):
        is_valid, ip = is_valid_ipv4("-1.2.3.4")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.-2.3.4")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)


class TestIsValidCIDR(CustomTestCase):
    def test_valid_cidr_returns_true_and_cleaned_cidr(self):
        is_valid, cidr = is_valid_cidr("192.168.1.0/24")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "192.168.1.0/24")

    def test_valid_cidr_edge_cases(self):
        is_valid, cidr = is_valid_cidr("0.0.0.0/0")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "0.0.0.0/0")

        is_valid, cidr = is_valid_cidr("255.255.255.255/32")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "255.255.255.255/32")

        is_valid, cidr = is_valid_cidr("10.0.0.0/8")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "10.0.0.0/8")

    def test_cidr_with_whitespace_strips_and_validates(self):
        is_valid, cidr = is_valid_cidr("  192.168.1.0/24")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "192.168.1.0/24")

        is_valid, cidr = is_valid_cidr("192.168.1.0/24  ")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "192.168.1.0/24")

        is_valid, cidr = is_valid_cidr("  192.168.1.0/24  ")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "192.168.1.0/24")

    def test_invalid_cidr_out_of_range_octets(self):
        invalid = [
            "256.1.1.0/24",
            "1.256.1.0/24",
            "1.1.256.0/24",
            "999.999.999.999/24",
        ]

        for value in invalid:
            is_valid, cidr = is_valid_cidr(value)
            self.assertFalse(is_valid)
            self.assertIsNone(cidr)

    def test_invalid_cidr_incomplete_format(self):
        invalid = [
            "192.168.1/24",
            "192.168/24",
            "192/24",
            "/24",
        ]

        for value in invalid:
            is_valid, cidr = is_valid_cidr(value)
            self.assertFalse(is_valid)
            self.assertIsNone(cidr)

    def test_invalid_cidr_too_many_octets(self):
        is_valid, cidr = is_valid_cidr("1.2.3.4.5/24")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

    def test_invalid_cidr_domains(self):
        is_valid, cidr = is_valid_cidr("example.com/24")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("sub.example.com/16")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

    def test_invalid_cidr_ipv6_addresses(self):
        is_valid, cidr = is_valid_cidr("2001:db8::/32")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("::1/128")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

    def test_invalid_cidr_random_strings(self):
        is_valid, cidr = is_valid_cidr("/w00tw00t.at.ISC.SANS.DFind:)")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("not a cidr")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

    def test_invalid_cidr_special_characters(self):
        is_valid, cidr = is_valid_cidr("192.168.1.0/24#comment")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("192.168.1.0/24 # comment")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("10.0.0.0/8 some text")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

    def test_invalid_cidr_negative_numbers(self):
        invalid = [
            "-1.1.1.1/24",
            "192.168.1.0/-1",
            "192.168.1.0/33",
        ]

        for value in invalid:
            is_valid, cidr = is_valid_cidr(value)
            self.assertFalse(is_valid)
            self.assertIsNone(cidr)


class TestIsWhatsmyipDomain(CustomTestCase):
    def test_returns_true_for_known_domain(self):
        WhatsMyIPDomain.objects.create(domain="some.domain.com")
        result = is_whatsmyip_domain("some.domain.com")
        self.assertTrue(result)

    def test_returns_false_for_unknown_domain(self):
        result = is_whatsmyip_domain("another.domain.com")
        self.assertFalse(result)


class TestCorrectIpReputationTestCase(CustomTestCase):
    def test_returns_mass_scanner_when_in_database(self):
        MassScanner.objects.create(ip_address="1.2.3.4")
        result = correct_ip_reputation("1.2.3.4", "known attacker")
        self.assertEqual(result, "mass scanner")

    def test_returns_original_when_not_in_database(self):
        result = correct_ip_reputation("1.2.3.4", "known attacker")
        self.assertEqual(result, "known attacker")

    def test_checks_mass_scanner_for_empty_reputation(self):
        MassScanner.objects.create(ip_address="1.2.3.4")
        result = correct_ip_reputation("1.2.3.4", "")
        self.assertEqual(result, "mass scanner")

    def test_preserves_other_reputations(self):
        MassScanner.objects.create(ip_address="1.2.3.4")
        result = correct_ip_reputation("1.2.3.4", "bot")
        self.assertEqual(result, "bot")


class IocsFromHitsTestCase(CustomTestCase):
    def _create_hit(
        self,
        src_ip="1.2.3.4",
        dest_port=22,
        timestamp="2025-01-01T12:00:00.000Z",
        hit_type="Cowrie",
        ip_rep="",
        asn=None,
        sensor=None,
    ):
        hit = {
            "src_ip": src_ip,
            "dest_port": dest_port,
            "@timestamp": timestamp,
            "type": hit_type,
            "ip_rep": ip_rep,
        }
        if asn:
            hit["geoip"] = {"asn": asn}
        if sensor:
            hit["_sensor"] = sensor
        return hit

    def test_creates_ioc_from_single_hit(self):
        hits = [self._create_hit(src_ip="8.8.8.8", dest_port=22)]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.name, "8.8.8.8")
        self.assertEqual(ioc.type, IP)

    def test_groups_hits_by_ip(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", dest_port=22),
            self._create_hit(src_ip="8.8.8.8", dest_port=80),
            self._create_hit(src_ip="8.8.8.8", dest_port=443),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.attack_count, 1)
        self.assertEqual(ioc.interaction_count, 3)

    def test_creates_separate_iocs_for_different_ips(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8"),
            self._create_hit(src_ip="1.1.1.1"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 2)
        names = {ioc.name for ioc, sensors in iocs}
        self.assertEqual(names, {"8.8.8.8", "1.1.1.1"})

    def test_aggregates_destination_ports(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", dest_port=22),
            self._create_hit(src_ip="8.8.8.8", dest_port=80),
            self._create_hit(src_ip="8.8.8.8", dest_port=443),
        ]
        iocs = iocs_from_hits(hits)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.destination_ports, [22, 80, 443])

    def test_deduplicates_ports(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", dest_port=22),
            self._create_hit(src_ip="8.8.8.8", dest_port=22),
            self._create_hit(src_ip="8.8.8.8", dest_port=22),
        ]
        iocs = iocs_from_hits(hits)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.destination_ports, [22])

    def test_handles_missing_dest_port(self):
        hits = [
            {"src_ip": "8.8.8.8", "@timestamp": "2025-01-01T12:00:00.000Z"},
        ]
        iocs = iocs_from_hits(hits)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.destination_ports, [])

    def test_extracts_asn_from_geoip(self):
        hits = [self._create_hit(src_ip="8.8.8.8", asn=15169)]
        iocs = iocs_from_hits(hits)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.asn, 15169)

    def test_handles_missing_geoip(self):
        hits = [{"src_ip": "8.8.8.8", "@timestamp": "2025-01-01T12:00:00.000Z"}]
        iocs = iocs_from_hits(hits)
        ioc, sensors = iocs[0]
        self.assertIsNone(ioc.asn)

    def test_extracts_timestamps(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", timestamp="2025-01-01T10:00:00.000Z"),
            self._create_hit(src_ip="8.8.8.8", timestamp="2025-01-01T12:00:00.000Z"),
            self._create_hit(src_ip="8.8.8.8", timestamp="2025-01-01T11:00:00.000Z"),
        ]
        iocs = iocs_from_hits(hits)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.first_seen, datetime.fromisoformat("2025-01-01T10:00:00.000Z"))
        self.assertEqual(ioc.last_seen, datetime.fromisoformat("2025-01-01T12:00:00.000Z"))

    def test_filters_loopback_addresses(self):
        hits = [
            self._create_hit(src_ip="127.0.0.1"),
            self._create_hit(src_ip="8.8.8.8"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.name, "8.8.8.8")

    def test_filters_private_addresses(self):
        hits = [
            self._create_hit(src_ip="192.168.1.1"),
            self._create_hit(src_ip="10.0.0.1"),
            self._create_hit(src_ip="172.16.0.1"),
            self._create_hit(src_ip="8.8.8.8"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.name, "8.8.8.8")

    def test_filters_multicast_addresses(self):
        hits = [
            self._create_hit(src_ip="224.0.0.1"),
            self._create_hit(src_ip="8.8.8.8"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.name, "8.8.8.8")

    def test_filters_link_local_addresses(self):
        hits = [
            self._create_hit(src_ip="169.254.1.1"),
            self._create_hit(src_ip="8.8.8.8"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.name, "8.8.8.8")

    def test_filters_reserved_addresses(self):
        hits = [
            self._create_hit(src_ip="0.0.0.0"),
            self._create_hit(src_ip="8.8.8.8"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.name, "8.8.8.8")

    def test_heralding_counts_login_attempts(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", hit_type="Heralding"),
            self._create_hit(src_ip="8.8.8.8", hit_type="Heralding"),
            self._create_hit(src_ip="8.8.8.8", hit_type="Heralding"),
        ]
        iocs = iocs_from_hits(hits)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.login_attempts, 3)

    def test_non_heralding_no_login_attempts(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", hit_type="Cowrie"),
            self._create_hit(src_ip="8.8.8.8", hit_type="Cowrie"),
        ]
        iocs = iocs_from_hits(hits)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.login_attempts, 0)

    def test_corrects_ip_reputation(self):
        MassScanner.objects.create(ip_address="8.8.8.8")
        hits = [self._create_hit(src_ip="8.8.8.8", ip_rep="known attacker")]
        iocs = iocs_from_hits(hits)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.ip_reputation, "mass scanner")

    def test_empty_hits_returns_empty_list(self):
        iocs = iocs_from_hits([])
        self.assertEqual(iocs, [])

    def test_firehol_enrichment_exact_ip_match(self):
        """Test that IOCs get FireHol categories for exact IP matches (.ipset files)"""
        FireHolList.objects.create(ip_address="8.8.8.8", source="blocklist_de")
        FireHolList.objects.create(ip_address="8.8.8.8", source="greensnow")

        hits = [self._create_hit(src_ip="8.8.8.8")]
        iocs = iocs_from_hits(hits)

        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertIn("blocklist_de", ioc.firehol_categories)
        self.assertIn("greensnow", ioc.firehol_categories)
        self.assertEqual(len(ioc.firehol_categories), 2)

    def test_firehol_enrichment_network_range_match(self):
        """Test that IOCs get FireHol categories when IP is within a CIDR range (.netset files)"""
        FireHolList.objects.create(ip_address="8.8.8.0/24", source="dshield")

        hits = [self._create_hit(src_ip="8.8.8.100")]
        iocs = iocs_from_hits(hits)

        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertIn("dshield", ioc.firehol_categories)

    def test_firehol_enrichment_no_match(self):
        """Test that IOCs have empty FireHol categories when there's no match"""
        FireHolList.objects.create(ip_address="1.1.1.1", source="blocklist_de")
        FireHolList.objects.create(ip_address="9.9.9.0/24", source="dshield")

        hits = [self._create_hit(src_ip="8.8.8.8")]
        iocs = iocs_from_hits(hits)

        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertEqual(ioc.firehol_categories, [])

    def test_firehol_enrichment_mixed_match(self):
        """Test FireHol enrichment with both exact match and network range match"""
        FireHolList.objects.create(ip_address="8.8.8.8", source="blocklist_de")
        FireHolList.objects.create(ip_address="8.8.0.0/16", source="dshield")

        hits = [self._create_hit(src_ip="8.8.8.8")]
        iocs = iocs_from_hits(hits)

        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertIn("blocklist_de", ioc.firehol_categories)
        self.assertIn("dshield", ioc.firehol_categories)

    def test_firehol_enrichment_deduplicates_sources(self):
        """Test that duplicate sources are not added"""
        FireHolList.objects.create(ip_address="8.8.8.8", source="blocklist_de")
        FireHolList.objects.create(ip_address="8.8.0.0/16", source="blocklist_de")

        hits = [self._create_hit(src_ip="8.8.8.8")]
        iocs = iocs_from_hits(hits)

        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        # Should only have one instance of blocklist_de
        self.assertEqual(ioc.firehol_categories.count("blocklist_de"), 1)

    def test_collects_sensors_from_hits(self):
        """Test that sensors are collected from hits and returned"""
        from greedybear.models import Sensor

        sensor1 = Sensor.objects.create(address="10.0.0.1")
        sensor2 = Sensor.objects.create(address="10.0.0.2")

        hits = [
            self._create_hit(src_ip="8.8.8.8", sensor=sensor1),
            self._create_hit(src_ip="8.8.8.8", sensor=sensor2),
            self._create_hit(src_ip="8.8.8.8", sensor=sensor1),  # Duplicate - should be deduplicated
        ]
        iocs = iocs_from_hits(hits)

        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertEqual(len(sensors), 2)
        sensor_addresses = {s.address for s in sensors}
        self.assertEqual(sensor_addresses, {"10.0.0.1", "10.0.0.2"})

    def test_returns_empty_sensors_when_no_sensor_in_hits(self):
        """Test that empty sensor list is returned when hits have no sensor"""
        hits = [self._create_hit(src_ip="8.8.8.8")]
        iocs = iocs_from_hits(hits)

        self.assertEqual(len(iocs), 1)
        ioc, sensors = iocs[0]
        self.assertEqual(sensors, [])


class ThreatfoxSubmissionTestCase(ExtractionTestCase):
    def setUp(self):
        self.mock_log = Mock()

    def _create_mock_payload_request(self):
        mock = self._create_mock_ioc()
        mock.payload_request = True
        mock.general_honeypot.all.return_value = []
        return mock

    def test_skips_non_payload_request_iocs(self):
        ioc_record = self._create_mock_ioc()
        threatfox_submission(ioc_record, ["http://malicious.com/payload"], self.mock_log)
        self.mock_log.warning.assert_not_called()

    @patch("greedybear.cronjobs.extraction.utils.settings")
    def test_warns_when_api_key_missing(self, mock_settings):
        mock_settings.THREATFOX_API_KEY = None
        ioc_record = self._create_mock_payload_request()
        threatfox_submission(ioc_record, ["http://malicious.com/payload"], self.mock_log)
        self.mock_log.warning.assert_called_once_with("Threatfox API Key not available")

    @patch("greedybear.cronjobs.extraction.utils.settings")
    def test_skips_urls_without_path(self, mock_settings):
        mock_settings.THREATFOX_API_KEY = "test-key"
        ioc_record = self._create_mock_payload_request()
        threatfox_submission(ioc_record, ["http://malicious.com", "http://evil.com/"], self.mock_log)
        self.assertTrue(any("skipping" in str(call) for call in self.mock_log.info.call_args_list))

    @patch("greedybear.cronjobs.extraction.utils.requests.post")
    @patch("greedybear.cronjobs.extraction.utils.settings")
    def test_submits_urls_with_path(self, mock_settings, mock_post):
        mock_settings.THREATFOX_API_KEY = "test-key"
        mock_post.return_value = Mock(text='{"status": "ok"}')
        mock_honeypot_cowrie = Mock()
        mock_honeypot_cowrie.name = "Cowrie"
        ioc_record = self._create_mock_payload_request()
        ioc_record.general_honeypot.all.return_value = [mock_honeypot_cowrie]
        threatfox_submission(ioc_record, ["http://malicious.com/payload.sh"], self.mock_log)
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        self.assertEqual(call_kwargs["headers"]["Auth-Key"], "test-key")
        self.assertIn("http://malicious.com/payload.sh", call_kwargs["json"]["iocs"])

    @patch("greedybear.cronjobs.extraction.utils.requests.post")
    @patch("greedybear.cronjobs.extraction.utils.settings")
    def test_includes_honeypot_names_in_comment(self, mock_settings, mock_post):
        mock_settings.THREATFOX_API_KEY = "test-key"
        mock_post.return_value = Mock(text='{"status": "ok"}')
        ioc_record = self._create_mock_payload_request()
        mock_honeypot_cowrie = Mock()
        mock_honeypot_cowrie.name = "Cowrie"
        mock_honeypot_log4pot = Mock()
        mock_honeypot_log4pot.name = "Log4pot"
        mock_honeypot_dionaea = Mock()
        mock_honeypot_dionaea.name = "Dionaea"
        ioc_record.general_honeypot.all.return_value = [mock_honeypot_cowrie, mock_honeypot_log4pot, mock_honeypot_dionaea]
        threatfox_submission(ioc_record, ["http://malicious.com/payload.sh"], self.mock_log)
        call_kwargs = mock_post.call_args[1]
        comment = call_kwargs["json"]["comment"]
        self.assertIn("Cowrie", comment)
        self.assertIn("Log4pot", comment)
        self.assertIn("Dionaea", comment)

    @patch("greedybear.cronjobs.extraction.utils.requests.post")
    @patch("greedybear.cronjobs.extraction.utils.settings")
    def test_logs_successful_submission(self, mock_settings, mock_post):
        mock_settings.THREATFOX_API_KEY = "test-key"
        mock_post.return_value = Mock(text='{"status": "ok"}')
        ioc_record = self._create_mock_payload_request()
        threatfox_submission(ioc_record, ["http://malicious.com/payload.sh"], self.mock_log)
        self.assertTrue(any("successful" in str(call) for call in self.mock_log.info.call_args_list))

    @patch("greedybear.cronjobs.extraction.utils.settings")
    def test_filters_mixed_urls(self, mock_settings):
        mock_settings.THREATFOX_API_KEY = "test-key"
        ioc_record = self._create_mock_payload_request()

        with patch("greedybear.cronjobs.extraction.utils.requests.post") as mock_post:
            mock_post.return_value = Mock(text='{"status": "ok"}')
            urls = [
                "http://malicious.com",  # No path - skip
                "http://evil.com/",  # Root path - skip
                "http://bad.com/malware.exe",  # Has path - submit
                "http://worse.com/path/to/payload",  # Has path - submit
            ]
            threatfox_submission(ioc_record, urls, self.mock_log)

            call_kwargs = mock_post.call_args[1]
            submitted_urls = call_kwargs["json"]["iocs"]
            self.assertEqual(len(submitted_urls), 2)
            self.assertIn("http://bad.com/malware.exe", submitted_urls)
            self.assertIn("http://worse.com/path/to/payload", submitted_urls)
