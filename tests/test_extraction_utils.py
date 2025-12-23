from datetime import datetime
from unittest.mock import Mock, patch

from greedybear.consts import DOMAIN, IP
from greedybear.cronjobs.extraction.utils import correct_ip_reputation, get_ioc_type, iocs_from_hits, is_whatsmyip_domain, threatfox_submission
from greedybear.models import MassScanner, WhatsMyIPDomain

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
        return hit

    def test_creates_ioc_from_single_hit(self):
        hits = [self._create_hit(src_ip="8.8.8.8", dest_port=22)]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].name, "8.8.8.8")
        self.assertEqual(iocs[0].type, IP)

    def test_groups_hits_by_ip(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", dest_port=22),
            self._create_hit(src_ip="8.8.8.8", dest_port=80),
            self._create_hit(src_ip="8.8.8.8", dest_port=443),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].attack_count, 1)
        self.assertEqual(iocs[0].interaction_count, 3)

    def test_creates_separate_iocs_for_different_ips(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8"),
            self._create_hit(src_ip="1.1.1.1"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 2)
        names = {ioc.name for ioc in iocs}
        self.assertEqual(names, {"8.8.8.8", "1.1.1.1"})

    def test_aggregates_destination_ports(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", dest_port=22),
            self._create_hit(src_ip="8.8.8.8", dest_port=80),
            self._create_hit(src_ip="8.8.8.8", dest_port=443),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(iocs[0].destination_ports, [22, 80, 443])

    def test_deduplicates_ports(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", dest_port=22),
            self._create_hit(src_ip="8.8.8.8", dest_port=22),
            self._create_hit(src_ip="8.8.8.8", dest_port=22),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(iocs[0].destination_ports, [22])

    def test_handles_missing_dest_port(self):
        hits = [
            {"src_ip": "8.8.8.8", "@timestamp": "2025-01-01T12:00:00.000Z"},
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(iocs[0].destination_ports, [])

    def test_extracts_asn_from_geoip(self):
        hits = [self._create_hit(src_ip="8.8.8.8", asn=15169)]
        iocs = iocs_from_hits(hits)
        self.assertEqual(iocs[0].asn, 15169)

    def test_handles_missing_geoip(self):
        hits = [{"src_ip": "8.8.8.8", "@timestamp": "2025-01-01T12:00:00.000Z"}]
        iocs = iocs_from_hits(hits)
        self.assertIsNone(iocs[0].asn)

    def test_extracts_timestamps(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", timestamp="2025-01-01T10:00:00.000Z"),
            self._create_hit(src_ip="8.8.8.8", timestamp="2025-01-01T12:00:00.000Z"),
            self._create_hit(src_ip="8.8.8.8", timestamp="2025-01-01T11:00:00.000Z"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(iocs[0].first_seen, datetime.fromisoformat("2025-01-01T10:00:00.000Z"))
        self.assertEqual(iocs[0].last_seen, datetime.fromisoformat("2025-01-01T12:00:00.000Z"))

    def test_filters_loopback_addresses(self):
        hits = [
            self._create_hit(src_ip="127.0.0.1"),
            self._create_hit(src_ip="8.8.8.8"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].name, "8.8.8.8")

    def test_filters_private_addresses(self):
        hits = [
            self._create_hit(src_ip="192.168.1.1"),
            self._create_hit(src_ip="10.0.0.1"),
            self._create_hit(src_ip="172.16.0.1"),
            self._create_hit(src_ip="8.8.8.8"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].name, "8.8.8.8")

    def test_filters_multicast_addresses(self):
        hits = [
            self._create_hit(src_ip="224.0.0.1"),
            self._create_hit(src_ip="8.8.8.8"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].name, "8.8.8.8")

    def test_filters_link_local_addresses(self):
        hits = [
            self._create_hit(src_ip="169.254.1.1"),
            self._create_hit(src_ip="8.8.8.8"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].name, "8.8.8.8")

    def test_filters_reserved_addresses(self):
        hits = [
            self._create_hit(src_ip="0.0.0.0"),
            self._create_hit(src_ip="8.8.8.8"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].name, "8.8.8.8")

    def test_heralding_counts_login_attempts(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", hit_type="Heralding"),
            self._create_hit(src_ip="8.8.8.8", hit_type="Heralding"),
            self._create_hit(src_ip="8.8.8.8", hit_type="Heralding"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(iocs[0].login_attempts, 3)

    def test_non_heralding_no_login_attempts(self):
        hits = [
            self._create_hit(src_ip="8.8.8.8", hit_type="Cowrie"),
            self._create_hit(src_ip="8.8.8.8", hit_type="Cowrie"),
        ]
        iocs = iocs_from_hits(hits)
        self.assertEqual(iocs[0].login_attempts, 0)

    def test_corrects_ip_reputation(self):
        MassScanner.objects.create(ip_address="8.8.8.8")
        hits = [self._create_hit(src_ip="8.8.8.8", ip_rep="known attacker")]
        iocs = iocs_from_hits(hits)
        self.assertEqual(iocs[0].ip_reputation, "mass scanner")

    def test_empty_hits_returns_empty_list(self):
        iocs = iocs_from_hits([])
        self.assertEqual(iocs, [])


class ThreatfoxSubmissionTestCase(ExtractionTestCase):
    def setUp(self):
        self.mock_log = Mock()

    def _create_mock_payload_request(self, honeypot_names=None):
        mock = self._create_mock_ioc()
        mock.payload_request = True
        # Create mock honeypots for general_honeypot M2M
        mock_honeypots = []
        if honeypot_names:
            for name in honeypot_names:
                hp = Mock()
                hp.name = name
                mock_honeypots.append(hp)
        mock.general_honeypot.all.return_value = mock_honeypots
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
        ioc_record = self._create_mock_payload_request(honeypot_names=["Cowrie"])
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
        # Use general_honeypot M2M for all honeypot associations
        ioc_record = self._create_mock_payload_request(honeypot_names=["Cowrie", "Log4Pot", "Dionaea"])
        threatfox_submission(ioc_record, ["http://malicious.com/payload.sh"], self.mock_log)
        call_kwargs = mock_post.call_args[1]
        comment = call_kwargs["json"]["comment"]
        self.assertIn("cowrie", comment)
        self.assertIn("log4pot", comment)
        self.assertIn("dionaea", comment)

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
