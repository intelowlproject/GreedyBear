"""
Tests for the Heralding credential-catching honeypot extraction strategy.
"""

from unittest.mock import Mock, patch

from greedybear.consts import SCANNER
from greedybear.cronjobs.extraction.strategies.heralding import (
    HERALDING_HONEYPOT,
    HERALDING_PROTOCOLS,
    HERALDING_SOURCE,
    HeraldingExtractionStrategy,
)

from . import ExtractionTestCase


class TestHeraldingExtractionStrategy(ExtractionTestCase):
    """Tests for the main extract_from_hits entrypoint."""

    def setUp(self):
        super().setUp()
        self.strategy = HeraldingExtractionStrategy(
            honeypot="Heralding",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.threatfox_submission")
    def test_extract_scanner_ips(self, mock_threatfox, mock_iocs_from_hits):
        """Scanner IPs are extracted as SCANNER-type IOCs tagged with Heralding."""
        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_iocs_from_hits.return_value = [mock_ioc]
        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 22, "protocol": "ssh", "@timestamp": "2025-01-01T00:00:00"}]
        self.strategy.extract_from_hits(hits)

        mock_iocs_from_hits.assert_called_once_with(hits)
        self.strategy.ioc_processor.add_ioc.assert_any_call(
            mock_ioc,
            attack_type=SCANNER,
            general_honeypot_name=HERALDING_HONEYPOT,
        )
        self.assertEqual(len(self.strategy.ioc_records), 1)
        mock_threatfox.assert_called_once()

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    def test_none_ioc_record_skipped(self, mock_iocs_from_hits):
        """IOC records that resolve to None are silently skipped."""
        mock_ioc = self._create_mock_ioc()
        mock_iocs_from_hits.return_value = [mock_ioc]
        self.strategy.ioc_processor.add_ioc = Mock(return_value=None)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 22, "@timestamp": "2025-01-01T00:00:00"}]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(len(self.strategy.ioc_records), 0)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.threatfox_submission")
    def test_multiple_scanners(self, mock_threatfox, mock_iocs_from_hits):
        """Multiple scanner IPs from the same batch are all processed."""
        ioc1 = self._create_mock_ioc("1.2.3.4")
        ioc2 = self._create_mock_ioc("5.6.7.8")
        mock_iocs_from_hits.return_value = [ioc1, ioc2]
        self.strategy.ioc_processor.add_ioc = Mock(side_effect=[ioc1, ioc2])

        hits = [
            {"src_ip": "1.2.3.4", "dest_port": 22, "protocol": "ssh", "@timestamp": "2025-01-01T00:00:00"},
            {"src_ip": "5.6.7.8", "dest_port": 21, "protocol": "ftp", "@timestamp": "2025-01-01T00:00:00"},
        ]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(len(self.strategy.ioc_records), 2)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_extract_from_hits_calls_both_phases(self, mock_tag_objects, mock_iocs_from_hits):
        """extract_from_hits runs both scanner extraction and credential classification."""
        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_iocs_from_hits.return_value = [mock_ioc]
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 22, "protocol": "ssh", "@timestamp": "2025-01-01T00:00:00"}]

        with (
            patch.object(self.strategy, "_get_scanners", wraps=self.strategy._get_scanners) as spy_scanners,
            patch.object(self.strategy, "_classify_credential_attacks", wraps=self.strategy._classify_credential_attacks) as spy_classify,
        ):
            self.strategy.extract_from_hits(hits)

        spy_scanners.assert_called_once_with(hits)
        spy_classify.assert_called_once_with(hits)


class TestHeraldingProtocolExtraction(ExtractionTestCase):
    """Tests for _extract_protocol helper."""

    def setUp(self):
        super().setUp()
        self.strategy = HeraldingExtractionStrategy(
            honeypot="Heralding",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    def test_known_protocol_returned(self):
        for proto in ["ssh", "ftp", "telnet", "http", "https", "pop3", "imap", "smtp", "vnc", "rdp"]:
            with self.subTest(protocol=proto):
                hit = {"src_ip": "1.2.3.4", "protocol": proto}
                result = self.strategy._extract_protocol(hit)
                self.assertEqual(result, proto)

    def test_protocol_normalised_to_lowercase(self):
        hit = {"src_ip": "1.2.3.4", "protocol": "SSH"}
        result = self.strategy._extract_protocol(hit)
        self.assertEqual(result, "ssh")

    def test_protocol_with_whitespace_stripped(self):
        hit = {"src_ip": "1.2.3.4", "protocol": "  ftp  "}
        result = self.strategy._extract_protocol(hit)
        self.assertEqual(result, "ftp")

    def test_missing_protocol_field_returns_none(self):
        hit = {"src_ip": "1.2.3.4"}
        result = self.strategy._extract_protocol(hit)
        self.assertIsNone(result)

    def test_empty_protocol_field_returns_none(self):
        hit = {"src_ip": "1.2.3.4", "protocol": ""}
        result = self.strategy._extract_protocol(hit)
        self.assertIsNone(result)

    def test_unknown_protocol_returns_none(self):
        hit = {"src_ip": "1.2.3.4", "protocol": "unknown_proto"}
        result = self.strategy._extract_protocol(hit)
        self.assertIsNone(result)


class TestHeraldingCredentialClassification(ExtractionTestCase):
    """Tests for _classify_credential_attacks and protocol tagging logic."""

    def setUp(self):
        super().setUp()
        self.strategy = HeraldingExtractionStrategy(
            honeypot="Heralding",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_protocol_tagged_on_ioc(self, mock_tag_objects, mock_iocs_from_hits):
        """A valid protocol generates a Tag on the matching IOC."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        hits = [{"src_ip": "1.2.3.4", "protocol": "ssh"}]
        self.strategy.extract_from_hits(hits)

        mock_tag_objects.get_or_create.assert_called_once_with(
            ioc=mock_ioc_record,
            key="protocol",
            value="ssh",
            source=HERALDING_SOURCE,
        )

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_multiple_protocols_all_tagged(self, mock_tag_objects, mock_iocs_from_hits):
        """An IP that attacks multiple protocols gets one tag per protocol."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        hits = [
            {"src_ip": "1.2.3.4", "protocol": "ssh"},
            {"src_ip": "1.2.3.4", "protocol": "ftp"},
            {"src_ip": "1.2.3.4", "protocol": "telnet"},
        ]
        self.strategy.extract_from_hits(hits)

        tagged_values = {call[1]["value"] for call in mock_tag_objects.get_or_create.call_args_list}
        self.assertEqual(tagged_values, {"ssh", "ftp", "telnet"})

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_duplicate_protocol_per_ip_deduplicated(self, mock_tag_objects, mock_iocs_from_hits):
        """Repeated hits for the same IP+protocol only produce a single tag attempt."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        hits = [
            {"src_ip": "1.2.3.4", "protocol": "ssh"},
            {"src_ip": "1.2.3.4", "protocol": "ssh"},
            {"src_ip": "1.2.3.4", "protocol": "ssh"},
        ]
        self.strategy.extract_from_hits(hits)

        # Only one get_or_create call despite three hits
        ssh_calls = [c for c in mock_tag_objects.get_or_create.call_args_list if c[1]["value"] == "ssh"]
        self.assertEqual(len(ssh_calls), 1)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_missing_src_ip_skipped(self, mock_tag_objects, mock_iocs_from_hits):
        """Hits without src_ip are silently ignored in classification."""
        mock_iocs_from_hits.return_value = []
        hits = [{"protocol": "ssh"}]
        self.strategy.extract_from_hits(hits)

        mock_tag_objects.get_or_create.assert_not_called()

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_unknown_protocol_not_tagged(self, mock_tag_objects, mock_iocs_from_hits):
        """Hits with an unknown protocol value do not produce tags."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record

        hits = [{"src_ip": "1.2.3.4", "protocol": "bogus_protocol"}]
        self.strategy.extract_from_hits(hits)

        mock_tag_objects.get_or_create.assert_not_called()

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_unknown_scanner_ip_skipped(self, mock_tag_objects, mock_iocs_from_hits):
        """Source IPs not in the IOC repo are silently skipped during tagging."""
        mock_iocs_from_hits.return_value = []
        self.mock_ioc_repo.get_ioc_by_name.return_value = None

        hits = [{"src_ip": "9.9.9.9", "protocol": "ssh"}]
        self.strategy.extract_from_hits(hits)

        mock_tag_objects.get_or_create.assert_not_called()

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_new_tag_increments_counter(self, mock_tag_objects, mock_iocs_from_hits):
        """Creating a new protocol tag increments protocol_tags_added."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        hits = [{"src_ip": "1.2.3.4", "protocol": "ftp"}]
        self.strategy.extract_from_hits(hits)

        self.assertGreater(self.strategy.protocol_tags_added, 0)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_existing_tag_not_counted(self, mock_tag_objects, mock_iocs_from_hits):
        """Tags that already exist (get_or_create returns created=False) do not increment counter."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), False)

        hits = [{"src_ip": "1.2.3.4", "protocol": "ssh"}]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(self.strategy.protocol_tags_added, 0)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_two_ips_each_get_tagged_separately(self, mock_tag_objects, mock_iocs_from_hits):
        """Different scanner IPs each receive their own protocol tags."""
        mock_iocs_from_hits.return_value = []
        ioc1 = self._create_mock_ioc("1.2.3.4")
        ioc2 = self._create_mock_ioc("5.6.7.8")
        self.mock_ioc_repo.get_ioc_by_name.side_effect = lambda name: {
            "1.2.3.4": ioc1,
            "5.6.7.8": ioc2,
        }.get(name)
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        hits = [
            {"src_ip": "1.2.3.4", "protocol": "ssh"},
            {"src_ip": "5.6.7.8", "protocol": "ftp"},
        ]
        self.strategy.extract_from_hits(hits)

        calls = mock_tag_objects.get_or_create.call_args_list
        ioc_args = {call[1]["ioc"]: call[1]["value"] for call in calls}
        self.assertEqual(ioc_args[ioc1], "ssh")
        self.assertEqual(ioc_args[ioc2], "ftp")

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_scanner_from_ioc_cache_used(self, mock_tag_objects, mock_iocs_from_hits):
        """IPs already in self.ioc_records use the in-memory cache, not the repo."""
        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_iocs_from_hits.return_value = [mock_ioc]
        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        hits = [{"src_ip": "1.2.3.4", "protocol": "http"}]
        self.strategy.extract_from_hits(hits)

        # get_ioc_by_name should NOT have been called because the record was in
        # ioc_records (which seeds the cache in _classify_credential_attacks)
        self.mock_ioc_repo.get_ioc_by_name.assert_not_called()

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Tag.objects")
    def test_hits_without_protocol_produce_no_tags(self, mock_tag_objects, mock_iocs_from_hits):
        """Hits that lack the protocol field are ignored during classification."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record

        hits = [{"src_ip": "1.2.3.4", "dest_port": 22}]
        self.strategy.extract_from_hits(hits)

        mock_tag_objects.get_or_create.assert_not_called()


class TestHeraldingProtocolSet(ExtractionTestCase):
    """Validate the HERALDING_PROTOCOLS set for completeness and correctness."""

    def test_common_protocols_present(self):
        expected = {"ssh", "telnet", "ftp", "http", "https", "pop3", "imap", "smtp", "vnc", "rdp"}
        for proto in expected:
            self.assertIn(proto, HERALDING_PROTOCOLS, f"Protocol {proto!r} missing from HERALDING_PROTOCOLS")

    def test_protocols_all_lowercase(self):
        for proto in HERALDING_PROTOCOLS:
            self.assertEqual(proto, proto.lower(), f"Protocol {proto!r} is not lowercase")

    def test_is_frozenset(self):
        self.assertIsInstance(HERALDING_PROTOCOLS, frozenset)

    def test_database_protocols_present(self):
        db_protocols = {"postgresql", "mysql", "mssql"}
        for proto in db_protocols:
            self.assertIn(proto, HERALDING_PROTOCOLS, f"DB protocol {proto!r} missing from HERALDING_PROTOCOLS")


class TestHeraldingFactoryIntegration(ExtractionTestCase):
    """Integration test: factory produces a HeraldingExtractionStrategy for 'Heralding'."""

    def test_factory_returns_heralding_strategy(self):
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        factory = ExtractionStrategyFactory(
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )
        strategy = factory.get_strategy("Heralding")
        self.assertIsInstance(strategy, HeraldingExtractionStrategy)

    def test_factory_returns_generic_for_unknown(self):
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory
        from greedybear.cronjobs.extraction.strategies.generic import GenericExtractionStrategy

        factory = ExtractionStrategyFactory(
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )
        strategy = factory.get_strategy("UnknownHoneypot")
        self.assertIsInstance(strategy, GenericExtractionStrategy)
