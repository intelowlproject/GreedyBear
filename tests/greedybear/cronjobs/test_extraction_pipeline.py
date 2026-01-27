# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
End-to-end tests for the ExtractionPipeline class.

Tests the complete extraction workflow from Elasticsearch hits
through strategy selection, IOC extraction, and scoring.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

from greedybear.models import IOC
from tests import CustomTestCase


class ExtractionPipelineTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.mock_ioc_repo = MagicMock()
        self.mock_sensor_repo = MagicMock()
        self.mock_session_repo = MagicMock()

    def _create_mock_ioc(
        self,
        name="1.2.3.4",
        ioc_type="ip",
        attack_count=1,
        interaction_count=1,
        related_urls=None,
        destination_ports=None,
        login_attempts=0,
        days_seen=None,
        last_seen=None,
        ip_reputation="",
        asn=1234,
    ):
        mock = MagicMock(spec=IOC)
        mock.name = name
        mock.type = ioc_type
        mock.scanner = False
        mock.payload_request = False
        mock.attack_count = attack_count
        mock.interaction_count = interaction_count
        mock.related_urls = related_urls if related_urls is not None else []
        mock.destination_ports = destination_ports if destination_ports is not None else []
        mock.days_seen = days_seen if days_seen is not None else []
        mock.login_attempts = login_attempts
        mock.last_seen = last_seen if last_seen is not None else datetime.now()
        mock.ip_reputation = ip_reputation
        mock.asn = asn
        mock.number_of_days_seen = len(mock.days_seen)
        return mock


class MockElasticHit:
    """Mock Elasticsearch hit that behaves like AttrDict from elasticsearch-dsl."""

    def __init__(self, data: dict):
        self._data = data

    def __getitem__(self, key):
        return self._data[key]

    def __contains__(self, key):
        return key in self._data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def to_dict(self):
        return self._data.copy()


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

    def _create_pipeline_with_mocks(self):
        """Helper to create a pipeline with mocked dependencies."""
        with (
            patch("greedybear.cronjobs.extraction.pipeline.SensorRepository") as mock_sensor,
            patch("greedybear.cronjobs.extraction.pipeline.IocRepository") as mock_ioc,
            patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository") as mock_elastic,
        ):
            from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

            pipeline = ExtractionPipeline()
            # Store mocks for later access
            pipeline._mock_elastic = mock_elastic.return_value
            pipeline._mock_ioc = mock_ioc.return_value
            pipeline._mock_sensor = mock_sensor.return_value
            return pipeline

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_skips_hits_without_src_ip(self, mock_factory, mock_scores):
        """Hits without src_ip should be skipped."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            MockElasticHit({"type": "Cowrie"}),  # missing src_ip
            MockElasticHit({"src_ip": "", "type": "Cowrie"}),  # empty src_ip
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
        ]
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline.execute()

        self.assertEqual(result, 0)
        mock_factory.return_value.get_strategy.assert_not_called()

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
    def test_handles_strategy_exception_gracefully(self, mock_factory, mock_scores):
        """Strategy exceptions should be caught and logged, not crash pipeline."""
        pipeline = self._create_pipeline_with_mocks()
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


class TestExecuteScoring(ExtractionPipelineTestCase):
    """Tests for scoring logic in execute()."""

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
    @patch("greedybear.cronjobs.extraction.pipeline.SensorRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.IocRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository")
    def test_handles_empty_search_result(self, mock_elastic, mock_ioc, mock_sensor, mock_factory, mock_scores):
        """Should handle empty Elasticsearch response gracefully."""
        from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

        pipeline = ExtractionPipeline()
        pipeline.elastic_repo.search.return_value = []
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline.execute()

        self.assertEqual(result, 0)
        mock_factory.return_value.get_strategy.assert_not_called()
        mock_scores.return_value.score_only.assert_not_called()
