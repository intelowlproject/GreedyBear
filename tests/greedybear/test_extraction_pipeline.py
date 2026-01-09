"""
Django unit tests for ExtractionPipeline.

Tests validate:
- Pipeline initialization
- Strategy execution
- Error handling
- Empty state handling
"""
from unittest.mock import Mock, patch

from django.test import TestCase

from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline


class DummyExtractionStrategy:
    """Dummy strategy for testing pipeline execution."""

    def __init__(self, honeypot_name, ioc_repo, sensor_repo):
        self.honeypot = honeypot_name
        self.ioc_repo = ioc_repo
        self.sensor_repo = sensor_repo
        self.ioc_records = []

    def extract_from_hits(self, hits):
        """Extract IOCs from hits - dummy implementation."""
        for hit in hits:
            if "src_ip" in hit:
                mock_ioc = Mock()
                mock_ioc.name = hit["src_ip"]
                self.ioc_records.append(mock_ioc)


class FailingDummyStrategy(DummyExtractionStrategy):
    """Dummy strategy that raises an exception for testing error handling."""

    def extract_from_hits(self, hits):
        """Raise an exception to test error handling."""
        raise ValueError("Test exception from strategy")


class TestExtractionPipeline(TestCase):
    """Test cases for ExtractionPipeline."""

    def setUp(self):
        """Set up test fixtures."""
        self.pipeline = ExtractionPipeline()
        self.mock_elastic_repo = Mock()
        self.mock_ioc_repo = Mock()
        self.mock_sensor_repo = Mock()

        # Replace repositories with mocks
        self.pipeline.elastic_repo = self.mock_elastic_repo
        self.pipeline.ioc_repo = self.mock_ioc_repo
        self.pipeline.sensor_repo = self.mock_sensor_repo

    def test_pipeline_initializes_correctly(self):
        """Test that pipeline initializes with correct repositories."""
        pipeline = ExtractionPipeline()
        self.assertIsNotNone(pipeline.elastic_repo)
        self.assertIsNotNone(pipeline.ioc_repo)
        self.assertIsNotNone(pipeline.sensor_repo)
        self.assertIsNotNone(pipeline.log)

    def test_minutes_back_to_lookup_when_ioc_repo_is_empty(self):
        """Test _minutes_back_to_lookup returns initial timespan when repo is empty."""
        self.mock_ioc_repo.is_empty.return_value = True
        result = self.pipeline._minutes_back_to_lookup
        # Should return INITIAL_EXTRACTION_TIMESPAN (3 days = 4320 minutes by default)
        # We'll just check it's a positive integer
        self.assertIsInstance(result, int)
        self.assertGreater(result, 0)

    def test_minutes_back_to_lookup_when_ioc_repo_has_data(self):
        """Test _minutes_back_to_lookup returns extraction interval when repo has data."""
        self.mock_ioc_repo.is_empty.return_value = False
        # Patch the imported constants in the pipeline module
        with patch("greedybear.cronjobs.extraction.pipeline.EXTRACTION_INTERVAL", 10):
            with patch("greedybear.cronjobs.extraction.pipeline.LEGACY_EXTRACTION", False):
                result = self.pipeline._minutes_back_to_lookup
                self.assertEqual(result, 10)

    def test_execute_with_no_hits_returns_zero(self):
        """Test execute() returns 0 when no hits are found."""
        self.mock_elastic_repo.search.return_value = []
        self.mock_ioc_repo.is_empty.return_value = False

        with patch("greedybear.cronjobs.extraction.pipeline.UpdateScores"):
            result = self.pipeline.execute()
            self.assertEqual(result, 0)

    def test_execute_with_empty_hits_by_honeypot_returns_zero(self):
        """Test execute() returns 0 when hits_by_honeypot is empty after filtering."""
        # Create mock hits that will be filtered out (missing src_ip or type)
        # Mock objects that support dict-like access via __getitem__ and __contains__
        mock_hit1 = Mock()
        mock_hit1.to_dict.return_value = {}  # Missing src_ip and type
        mock_hit1.__contains__ = Mock(side_effect=lambda key: False)
        mock_hit1.__getitem__ = Mock(side_effect=KeyError("key not found"))

        mock_hit2 = Mock()
        mock_hit2.to_dict.return_value = {"src_ip": ""}  # Empty src_ip
        mock_hit2.__contains__ = Mock(side_effect=lambda key: key == "src_ip")
        mock_hit2.__getitem__ = Mock(side_effect=lambda key: "" if key == "src_ip" else KeyError(f"{key} not found"))

        self.mock_elastic_repo.search.return_value = [mock_hit1, mock_hit2]
        self.mock_ioc_repo.is_empty.return_value = False

        with patch("greedybear.cronjobs.extraction.pipeline.UpdateScores"):
            result = self.pipeline.execute()
            self.assertEqual(result, 0)

    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_execute_with_valid_hits_processes_strategies(self, mock_update_scores, mock_factory_class):
        """Test execute() processes hits through strategies correctly."""
        # Setup mock hits that support dict-like access
        mock_hit1 = Mock()
        mock_hit1.to_dict.return_value = {"src_ip": "1.2.3.4", "type": "TestHoneypot"}
        mock_hit1.__contains__ = Mock(side_effect=lambda key: key in ["src_ip", "type"])
        mock_hit1.__getitem__ = Mock(side_effect=lambda key: {"src_ip": "1.2.3.4", "type": "TestHoneypot"}[key])

        mock_hit2 = Mock()
        mock_hit2.to_dict.return_value = {"src_ip": "5.6.7.8", "type": "TestHoneypot"}
        mock_hit2.__contains__ = Mock(side_effect=lambda key: key in ["src_ip", "type"])
        mock_hit2.__getitem__ = Mock(side_effect=lambda key: {"src_ip": "5.6.7.8", "type": "TestHoneypot"}[key])

        self.mock_elastic_repo.search.return_value = [mock_hit1, mock_hit2]
        self.mock_ioc_repo.is_empty.return_value = False
        self.mock_ioc_repo.is_ready_for_extraction.return_value = True

        # Setup mock factory and strategy
        mock_factory = Mock()
        mock_factory_class.return_value = mock_factory
        mock_strategy = DummyExtractionStrategy("TestHoneypot", self.mock_ioc_repo, self.mock_sensor_repo)
        mock_factory.get_strategy.return_value = mock_strategy

        mock_update_scores_instance = Mock()
        mock_update_scores.return_value = mock_update_scores_instance

        result = self.pipeline.execute()

        # Verify factory was created with correct repos
        mock_factory_class.assert_called_once_with(self.mock_ioc_repo, self.mock_sensor_repo)
        # Verify strategy was retrieved for the honeypot
        mock_factory.get_strategy.assert_called_once_with("TestHoneypot")
        # Verify extract_from_hits was called
        self.assertEqual(len(mock_strategy.ioc_records), 2)
        # Verify UpdateScores was called
        mock_update_scores_instance.score_only.assert_called_once()
        # Verify result is the count of IOC records
        self.assertEqual(result, 2)

    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_execute_skips_honeypots_not_ready_for_extraction(self, mock_update_scores, mock_factory_class):
        """Test execute() skips honeypots that are not ready for extraction."""
        mock_hit = Mock()
        mock_hit.to_dict.return_value = {"src_ip": "1.2.3.4", "type": "SkipHoneypot"}
        mock_hit.__contains__ = Mock(side_effect=lambda key: key in ["src_ip", "type"])
        mock_hit.__getitem__ = Mock(side_effect=lambda key: {"src_ip": "1.2.3.4", "type": "SkipHoneypot"}[key])

        self.mock_elastic_repo.search.return_value = [mock_hit]
        self.mock_ioc_repo.is_empty.return_value = False
        self.mock_ioc_repo.is_ready_for_extraction.return_value = False

        mock_factory = Mock()
        mock_factory_class.return_value = mock_factory

        result = self.pipeline.execute()

        # Verify strategy was never retrieved
        mock_factory.get_strategy.assert_not_called()
        # Verify result is 0
        self.assertEqual(result, 0)

    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_execute_handles_strategy_exceptions_gracefully(self, mock_update_scores, mock_factory_class):
        """Test execute() handles exceptions from strategies gracefully."""
        mock_hit = Mock()
        mock_hit.to_dict.return_value = {"src_ip": "1.2.3.4", "type": "FailingHoneypot"}
        mock_hit.__contains__ = Mock(side_effect=lambda key: key in ["src_ip", "type"])
        mock_hit.__getitem__ = Mock(side_effect=lambda key: {"src_ip": "1.2.3.4", "type": "FailingHoneypot"}[key])

        self.mock_elastic_repo.search.return_value = [mock_hit]
        self.mock_ioc_repo.is_empty.return_value = False
        self.mock_ioc_repo.is_ready_for_extraction.return_value = True

        # Setup failing strategy
        mock_factory = Mock()
        mock_factory_class.return_value = mock_factory
        failing_strategy = FailingDummyStrategy("FailingHoneypot", self.mock_ioc_repo, self.mock_sensor_repo)
        mock_factory.get_strategy.return_value = failing_strategy

        mock_update_scores_instance = Mock()
        mock_update_scores.return_value = mock_update_scores_instance

        # Should not raise exception
        result = self.pipeline.execute()

        # Verify strategy was called
        mock_factory.get_strategy.assert_called_once_with("FailingHoneypot")
        # Verify UpdateScores was not called since no IOCs were extracted
        mock_update_scores_instance.score_only.assert_not_called()
        # Verify result is 0 (no IOCs extracted due to exception)
        self.assertEqual(result, 0)

    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_execute_extracts_sensors_from_hits(self, mock_update_scores, mock_factory_class):
        """Test execute() extracts sensor IPs from hits."""
        mock_hit = Mock()
        hit_dict = {
            "src_ip": "1.2.3.4",
            "type": "TestHoneypot",
            "t-pot_ip_ext": "192.168.1.1",
        }
        mock_hit.to_dict.return_value = hit_dict
        mock_hit.__contains__ = Mock(side_effect=lambda key: key in hit_dict)
        mock_hit.__getitem__ = Mock(side_effect=lambda key: hit_dict[key])

        self.mock_elastic_repo.search.return_value = [mock_hit]
        self.mock_ioc_repo.is_empty.return_value = False
        self.mock_ioc_repo.is_ready_for_extraction.return_value = True

        mock_factory = Mock()
        mock_factory_class.return_value = mock_factory
        mock_strategy = DummyExtractionStrategy("TestHoneypot", self.mock_ioc_repo, self.mock_sensor_repo)
        mock_factory.get_strategy.return_value = mock_strategy

        mock_update_scores_instance = Mock()
        mock_update_scores.return_value = mock_update_scores_instance

        self.pipeline.execute()

        # Verify sensor was added
        self.mock_sensor_repo.add_sensor.assert_called_once_with("192.168.1.1")

    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_execute_processes_multiple_honeypots(self, mock_update_scores, mock_factory_class):
        """Test execute() processes hits from multiple honeypots."""
        mock_hit1 = Mock()
        hit1_dict = {"src_ip": "1.2.3.4", "type": "HoneypotA"}
        mock_hit1.to_dict.return_value = hit1_dict
        mock_hit1.__contains__ = Mock(side_effect=lambda key: key in hit1_dict)
        mock_hit1.__getitem__ = Mock(side_effect=lambda key: hit1_dict[key])

        mock_hit2 = Mock()
        hit2_dict = {"src_ip": "5.6.7.8", "type": "HoneypotB"}
        mock_hit2.to_dict.return_value = hit2_dict
        mock_hit2.__contains__ = Mock(side_effect=lambda key: key in hit2_dict)
        mock_hit2.__getitem__ = Mock(side_effect=lambda key: hit2_dict[key])

        self.mock_elastic_repo.search.return_value = [mock_hit1, mock_hit2]
        self.mock_ioc_repo.is_empty.return_value = False
        self.mock_ioc_repo.is_ready_for_extraction.return_value = True

        mock_factory = Mock()
        mock_factory_class.return_value = mock_factory

        strategy_a = DummyExtractionStrategy("HoneypotA", self.mock_ioc_repo, self.mock_sensor_repo)
        strategy_b = DummyExtractionStrategy("HoneypotB", self.mock_ioc_repo, self.mock_sensor_repo)
        mock_factory.get_strategy.side_effect = [strategy_a, strategy_b]

        mock_update_scores_instance = Mock()
        mock_update_scores.return_value = mock_update_scores_instance

        result = self.pipeline.execute()

        # Verify both strategies were called
        self.assertEqual(mock_factory.get_strategy.call_count, 2)
        # Verify both IOCs were extracted
        self.assertEqual(len(strategy_a.ioc_records), 1)
        self.assertEqual(len(strategy_b.ioc_records), 1)
        # Verify UpdateScores was called with combined records
        mock_update_scores_instance.score_only.assert_called_once()
        # Verify result is total count
        self.assertEqual(result, 2)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_execute_does_not_call_update_scores_when_no_ioc_records(self, mock_update_scores):
        """Test execute() does not call UpdateScores when no IOC records are extracted."""
        self.mock_elastic_repo.search.return_value = []
        self.mock_ioc_repo.is_empty.return_value = False

        result = self.pipeline.execute()

        # Verify UpdateScores was not instantiated
        mock_update_scores.assert_not_called()
        self.assertEqual(result, 0)
