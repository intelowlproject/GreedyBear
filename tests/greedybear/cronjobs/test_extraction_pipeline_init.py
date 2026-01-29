# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
Tests for ExtractionPipeline initialization and time window calculation.
"""

from unittest.mock import patch

from tests import ExtractionTestCase


class TestExtractionPipelineInit(ExtractionTestCase):
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


class TestMinutesBackToLookup(ExtractionTestCase):
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
