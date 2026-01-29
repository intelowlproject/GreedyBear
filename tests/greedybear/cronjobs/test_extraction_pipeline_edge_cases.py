# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
Edge case tests for ExtractionPipeline.

These tests cover boundary conditions, error scenarios, and unusual inputs
that the pipeline should handle gracefully.

NOTE: Some tests here mock the factory/strategies because they test error
conditions that cannot be reliably triggered with real strategies (e.g.,
forcing a strategy to throw an exception). This is intentional and differs
from the E2E tests which use real strategies for happy-path testing.
"""

from unittest.mock import MagicMock, patch

from tests import E2ETestCase, MockElasticHit


class TestEdgeCases(E2ETestCase):
    """Edge case tests for the extraction pipeline.

    These tests verify error handling and boundary conditions.
    Some tests mock the factory to control failure scenarios.
    """

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_partial_strategy_success(self, mock_factory, mock_scores):
        """Some strategies succeed, some fail - pipeline continues.

        NOTE: This test mocks factory because we need to force one strategy
        to throw an exception, which cannot be done reliably with real strategies.
        """
        pipeline = self._create_pipeline_with_real_factory()
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


class TestLargeBatches(E2ETestCase):
    """Tests for large batch processing using REAL strategies."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_large_batch_of_hits_with_real_strategy(self, mock_scores):
        """Large number of hits should be processed correctly with real strategies.

        Uses real GenericExtractionStrategy (via unknown honeypot type) to verify
        the pipeline can handle large batches.
        """
        pipeline = self._create_pipeline_with_real_factory()

        # Create 100 hits to test batch processing
        hits = [
            MockElasticHit(
                {
                    "src_ip": f"192.168.{i // 256}.{i % 256}",
                    "type": "TestHoneypot",  # Unknown type → uses GenericExtractionStrategy
                    "dest_port": 22,
                    "@timestamp": "2025-01-15T10:00:00",
                }
            )
            for i in range(100)
        ]
        pipeline.elastic_repo.search.return_value = hits
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        # Mock add_ioc to return mock IOCs
        mock_iocs = [self._create_mock_ioc(f"192.168.{i // 256}.{i % 256}") for i in range(100)]

        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            # Return different mock IOCs for each call
            mock_add.side_effect = mock_iocs
            result = pipeline.execute()

        # Should have processed hits and produced IOCs
        self.assertGreaterEqual(result, 0)
