# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
Tests for ExtractionStrategyFactory.
"""

from unittest.mock import MagicMock

from tests import ExtractionTestCase


class TestExtractionStrategyFactory(ExtractionTestCase):
    """Tests for ExtractionStrategyFactory."""

    def test_factory_creates_cowrie_strategy_for_cowrie(self):
        """Factory should return CowrieExtractionStrategy for 'Cowrie' honeypot."""
        from greedybear.cronjobs.extraction.strategies import CowrieExtractionStrategy
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        factory = ExtractionStrategyFactory(MagicMock(), MagicMock())
        strategy = factory.get_strategy("Cowrie")

        self.assertIsInstance(strategy, CowrieExtractionStrategy)

    def test_factory_creates_log4pot_strategy_for_log4pot(self):
        """Factory should return Log4potExtractionStrategy for 'Log4pot' honeypot."""
        from greedybear.cronjobs.extraction.strategies import Log4potExtractionStrategy
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        factory = ExtractionStrategyFactory(MagicMock(), MagicMock())
        strategy = factory.get_strategy("Log4pot")

        self.assertIsInstance(strategy, Log4potExtractionStrategy)

    def test_factory_creates_generic_strategy_for_unknown(self):
        """Factory should return GenericExtractionStrategy for unknown honeypots."""
        from greedybear.cronjobs.extraction.strategies import GenericExtractionStrategy
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        factory = ExtractionStrategyFactory(MagicMock(), MagicMock())
        strategy = factory.get_strategy("UnknownHoneypot")

        self.assertIsInstance(strategy, GenericExtractionStrategy)
        self.assertEqual(strategy.honeypot, "UnknownHoneypot")

    def test_factory_case_sensitive_honeypot_names(self):
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

    def test_factory_strategies_have_correct_honeypot_name(self):
        """Factory-created strategies should have the correct honeypot name."""
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        factory = ExtractionStrategyFactory(MagicMock(), MagicMock())

        cowrie_strategy = factory.get_strategy("Cowrie")
        self.assertEqual(cowrie_strategy.honeypot, "Cowrie")

        log4pot_strategy = factory.get_strategy("Log4pot")
        self.assertEqual(log4pot_strategy.honeypot, "Log4pot")

        generic_strategy = factory.get_strategy("Heralding")
        self.assertEqual(generic_strategy.honeypot, "Heralding")

    def test_factory_passes_repositories_to_strategies(self):
        """Factory should pass repositories to created strategies."""
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        mock_ioc_repo = MagicMock()
        mock_sensor_repo = MagicMock()

        factory = ExtractionStrategyFactory(mock_ioc_repo, mock_sensor_repo)
        strategy = factory.get_strategy("Cowrie")

        self.assertEqual(strategy.ioc_repo, mock_ioc_repo)
        self.assertEqual(strategy.sensor_repo, mock_sensor_repo)
