from unittest.mock import MagicMock, patch

from django.test import TestCase
from greedybear.cronjobs.monitor_honeypots import MonitorHoneypots
from greedybear.models import GeneralHoneypot


class MonitorHoneypotsTestCase(TestCase):
    def setUp(self):
        """Creating two honeypots in the database for testing."""
        self.honeypot1 = GeneralHoneypot.objects.create(name="Log4pot", active=True)
        self.honeypot2 = GeneralHoneypot.objects.create(name="Cowrie", active=True)

    @patch("greedybear.cronjobs.monitor_honeypots.ElasticRepository")
    def test_run_all_active_honeypots_are_hit(self, mock_elastic_repo_class):
        # Setup mock responses
        mock_elastic_repo = mock_elastic_repo_class.return_value

        mock_elastic_repo.has_honeypot_been_hit.return_value = True
        cronjob = MonitorHoneypots(minutes_back=60)
        cronjob.log = MagicMock()

        # Run the cronjob
        cronjob.execute()

        self.assertEqual(mock_elastic_repo.has_honeypot_been_hit.call_count, 2)

        info_calls = [call[0][0] for call in cronjob.log.info.call_args_list]
        warning_calls = [call[0][0] for call in cronjob.log.warning.call_args_list]

        self.assertEqual(len([msg for msg in info_calls if "logs available" in msg]), 2)
        self.assertEqual(len(warning_calls), 0)

    @patch("greedybear.cronjobs.monitor_honeypots.ElasticRepository")
    def test_run_some_active_honeypots_are_hit(self, mock_elastic_repo_class):
        # Setup mock responses
        mock_elastic_repo = mock_elastic_repo_class.return_value
        mock_elastic_repo.has_honeypot_been_hit.side_effect = [True, False]
        cronjob = MonitorHoneypots(minutes_back=60)
        cronjob.log = MagicMock()

        # Run the cronjob
        cronjob.execute()

        self.assertEqual(mock_elastic_repo.has_honeypot_been_hit.call_count, 2)

        info_calls = [call[0][0] for call in cronjob.log.info.call_args_list]
        warning_calls = [call[0][0] for call in cronjob.log.warning.call_args_list]

        self.assertEqual(len([msg for msg in info_calls if "logs available" in msg]), 1)
        self.assertEqual(len(warning_calls), 1)

    @patch("greedybear.cronjobs.monitor_honeypots.ElasticRepository")
    def test_run_no_active_honeypots_are_hit(self, mock_elastic_repo_class):
        # Setup mock responses
        mock_elastic_repo = mock_elastic_repo_class.return_value
        mock_elastic_repo.has_honeypot_been_hit.return_value = False
        cronjob = MonitorHoneypots(minutes_back=60)
        cronjob.log = MagicMock()

        # Run the cronjob
        cronjob.execute()

        self.assertEqual(mock_elastic_repo.has_honeypot_been_hit.call_count, 2)

        info_calls = [call[0][0] for call in cronjob.log.info.call_args_list]
        warning_calls = [call[0][0] for call in cronjob.log.warning.call_args_list]

        self.assertEqual(len([msg for msg in info_calls if "logs available" in msg]), 0)
        self.assertEqual(len(warning_calls), 2)
