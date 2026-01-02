from unittest.mock import MagicMock, patch

from django.test import TestCase
from greedybear.cronjobs.monitor_honeypots import MonitorHoneypots
from greedybear.models import GeneralHoneypot


class MonitorHoneypotsIntegrationTest(TestCase):
    def setUp(self):
        """Creating two honeypots in the database for testing."""
        self.honeypot1 = GeneralHoneypot.objects.create(name="Log4pot", active=True)
        self.honeypot2 = GeneralHoneypot.objects.create(name="Cowrie", active=True)

    @patch("greedybear.cronjobs.monitor_honeypots.ElasticRepository")
    def test_honeypots_logs(self, mock_elastic_repo_class):
        # Setup mock responses
        mock_elastic_repo = mock_elastic_repo_class.return_value

        def has_been_hit(minutes_back, honeypot_name):
            return honeypot_name == "Log4pot"

        mock_elastic_repo.has_honeypot_been_hit.side_effect = has_been_hit
        cronjob = MonitorHoneypots(minutes_back=60)
        cronjob.log = MagicMock()

        # Run the cronjob
        cronjob.execute()

        self.assertEqual(mock_elastic_repo.has_honeypot_been_hit.call_count, 2)

        info_calls = [call[0][0] for call in cronjob.log.info.call_args_list]
        warning_calls = [call[0][0] for call in cronjob.log.warning.call_args_list]

        self.assertTrue(any("logs available" in msg for msg in info_calls))
        self.assertTrue(any("no logs available" in msg for msg in warning_calls))
