from datetime import datetime, timedelta
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

from greedybear.cronjobs.monitor_logs import MonitorLogs
from greedybear.slack import send_message


class MonitorLogsTestCase(TestCase):
    @patch("greedybear.cronjobs.monitor_logs.Path.stat")
    @patch("greedybear.cronjobs.monitor_logs.Path.exists")
    @patch("greedybear.cronjobs.monitor_logs.send_message")
    def test_logs_recent_activity(self, mock_send, mock_exists, mock_stat):
        # Setup mock responses
        mock_exists.return_value = True

        recent_time = datetime.now().timestamp()
        old_time = (datetime.now() - timedelta(hours=2)).timestamp()

        # Side effect for multiple calls
        def stat_side_effect():
            mock_stat_result = MagicMock()
            if stat_side_effect.call_count == 0:
                mock_stat_result.st_mtime = recent_time
            else:
                mock_stat_result.st_mtime = old_time
            stat_side_effect.call_count += 1
            return mock_stat_result

        stat_side_effect.call_count = 0
        mock_stat.side_effect = stat_side_effect

        # Run the cronjob
        cronjob = MonitorLogs()
        cronjob.execute()

        mock_send.assert_called_once_with("found errors in log file greedybear_errors.log")
