from datetime import datetime, timedelta
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

from greedybear.cronjobs.monitor_logs import MonitorLogs
from greedybear.slack import send_message


class MonitorLogsTestCase(TestCase):
    @patch("greedybear.cronjobs.monitor_logs.Path.exists")
    @patch("greedybear.cronjobs.monitor_logs.Path.stat")
    @patch("greedybear.cronjobs.monitor_logs.send_message")
    def test_run_all_recent_logs(self, mock_send, mock_stat, mock_exists):
        # Setup mock responses
        mock_exists.return_value = True

        # Simulate all recent activity
        recent_time = datetime.now().timestamp()
        mock_stat.return_value.st_mtime = recent_time

        # Run the cronjob
        cronjob = MonitorLogs()
        cronjob.execute()

        self.assertEqual(mock_send.call_count, 4)

    @patch("greedybear.cronjobs.monitor_logs.Path.exists")
    @patch("greedybear.cronjobs.monitor_logs.Path.stat")
    @patch("greedybear.cronjobs.monitor_logs.send_message")
    def test_run_some_recent_logs(self, mock_send, mock_stat, mock_exists):
        # Setup mock responses
        mock_exists.return_value = True

        recent_time = datetime.now().timestamp()
        old_time = (datetime.now() - timedelta(hours=2)).timestamp()

        # Side effect for multiple calls
        mock_stat.side_effect = [
            MagicMock(spec=["st_mtime"], st_mtime=recent_time),
            MagicMock(spec=["st_mtime"], st_mtime=old_time),
            MagicMock(spec=["st_mtime"], st_mtime=old_time),
            MagicMock(spec=["st_mtime"], st_mtime=old_time),
        ]

        # Run the cronjob
        cronjob = MonitorLogs()
        cronjob.execute()

        mock_send.assert_called_once_with("found errors in log file greedybear_errors.log")

    @patch("greedybear.cronjobs.monitor_logs.Path.exists")
    @patch("greedybear.cronjobs.monitor_logs.Path.stat")
    @patch("greedybear.cronjobs.monitor_logs.send_message")
    def test_run_no_recent_logs(self, mock_send, mock_stat, mock_exists):
        # Setup mock responses
        mock_exists.return_value = True

        # Simulate no recent activity
        mock_stat.return_value.st_mtime = (datetime.now() - timedelta(hours=3)).timestamp()

        # Run the cronjob
        cronjob = MonitorLogs()
        cronjob.execute()

        mock_send.assert_not_called()

    @patch("greedybear.cronjobs.monitor_logs.Path.exists")
    @patch("greedybear.cronjobs.monitor_logs.Path.stat")
    @patch("greedybear.cronjobs.monitor_logs.send_message")
    def test_run_no_file(self, mock_send, mock_stat, mock_exists):
        # Setup mock responses
        mock_exists.return_value = False

        # Run the cronjob
        cronjob = MonitorLogs()
        cronjob.execute()

        mock_send.assert_not_called()
