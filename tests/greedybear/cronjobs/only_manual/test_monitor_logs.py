from unittest.mock import patch
from django.test import TestCase
from greedybear.cronjobs.monitor_logs import MonitorLogs


class MonitorLogsTestCase(TestCase):

    @patch("greedybear.cronjobs.monitor_logs.send_message")
    def test_sensors(self, mock_send_message):
        a = MonitorLogs()
        a.execute()
        self.assertTrue(a.success)
        self.assertTrue(mock_send_message.called)
