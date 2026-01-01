from unittest.mock import MagicMock, patch

from greedybear.cronjobs.tor_exit_nodes import TorExitNodesCron
from greedybear.models import IOC, TorExitNodes
from tests import CustomTestCase


class TorExitNodesCronTestCase(CustomTestCase):
    @patch("greedybear.cronjobs.tor_exit_nodes.requests.get")
    def test_run(self, mock_get):
        # Setup mock response with sample Tor exit node data
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"""ExitNode D2A4BEE6754A9711EB0FAC47F3059BE6FC0D72C7
Published 2022-08-17 18:11:11
LastStatus 2022-08-18 14:00:00
ExitAddress 93.95.230.253 2022-08-18 14:44:33

ExitNode 7E1234567890ABCDEF1234567890ABC123456789
Published 2022-08-17 18:12:00
LastStatus 2022-08-18 14:00:00
ExitAddress 91.192.100.61 2022-08-18 14:44:00"""
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        # Run the cronjob
        cronjob = TorExitNodesCron()
        cronjob.execute()

        # Check TorExitNodes entries were created
        self.assertTrue(TorExitNodes.objects.filter(ip_address="93.95.230.253").exists())
        self.assertTrue(TorExitNodes.objects.filter(ip_address="91.192.100.61").exists())

        # Verify correct number of Tor exit nodes
        self.assertEqual(TorExitNodes.objects.count(), 2)

    @patch("greedybear.cronjobs.tor_exit_nodes.requests.get")
    def test_run_with_duplicate_ips(self, mock_get):
        # Setup mock response with duplicate IPs
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"""ExitAddress 93.95.230.253 2022-08-18 14:44:33
ExitAddress 93.95.230.253 2022-08-18 14:45:00
ExitAddress 91.192.100.61 2022-08-18 14:44:00"""
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        # Run the cronjob
        cronjob = TorExitNodesCron()
        cronjob.execute()

        # Verify duplicates are not created
        self.assertEqual(TorExitNodes.objects.filter(ip_address="93.95.230.253").count(), 1)
        self.assertEqual(TorExitNodes.objects.count(), 2)

    @patch("greedybear.cronjobs.tor_exit_nodes.requests.get")
    def test_ioc_updated_on_new_tor_node(self, mock_get):
        # Create an existing IOC
        ioc = IOC.objects.create(name="93.95.230.253", type="ip")
        self.assertNotEqual(ioc.ip_reputation, "tor exit node")

        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"ExitAddress 93.95.230.253 2022-08-18 14:44:33"
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        # Run the cronjob
        cronjob = TorExitNodesCron()
        cronjob.execute()

        # Verify IOC was updated with Tor exit node reputation
        ioc.refresh_from_db()
        self.assertEqual(ioc.ip_reputation, "tor exit node")

    @patch("greedybear.cronjobs.tor_exit_nodes.requests.get")
    def test_run_empty_response(self, mock_get):
        # Setup mock response with empty data
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b""
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        # Run the cronjob
        cronjob = TorExitNodesCron()
        cronjob.execute()

        # Verify no entries were created
        self.assertEqual(TorExitNodes.objects.count(), 0)
