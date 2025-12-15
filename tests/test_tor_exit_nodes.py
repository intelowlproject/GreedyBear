from unittest.mock import patch, Mock

from . import CustomTestCase

from greedybear.cronjobs.tor_exit_nodes import TorExitNodesCron
from greedybear.models import TorExitNodes, IOC


class TorExitNodesCronTestCase(CustomTestCase):
    def test_tor_exit_nodes_cron_creates_records_and_updates_ioc(self):
        # prepare a fake response similar to the Tor project's exit-addresses format
        sample = b"ExitNode ABCDEF1234567890\n"
        sample += b"ExitAddress 99.99.99.99 2025-12-15 00:00:00\n"
        sample += b"ExitAddress 123.123.123.123 2025-12-15 00:00:00\n"

        fake_resp = Mock()
        fake_resp.status_code = 200
        fake_resp.iter_lines.return_value = sample.split(b"\n")

        with patch("greedybear.cronjobs.tor_exit_nodes.requests.get", return_value=fake_resp):
            # ensure IOC 99.99.99.99 exists from CustomTestCase (ioc_2)
            self.assertTrue(IOC.objects.filter(name="99.99.99.99").exists())
            TorExitNodesCron().execute()

        # check that tor exit nodes were created
        self.assertTrue(TorExitNodes.objects.filter(ip_address="99.99.99.99").exists())
        self.assertTrue(TorExitNodes.objects.filter(ip_address="123.123.123.123").exists())

        # existing IOC for 99.99.99.99 should have been updated to 'tor exit node'
        ioc = IOC.objects.get(name="99.99.99.99")
        self.assertEqual(ioc.ip_reputation, "tor exit node")
