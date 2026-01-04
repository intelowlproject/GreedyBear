from unittest.mock import MagicMock, patch

from greedybear.cronjobs.firehol import FireHolCron
from greedybear.models import FireHolList
from tests import CustomTestCase


class FireHolCronTestCase(CustomTestCase):
    @patch("greedybear.cronjobs.firehol.requests.get")
    def test_run(self, mock_get):
        # Setup mock responses
        mock_response_blocklist_de = MagicMock()
        mock_response_blocklist_de.status_code = 200
        mock_response_blocklist_de.text = "# blocklist_de\n1.1.1.1\n2.2.2.2"

        mock_response_greensnow = MagicMock()
        mock_response_greensnow.status_code = 200
        mock_response_greensnow.text = "# greensnow\n3.3.3.3"

        mock_response_bruteforceblocker = MagicMock()
        mock_response_bruteforceblocker.status_code = 200
        mock_response_bruteforceblocker.text = "# bruteforceblocker\n1.1.1.1"

        mock_response_dshield = MagicMock()
        mock_response_dshield.status_code = 200
        mock_response_dshield.text = "# dshield\n4.4.4.0/24"

        # Side effect for multiple calls
        def side_effect(url, timeout):
            if "blocklist_de" in url:
                return mock_response_blocklist_de
            elif "greensnow" in url:
                return mock_response_greensnow
            elif "bruteforceblocker" in url:
                return mock_response_bruteforceblocker
            elif "dshield" in url:
                return mock_response_dshield
            return MagicMock(status_code=404)

        mock_get.side_effect = side_effect

        # Run the cronjob
        cronjob = FireHolCron()
        cronjob.execute()

        # Check FireHolList entries were created
        self.assertTrue(FireHolList.objects.filter(ip_address="1.1.1.1", source="blocklist_de").exists())
        self.assertTrue(FireHolList.objects.filter(ip_address="2.2.2.2", source="blocklist_de").exists())
        self.assertTrue(FireHolList.objects.filter(ip_address="3.3.3.3", source="greensnow").exists())
        self.assertTrue(FireHolList.objects.filter(ip_address="1.1.1.1", source="bruteforceblocker").exists())
        self.assertTrue(FireHolList.objects.filter(ip_address="4.4.4.0/24", source="dshield").exists())

        # Verify FireHolList data is available for IOC enrichment at creation time
        # (Note: Enrichment now happens in iocs_from_hits during IOC creation, not here)
        firehol_entries = FireHolList.objects.filter(ip_address="1.1.1.1")
        self.assertEqual(firehol_entries.count(), 2)
        sources = list(firehol_entries.values_list("source", flat=True))
        self.assertIn("blocklist_de", sources)
        self.assertIn("bruteforceblocker", sources)
