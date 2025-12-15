from unittest.mock import patch, Mock

from . import CustomTestCase

from greedybear.cronjobs.basic_enrichment import BasicEnrichmentCron
from greedybear.models import EnrichmentTag, IOC


class BasicEnrichmentCronTestCase(CustomTestCase):
    def test_basic_enrichment_creates_tags_and_links_ioc(self):
        sample = b"# comment header\n99.99.99.99\n123.123.123.123\n"

        fake_resp = Mock()
        fake_resp.status_code = 200
        fake_resp.text = sample.decode()

        with patch("greedybear.cronjobs.basic_enrichment.requests.get", return_value=fake_resp):
            # IOC 99.99.99.99 exists from fixtures
            self.assertTrue(IOC.objects.filter(name="99.99.99.99").exists())
            BasicEnrichmentCron().execute()

        self.assertTrue(EnrichmentTag.objects.filter(ip_address="99.99.99.99").exists())
        self.assertTrue(EnrichmentTag.objects.filter(ip_address="123.123.123.123").exists())

        tag = EnrichmentTag.objects.get(ip_address="99.99.99.99")
        self.assertEqual(tag.ioc.name, "99.99.99.99")
