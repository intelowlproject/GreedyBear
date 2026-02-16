from greedybear.models import GeneralHoneypot, Statistics, ViewType
from tests import CustomTestCase


class StatisticsViewTestCase(CustomTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        Statistics.objects.all().delete()
        Statistics.objects.create(source="140.246.171.141", view=ViewType.FEEDS_VIEW.value)
        Statistics.objects.create(source="140.246.171.141", view=ViewType.ENRICHMENT_VIEW.value)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        Statistics.objects.all().delete()

    def test_200_feeds_sources(self):
        response = self.client.get("/api/statistics/sources/feeds")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Sources"], 1)

    def test_200_feeds_downloads(self):
        response = self.client.get("/api/statistics/downloads/feeds")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Downloads"], 1)

    def test_200_enrichment_sources(self):
        response = self.client.get("/api/statistics/sources/enrichment")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Sources"], 1)

    def test_200_enrichment_requests(self):
        response = self.client.get("/api/statistics/requests/enrichment")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Requests"], 1)

    def test_200_feed_types(self):
        # Count honeypots before adding new one
        initial_count = GeneralHoneypot.objects.count()
        # add a general honeypot without associated ioc
        GeneralHoneypot(name="Tanner", active=True).save()
        self.assertEqual(GeneralHoneypot.objects.count(), initial_count + 1)

        response = self.client.get("/api/statistics/feeds_types")
        self.assertEqual(response.status_code, 200)
        # Expecting 3 because setupTestData creates 3 IOCs (ioc, ioc_2, ioc_domain) associated with Heralding
        self.assertEqual(response.json()[0]["Heralding"], 3)
        self.assertEqual(response.json()[0]["Ciscoasa"], 2)
        self.assertEqual(response.json()[0]["Log4pot"], 3)
        self.assertEqual(response.json()[0]["Cowrie"], 3)
        self.assertEqual(response.json()[0]["Tanner"], 0)
