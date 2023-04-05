from greedybear.consts import FEEDS_LICENSE
from greedybear.models import GeneralHoneypot, Statistics, viewType
from rest_framework.test import APIClient

from . import CustomTestCase


class EnrichmentViewTestCase(CustomTestCase):
    def setUp(self):
        # setup client
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_for_vaild_unregistered_ip(self):
        """Check for a valid IP that is unavaliable in DB"""
        response = self.client.get("/api/enrichment?query=192.168.0.1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], False)

    def test_for_invaild_unregistered_ip(self):
        """Check for a IP that Fails Regex Checks and is unavaliable in DB"""
        response = self.client.get("/api/enrichment?query=30.168.1.255.1")
        self.assertEqual(response.status_code, 400)

    def test_for_vaild_registered_ip(self):
        """Check for a valid IP that is avaliable in DB"""
        response = self.client.get("/api/enrichment?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], True)
        self.assertEqual(response.json()["ioc"]["name"], self.ioc.name)
        self.assertEqual(response.json()["ioc"]["type"], self.ioc.type)
        self.assertEqual(
            response.json()["ioc"]["first_seen"],
            self.ioc.first_seen.isoformat(sep="T", timespec="microseconds"),
        )
        self.assertEqual(
            response.json()["ioc"]["last_seen"],
            self.ioc.last_seen.isoformat(sep="T", timespec="microseconds"),
        )
        self.assertEqual(response.json()["ioc"]["number_of_days_seen"], self.ioc.number_of_days_seen)
        self.assertEqual(response.json()["ioc"]["times_seen"], self.ioc.times_seen)
        self.assertEqual(response.json()["ioc"]["log4j"], self.ioc.log4j)
        self.assertEqual(response.json()["ioc"]["cowrie"], self.ioc.cowrie)
        self.assertEqual(response.json()["ioc"]["general_honeypot"][0], self.heralding.pk)  # FEEDS
        self.assertEqual(response.json()["ioc"]["general_honeypot"][1], self.ciscoasa.pk)  # FEEDS
        self.assertEqual(response.json()["ioc"]["scanner"], self.ioc.scanner)
        self.assertEqual(response.json()["ioc"]["payload_request"], self.ioc.payload_request)

    def test_for_invalid_authentication(self):
        """Check for a invalid authentication"""
        self.client.logout()
        response = self.client.get("/api/enrichment?query=140.246.171.141")
        self.assertEqual(response.status_code, 401)


class FeedsViewTestCase(CustomTestCase):
    def test_200_all_feeds(self):
        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["license"], FEEDS_LICENSE)
        self.assertEqual(response.json()["iocs"][0]["feed_type"], "log4j")
        self.assertEqual(response.json()["iocs"][0]["times_seen"], 1)
        self.assertEqual(response.json()["iocs"][0]["scanner"], True)
        self.assertEqual(response.json()["iocs"][0]["payload_request"], True)

    def test_200_general_feeds(self):
        response = self.client.get("/api/feeds/heralding/all/recent.json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["license"], FEEDS_LICENSE)
        self.assertEqual(response.json()["iocs"][0]["feed_type"], "heralding")
        self.assertEqual(response.json()["iocs"][0]["times_seen"], 1)
        self.assertEqual(response.json()["iocs"][0]["scanner"], True)
        self.assertEqual(response.json()["iocs"][0]["payload_request"], True)

    def test_400_feeds(self):
        response = self.client.get("/api/feeds/test/all/recent.json")
        self.assertEqual(response.status_code, 400)

    def test_200_feeds_pagination(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_400_feeds_pagination(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=test&age=recent")
        self.assertEqual(response.status_code, 400)


class StatisticsViewTestCase(CustomTestCase):
    @classmethod
    def setUpClass(self):
        super(StatisticsViewTestCase, self).setUpClass()
        Statistics.objects.all().delete()
        Statistics.objects.create(source="140.246.171.141", view=viewType.FEEDS_VIEW.value)
        Statistics.objects.create(source="140.246.171.141", view=viewType.ENRICHMENT_VIEW.value)

    @classmethod
    def tearDownClass(self):
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
        self.assertEqual(GeneralHoneypot.objects.count(), 2)
        # add a general honeypot without associated ioc
        GeneralHoneypot(name="Tanner", active=True).save()
        self.assertEqual(GeneralHoneypot.objects.count(), 3)

        response = self.client.get("/api/statistics/feeds_types")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Heralding"], 1)
        self.assertEqual(response.json()[0]["Ciscoasa"], 1)
        self.assertEqual(response.json()[0]["Log4j"], 1)
        self.assertEqual(response.json()[0]["Cowrie"], 1)
        self.assertEqual(response.json()[0]["Tanner"], 0)


class GeneralHoneypotViewTestCase(CustomTestCase):
    def test_200_all_general_honeypots(self):
        self.assertEqual(GeneralHoneypot.objects.count(), 2)
        # add a general honeypot not active
        GeneralHoneypot(name="Adbhoney", active=False).save()
        self.assertEqual(GeneralHoneypot.objects.count(), 3)

        response = self.client.get("/api/general_honeypot")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), ["Heralding", "Ciscoasa", "Adbhoney"])

    def test_200_active_general_honeypots(self):
        self.assertEqual(GeneralHoneypot.objects.count(), 2)
        response = self.client.get("/api/general_honeypot?onlyActive=true")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), ["Heralding", "Ciscoasa"])
