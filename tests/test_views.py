from datetime import datetime

from certego_saas.apps.user.models import User
from django.test import TestCase
from greedybear.consts import FEEDS_LICENSE
from greedybear.models import IOC
from rest_framework.test import APIClient


class EnrichmentViewTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super(EnrichmentViewTestCase, cls).setUpClass()
        current_time = datetime.utcnow()
        cls.ioc = IOC.objects.create(
            name="140.246.171.141",
            type="testing_type",
            first_seen=current_time,
            last_seen=current_time,
            days_seen=[current_time],
            number_of_days_seen=1,
            times_seen=1,
            log4j=True,
            cowrie=True,
            general=["heralding", "ciscoasa"],  # FEEDS
            scanner=True,
            payload_request=True,
            related_urls=[],
        )

        cls.superuser = User.objects.create_superuser(username="test", email="test@greedybear.com", password="test")

    def test_for_vaild_unregistered_ip(self):
        """Check for a valid IP that is unavaliable in DB"""
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get("/api/enrichment?query=192.168.0.1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], False)

    def test_for_invaild_unregistered_ip(self):
        """Check for a IP that Fails Regex Checks and is unavaliable in DB"""
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get("/api/enrichment?query=30.168.1.255.1")
        self.assertEqual(response.status_code, 400)

    def test_for_vaild_registered_ip(self):
        """Check for a valid IP that is avaliable in DB"""
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
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
        self.assertEqual(response.json()["ioc"]["general"], self.ioc.general)  # FEEDS
        self.assertEqual(response.json()["ioc"]["scanner"], self.ioc.scanner)
        self.assertEqual(response.json()["ioc"]["payload_request"], self.ioc.payload_request)

    def test_for_invalid_authentication(self):
        """Check for a invalid authentication"""
        response = self.client.get("/api/enrichment?query=140.246.171.141")
        self.assertEqual(response.status_code, 401)


class FeedsViewTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super(FeedsViewTestCase, cls).setUpClass()
        current_time = datetime.utcnow()
        cls.ioc = IOC.objects.create(
            name="140.246.171.141",
            type="testing_type",
            first_seen=current_time,
            last_seen=current_time,
            days_seen=[current_time],
            number_of_days_seen=1,
            times_seen=1,
            log4j=True,
            cowrie=False,
            general=["heralding", "ciscoasa"],  # FEEDS
            scanner=True,
            payload_request=False,
            related_urls=[],
        )

        cls.superuser = User.objects.create_superuser(username="test", email="test@greedybear.com", password="test")

    def test_200_feeds(self):
        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["license"], FEEDS_LICENSE)
        self.assertEqual(response.json()["iocs"][0]["feed_type"], "log4j")
        self.assertEqual(response.json()["iocs"][0]["times_seen"], 1)
        self.assertEqual(response.json()["iocs"][0]["scanner"], True)
        self.assertEqual(response.json()["iocs"][0]["payload_request"], False)

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
