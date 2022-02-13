from datetime import datetime
from django.test import TestCase
from greedybear.models import IOC


class EnrichmentViewTestCase(TestCase):
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
        current_time = datetime.utcnow()
        IOC.objects.create(
            name="140.246.171.141",
            type="testing_type",
            first_seen=current_time,
            last_seen=current_time,
            days_seen=[current_time],
            number_of_days_seen=1,
            times_seen=1,
            log4j=True,
            cowrie=True,
            scanner=True,
            payload_request=True,
            related_urls=[],
        )
        response = self.client.get("/api/enrichment?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], True)
        self.assertEqual(response.json()["ioc"]["name"], "140.246.171.141")
        self.assertEqual(response.json()["ioc"]["type"], "testing_type")
        self.assertEqual(
            response.json()["ioc"]["first_seen"],
            current_time.isoformat(sep="T", timespec="microseconds"),
        )
        self.assertEqual(
            response.json()["ioc"]["last_seen"],
            current_time.isoformat(sep="T", timespec="microseconds"),
        )
        self.assertEqual(response.json()["ioc"]["number_of_days_seen"], 1)
        self.assertEqual(response.json()["ioc"]["times_seen"], 1)
        self.assertEqual(response.json()["ioc"]["log4j"], True)
        self.assertEqual(response.json()["ioc"]["cowrie"], True)
        self.assertEqual(response.json()["ioc"]["scanner"], True)
        self.assertEqual(response.json()["ioc"]["payload_request"], True)