from datetime import datetime
from django.test import TestCase
from greedybear.models import IOC

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
            scanner=True,
            payload_request=True,
            related_urls=[],
        )

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
        self.assertEqual(response.json()["ioc"]["scanner"], self.ioc.scanner)
        self.assertEqual(response.json()["ioc"]["payload_request"], self.ioc.payload_request)