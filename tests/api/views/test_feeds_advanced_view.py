from django.conf import settings
from rest_framework.test import APIClient

from greedybear.models import Sensor
from tests import CustomTestCase


class FeedsAdvancedViewTestCase(CustomTestCase):
    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_200_all_feeds(self):
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)
        if settings.FEEDS_LICENSE:
            self.assertEqual(response.json()["license"], settings.FEEDS_LICENSE)
        else:
            self.assertNotIn("license", response.json())

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        self.assertEqual(set(target_ioc["feed_type"]), {"log4pot", "cowrie", "heralding", "ciscoasa"})
        self.assertEqual(target_ioc["attack_count"], 1)
        self.assertEqual(target_ioc["scanner"], True)
        self.assertEqual(target_ioc["payload_request"], True)
        self.assertEqual(target_ioc["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(target_ioc["expected_interactions"], self.ioc.expected_interactions)

    def test_200_general_feeds(self):
        response = self.client.get("/api/feeds/advanced/?feed_type=heralding")
        self.assertEqual(response.status_code, 200)
        if settings.FEEDS_LICENSE:
            self.assertEqual(response.json()["license"], settings.FEEDS_LICENSE)
        else:
            self.assertNotIn("license", response.json())

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        self.assertEqual(set(target_ioc["feed_type"]), {"log4pot", "cowrie", "heralding", "ciscoasa"})
        self.assertEqual(target_ioc["attack_count"], 1)
        self.assertEqual(target_ioc["scanner"], True)
        self.assertEqual(target_ioc["payload_request"], True)
        self.assertEqual(target_ioc["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(target_ioc["expected_interactions"], self.ioc.expected_interactions)

    def test_400_feeds(self):
        response = self.client.get("/api/feeds/advanced/?attack_type=test")
        self.assertEqual(response.status_code, 400)

    def test_200_feeds_pagination(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 4)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_include(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&include_reputation=mass%20scanner")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_exclude_mass(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&exclude_reputation=mass%20scanner")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_exclude_tor(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&exclude_reputation=tor%20exit%20node")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_400_feeds_pagination(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&attack_type=test")
        self.assertEqual(response.status_code, 400)

    def test_200_feed_contains_attacker_and_sensor_countries(self):
        """
        Ensures that the response includes the new fields:
        - attacker_country (from IOC)
        - sensor_countries (from related sensors)
        """

        # Create sensors explicitly for THIS test
        sensor1 = Sensor.objects.create(address="10.0.0.1", country="Nepal")
        sensor2 = Sensor.objects.create(address="10.0.0.2", country="Germany")

        # Attach sensors to IOC
        self.ioc.sensors.add(sensor1, sensor2)
        self.ioc.attacker_country = "Bhutan"
        self.ioc.save()

        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        self.assertEqual(target_ioc["attacker_country"], "Bhutan")

        self.assertEqual(target_ioc["sensor_countries"], ["Germany", "Nepal"])
