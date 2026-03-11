from greedybear.models import IOC, GeneralHoneypot, IocType, Statistics, ViewType
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

    def test_200_countries(self):
        # Create IOCs with attacker_country set
        ioc_cn = IOC.objects.create(
            name="1.2.3.4",
            type=IocType.IP.value,
            first_seen=self.current_time,
            last_seen=self.current_time,
            days_seen=[self.current_time],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            attacker_country="China",
        )
        ioc_cn2 = IOC.objects.create(
            name="1.2.3.5",
            type=IocType.IP.value,
            first_seen=self.current_time,
            last_seen=self.current_time,
            days_seen=[self.current_time],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            attacker_country="China",
        )
        ioc_us = IOC.objects.create(
            name="1.2.3.6",
            type=IocType.IP.value,
            first_seen=self.current_time,
            last_seen=self.current_time,
            days_seen=[self.current_time],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            attacker_country="United States",
        )
        ioc_inactive = IOC.objects.create(
            name="1.2.3.7",
            type=IocType.IP.value,
            first_seen=self.current_time,
            last_seen=self.current_time,
            days_seen=[self.current_time],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            attacker_country="Russia",
        )
        ioc_cn.general_honeypot.add(self.heralding)
        ioc_cn2.general_honeypot.add(self.heralding)
        ioc_us.general_honeypot.add(self.heralding)
        # ioc_inactive is only attached to an inactive honeypot (should be excluded)
        ioc_inactive.general_honeypot.add(self.ddospot)

        response = self.client.get("/api/statistics/countries")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        countries = [item["country"] for item in data]
        counts = {item["country"]: item["count"] for item in data}
        # China should appear twice, United States once; Russia (inactive honeypot) must be excluded
        self.assertIn("China", countries)
        self.assertIn("United States", countries)
        self.assertNotIn("Russia", countries)
        self.assertEqual(counts["China"], 2)
        self.assertEqual(counts["United States"], 1)
        # Results must be ordered descending by count
        count_values = [item["count"] for item in data]
        self.assertEqual(count_values, sorted(count_values, reverse=True))

        ioc_cn.delete()
        ioc_cn2.delete()
        ioc_us.delete()
        ioc_inactive.delete()
