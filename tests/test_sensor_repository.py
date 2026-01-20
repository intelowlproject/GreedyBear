from greedybear.cronjobs.repositories import SensorRepository
from greedybear.models import Sensor

from . import CustomTestCase


class TestSensorRepository(CustomTestCase):
    def setUp(self):
        self.repo = SensorRepository()

    def test_sensors_property_returns_cached_sensors(self):
        self.repo.add_sensor("192.168.1.1")
        self.repo.add_sensor("192.168.1.2")
        result = self.repo.sensors
        self.assertEqual(len(result), 2)
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.2", result)

    def test_add_sensor_creates_new_sensor(self):
        result = self.repo.add_sensor("192.168.1.3")
        self.assertTrue(result)
        self.assertTrue(Sensor.objects.filter(address="192.168.1.3").exists())
        self.assertIn("192.168.1.3", self.repo.cache)

    def test_add_sensor_returns_false_for_existing_sensor(self):
        self.repo.add_sensor("192.168.1.1")
        result = self.repo.add_sensor("192.168.1.1")
        self.assertFalse(result)
        self.assertEqual(Sensor.objects.filter(address="192.168.1.1").count(), 1)

    def test_add_sensor_rejects_non_ip(self):
        result = self.repo.add_sensor("not-an-ip")
        self.assertFalse(result)
        self.assertFalse(Sensor.objects.filter(address="not-an-ip").exists())

    def test_add_sensor_rejects_domain(self):
        result = self.repo.add_sensor("example.com")
        self.assertFalse(result)
        self.assertFalse(Sensor.objects.filter(address="example.com").exists())

    def test_cache_populated_on_init(self):
        Sensor.objects.create(address="192.168.1.1")
        Sensor.objects.create(address="192.168.1.2")
        repo = SensorRepository()
        self.assertEqual(len(repo.cache), 2)
        self.assertIn("192.168.1.1", repo.cache)
        self.assertIn("192.168.1.2", repo.cache)

    def test_add_sensor_updates_cache(self):
        initial_cache_size = len(self.repo.cache)
        self.repo.add_sensor("192.168.1.1")
        self.assertEqual(len(self.repo.cache), initial_cache_size + 1)

    def test_add_sensor_accepts_valid_ipv4(self):
        test_ips = ["1.2.3.4", "192.168.1.1", "10.0.0.1", "8.8.8.8"]
        for ip in test_ips:
            result = self.repo.add_sensor(ip)
            self.assertTrue(result)
