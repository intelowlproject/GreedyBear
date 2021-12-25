from unittest import TestCase

from greedybear.cronjobs import attacks
from greedybear.models import IOC


class AttacksTestCase(TestCase):
    def test_sensors(self, *args, **kwargs):
        a = attacks.ExtractAttacks()
        a.run()
        self.assertTrue(a.success)
        iocs = IOC.objects.all()
        self.assertTrue(iocs)
