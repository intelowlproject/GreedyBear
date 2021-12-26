from unittest import TestCase

from greedybear.cronjobs import log4pot
from greedybear.models import IOC


class Log4PotTestCase(TestCase):
    def test_sensors(self, *args, **kwargs):
        a = log4pot.ExtractLog4Pot()
        a.execute()
        self.assertTrue(a.success)
        iocs = IOC.objects.filter(log4j=True)
        self.assertTrue(iocs)
