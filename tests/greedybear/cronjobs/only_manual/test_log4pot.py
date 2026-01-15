# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from greedybear.cronjobs import log4pot
from greedybear.models import IOC
from tests import ExtractionTestCase


class Log4PotTestCase(ExtractionTestCase):
    def test_sensors(self, *args, **kwargs):
        a = log4pot.ExtractLog4Pot()
        a.execute()
        self.assertTrue(a.success)
        iocs = IOC.objects.filter(log4j=True)
        self.assertTrue(iocs)
