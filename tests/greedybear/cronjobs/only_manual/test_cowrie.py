# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from unittest import TestCase

from greedybear.cronjobs import cowrie
from greedybear.models import IOC


class CowrieTestCase(TestCase):
    def test_sensors(self, *args, **kwargs):
        a = cowrie.ExtractCowrie()
        a.execute()
        self.assertTrue(a.success)
        iocs = IOC.objects.filter(cowrie=True)
        self.assertTrue(iocs)
