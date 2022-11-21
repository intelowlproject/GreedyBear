# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from unittest import TestCase

from django.db.models import Q

from greedybear.cronjobs import general
from greedybear.models import IOC

# FEEDS


class GeneralTestCase(TestCase):
    def test_sensors(self, *args, **kwargs):
        a = general.ExtractGeneral()
        a.execute()
        self.assertTrue(a.success)
        iocs = []
        for hp in ["heralding", "ciscoasa"]:
            iocs.extend(IOC.objects.filter(Q(general__icontains=hp)))
        self.assertTrue(iocs)
