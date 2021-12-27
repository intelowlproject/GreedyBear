# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from unittest import TestCase

from greedybear.cronjobs import sensors
from greedybear.models import Sensors


class SensorsTestCase(TestCase):
    def test_sensors(self, *args, **kwargs):
        s = sensors.ExtractSensors()
        s.execute()
        self.assertTrue(s.success)
        s_ob = Sensors.objects.all()
        self.assertTrue(s_ob)
