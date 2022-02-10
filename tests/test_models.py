import datetime
from django.test import TestCase
from greedybear.models import IOC


class ModelsTestCase(TestCase):
    def test_ioc_model(self):
        current_time = datetime.datetime.now()
        ioc = IOC.objects.create(
            name="testing_ioc",
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
        self.assertEqual(ioc.name, "testing_ioc")
        self.assertEqual(ioc.type, "testing_type")
        self.assertEqual(ioc.first_seen, current_time)
        self.assertEqual(ioc.last_seen, current_time)
        self.assertEqual(ioc.days_seen, [current_time])
        self.assertEqual(ioc.number_of_days_seen, 1)
        self.assertEqual(ioc.times_seen, 1)
        self.assertEqual(ioc.log4j, True)
        self.assertEqual(ioc.cowrie, True)
        self.assertEqual(ioc.scanner, True)
        self.assertEqual(ioc.payload_request, True)
        self.assertEqual(ioc.related_urls, [])
