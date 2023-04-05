from greedybear.models import Statistics, iocType, viewType

from . import CustomTestCase


class ModelsTestCase(CustomTestCase):
    def test_ioc_model(self):
        self.assertEqual(self.ioc.name, "140.246.171.141")
        self.assertEqual(self.ioc.type, iocType.IP.value)
        self.assertEqual(self.ioc.first_seen, self.current_time)
        self.assertEqual(self.ioc.last_seen, self.current_time)
        self.assertEqual(self.ioc.days_seen, [self.current_time])
        self.assertEqual(self.ioc.number_of_days_seen, 1)
        self.assertEqual(self.ioc.times_seen, 1)
        self.assertEqual(self.ioc.log4j, True)
        self.assertEqual(self.ioc.cowrie, True)
        self.assertEqual(self.ioc.scanner, True)
        self.assertEqual(self.ioc.payload_request, True)
        self.assertEqual(self.ioc.related_urls, [])

        self.assertIn(self.heralding, self.ioc.general_honeypot.all())
        self.assertIn(self.ciscoasa, self.ioc.general_honeypot.all())

    def test_statistics_model(self):
        self.statistic = Statistics.objects.create(source="140.246.171.141", view=viewType.ENRICHMENT_VIEW.value, request_date=self.current_time)
        self.assertEqual(self.statistic.source, "140.246.171.141")
        self.assertEqual(self.statistic.view, viewType.ENRICHMENT_VIEW.value)
        self.assertEqual(self.statistic.request_date, self.current_time)

    def test_general_honeypot_model(self):
        self.assertEqual(self.heralding.name, "Heralding")
        self.assertEqual(self.heralding.active, True)
