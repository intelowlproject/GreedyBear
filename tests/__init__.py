from datetime import datetime

from certego_saas.apps.user.models import User
from django.test import TestCase
from greedybear.models import IOC, GeneralHoneypot, iocType


class CustomTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        super(CustomTestCase, cls).setUpTestData()

        cls.heralding = GeneralHoneypot.objects.create(name="Heralding", active=True)
        cls.ciscoasa = GeneralHoneypot.objects.create(name="Ciscoasa", active=True)

        cls.current_time = datetime.utcnow()
        cls.ioc = IOC.objects.create(
            name="140.246.171.141",
            type=iocType.IP.value,
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            days_seen=[cls.current_time],
            number_of_days_seen=1,
            times_seen=1,
            log4j=True,
            cowrie=True,
            scanner=True,
            payload_request=True,
            related_urls=[],
        )

        cls.ioc.general_honeypot.add(cls.heralding)  # FEEDS
        cls.ioc.general_honeypot.add(cls.ciscoasa)  # FEEDS
        cls.ioc.save()

        try:
            cls.superuser = User.objects.get(is_superuser=True)
        except User.DoesNotExist:
            cls.superuser = User.objects.create_superuser(username="test", email="test@greedybear.com", password="test")

    @classmethod
    def tearDownClass(self):
        # db clean
        GeneralHoneypot.objects.all().delete()
        IOC.objects.all().delete()
