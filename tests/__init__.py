from datetime import datetime

from certego_saas.apps.user.models import User
from django.test import TestCase
from greedybear.models import IOC, CowrieSession, GeneralHoneypot, iocType


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
            attack_count=1,
            interaction_count=1,
            log4j=True,
            cowrie=True,
            scanner=True,
            payload_request=True,
            related_urls=[],
            ip_reputation="mass scanner",
            asn="12345",
            destination_ports=[22, 23, 24],
            login_attempts=1,
        )

        cls.ioc.general_honeypot.add(cls.heralding)  # FEEDS
        cls.ioc.general_honeypot.add(cls.ciscoasa)  # FEEDS
        cls.ioc.save()

        cls.cowrie_session = CowrieSession.objects.create(
            session_id=int("ffffffffffff", 16),
            start_time=cls.current_time,
            duration=1.234,
            login_attempt=True,
            credentials=["root | root"],
            command_execution=False,
            interaction_count=5,
            source=cls.ioc,
        )
        cls.cowrie_session.save()

        try:
            cls.superuser = User.objects.get(is_superuser=True)
        except User.DoesNotExist:
            cls.superuser = User.objects.create_superuser(username="test", email="test@greedybear.com", password="test")

    @classmethod
    def tearDownClass(self):
        # db clean
        GeneralHoneypot.objects.all().delete()
        IOC.objects.all().delete()
