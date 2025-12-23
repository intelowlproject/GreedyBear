from datetime import datetime
from hashlib import sha256
from unittest.mock import Mock

from certego_saas.apps.user.models import User
from django.test import TestCase
from greedybear.models import IOC, CommandSequence, CowrieSession, GeneralHoneypot, iocType


class CustomTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        super(CustomTestCase, cls).setUpTestData()

        cls.heralding = GeneralHoneypot.objects.create(name="Heralding", active=True)
        cls.ciscoasa = GeneralHoneypot.objects.create(name="Ciscoasa", active=True)
        cls.ddospot = GeneralHoneypot.objects.create(name="Ddospot", active=False)
        cls.log4pot = GeneralHoneypot.objects.create(name="Log4Pot", active=True)
        cls.cowrie = GeneralHoneypot.objects.create(name="Cowrie", active=True)

        cls.current_time = datetime.now()
        cls.ioc = IOC.objects.create(
            name="140.246.171.141",
            type=iocType.IP.value,
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            days_seen=[cls.current_time],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            scanner=True,
            payload_request=True,
            related_urls=[],
            ip_reputation="",
            asn="12345",
            destination_ports=[22, 23, 24],
            login_attempts=1,
            recurrence_probability=0.1,
            expected_interactions=11.1,
        )

        cls.ioc_2 = IOC.objects.create(
            name="99.99.99.99",
            type=iocType.IP.value,
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            days_seen=[cls.current_time],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            scanner=True,
            payload_request=True,
            related_urls=[],
            ip_reputation="mass scanner",
            asn="12345",
            destination_ports=[22, 23, 24],
            login_attempts=1,
            recurrence_probability=0.1,
            expected_interactions=11.1,
        )

        cls.ioc_3 = IOC.objects.create(
            name="100.100.100.100",
            type=iocType.IP.value,
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            days_seen=[cls.current_time],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            scanner=True,
            payload_request=True,
            related_urls=[],
            ip_reputation="tor exit node",
            asn="12345",
            destination_ports=[22, 23, 24],
            login_attempts=1,
            recurrence_probability=0.1,
            expected_interactions=11.1,
        )

        cls.ioc_domain = IOC.objects.create(
            name="malicious.example.com",
            type=iocType.DOMAIN.value,
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            days_seen=[cls.current_time],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            scanner=False,
            payload_request=True,
            related_urls=[],
            ip_reputation="",
            asn=None,
            destination_ports=[],
            login_attempts=0,
            recurrence_probability=0.2,
            expected_interactions=5.5,
        )

        cls.ioc.general_honeypot.add(cls.heralding)  # FEEDS
        cls.ioc.general_honeypot.add(cls.ciscoasa)  # FEEDS
        cls.ioc.general_honeypot.add(cls.log4pot)
        cls.ioc.general_honeypot.add(cls.cowrie)
        cls.ioc.save()
        cls.ioc_2.general_honeypot.add(cls.heralding)  # FEEDS
        cls.ioc_2.general_honeypot.add(cls.ciscoasa)  # FEEDS
        cls.ioc_2.general_honeypot.add(cls.log4pot)
        cls.ioc_2.general_honeypot.add(cls.cowrie)
        cls.ioc_2.save()
        cls.ioc_3.general_honeypot.add(cls.cowrie)
        cls.ioc_3.general_honeypot.add(cls.log4pot)
        cls.ioc_domain.general_honeypot.add(cls.heralding)  # FEEDS
        cls.ioc_domain.general_honeypot.add(cls.log4pot)
        cls.ioc_domain.save()

        cls.cmd_seq = ["cd foo", "ls -la"]
        cls.hash = sha256("\n".join(cls.cmd_seq).encode()).hexdigest()
        cls.command_sequence = CommandSequence.objects.create(
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            commands=cls.cmd_seq,
            commands_hash=cls.hash,
            cluster=11,
        )
        cls.command_sequence.save()

        cls.cowrie_session = CowrieSession.objects.create(
            session_id=int("ffffffffffff", 16),
            start_time=cls.current_time,
            duration=1.234,
            login_attempt=True,
            credentials=["root | root"],
            command_execution=True,
            interaction_count=5,
            source=cls.ioc,
            commands=cls.command_sequence,
        )
        cls.cowrie_session.save()

        cls.cmd_seq_2 = ["cd bar", "ls -la"]
        cls.command_sequence_2 = CommandSequence.objects.create(
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            commands=cls.cmd_seq_2,
            commands_hash=sha256("\n".join(cls.cmd_seq_2).encode()).hexdigest(),
            cluster=11,
        )
        cls.command_sequence_2.save()

        cls.cowrie_session_2 = CowrieSession.objects.create(
            session_id=int("eeeeeeeeeeee", 16),
            start_time=cls.current_time,
            duration=2.234,
            login_attempt=True,
            credentials=["user | user"],
            command_execution=True,
            interaction_count=5,
            source=cls.ioc_2,
            commands=cls.command_sequence_2,
        )
        cls.cowrie_session_2.save()

        try:
            cls.superuser = User.objects.get(is_superuser=True)
        except User.DoesNotExist:
            cls.superuser = User.objects.create_superuser(username="test", email="test@greedybear.com", password="test")
        try:
            cls.regular_user = User.objects.get(is_superuser=False)
        except User.DoesNotExist:
            cls.regular_user = User.objects.create_user(username="regular", email="regular@greedybear.com", password="regular")

    @classmethod
    def tearDownClass(self):
        # db clean
        GeneralHoneypot.objects.all().delete()
        IOC.objects.all().delete()
        CowrieSession.objects.all().delete()
        CommandSequence.objects.all().delete()


class ExtractionTestCase(CustomTestCase):
    def setUp(self):
        self.mock_ioc_repo = Mock()
        self.mock_sensor_repo = Mock()
        self.mock_session_repo = Mock()

    def _create_mock_ioc(
        self,
        name="1.2.3.4",
        ioc_type="ip",
        attack_count=1,
        interaction_count=1,
        related_urls=[],
        destination_ports=[],
        login_attempts=0,
        days_seen=[],
        last_seen=datetime.now(),
        ip_reputation="",
        asn=1234,
    ):
        mock = Mock(spec=IOC)
        mock.name = name
        mock.type = ioc_type
        mock.scanner = False
        mock.payload_request = False
        mock.attack_count = attack_count
        mock.interaction_count = interaction_count
        mock.related_urls = related_urls
        mock.destination_ports = destination_ports
        mock.days_seen = days_seen
        mock.login_attempts = login_attempts
        mock.last_seen = last_seen
        mock.ip_reputation = ip_reputation
        mock.asn = asn
        mock.number_of_days_seen = len(mock.days_seen)
        return mock
