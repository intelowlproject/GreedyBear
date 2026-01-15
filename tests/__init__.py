from datetime import datetime
from hashlib import sha256

from certego_saas.apps.user.models import User
from django.test import TestCase
from greedybear.models import IOC, CommandSequence, CowrieSession, GeneralHoneypot, iocType


class CustomTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        super(CustomTestCase, cls).setUpTestData()

        cls.heralding = GeneralHoneypot.objects.create(name="Heralding", active=True)
        cls.ciscoasa = GeneralHoneypot.objects.create(name="Ciscoasa", active=True)

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
            log4j=True,
            cowrie=True,
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
            log4j=True,
            cowrie=True,
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
            log4j=False,
            cowrie=True,
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

        cls.ioc.general_honeypot.add(cls.heralding)  # FEEDS
        cls.ioc.general_honeypot.add(cls.ciscoasa)  # FEEDS
        cls.ioc.save()
        cls.ioc_2.general_honeypot.add(cls.heralding)  # FEEDS
        cls.ioc_2.general_honeypot.add(cls.ciscoasa)  # FEEDS
        cls.ioc_2.save()

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


class ExtractionTestCase(TestCase):
    """
    Base class for extraction/integration tests that require
    a live ElasticSearch connection (only_manual tests).

    These tests are run manually and not part of CI.
    They use Django's TestCase for proper database transaction handling.

    WARNING: ElasticSearch operations are NOT rolled back after tests.
    Django's TestCase only handles Postgres transaction rollback.
    Any data written to ElasticSearch during tests will persist.
    Consider manual cleanup of ES indices if needed.

    NOTE: Running these tests requires the Postgres user to have
    CREATEDB privileges to create the test database.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Common setup for extraction tests can go here

    @classmethod
    def tearDownClass(cls):
        # Common cleanup for extraction tests
        # NOTE: This does NOT clean up ElasticSearch data
        super().tearDownClass()
