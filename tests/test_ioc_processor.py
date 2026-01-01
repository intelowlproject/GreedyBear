from datetime import date, datetime
from unittest.mock import patch

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.extraction.ioc_processor import IocProcessor
from greedybear.models import iocType

from . import ExtractionTestCase


class TestAddIoc(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.processor = IocProcessor(self.mock_ioc_repo, self.mock_sensor_repo)

    def test_filters_sensor_ips(self):
        self.mock_sensor_repo.sensors = {"192.168.1.1"}
        ioc = self._create_mock_ioc(name="192.168.1.1")

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.assertIsNone(result)
        self.mock_ioc_repo.save.assert_not_called()

    @patch("greedybear.cronjobs.extraction.ioc_processor.is_whatsmyip_domain")
    def test_filters_whatsmyip_domains(self, mock_whatsmyip):
        mock_whatsmyip.return_value = True
        self.mock_sensor_repo.sensors = set()
        ioc = self._create_mock_ioc(name="some.domain.com", ioc_type=iocType.DOMAIN)

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.assertIsNone(result)
        mock_whatsmyip.assert_called_once_with("some.domain.com")
        self.mock_ioc_repo.save.assert_not_called()

    def test_creates_new_ioc_when_not_exists(self):
        self.mock_sensor_repo.sensors = set()
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        new_ioc = self._create_mock_ioc()
        self.mock_ioc_repo.save.return_value = new_ioc

        result = self.processor.add_ioc(new_ioc, attack_type=SCANNER)

        self.mock_ioc_repo.get_ioc_by_name.assert_called_once_with("1.2.3.4")
        self.mock_ioc_repo.save.assert_called()
        self.assertIsNotNone(result)

    def test_updates_existing_ioc_when_exists(self):
        self.mock_sensor_repo.sensors = set()
        existing_ioc = self._create_mock_ioc(attack_count=5)
        self.mock_ioc_repo.get_ioc_by_name.return_value = existing_ioc
        new_ioc = self._create_mock_ioc(attack_count=1)
        self.mock_ioc_repo.save.return_value = existing_ioc

        result = self.processor.add_ioc(new_ioc, attack_type=SCANNER)

        self.mock_ioc_repo.get_ioc_by_name.assert_called_once_with("1.2.3.4")
        self.assertEqual(result.attack_count, 6)

    def test_sets_scanner_flag_for_scanner_attack_type(self):
        self.mock_sensor_repo.sensors = set()
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc()
        self.mock_ioc_repo.save.return_value = ioc

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.assertTrue(result.scanner)
        self.assertFalse(result.payload_request)

    def test_sets_payload_request_flag_for_payload_attack_type(self):
        self.mock_sensor_repo.sensors = set()
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc()
        self.mock_ioc_repo.save.return_value = ioc

        result = self.processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST)

        self.assertFalse(result.scanner)
        self.assertTrue(result.payload_request)

    def test_adds_general_honeypot_when_provided(self):
        self.mock_sensor_repo.sensors = set()
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc()
        self.mock_ioc_repo.save.return_value = ioc
        self.mock_ioc_repo.add_honeypot_to_ioc.return_value = ioc

        self.processor.add_ioc(ioc, attack_type=SCANNER, general_honeypot_name="TestHoneypot")

        self.mock_ioc_repo.add_honeypot_to_ioc.assert_called_once_with("TestHoneypot", ioc)

    def test_skips_general_honeypot_when_not_provided(self):
        self.mock_sensor_repo.sensors = set()
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc()
        self.mock_ioc_repo.save.return_value = ioc

        self.processor.add_ioc(ioc, attack_type=SCANNER, general_honeypot_name=None)

        self.mock_ioc_repo.add_honeypot_to_ioc.assert_not_called()

    def test_updates_days_seen_on_add(self):
        self.mock_sensor_repo.sensors = set()
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc(days_seen=[], last_seen=datetime(2025, 1, 1, 12, 0, 0))
        self.mock_ioc_repo.save.return_value = ioc

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.assertEqual(len(result.days_seen), 1)
        self.assertEqual(result.number_of_days_seen, 1)

    def test_full_create_flow(self):
        self.mock_sensor_repo.sensors = set()
        self.mock_ioc_repo.get_ioc_by_name.return_value = None

        ioc = self._create_mock_ioc(
            name="1.2.3.4",
            related_urls=["http://example.com"],
            destination_ports=[80, 443],
            days_seen=[],
            last_seen=datetime(2025, 1, 1, 12, 0, 0),
        )
        self.mock_ioc_repo.save.return_value = ioc

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.mock_ioc_repo.get_ioc_by_name.assert_called_once()
        self.assertEqual(self.mock_ioc_repo.save.call_count, 2)  # Once for create, once at end
        self.assertTrue(result.scanner)
        self.assertEqual(len(result.days_seen), 1)

    def test_full_update_flow(self):
        self.mock_sensor_repo.sensors = set()

        existing = self._create_mock_ioc(
            attack_count=5,
            interaction_count=10,
            related_urls=["http://a.com"],
            destination_ports=[80],
            days_seen=[date(2025, 1, 1)],
            last_seen=datetime(2025, 1, 1, 12, 0, 0),
        )
        self.mock_ioc_repo.get_ioc_by_name.return_value = existing

        new = self._create_mock_ioc(
            attack_count=1,
            interaction_count=5,
            related_urls=["http://b.com"],
            destination_ports=[443],
            last_seen=datetime(2025, 1, 2, 12, 0, 0),
        )

        self.mock_ioc_repo.save.return_value = existing

        result = self.processor.add_ioc(new, attack_type=PAYLOAD_REQUEST)

        self.assertEqual(result.attack_count, 6)
        self.assertEqual(result.interaction_count, 15)
        self.assertEqual(len(result.related_urls), 2)
        self.assertEqual(len(result.destination_ports), 2)
        self.assertEqual(len(result.days_seen), 2)
        self.assertTrue(result.payload_request)

    @patch("greedybear.cronjobs.extraction.ioc_processor.is_whatsmyip_domain")
    def test_only_checks_whatsmyip_for_domains(self, mock_whatsmyip):
        self.mock_sensor_repo.sensors = set()
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc(name="1.2.3.4", ioc_type=iocType.IP)
        self.mock_ioc_repo.save.return_value = ioc

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        mock_whatsmyip.assert_not_called()
        self.assertIsNotNone(result)


class TestMergeIocs(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.processor = IocProcessor(self.mock_ioc_repo, self.mock_sensor_repo)

    def test_increment_and_add(self):
        existing = self._create_mock_ioc(
            attack_count=5,
            interaction_count=10,
            login_attempts=5,
        )
        new = self._create_mock_ioc(
            attack_count=1,
            interaction_count=3,
            login_attempts=2,
        )

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.attack_count, 6)
        self.assertEqual(result.interaction_count, 13)
        self.assertEqual(result.login_attempts, 7)

    def test_deduplication(self):
        existing = self._create_mock_ioc(
            related_urls=["http://a.com", "http://b.com"],
            destination_ports=[80, 443],
        )
        new = self._create_mock_ioc(
            related_urls=["http://b.com", "http://c.com"],
            destination_ports=[443, 8080],
        )

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(
            sorted(result.related_urls),
            ["http://a.com", "http://b.com", "http://c.com"],
        )
        self.assertEqual(result.destination_ports, [80, 443, 8080])

    def test_updating(self):
        old_time = datetime(2025, 1, 1, 12, 0, 0)
        new_time = datetime(2025, 1, 2, 12, 0, 0)
        existing = self._create_mock_ioc(last_seen=old_time, ip_reputation="old", asn=12)
        new = self._create_mock_ioc(last_seen=new_time, ip_reputation="new", asn=23)

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.last_seen, new_time)
        self.assertEqual(result.ip_reputation, "new")
        self.assertEqual(result.asn, 23)

    def test_handles_empty_urls_and_ports(self):
        existing = self._create_mock_ioc(related_urls=[], destination_ports=[])
        new = self._create_mock_ioc(related_urls=[], destination_ports=[])

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.related_urls, [])
        self.assertEqual(result.destination_ports, [])


class TestUpdateDaysSeen(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.processor = IocProcessor(self.mock_ioc_repo, self.mock_sensor_repo)

    def test_appends_new_date(self):
        ioc = self._create_mock_ioc(
            days_seen=[date(2025, 1, 1)],
            last_seen=datetime(2025, 1, 2, 12, 0, 0),
        )
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)

        self.assertIn(date(2025, 1, 2), result.days_seen)
        self.assertEqual(result.number_of_days_seen, 2)

    def test_skips_duplicate_date(self):
        ioc = self._create_mock_ioc(
            days_seen=[date(2025, 1, 2)],
            last_seen=datetime(2025, 1, 2, 15, 0, 0),
        )
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)

        self.assertEqual(len(result.days_seen), 1)
        self.assertEqual(result.number_of_days_seen, 1)

    def test_handles_empty_days_seen(self):
        ioc = self._create_mock_ioc(
            days_seen=[],
            last_seen=datetime(2025, 1, 1, 12, 0, 0),
        )
        ioc.number_of_days_seen = 0

        result = self.processor._update_days_seen(ioc)

        self.assertEqual(len(result.days_seen), 1)
        self.assertEqual(result.number_of_days_seen, 1)
        self.assertIn(date(2025, 1, 1), result.days_seen)

    def test_multiple_updates_same_day(self):
        ioc = self._create_mock_ioc(
            days_seen=[date(2025, 1, 1)],
            last_seen=datetime(2025, 1, 1, 12, 0, 0),
        )
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)
        self.assertEqual(len(result.days_seen), 1)

        result.last_seen = datetime(2025, 1, 1, 18, 0, 0)
        result = self.processor._update_days_seen(result)
        self.assertEqual(len(result.days_seen), 1)

    def test_handles_date_boundaries(self):
        ioc = self._create_mock_ioc(
            days_seen=[date(2025, 1, 1)],
            last_seen=datetime(2025, 1, 1, 23, 59, 59),
        )
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)
        self.assertEqual(len(result.days_seen), 1)

        result.last_seen = datetime(2025, 1, 2, 0, 0, 0)
        result = self.processor._update_days_seen(result)
        self.assertEqual(len(result.days_seen), 2)
