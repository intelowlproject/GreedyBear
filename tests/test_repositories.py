from datetime import datetime
from unittest.mock import Mock, patch

from greedybear.cronjobs.repositories import CowrieSessionRepository, ElasticRepository, IocRepository, SensorRepository, get_time_window
from greedybear.models import IOC, CommandSequence, CowrieSession, GeneralHoneypot, Sensor

from . import CustomTestCase


class TestIocRepository(CustomTestCase):
    def setUp(self):
        self.repo = IocRepository()

    def test_get_ioc_by_name_returns_existing(self):
        result = self.repo.get_ioc_by_name("140.246.171.141")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "140.246.171.141")

    def test_get_ioc_by_name_returns_none_for_missing(self):
        result = self.repo.get_ioc_by_name("8.8.8.8")
        self.assertIsNone(result)

    def test_save_creates_new_ioc(self):
        ioc = IOC(name="1.2.3.4", type="ip")
        result = self.repo.save(ioc)
        self.assertIsNotNone(result.pk)
        self.assertTrue(IOC.objects.filter(name="1.2.3.4").exists())

    def test_save_updates_existing_ioc(self):
        ioc = self.repo.get_ioc_by_name("140.246.171.141")
        original_attack_count = ioc.attack_count

        ioc.attack_count = 10
        result = self.repo.save(ioc)
        self.assertEqual(result.attack_count, 10)
        self.assertEqual(IOC.objects.get(name="140.246.171.141").attack_count, 10)

        ioc.attack_count = original_attack_count
        result = self.repo.save(ioc)
        self.assertEqual(result.attack_count, original_attack_count)
        self.assertEqual(IOC.objects.get(name="140.246.171.141").attack_count, original_attack_count)

    def test_create_honeypot(self):
        self.repo.create_honeypot("NewHoneypot")
        self.assertTrue(GeneralHoneypot.objects.filter(name="NewHoneypot").exists())
        hp = GeneralHoneypot.objects.get(name="NewHoneypot")
        self.assertTrue(hp.active)

    def test_get_active_honeypots_returns_only_active(self):
        GeneralHoneypot.objects.create(name="TestActivePot1", active=True)
        GeneralHoneypot.objects.create(name="TestActivePot2", active=True)
        GeneralHoneypot.objects.create(name="TestInactivePot", active=False)

        result = self.repo.get_active_honeypots()
        names = [hp.name for hp in result]

        self.assertIn("TestActivePot1", names)
        self.assertIn("TestActivePot2", names)
        self.assertNotIn("TestInactivePot", names)

    def test_get_active_honeypots_returns_empty_if_none_active(self):
        GeneralHoneypot.objects.update(active=False)

        result = self.repo.get_active_honeypots()
        self.assertEqual(len(result), 0)

        GeneralHoneypot.objects.update(active=True)

    def test_get_hp_by_name_returns_existing(self):
        GeneralHoneypot.objects.create(name="TestPot", active=True)
        result = self.repo.get_hp_by_name("TestPot")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "TestPot")

    def test_get_hp_by_name_returns_none_for_missing(self):
        result = self.repo.get_hp_by_name("nonexistent")
        self.assertIsNone(result)

    def test_is_empty_returns_false_when_has_iocs(self):
        result = self.repo.is_empty()
        self.assertFalse(result)

    def test_is_enabled_returns_true_for_cowrie(self):
        result = self.repo.is_enabled("Cowrie")
        self.assertTrue(result)

    def test_is_enabled_returns_true_for_log4pot(self):
        result = self.repo.is_enabled("Log4pot")
        self.assertTrue(result)

    def test_is_enabled_returns_true_for_active_honeypot(self):
        result = self.repo.is_enabled("Heralding")
        self.assertTrue(result)

    def test_is_enabled_returns_false_for_inactive_honeypot(self):
        result = self.repo.is_enabled("Ddospot")
        self.assertFalse(result)

    def test_add_honeypot_to_ioc_adds_new_honeypot(self):
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        honeypot = GeneralHoneypot.objects.create(name="TestPot", active=True)
        result = self.repo.add_honeypot_to_ioc("TestPot", ioc)
        self.assertIn(honeypot, result.general_honeypot.all())

    def test_add_honeypot_to_ioc_idempotent(self):
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        honeypot = GeneralHoneypot.objects.create(name="TestPot", active=True)
        ioc.general_honeypot.add(honeypot)
        initial_count = ioc.general_honeypot.count()
        result = self.repo.add_honeypot_to_ioc("TestPot", ioc)
        self.assertEqual(result.general_honeypot.count(), initial_count)
        self.assertEqual(ioc.general_honeypot.count(), 1)

    def test_add_honeypot_to_ioc_multiple_honeypots(self):
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        hp1 = GeneralHoneypot.objects.create(name="Pot1", active=True)
        hp2 = GeneralHoneypot.objects.create(name="Pot2", active=True)
        self.repo.add_honeypot_to_ioc("Pot1", ioc)
        self.repo.add_honeypot_to_ioc("Pot2", ioc)
        self.assertEqual(ioc.general_honeypot.count(), 2)
        self.assertIn(hp1, ioc.general_honeypot.all())
        self.assertIn(hp2, ioc.general_honeypot.all())

    def test_existing_honeypots(self):
        self.assertIn("Cowrie", self.repo._honeypot_cache)
        self.assertIn("Log4pot", self.repo._honeypot_cache)
        self.assertIn("Heralding", self.repo._honeypot_cache)
        self.assertIn("Ciscoasa", self.repo._honeypot_cache)
        self.assertIn("Ddospot", self.repo._honeypot_cache)

    def test_is_ready_for_extraction_creates_and_enables(self):
        self.repo._honeypot_cache["foopot"] = True
        result = self.repo.is_ready_for_extraction("FooPot")
        self.assertTrue(result)


class TestSensorRepository(CustomTestCase):
    def setUp(self):
        self.repo = SensorRepository()

    def test_sensors_property_returns_cached_sensors(self):
        self.repo.add_sensor("192.168.1.1")
        self.repo.add_sensor("192.168.1.2")
        result = self.repo.sensors
        self.assertEqual(len(result), 2)
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.2", result)

    def test_add_sensor_creates_new_sensor(self):
        result = self.repo.add_sensor("192.168.1.3")
        self.assertTrue(result)
        self.assertTrue(Sensor.objects.filter(address="192.168.1.3").exists())
        self.assertIn("192.168.1.3", self.repo.cache)

    def test_add_sensor_returns_false_for_existing_sensor(self):
        self.repo.add_sensor("192.168.1.1")
        result = self.repo.add_sensor("192.168.1.1")
        self.assertFalse(result)
        self.assertEqual(Sensor.objects.filter(address="192.168.1.1").count(), 1)

    def test_add_sensor_rejects_non_ip(self):
        result = self.repo.add_sensor("not-an-ip")
        self.assertFalse(result)
        self.assertFalse(Sensor.objects.filter(address="not-an-ip").exists())

    def test_add_sensor_rejects_domain(self):
        result = self.repo.add_sensor("example.com")
        self.assertFalse(result)
        self.assertFalse(Sensor.objects.filter(address="example.com").exists())

    def test_cache_populated_on_init(self):
        Sensor.objects.create(address="192.168.1.1")
        Sensor.objects.create(address="192.168.1.2")
        repo = SensorRepository()
        self.assertEqual(len(repo.cache), 2)
        self.assertIn("192.168.1.1", repo.cache)
        self.assertIn("192.168.1.2", repo.cache)

    def test_add_sensor_updates_cache(self):
        initial_cache_size = len(self.repo.cache)
        self.repo.add_sensor("192.168.1.1")
        self.assertEqual(len(self.repo.cache), initial_cache_size + 1)

    def test_add_sensor_accepts_valid_ipv4(self):
        test_ips = ["1.2.3.4", "192.168.1.1", "10.0.0.1", "8.8.8.8"]
        for ip in test_ips:
            result = self.repo.add_sensor(ip)
            self.assertTrue(result)


class TestCowrieSessionRepository(CustomTestCase):
    def setUp(self):
        self.repo = CowrieSessionRepository()

    def test_get_or_create_session_creates_new(self):
        source_ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        result = self.repo.get_or_create_session(session_id="123456", source=source_ioc)
        self.assertIsNotNone(result)
        self.assertEqual(result.session_id, int("123456", 16))
        self.assertEqual(result.source, source_ioc)

    def test_get_or_create_session_returns_existing(self):
        existing_session_id = "ffffffffffff"
        source = self.cowrie_session.source
        result = self.repo.get_or_create_session(existing_session_id, source=source)
        self.assertEqual(result.pk, int(existing_session_id, 16))
        self.assertTrue(result.login_attempt)

    def test_get_or_create_raises_on_invalid_session_id(self):
        session_id = "gggggggggggg"
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        with self.assertRaises(ValueError):
            self.repo.get_or_create_session(session_id, source=source)

    def test_save_session_persists_to_database(self):
        source_ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        session = CowrieSession(session_id=12345, source=source_ioc)
        result = self.repo.save_session(session)
        self.assertIsNotNone(result.pk)
        self.assertTrue(CowrieSession.objects.filter(session_id=12345).exists())

    def test_save_session_updates_existing(self):
        existing_session_id = "ffffffffffff"
        source = self.cowrie_session.source
        session = self.repo.get_or_create_session(existing_session_id, source=source)

        original_interaction_count = session.interaction_count
        session.interaction_count = 10
        result = self.repo.save_session(session)
        self.assertEqual(result.interaction_count, 10)
        self.assertEqual(CowrieSession.objects.get(session_id=int(existing_session_id, 16)).interaction_count, 10)

        session.interaction_count = original_interaction_count
        result = self.repo.save_session(session)
        self.assertEqual(result.interaction_count, original_interaction_count)
        self.assertEqual(CowrieSession.objects.get(session_id=int(existing_session_id, 16)).interaction_count, original_interaction_count)

    def test_get_command_sequence_by_hash_returns_existing(self):
        existing = self.command_sequence
        result = self.repo.get_command_sequence_by_hash(existing.commands_hash)
        self.assertIsNotNone(result)
        self.assertEqual(result.pk, existing.pk)
        self.assertEqual(result.commands_hash, existing.commands_hash)

    def test_get_command_sequence_by_hash_returns_none_for_missing(self):
        result = self.repo.get_command_sequence_by_hash("nonexistent")
        self.assertIsNone(result)

    def test_save_command_sequence_persists_to_database(self):
        cmd_seq = CommandSequence(
            commands=["ls", "pwd", "whoami"],
            commands_hash="def456",
        )
        result = self.repo.save_command_sequence(cmd_seq)
        self.assertIsNotNone(result.pk)
        self.assertTrue(CommandSequence.objects.filter(commands_hash="def456").exists())

    def test_save_command_sequence_updates_existing(self):
        existing = self.command_sequence
        existing.last_seen = datetime(2025, 1, 2)
        self.repo.save_command_sequence(existing)
        updated = CommandSequence.objects.get(commands_hash=existing.commands_hash)
        self.assertEqual(updated.last_seen.date(), datetime(2025, 1, 2).date())

    def test_get_or_create_session_with_hex_session_id(self):
        session_id = "abc123"
        source_ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        result = self.repo.get_or_create_session(session_id=session_id, source=source_ioc)
        self.assertEqual(result.session_id, int(session_id, 16))

    def test_command_sequence_unique_hash_constraint(self):
        existing = self.command_sequence
        with self.assertRaises(Exception):
            CommandSequence.objects.create(
                commands=["different", "commands"],
                commands_hash=existing.commands_hash,
            )


class TestElasticRepository(CustomTestCase):
    def setUp(self):
        self.mock_client = Mock()
        self.mock_client.ping.return_value = True

        patcher = patch("greedybear.cronjobs.repositories.elastic.settings")
        self.mock_settings = patcher.start()
        self.mock_settings.ELASTIC_CLIENT = self.mock_client
        self.addCleanup(patcher.stop)

        self.repo = ElasticRepository()

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_has_honeypot_been_hit_returns_true_when_hits_exist(self, mock_search_class):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_q = Mock()
        with patch.object(self.repo, "_standard_query", return_value=mock_q):
            mock_search.query.return_value = mock_search
            mock_search.filter.return_value = mock_search
            mock_search.count.return_value = 1

            result = self.repo.has_honeypot_been_hit(minutes_back_to_lookup=10, honeypot_name="test_honeypot")
            self.assertTrue(result)
            mock_search.query.assert_called_once_with(mock_q)
            mock_search.filter.assert_called_once_with("term", **{"type.keyword": "test_honeypot"})
            mock_search.count.assert_called_once()

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_has_honeypot_been_hit_returns_false_when_no_hits(self, mock_search_class):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_q = Mock()
        with patch.object(self.repo, "_standard_query", return_value=mock_q):
            mock_search.query.return_value = mock_search
            mock_search.filter.return_value = mock_search
            mock_search.count.return_value = 0

            result = self.repo.has_honeypot_been_hit(minutes_back_to_lookup=10, honeypot_name="test_honeypot")

            self.assertFalse(result)
            mock_search.query.assert_called_once_with(mock_q)
            mock_search.filter.assert_called_once_with("term", **{"type.keyword": "test_honeypot"})
            mock_search.count.assert_called_once()

    def test_healthcheck_passes_when_ping_succeeds(self):
        self.mock_client.ping.return_value = True
        self.repo._healthcheck()
        self.mock_client.ping.assert_called_once()

    def test_healthcheck_raises_when_ping_fails(self):
        self.mock_client.ping.return_value = False
        with self.assertRaises(ElasticRepository.ElasticServerDownException) as ctx:
            self.repo._healthcheck()
        self.assertIn("not reachable", str(ctx.exception))

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    @patch("greedybear.cronjobs.repositories.elastic.LEGACY_EXTRACTION", False)
    def test_search_returns_cached_list_not_generator(self, mock_search_class):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.source.return_value = mock_search

        mock_hits = [{"name": f"hit{i}", "@timestamp": i} for i in range(20_000)]
        mock_search.scan.return_value = iter(mock_hits)

        first_iteration = list(self.repo.search(minutes_back_to_lookup=10))
        second_iteration = list(self.repo.search(minutes_back_to_lookup=10))
        self.assertEqual(len(first_iteration), 20_000)
        self.assertEqual(len(second_iteration), 20_000)

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    @patch("greedybear.cronjobs.repositories.elastic.LEGACY_EXTRACTION", False)
    def test_search_returns_ordered_list(self, mock_search_class):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.source.return_value = mock_search

        mock_hits = [{"name": f"hit{i}", "@timestamp": i % 7} for i in range(20_000)]
        mock_search.scan.return_value = iter(mock_hits)

        result = list(self.repo.search(minutes_back_to_lookup=10))
        is_ordered = all(a["@timestamp"] <= b["@timestamp"] for a, b in zip(result, result[1:]))
        self.assertTrue(is_ordered)

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    @patch("greedybear.cronjobs.repositories.elastic.LEGACY_EXTRACTION", True)
    def test_search_legacy_mode_uses_relative_time(self, mock_search_class):
        """Test legacy extraction uses relative time queries"""
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.source.return_value = mock_search
        mock_search.scan.return_value = iter([])

        # Verify query was called (legacy mode uses different query structure)
        self.repo.search(minutes_back_to_lookup=11)
        mock_search.query.assert_called_once()

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    @patch("greedybear.cronjobs.repositories.elastic.LEGACY_EXTRACTION", False)
    @patch("greedybear.cronjobs.repositories.elastic.get_time_window")
    def test_search_non_legacy_uses_time_window(self, mock_get_time_window, mock_search_class):
        """Test non-legacy extraction uses get_time_window"""
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.source.return_value = mock_search
        mock_search.scan.return_value = iter([])

        window_start = datetime(2025, 1, 1, 12, 0, 0)
        window_end = datetime(2025, 1, 1, 12, 10, 0)
        mock_get_time_window.return_value = (window_start, window_end)

        self.repo.search(minutes_back_to_lookup=10)

        mock_get_time_window.assert_called_once()

    @patch("greedybear.cronjobs.repositories.elastic.get_time_window")
    @patch("greedybear.cronjobs.repositories.elastic.datetime")
    def test_standard_query_returns_correct_query(self, mock_datetime, mock_get_time_window):
        now = datetime(2023, 1, 1, 0, 0, 0)
        mock_datetime.now.return_value = now
        window_start = "2022-12-31T23:50:00"
        window_end = "2023-01-01T00:00:00"
        mock_get_time_window.return_value = (window_start, window_end)

        q = self.repo._standard_query(minutes_back_to_lookup=10)

        expected_dict = {"range": {"@timestamp": {"gte": window_start, "lt": window_end}}}
        self.assertEqual(q.to_dict(), expected_dict)
        mock_get_time_window.assert_called_once_with(now, 10)


class TestTimeWindowCalculation(CustomTestCase):
    def test_basic_10min_window(self):
        """Test a basic window without custom lookback"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference, lookback_minutes=10, extraction_interval=10)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 10, 14, 10)  # 14:10

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_with_custom_lookback(self):
        """Test window with custom lookback time"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference, lookback_minutes=15, extraction_interval=10)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 10, 14, 5)  # 14:05

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_with_custom_extraction_interval(self):
        """Test window with custom extraction interval time"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference, lookback_minutes=15, extraction_interval=15)

        expected_end = datetime(2024, 1, 10, 14, 15)  # 14:15
        expected_start = datetime(2024, 1, 10, 14, 00)  # 14:00

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_exact_boundary(self):
        """Test behavior when reference time is exactly on a window boundary"""
        reference = datetime(2024, 1, 10, 14, 20)  # 14:20 exactly
        start, end = get_time_window(reference, lookback_minutes=10, extraction_interval=10)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 10, 14, 10)  # 14:10

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_invalid_lookback(self):
        """Test that function raises ValueError for invalid lookback"""
        reference = datetime(2024, 1, 10, 14, 23)

        with self.assertRaises(ValueError):
            get_time_window(reference, lookback_minutes=5, extraction_interval=10)

    def test_invalid_extraction_interval(self):
        """Test that function raises ValueError for invalid extraction interval"""
        reference = datetime(2024, 1, 10, 14, 23)

        with self.assertRaises(ValueError):
            get_time_window(reference, lookback_minutes=10, extraction_interval=9)

    def test_day_boundary_crossing(self):
        """Test behavior when window crosses a day boundary"""
        reference = datetime(2024, 1, 11, 0, 5)  # 00:00
        start, end = get_time_window(reference, lookback_minutes=10, extraction_interval=10)

        expected_end = datetime(2024, 1, 11, 0, 0)  # 00:00
        expected_start = datetime(2024, 1, 10, 23, 50)  # 23:50 on previous day

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_large_lookback(self):
        """Test with a large lookback that crosses multiple days"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference, lookback_minutes=60 * 24 * 3, extraction_interval=10)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 7, 14, 20)  # 14:20, 3 days earlier

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)
