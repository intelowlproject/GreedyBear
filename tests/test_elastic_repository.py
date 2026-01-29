from datetime import datetime
from unittest.mock import Mock, patch

from greedybear.cronjobs.repositories import ElasticRepository, get_time_window

from . import CustomTestCase


class TestElasticRepository(CustomTestCase):
    def setUp(self):
        self.mock_client = Mock()
        self.mock_client.ping.return_value = True

        patcher = patch("greedybear.cronjobs.repositories.elastic.settings")
        self.mock_settings = patcher.start()
        self.mock_settings.ELASTIC_CLIENT = self.mock_client
        self.addCleanup(patcher.stop)

        self.repo = ElasticRepository()

    @patch("greedybear.cronjobs.repositories.elastic.get_time_window")
    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_has_honeypot_been_hit_returns_true_when_hits_exist(self, mock_search_class, mock_get_time_window):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.filter.return_value = mock_search
        mock_search.count.return_value = 1
        mock_get_time_window.return_value = (datetime(2025, 1, 1), datetime(2025, 1, 1, 0, 10))

        result = self.repo.has_honeypot_been_hit(minutes_back_to_lookup=10, honeypot_name="test_honeypot")
        self.assertTrue(result)
        mock_search.query.assert_called_once()
        mock_search.filter.assert_called_once_with("term", **{"type.keyword": "test_honeypot"})
        mock_search.count.assert_called_once()

    @patch("greedybear.cronjobs.repositories.elastic.get_time_window")
    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_has_honeypot_been_hit_returns_false_when_no_hits(self, mock_search_class, mock_get_time_window):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.filter.return_value = mock_search
        mock_search.count.return_value = 0
        mock_get_time_window.return_value = (datetime(2025, 1, 1), datetime(2025, 1, 1, 0, 10))

        result = self.repo.has_honeypot_been_hit(minutes_back_to_lookup=10, honeypot_name="test_honeypot")

        self.assertFalse(result)
        mock_search.query.assert_called_once()
        mock_search.filter.assert_called_once_with("term", **{"type.keyword": "test_honeypot"})
        mock_search.count.assert_called_once()

    def test_healthcheck_passes_when_ping_succeeds(self):
        self.mock_client.ping.return_value = True
        self.repo._healthcheck()
        self.mock_client.ping.assert_called_once()

    def test_healthcheck_raises_when_ping_fails(self):
        self.mock_client.ping.return_value = False
        with self.assertRaises(ElasticRepository.ElasticServerDownError) as ctx:
            self.repo._healthcheck()
        self.assertIn("not reachable", str(ctx.exception))

    @patch("greedybear.cronjobs.repositories.elastic.get_time_window")
    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_search_yields_all_hits_across_chunks(self, mock_search_class, mock_get_time_window):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.source.return_value = mock_search

        mock_hits = [{"name": f"hit{i}", "@timestamp": i} for i in range(20_000)]
        mock_search.scan.return_value = iter(mock_hits)
        mock_get_time_window.return_value = (datetime(2025, 1, 1, 12, 0), datetime(2025, 1, 1, 12, 10))

        chunks = list(self.repo.search(minutes_back_to_lookup=10))
        all_hits = [hit for chunk in chunks for hit in chunk]
        self.assertEqual(len(all_hits), 20_000)

    @patch("greedybear.cronjobs.repositories.elastic.get_time_window")
    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_search_returns_ordered_hits_within_chunks(self, mock_search_class, mock_get_time_window):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.source.return_value = mock_search

        mock_hits = [{"name": f"hit{i}", "@timestamp": i % 7} for i in range(20_000)]
        mock_search.scan.return_value = iter(mock_hits)
        mock_get_time_window.return_value = (datetime(2025, 1, 1, 12, 0), datetime(2025, 1, 1, 12, 10))

        chunks = list(self.repo.search(minutes_back_to_lookup=10))
        for chunk in chunks:
            is_ordered = all(a["@timestamp"] <= b["@timestamp"] for a, b in zip(chunk, chunk[1:], strict=False))
            self.assertTrue(is_ordered)

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    @patch("greedybear.cronjobs.repositories.elastic.get_time_window")
    def test_search_uses_time_window(self, mock_get_time_window, mock_search_class):
        """Test extraction uses get_time_window"""
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.source.return_value = mock_search
        mock_search.scan.return_value = iter([])

        window_start = datetime(2025, 1, 1, 12, 0, 0)
        window_end = datetime(2025, 1, 1, 12, 10, 0)
        mock_get_time_window.return_value = (window_start, window_end)

        list(self.repo.search(minutes_back_to_lookup=10))

        mock_get_time_window.assert_called_once()


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
