from datetime import datetime

from greedybear.cronjobs.base import get_time_window

from . import CustomTestCase


class TimeWindowCalculationTestCase(CustomTestCase):
    def test_basic_10min_window(self):
        """Test a basic 10-minute window without additional lookback"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference, 10)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 10, 14, 10)  # 14:10

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_with_additional_lookback(self):
        """Test window with additional lookback time"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference, 10, additional_lookback=5)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 10, 14, 5)  # 14:05

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_exact_boundary(self):
        """Test behavior when reference time is exactly on a window boundary"""
        reference = datetime(2024, 1, 10, 14, 20)  # 14:20 exactly
        start, end = get_time_window(reference, 10)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 10, 14, 10)  # 14:10

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_invalid_window_size(self):
        """Test that function raises ValueError for invalid window size"""
        reference = datetime(2024, 1, 10, 14, 23)

        with self.assertRaises(ValueError):
            get_time_window(reference, 0)

    def test_day_boundary_crossing(self):
        """Test behavior when window crosses a day boundary"""
        reference = datetime(2024, 1, 11, 0, 5)  # 00:00
        start, end = get_time_window(reference, 10)

        expected_end = datetime(2024, 1, 11, 0, 0)  # 00:00
        expected_start = datetime(2024, 1, 10, 23, 50)  # 23:50 on previous day

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_non_standard_window_size(self):
        """Test with an unusual window size (7 minutes)"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference, 7)

        expected_end = datetime(2024, 1, 10, 14, 21)  # 14:21
        expected_start = datetime(2024, 1, 10, 14, 14)  # 14:14

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_large_window_size(self):
        """Test with a large window size (3 days)"""
        reference = datetime(2024, 1, 10, 14, 45)  # 14:45
        start, end = get_time_window(reference, 60)

        expected_end = datetime(2024, 1, 10, 14, 0)  # 14:00
        expected_start = datetime(2024, 1, 10, 13, 0)  # 13:00

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_large_additional_lookback(self):
        """Test with a large additional lookback that crosses multiple days"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference, 10, additional_lookback=60 * 24 * 3)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 7, 14, 10)  # 14:10, 3 days earlier

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)
