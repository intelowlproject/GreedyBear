from datetime import datetime

from greedybear.cronjobs.base import get_time_window

from . import CustomTestCase


class TimeWindowCalculationTestCase(CustomTestCase):
    def test_basic_10min_window(self):
        """Test a basic window without custom lookback"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 10, 14, 10)  # 14:10

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_with_custom_lookback(self):
        """Test window with custom lookback time"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference, lookback_minutes=15)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 10, 14, 5)  # 14:05

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_exact_boundary(self):
        """Test behavior when reference time is exactly on a window boundary"""
        reference = datetime(2024, 1, 10, 14, 20)  # 14:20 exactly
        start, end = get_time_window(reference)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 10, 14, 10)  # 14:10

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_invalid_lookback(self):
        """Test that function raises ValueError for invalid lookback"""
        reference = datetime(2024, 1, 10, 14, 23)

        with self.assertRaises(ValueError):
            get_time_window(reference, 5)

    def test_day_boundary_crossing(self):
        """Test behavior when window crosses a day boundary"""
        reference = datetime(2024, 1, 11, 0, 5)  # 00:00
        start, end = get_time_window(reference)

        expected_end = datetime(2024, 1, 11, 0, 0)  # 00:00
        expected_start = datetime(2024, 1, 10, 23, 50)  # 23:50 on previous day

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_large_lookback(self):
        """Test with a large lookback that crosses multiple days"""
        reference = datetime(2024, 1, 10, 14, 23)  # 14:23
        start, end = get_time_window(reference, lookback_minutes=60 * 24 * 3)

        expected_end = datetime(2024, 1, 10, 14, 20)  # 14:20
        expected_start = datetime(2024, 1, 7, 14, 20)  # 14:20, 3 days earlier

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)
