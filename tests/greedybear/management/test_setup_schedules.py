"""Tests for the setup_schedules management command."""

from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.test import TestCase, override_settings
from django_q.models import Schedule


class TestSetupSchedules(TestCase):
    """Test setup_schedules command with various EXTRACTION_INTERVAL values."""

    @patch("greedybear.cronjobs.schedules.Schedule")
    @override_settings(EXTRACTION_INTERVAL=10)
    def test_extraction_interval_10(self, mock_schedule):
        """Test schedules with EXTRACTION_INTERVAL=10."""
        mock_schedule.CRON = Schedule.CRON
        mock_schedule.objects.update_or_create = MagicMock()
        mock_schedule.objects.exclude = MagicMock(return_value=MagicMock())

        call_command("setup_schedules")

        # Check extraction schedule uses CRON type with interval 10
        calls = mock_schedule.objects.update_or_create.call_args_list
        extract_call = next(c for c in calls if c[1]["name"] == "extract_all")
        self.assertEqual(extract_call[1]["defaults"]["schedule_type"], Schedule.CRON)
        self.assertEqual(extract_call[1]["defaults"]["cron"], "*/10 * * * *")

        # Check training schedule minute is clamped correctly (10 / 3 * 2 = 6)
        train_call = next(c for c in calls if c[1]["name"] == "train_and_update")
        self.assertEqual(train_call[1]["defaults"]["cron"], "6 0 * * *")

    @patch("greedybear.cronjobs.schedules.Schedule")
    @override_settings(EXTRACTION_INTERVAL=60)
    def test_extraction_interval_60_clamps_minute(self, mock_schedule):
        """Test schedules with EXTRACTION_INTERVAL=60 (minute calculation: 60/3*2=40)."""
        mock_schedule.CRON = Schedule.CRON
        mock_schedule.objects.update_or_create = MagicMock()
        mock_schedule.objects.exclude = MagicMock(return_value=MagicMock())

        call_command("setup_schedules")

        # Check extraction schedule
        calls = mock_schedule.objects.update_or_create.call_args_list
        extract_call = next(c for c in calls if c[1]["name"] == "extract_all")
        self.assertEqual(extract_call[1]["defaults"]["cron"], "*/60 * * * *")

        # Training minute: int(60 / 3 * 2) = 40 (no clamping needed in this case)
        train_call = next(c for c in calls if c[1]["name"] == "train_and_update")
        self.assertEqual(train_call[1]["defaults"]["cron"], "40 0 * * *")

    @patch("greedybear.cronjobs.schedules.Schedule")
    @override_settings(EXTRACTION_INTERVAL=5)
    def test_extraction_interval_5(self, mock_schedule):
        """Test schedules with EXTRACTION_INTERVAL=5."""
        mock_schedule.CRON = Schedule.CRON
        mock_schedule.objects.update_or_create = MagicMock()
        mock_schedule.objects.exclude = MagicMock(return_value=MagicMock())

        call_command("setup_schedules")

        calls = mock_schedule.objects.update_or_create.call_args_list
        extract_call = next(c for c in calls if c[1]["name"] == "extract_all")
        self.assertEqual(extract_call[1]["defaults"]["cron"], "*/5 * * * *")

        # Training minute: 5 / 3 * 2 = 3
        train_call = next(c for c in calls if c[1]["name"] == "train_and_update")
        self.assertEqual(train_call[1]["defaults"]["cron"], "3 0 * * *")
