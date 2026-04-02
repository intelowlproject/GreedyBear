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

    @patch("greedybear.cronjobs.schedules.Schedule")
    @override_settings(EXTRACTION_INTERVAL=10, SECRET_KEY="test-secret")
    def test_external_weekly_jobs_cron_are_deterministic_and_outside_local_window(self, mock_schedule):
        """External weekly jobs run on Sunday at deterministic times outside 00:00-02:00."""
        mock_schedule.CRON = Schedule.CRON
        mock_schedule.objects.update_or_create = MagicMock()
        mock_schedule.objects.exclude = MagicMock(return_value=MagicMock())

        call_command("setup_schedules")
        first_calls = mock_schedule.objects.update_or_create.call_args_list

        mock_schedule.objects.update_or_create.reset_mock()
        call_command("setup_schedules")
        second_calls = mock_schedule.objects.update_or_create.call_args_list

        def get_cron(calls, name):
            return next(c for c in calls if c[1]["name"] == name)[1]["defaults"]["cron"]

        for job_name in (
            "get_mass_scanners",
            "get_whatsmyip",
            "extract_firehol_lists",
            "get_tor_exit_nodes",
            "enrich_threatfox",
            "enrich_abuseipdb",
        ):
            first_cron = get_cron(first_calls, job_name)
            second_cron = get_cron(second_calls, job_name)

            self.assertEqual(first_cron, second_cron)

            minute_str, hour_str, day_of_month, month, day_of_week = first_cron.split()
            hour = int(hour_str)
            minute = int(minute_str)

            self.assertGreaterEqual(hour, 2)
            self.assertLessEqual(hour, 23)
            self.assertGreaterEqual(minute, 0)
            self.assertLessEqual(minute, 59)
            self.assertEqual(day_of_month, "*")
            self.assertEqual(month, "*")
            self.assertEqual(day_of_week, "0")

    def test_orphan_schedules_are_deleted(self):
        """Test that orphaned schedules not in active_schedules list are deleted."""
        # Create an orphan schedule that's not in the active_schedules list
        Schedule.objects.create(
            name="old_deprecated_task",
            func="greedybear.tasks.deprecated_function",
            schedule_type=Schedule.CRON,
            cron="0 0 * * *",
        )

        # Create a valid schedule
        Schedule.objects.create(
            name="extract_all",
            func="greedybear.tasks.extract_all",
            schedule_type=Schedule.CRON,
            cron="*/10 * * * *",
        )

        # Run setup_schedules
        call_command("setup_schedules")

        # Orphan schedule should be deleted
        self.assertFalse(Schedule.objects.filter(name="old_deprecated_task").exists())

        # Valid schedule should still exist
        self.assertTrue(Schedule.objects.filter(name="extract_all").exists())
