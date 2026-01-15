from datetime import datetime, timedelta

from greedybear.cronjobs.repositories import FireHolRepository
from greedybear.models import FireHolList

from . import CustomTestCase


class TestFireHolRepository(CustomTestCase):
    """Tests for FireHolRepository."""

    def setUp(self):
        self.repo = FireHolRepository()

    def test_get_or_create_creates_new_entry(self):
        entry, created = self.repo.get_or_create("1.2.3.4", "blocklist_de")

        self.assertTrue(created)
        self.assertEqual(entry.ip_address, "1.2.3.4")
        self.assertEqual(entry.source, "blocklist_de")
        self.assertTrue(FireHolList.objects.filter(ip_address="1.2.3.4", source="blocklist_de").exists())

    def test_get_or_create_returns_existing(self):
        FireHolList.objects.create(ip_address="5.6.7.8", source="greensnow")

        entry, created = self.repo.get_or_create("5.6.7.8", "greensnow")

        self.assertFalse(created)
        self.assertEqual(entry.ip_address, "5.6.7.8")
        self.assertEqual(
            FireHolList.objects.filter(ip_address="5.6.7.8", source="greensnow").count(),
            1,
        )

    def test_cleanup_old_entries_custom_days(self):
        old_date = datetime.now() - timedelta(days=65)
        old_entry = FireHolList.objects.create(ip_address="4.4.4.4", source="test")
        FireHolList.objects.filter(pk=old_entry.pk).update(added=old_date)

        deleted_count = self.repo.cleanup_old_entries(days=60)

        self.assertEqual(deleted_count, 1)
