from greedybear.cronjobs.repositories import MassScannerRepository
from greedybear.models import MassScanner

from . import CustomTestCase


class TestMassScannerRepository(CustomTestCase):
    """Tests for MassScannerRepository."""

    def setUp(self):
        self.repo = MassScannerRepository()

    def test_get_or_create_creates_new_entry(self):
        scanner, created = self.repo.get_or_create("1.2.3.4", "test scanner")

        self.assertTrue(created)
        self.assertEqual(scanner.ip_address, "1.2.3.4")
        self.assertEqual(scanner.reason, "test scanner")
        self.assertTrue(MassScanner.objects.filter(ip_address="1.2.3.4").exists())

    def test_get_or_create_returns_existing(self):
        MassScanner.objects.create(ip_address="5.6.7.8", reason="existing")

        scanner, created = self.repo.get_or_create("5.6.7.8", "new reason")

        self.assertFalse(created)
        self.assertEqual(scanner.ip_address, "5.6.7.8")
        # Should keep original reason, not update it
        self.assertEqual(scanner.reason, "existing")
        self.assertEqual(MassScanner.objects.filter(ip_address="5.6.7.8").count(), 1)

    def test_get_or_create_without_reason(self):
        scanner, created = self.repo.get_or_create("7.7.7.7")

        self.assertTrue(created)
        self.assertEqual(scanner.ip_address, "7.7.7.7")
        self.assertEqual(scanner.reason, "")
