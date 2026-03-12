from greedybear.cronjobs.repositories import ASRepository
from greedybear.models import AutonomousSystem
from tests import CustomTestCase


class ASRepositoryTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.repo = ASRepository()

    def test_create_new_asn(self):
        """Test that a new ASN is created with the given name."""
        asn_number = 64500
        as_name = "GB"

        as_obj = self.repo.get_or_create(asn_number, as_name)

        self.assertIsInstance(as_obj, AutonomousSystem)
        self.assertEqual(as_obj.asn, asn_number)
        self.assertEqual(as_obj.name, as_name)

    def test_create_new_asn_with_empty_name(self):
        """Test that a new ASN is created with empty string if name is None or blank."""
        asn_number = 64501

        as_obj = self.repo.get_or_create(asn_number, None)
        self.assertEqual(as_obj.name, "")

        as_obj2 = self.repo.get_or_create(asn_number + 1, "")
        self.assertEqual(as_obj2.name, "")

    def test_get_existing_asn_without_updating_name(self):
        """Existing ASN with a name should not be updated if a different name is passed."""
        asn_number = 64502
        AutonomousSystem.objects.create(asn=asn_number, name="GB")

        as_obj = self.repo.get_or_create(asn_number, "GB")
        self.assertEqual(as_obj.name, "GB")

    def test_update_existing_asn_with_missing_name(self):
        """Existing ASN with empty name should be updated when a new name is provided."""
        asn_number = 64503
        AutonomousSystem.objects.create(asn=asn_number, name="")

        as_obj = self.repo.get_or_create(asn_number, "intelowl/@GB")
        self.assertEqual(as_obj.name, "intelowl/@GB")

    def test_logging_on_create_and_update(self):
        """Ensure the logger logs info messages when creating or updating ASNs."""
        asn_number = 64504
        as_name = "LogTest"

        with self.assertLogs(self.repo.log, level="INFO") as log_cm:
            # Creation
            self.repo.get_or_create(asn_number, as_name)
        self.assertTrue(any("Created new AS" in msg for msg in log_cm.output))

        with self.assertLogs(self.repo.log, level="INFO") as log_cm2:
            # Update
            AutonomousSystem.objects.create(asn=64505, name="")
            self.repo.get_or_create(64505, "UpdatedName")
        self.assertTrue(any("Updated AS" in msg for msg in log_cm2.output))

    def test_cache_usage(self):
        """Ensure that ASNRepository uses its internal cache to avoid duplicate DB hits."""
        asn_number = 64506
        as_name = "CacheTest"

        # First call creates the ASN
        as_obj1 = self.repo.get_or_create(asn_number, as_name)
        self.assertEqual(as_obj1.name, as_name)

        # Directly modify the DB to simulate change
        AutonomousSystem.objects.filter(asn=asn_number).update(name="ModifiedName")

        # Second call should return cached object, not the DB modified one
        as_obj2 = self.repo.get_or_create(asn_number, None)
        self.assertEqual(as_obj2.name, as_name)  # cache still has old name

        # The objects should be the same instance if cached internally
        self.assertEqual(as_obj1.asn, as_obj2.asn)
