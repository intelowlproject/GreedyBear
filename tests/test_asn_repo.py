from greedybear.cronjobs.repositories import ASNRepository
from greedybear.models import AutonomousSystem
from tests import CustomTestCase


class ASNRepositoryTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.repo = ASNRepository()

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
        self.assertTrue(any("Created new ASN" in msg for msg in log_cm.output))

        with self.assertLogs(self.repo.log, level="INFO") as log_cm2:
            # Update
            AutonomousSystem.objects.create(asn=64505, name="")
            self.repo.get_or_create(64505, "UpdatedName")
        self.assertTrue(any("Updated ASN" in msg for msg in log_cm2.output))
