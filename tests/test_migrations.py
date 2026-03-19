from django.db import IntegrityError
from django.test import tag

from . import MigrationTestCase


@tag("migration")
class TestRemoveHardcodedHoneypots(MigrationTestCase):
    """Tests that hardcoded honeypots are removed only when no IOC references them."""

    migrate_from = "0028_generalhoneypot_unique_generalhoneypot_name_ci"
    migrate_to = "0029_remove_hardcoded_honeypots"

    def test_honeypots_deleted_only_if_unused(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")
        GeneralHoneypot = self.old_state.apps.get_model(self.app_name, "GeneralHoneypot")

        used_hp = GeneralHoneypot.objects.get(name="Ciscoasa")

        ioc = IOC.objects.create()
        ioc.general_honeypot.add(used_hp)

        new_state = self.apply_tested_migration()
        hp_new = new_state.apps.get_model(self.app_name, "GeneralHoneypot")

        self.assertFalse(
            hp_new.objects.filter(name="Heralding").exists(),
            "Unused honeypot should be deleted",
        )

        self.assertTrue(
            hp_new.objects.filter(name="Ciscoasa").exists(),
            "Honeypot linked to IOC must not be deleted",
        )


@tag("migration")
class TestCowrieLog4jMigration(MigrationTestCase):
    """Tests migration of cowrie and log4j boolean flags into the GeneralHoneypot M2M relation."""

    migrate_from = "0029_remove_hardcoded_honeypots"
    migrate_to = "0030_migrate_cowrie_log4j"

    def test_boolean_flags_are_migrated_to_m2m(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")
        self.old_state.apps.get_model(self.app_name, "GeneralHoneypot")

        # creating iocs covering all flag combinations
        ioc_cowrie = IOC.objects.create(cowrie=True, log4j=False)
        ioc_log4j = IOC.objects.create(cowrie=False, log4j=True)
        ioc_both = IOC.objects.create(cowrie=True, log4j=True)
        ioc_none = IOC.objects.create(cowrie=False, log4j=False)

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")
        hp_new = new_state.apps.get_model(self.app_name, "GeneralHoneypot")

        # fetching migrated honeypots
        cowrie_hp = hp_new.objects.get(name="Cowrie")
        log4pot_hp = hp_new.objects.get(name="Log4pot")

        self.assertEqual(
            set(ioc_new.objects.get(id=ioc_cowrie.id).general_honeypot.all()),
            {cowrie_hp},
        )
        self.assertEqual(
            set(ioc_new.objects.get(id=ioc_log4j.id).general_honeypot.all()),
            {log4pot_hp},
        )
        self.assertEqual(
            set(ioc_new.objects.get(id=ioc_both.id).general_honeypot.all()),
            {cowrie_hp, log4pot_hp},
        )
        self.assertEqual(
            ioc_new.objects.get(id=ioc_none.id).general_honeypot.count(),
            0,
        )


@tag("migration")
class TestRemoveUnusedLog4pot(MigrationTestCase):
    """Tests that Log4pot is removed only when it has no associated IOCs.

    Fixes issue #773: Log4pot is active despite having no data.
    """

    migrate_from = "0033_disable_additional_honeypots"
    migrate_to = "0034_remove_unused_log4pot"

    def test_log4pot_deleted_if_unused(self):
        """Log4pot should be deleted if it has no associated IOCs."""
        GeneralHoneypot = self.old_state.apps.get_model(self.app_name, "GeneralHoneypot")

        # Ensure Log4pot exists (created by migration 0030)
        GeneralHoneypot.objects.get_or_create(name="Log4pot", defaults={"active": True})

        new_state = self.apply_tested_migration()
        hp_new = new_state.apps.get_model(self.app_name, "GeneralHoneypot")

        self.assertFalse(
            hp_new.objects.filter(name="Log4pot").exists(),
            "Log4pot with no IOCs should be deleted",
        )

    def test_log4pot_kept_if_has_iocs(self):
        """Log4pot should NOT be deleted if it has associated IOCs."""
        GeneralHoneypot = self.old_state.apps.get_model(self.app_name, "GeneralHoneypot")
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")

        log4pot_hp, _ = GeneralHoneypot.objects.get_or_create(name="Log4pot", defaults={"active": True})

        # Create an IOC and link it to Log4pot
        ioc = IOC.objects.create()
        ioc.general_honeypot.add(log4pot_hp)

        new_state = self.apply_tested_migration()
        hp_new = new_state.apps.get_model(self.app_name, "GeneralHoneypot")

        self.assertTrue(
            hp_new.objects.filter(name="Log4pot").exists(),
            "Log4pot with IOCs should NOT be deleted",
        )


@tag("migration")
class TestIocAsnToAutonomousSystem(MigrationTestCase):
    """Tests migration from IOC.asn -> IOC.autonomous_system."""

    migrate_from = "0042_credential_model_and_data_migration"
    migrate_to = "0043_autonomoussystem_remove_ioc_asn_and_more"

    def test_asn_migrated_to_autonomous_system(self):
        ioc_old = self.old_state.apps.get_model(self.app_name, "IOC")

        ioc1 = ioc_old.objects.create(asn=12345)
        ioc2 = ioc_old.objects.create(asn=67890)
        ioc3 = ioc_old.objects.create(asn=None)

        # Apply migration
        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")
        as_new = new_state.apps.get_model(self.app_name, "AutonomousSystem")

        ioc1_new = ioc_new.objects.get(pk=ioc1.pk)
        ioc2_new = ioc_new.objects.get(pk=ioc2.pk)
        ioc3_new = ioc_new.objects.get(pk=ioc3.pk)

        self.assertIsNotNone(ioc1_new.autonomous_system)
        self.assertEqual(ioc1_new.autonomous_system.asn, 12345)

        self.assertIsNotNone(ioc2_new.autonomous_system)
        self.assertEqual(ioc2_new.autonomous_system.asn, 67890)

        self.assertIsNone(ioc3_new.autonomous_system)

        self.assertEqual(as_new.objects.count(), 2)
        asns = set(as_new.objects.values_list("asn", flat=True))
        self.assertSetEqual(asns, {12345, 67890})

    def test_duplicate_asns_with_different_names(self):
        """Ensure migration does not duplicate ASNs."""
        ioc_old = self.old_state.apps.get_model(self.app_name, "IOC")

        ioc_old.objects.create(asn=12345)
        ioc_old.objects.create(asn=12345)

        new_state = self.apply_tested_migration()
        as_new = new_state.apps.get_model(self.app_name, "AutonomousSystem")

        self.assertEqual(as_new.objects.count(), 1)

    def test_large_number_of_iocs(self):
        """Ensure migration works correctly for many IOCs."""
        ioc_old = self.old_state.apps.get_model(self.app_name, "IOC")

        num_iocs = 3500
        asns = [10000 + i % 10 for i in range(num_iocs)]

        for asn in asns:
            ioc_old.objects.create(asn=asn)

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")
        as_new = new_state.apps.get_model(self.app_name, "AutonomousSystem")

        for ioc in ioc_new.objects.all():
            self.assertIsNotNone(ioc.autonomous_system)
            self.assertIn(ioc.autonomous_system.asn, range(10000, 10010))

        self.assertEqual(as_new.objects.count(), 10)


@tag("migration")
class TestCredentialModelMigration(MigrationTestCase):
    """Tests that credentials are correctly migrated from ArrayField to Credential model."""

    migrate_from = "0041_sharetoken"
    migrate_to = "0042_credential_model_and_data_migration"

    def test_credentials_migrated_to_credential_model(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")
        CowrieSession = self.old_state.apps.get_model(self.app_name, "CowrieSession")

        ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        session = CowrieSession.objects.create(
            session_id=1,
            source=ioc,
            credentials=["root | password123", "admin | admin"],
        )

        new_state = self.apply_tested_migration()
        Credential = new_state.apps.get_model(self.app_name, "Credential")
        CowrieSession = new_state.apps.get_model(self.app_name, "CowrieSession")

        self.assertEqual(Credential.objects.count(), 2)
        self.assertTrue(Credential.objects.filter(username="root", password="password123").exists())
        self.assertTrue(Credential.objects.filter(username="admin", password="admin").exists())

        session = CowrieSession.objects.get(session_id=1)
        self.assertEqual(session.credentials.count(), 2)


@tag("migration")
class TestCredentialProtocolMigration(MigrationTestCase):
    """Tests migration adding protocol support to Credential uniqueness."""

    migrate_from = "0043_autonomoussystem_remove_ioc_asn_and_more"
    migrate_to = "0044_credential_protocol"

    def test_default_protocol_set_and_uniqueness_includes_protocol(self):
        credential_old = self.old_state.apps.get_model(self.app_name, "Credential")

        legacy = credential_old.objects.create(username="root", password="root")

        new_state = self.apply_tested_migration()
        Credential = new_state.apps.get_model(self.app_name, "Credential")

        migrated = Credential.objects.get(pk=legacy.pk)
        self.assertEqual(migrated.protocol, "")

        with self.assertRaises(IntegrityError):
            Credential.objects.create(username="root", password="root", protocol="")

        Credential.objects.create(username="root", password="root", protocol="ssh")
        Credential.objects.create(username="root", password="root", protocol="ftp")
        self.assertEqual(Credential.objects.filter(username="root", password="root").count(), 3)
