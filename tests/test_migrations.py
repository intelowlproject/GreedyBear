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

    migrate_from = "0044_cowriefiletransfer"
    migrate_to = "0045_credential_protocol"

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


@tag("migration")
class TestSensorLabelMigration(MigrationTestCase):
    """Tests the addition of the label field to the Sensor model."""

    migrate_from = "0045_credential_protocol"
    migrate_to = "0046_sensor_label"

    def test_existing_sensors_get_empty_label(self):
        Sensor = self.old_state.apps.get_model(self.app_name, "Sensor")
        Sensor.objects.create(address="10.0.0.1")

        new_state = self.apply_tested_migration()
        sensor_new = new_state.apps.get_model(self.app_name, "Sensor")
        migrated = sensor_new.objects.get(address="10.0.0.1")
        self.assertEqual(migrated.label, "")


@tag("migration")
class TestIocIdentityUniquenessAndDedupe(MigrationTestCase):
    """Tests IOC duplicate merge and identity uniqueness enforcement."""

    migrate_from = "0050_attackeractivitybucket"
    migrate_to = "0051_ioc_identity_uniqueness_and_dedupe"

    def test_duplicate_iocs_are_merged(self):
        from datetime import datetime, timedelta

        IOC = self.old_state.apps.get_model(self.app_name, "IOC")
        Honeypot = self.old_state.apps.get_model(self.app_name, "Honeypot")
        Sensor = self.old_state.apps.get_model(self.app_name, "Sensor")
        Tag = self.old_state.apps.get_model(self.app_name, "Tag")
        CowrieSession = self.old_state.apps.get_model(self.app_name, "CowrieSession")

        hp1, _ = Honeypot.objects.get_or_create(name="Cowrie", defaults={"active": True})
        hp2, _ = Honeypot.objects.get_or_create(name="Heralding", defaults={"active": True})
        s1 = Sensor.objects.create(address="10.10.10.1")
        s2 = Sensor.objects.create(address="10.10.10.2")

        now = datetime.now()
        ioc1 = IOC.objects.create(
            name="1.2.3.4",
            type="ip",
            first_seen=now - timedelta(days=3),
            last_seen=now - timedelta(days=2),
            attack_count=2,
            interaction_count=5,
            login_attempts=1,
            related_urls=["http://a.example"],
            destination_ports=[22],
            firehol_categories=["scanner"],
        )
        ioc2 = IOC.objects.create(
            name="1.2.3.4",
            type="ip",
            first_seen=now - timedelta(days=5),
            last_seen=now - timedelta(days=1),
            attack_count=3,
            interaction_count=7,
            login_attempts=4,
            related_urls=["http://b.example"],
            destination_ports=[80],
            firehol_categories=["botnet"],
            ip_reputation="tor_exit_node",
        )
        ioc_other_type = IOC.objects.create(name="1.2.3.4", type="domain")

        ioc1.honeypots.add(hp1)
        ioc2.honeypots.add(hp2)
        ioc1.sensors.add(s1)
        ioc2.sensors.add(s2)

        Tag.objects.create(ioc=ioc2, key="source", value="threatfox", source="threatfox")
        CowrieSession.objects.create(session_id=42, source=ioc2, interaction_count=3)

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")
        tag_new = new_state.apps.get_model(self.app_name, "Tag")
        cowrie_session_new = new_state.apps.get_model(self.app_name, "CowrieSession")

        merged = ioc_new.objects.get(name="1.2.3.4", type="ip")
        self.assertEqual(ioc_new.objects.filter(name="1.2.3.4", type="ip").count(), 1)
        self.assertTrue(ioc_new.objects.filter(pk=ioc_other_type.pk, type="domain").exists())

        self.assertEqual(merged.attack_count, 5)
        self.assertEqual(merged.interaction_count, 12)
        self.assertEqual(merged.login_attempts, 5)
        self.assertEqual(merged.first_seen, now - timedelta(days=5))
        self.assertEqual(merged.last_seen, now - timedelta(days=1))
        self.assertEqual(sorted(merged.destination_ports), [22, 80])
        self.assertEqual(sorted(merged.firehol_categories), ["botnet", "scanner"])
        self.assertEqual(sorted(merged.related_urls), ["http://a.example", "http://b.example"])

        self.assertEqual(merged.honeypots.count(), 2)
        self.assertEqual(merged.sensors.count(), 2)
        self.assertEqual(tag_new.objects.filter(ioc_id=merged.pk).count(), 1)
        self.assertEqual(cowrie_session_new.objects.get(session_id=42).source_id, merged.pk)


@tag("migration")
class TestIocIdentityUniqueConstraint(MigrationTestCase):
    """Tests IOC identity unique constraint added in migration 0052."""

    migrate_from = "0051_ioc_identity_uniqueness_and_dedupe"
    migrate_to = "0052_ioc_unique_identity_constraint"

    def test_unique_constraint_is_enforced_after_migration(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")
        IOC.objects.create(name="9.9.9.9", type="ip")

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")

        with self.assertRaises(IntegrityError):
            ioc_new.objects.create(name="9.9.9.9", type="ip")

        ioc_new.objects.create(name="9.9.9.9", type="domain")
