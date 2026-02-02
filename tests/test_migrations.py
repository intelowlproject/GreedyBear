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
