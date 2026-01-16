from datetime import datetime, timedelta
from unittest.mock import Mock

from django.db import IntegrityError, transaction

from greedybear.cronjobs.repositories import IocRepository
from greedybear.models import IOC, GeneralHoneypot

from . import CustomTestCase


class TestIocRepository(CustomTestCase):
    def setUp(self):
        self.repo = IocRepository()

    def test_get_ioc_by_name_returns_existing(self):
        result = self.repo.get_ioc_by_name("140.246.171.141")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "140.246.171.141")

    def test_get_ioc_by_name_returns_none_for_missing(self):
        result = self.repo.get_ioc_by_name("8.8.8.8")
        self.assertIsNone(result)

    def test_save_creates_new_ioc(self):
        ioc = IOC(name="1.2.3.4", type="ip")
        result = self.repo.save(ioc)
        self.assertIsNotNone(result.pk)
        self.assertTrue(IOC.objects.filter(name="1.2.3.4").exists())

    def test_save_updates_existing_ioc(self):
        ioc = self.repo.get_ioc_by_name("140.246.171.141")
        original_attack_count = ioc.attack_count

        ioc.attack_count = 10
        result = self.repo.save(ioc)
        self.assertEqual(result.attack_count, 10)
        self.assertEqual(IOC.objects.get(name="140.246.171.141").attack_count, 10)

        ioc.attack_count = original_attack_count
        result = self.repo.save(ioc)
        self.assertEqual(result.attack_count, original_attack_count)
        self.assertEqual(IOC.objects.get(name="140.246.171.141").attack_count, original_attack_count)

    def test_create_honeypot(self):
        self.repo.create_honeypot("NewHoneypot")
        self.assertTrue(GeneralHoneypot.objects.filter(name="NewHoneypot").exists())
        hp = GeneralHoneypot.objects.get(name="NewHoneypot")
        self.assertTrue(hp.active)

    def test_get_active_honeypots_returns_only_active(self):
        GeneralHoneypot.objects.create(name="TestActivePot1", active=True)
        GeneralHoneypot.objects.create(name="TestActivePot2", active=True)
        GeneralHoneypot.objects.create(name="TestInactivePot", active=False)

        result = self.repo.get_active_honeypots()
        names = [hp.name for hp in result]

        self.assertIn("TestActivePot1", names)
        self.assertIn("TestActivePot2", names)
        self.assertNotIn("TestInactivePot", names)

    def test_get_active_honeypots_returns_empty_if_none_active(self):
        GeneralHoneypot.objects.update(active=False)

        result = self.repo.get_active_honeypots()
        self.assertEqual(len(result), 0)

        GeneralHoneypot.objects.update(active=True)

    def test_get_hp_by_name_returns_existing(self):
        GeneralHoneypot.objects.create(name="TestPot", active=True)
        result = self.repo.get_hp_by_name("TestPot")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "TestPot")

    def test_get_hp_by_name_returns_none_for_missing(self):
        result = self.repo.get_hp_by_name("nonexistent")
        self.assertIsNone(result)

    def test_is_empty_returns_false_when_has_iocs(self):
        result = self.repo.is_empty()
        self.assertFalse(result)

    def test_is_enabled_returns_true_for_cowrie(self):
        result = self.repo.is_enabled("Cowrie")
        self.assertTrue(result)

    def test_is_enabled_returns_true_for_log4pot(self):
        result = self.repo.is_enabled("Log4pot")
        self.assertTrue(result)

    def test_is_enabled_returns_true_for_active_honeypot(self):
        result = self.repo.is_enabled("Heralding")
        self.assertTrue(result)

    def test_is_enabled_returns_false_for_inactive_honeypot(self):
        result = self.repo.is_enabled("Ddospot")
        self.assertFalse(result)

    def test_add_honeypot_to_ioc_adds_new_honeypot(self):
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        honeypot = GeneralHoneypot.objects.create(name="TestPot", active=True)
        result = self.repo.add_honeypot_to_ioc("TestPot", ioc)
        self.assertIn(honeypot, result.general_honeypot.all())

    def test_add_honeypot_to_ioc_idempotent(self):
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        honeypot = GeneralHoneypot.objects.create(name="TestPot", active=True)
        ioc.general_honeypot.add(honeypot)
        initial_count = ioc.general_honeypot.count()
        result = self.repo.add_honeypot_to_ioc("TestPot", ioc)
        self.assertEqual(result.general_honeypot.count(), initial_count)
        self.assertEqual(ioc.general_honeypot.count(), 1)

    def test_add_honeypot_to_ioc_multiple_honeypots(self):
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        hp1 = GeneralHoneypot.objects.create(name="Pot1", active=True)
        hp2 = GeneralHoneypot.objects.create(name="Pot2", active=True)
        self.repo.add_honeypot_to_ioc("Pot1", ioc)
        self.repo.add_honeypot_to_ioc("Pot2", ioc)
        self.assertEqual(ioc.general_honeypot.count(), 2)
        self.assertIn(hp1, ioc.general_honeypot.all())
        self.assertIn(hp2, ioc.general_honeypot.all())

    def test_existing_honeypots(self):
        expected_honeypots = ["Cowrie", "Log4pot", "Heralding", "Ciscoasa", "Ddospot"]
        for hp_name in expected_honeypots:
            self.assertIn(self.repo._normalize_name(hp_name), self.repo._honeypot_cache)

    def test_is_ready_for_extraction_creates_and_enables(self):
        result = self.repo.is_ready_for_extraction("FooPot")
        self.assertTrue(result)
        self.assertTrue(GeneralHoneypot.objects.filter(name="FooPot").exists())

    def test_is_ready_for_extraction_case_insensitive(self):
        GeneralHoneypot.objects.create(name="Cowrie", active=True)
        result = self.repo.is_ready_for_extraction("cowrie")
        self.assertTrue(result)
        self.assertEqual(GeneralHoneypot.objects.filter(name__iexact="cowrie").count(), 1)

    def test_get_hp_by_name_insensitive(self):
        GeneralHoneypot.objects.create(name="Cowrie", active=True)
        result = self.repo.get_hp_by_name("cowrie")
        self.assertIsNotNone(result)

    def test_disabled_honeypot_case_insensitive(self):
        GeneralHoneypot.objects.create(name="Testpot69", active=False)

        # reiniting repo after DB change to refresh the cache
        repo = IocRepository()
        result = repo.is_ready_for_extraction("testpot69")
        self.assertFalse(result)

    def test_special_and_normal_honeypots(self):
        GeneralHoneypot.objects.create(name="NormalPot", active=False)

        repo = IocRepository()

        self.assertTrue(repo.is_ready_for_extraction("cowrie"))
        self.assertTrue(repo.is_ready_for_extraction("Log4Pot"))
        self.assertFalse(repo.is_ready_for_extraction("NormalPot"))
        self.assertFalse(repo.is_ready_for_extraction("normalpot"))

    def test_create_honeypot_case_insensitive_uniqueness(self):
        initial_count = GeneralHoneypot.objects.count()
        GeneralHoneypot.objects.create(name="TestPot123", active=True)
        self.assertEqual(GeneralHoneypot.objects.count(), initial_count + 1)

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                GeneralHoneypot.objects.create(name="testpot123", active=True)

        self.assertEqual(GeneralHoneypot.objects.count(), initial_count + 1)
        self.assertEqual(GeneralHoneypot.objects.get(name__iexact="testpot123").name, "TestPot123")

    def test_create_honeypot_integrity_error_handling(self):
        initial_count = GeneralHoneypot.objects.count()
        GeneralHoneypot.objects.create(name="Log4PotTest123", active=True)

        try:
            with transaction.atomic():
                GeneralHoneypot.objects.create(name="log4pottest123", active=True)
        except IntegrityError:
            hp = GeneralHoneypot.objects.filter(name__iexact="log4pottest123").first()

        self.assertEqual(hp.name, "Log4PotTest123")
        self.assertEqual(GeneralHoneypot.objects.count(), initial_count + 1)

    def test_create_new_honeypot_creates_and_updates_cache(self):
        self.repo._honeypot_cache.clear()
        hp = self.repo.create_honeypot("UniqueNewPot123")
        self.assertEqual(hp.name, "UniqueNewPot123")
        self.assertIn("uniquenewpot123", self.repo._honeypot_cache)
        self.assertTrue(hp.active)

        db_hp = GeneralHoneypot.objects.get(name="UniqueNewPot123")
        self.assertEqual(db_hp.name, "UniqueNewPot123")
        self.assertTrue(db_hp.active)

    def test_honeypot_unique_constraint_case_insensitive(self):
        initial_count = GeneralHoneypot.objects.count()
        hp1 = self.repo.create_honeypot("TestPot456")
        self.assertIsNotNone(hp1)

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                GeneralHoneypot.objects.create(name="testpot456", active=True)

        self.assertEqual(GeneralHoneypot.objects.filter(name__iexact="testpot456").count(), 1)
        self.assertEqual(GeneralHoneypot.objects.count(), initial_count + 1)

    def test_get_scanners_for_scoring_returns_scanners(self):
        # Create scanners
        IOC.objects.create(name="1.2.3.4", type="ip", scanner=True, cowrie=True)
        IOC.objects.create(name="5.6.7.8", type="ip", scanner=True, log4j=True)

        result = self.repo.get_scanners_for_scoring(["recurrence_probability", "expected_interactions"])

        names = [ioc.name for ioc in result]
        self.assertIn("1.2.3.4", names)
        self.assertIn("5.6.7.8", names)

    def test_get_scanners_for_scoring_excludes_non_scanners(self):
        IOC.objects.create(name="1.2.3.4", type="ip", scanner=False, cowrie=True)

        result = self.repo.get_scanners_for_scoring(["recurrence_probability"])

        names = [ioc.name for ioc in result]
        self.assertNotIn("1.2.3.4", names)

    def test_get_scanners_for_scoring_only_loads_specified_fields(self):
        IOC.objects.create(name="1.2.3.4", type="ip", scanner=True, cowrie=True, attack_count=100)

        result = list(self.repo.get_scanners_for_scoring(["recurrence_probability"]))

        # Check that our created IOC is in the results
        names = [ioc.name for ioc in result]
        self.assertIn("1.2.3.4", names)
        # Verify name field is accessible (field was loaded)
        test_ioc = next(ioc for ioc in result if ioc.name == "1.2.3.4")
        self.assertEqual(test_ioc.name, "1.2.3.4")

    def test_get_scanners_by_pks_returns_correct_iocs(self):
        ioc1 = IOC.objects.create(name="1.2.3.4", type="ip")
        ioc2 = IOC.objects.create(name="5.6.7.8", type="ip")
        IOC.objects.create(name="9.10.11.12", type="ip")  # Should not be returned

        result = list(self.repo.get_scanners_by_pks({ioc1.pk, ioc2.pk}))

        self.assertEqual(len(result), 2)
        values = [r["value"] for r in result]
        self.assertIn("1.2.3.4", values)
        self.assertIn("5.6.7.8", values)
        self.assertNotIn("9.10.11.12", values)

    def test_get_scanners_by_pks_includes_honeypot_annotation(self):
        hp = GeneralHoneypot.objects.create(name="TestPot", active=True)
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        ioc.general_honeypot.add(hp)

        result = list(self.repo.get_scanners_by_pks({ioc.pk}))

        self.assertEqual(len(result), 1)
        self.assertIn("honeypots", result[0])

    def test_get_recent_scanners_returns_recent_only(self):
        recent_date = datetime.now() - timedelta(days=5)
        old_date = datetime.now() - timedelta(days=40)

        IOC.objects.create(name="1.2.3.4", type="ip", scanner=True, cowrie=True, last_seen=recent_date)
        IOC.objects.create(name="5.6.7.8", type="ip", scanner=True, cowrie=True, last_seen=old_date)

        cutoff = datetime.now() - timedelta(days=30)
        result = list(self.repo.get_recent_scanners(cutoff, days_lookback=30))

        values = [r["value"] for r in result]
        self.assertIn("1.2.3.4", values)
        self.assertNotIn("5.6.7.8", values)

    def test_get_recent_scanners_excludes_non_scanners(self):
        recent_date = datetime.now() - timedelta(days=5)
        IOC.objects.create(name="1.2.3.4", type="ip", scanner=False, cowrie=True, last_seen=recent_date)

        cutoff = datetime.now() - timedelta(days=30)
        result = list(self.repo.get_recent_scanners(cutoff))

        values = [r["value"] for r in result]
        self.assertNotIn("1.2.3.4", values)

    def test_bulk_update_scores_updates_multiple_iocs(self):
        ioc1 = IOC.objects.create(name="1.2.3.4", type="ip", recurrence_probability=0.0)
        ioc2 = IOC.objects.create(name="5.6.7.8", type="ip", recurrence_probability=0.0)

        ioc1.recurrence_probability = 0.75
        ioc2.recurrence_probability = 0.85

        result = self.repo.bulk_update_scores([ioc1, ioc2], ["recurrence_probability"])

        self.assertEqual(result, 2)
        updated1 = IOC.objects.get(name="1.2.3.4")
        updated2 = IOC.objects.get(name="5.6.7.8")
        self.assertEqual(updated1.recurrence_probability, 0.75)
        self.assertEqual(updated2.recurrence_probability, 0.85)

    def test_bulk_update_scores_returns_zero_for_empty_list(self):
        result = self.repo.bulk_update_scores([], ["recurrence_probability"])
        self.assertEqual(result, 0)

    def test_bulk_update_scores_updates_multiple_fields(self):
        ioc = IOC.objects.create(
            name="1.2.3.4",
            type="ip",
            recurrence_probability=0.0,
            expected_interactions=0.0,
        )

        ioc.recurrence_probability = 0.75
        ioc.expected_interactions = 10.5

        result = self.repo.bulk_update_scores([ioc], ["recurrence_probability", "expected_interactions"])

        self.assertEqual(result, 1)
        updated = IOC.objects.get(name="1.2.3.4")
        self.assertEqual(updated.recurrence_probability, 0.75)
        self.assertEqual(updated.expected_interactions, 10.5)

    # Edge case tests
    def test_get_scanners_for_scoring_returns_empty_when_no_scanners(self):
        # Delete all existing scanners
        IOC.objects.filter(scanner=True).delete()

        result = list(self.repo.get_scanners_for_scoring(["recurrence_probability"]))

        self.assertEqual(len(result), 0)

    def test_get_scanners_for_scoring_excludes_inactive_honeypots(self):
        hp = GeneralHoneypot.objects.create(name="InactivePot", active=False)
        ioc = IOC.objects.create(name="1.2.3.4", type="ip", scanner=True)
        ioc.general_honeypot.add(hp)

        result = list(self.repo.get_scanners_for_scoring(["recurrence_probability"]))

        names = [ioc.name for ioc in result]
        self.assertNotIn("1.2.3.4", names)

    def test_get_scanners_for_scoring_with_multiple_honeypots(self):
        hp1 = GeneralHoneypot.objects.create(name="Pot1", active=True)
        hp2 = GeneralHoneypot.objects.create(name="Pot2", active=True)
        ioc = IOC.objects.create(name="1.2.3.4", type="ip", scanner=True)
        ioc.general_honeypot.add(hp1, hp2)

        result = list(self.repo.get_scanners_for_scoring(["recurrence_probability"]))

        names = [ioc.name for ioc in result]
        # Should appear only once despite multiple honeypots (distinct)
        self.assertEqual(names.count("1.2.3.4"), 1)

    def test_get_scanners_by_pks_with_empty_set(self):
        result = list(self.repo.get_scanners_by_pks(set()))

        self.assertEqual(len(result), 0)

    def test_get_scanners_by_pks_with_nonexistent_pks(self):
        result = list(self.repo.get_scanners_by_pks({99999, 99998}))

        self.assertEqual(len(result), 0)

    def test_get_scanners_by_pks_ioc_with_no_honeypots(self):
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")

        result = list(self.repo.get_scanners_by_pks({ioc.pk}))

        self.assertEqual(len(result), 1)
        self.assertIn("honeypots", result[0])

    def test_get_recent_scanners_all_iocs_older_than_cutoff(self):
        old_date = datetime.now() - timedelta(days=40)
        IOC.objects.create(name="1.2.3.4", type="ip", scanner=True, cowrie=True, last_seen=old_date)

        cutoff = datetime.now() - timedelta(days=30)
        result = list(self.repo.get_recent_scanners(cutoff))

        values = [r["value"] for r in result]
        self.assertNotIn("1.2.3.4", values)

    def test_get_recent_scanners_with_inactive_honeypot(self):
        hp = GeneralHoneypot.objects.create(name="InactivePot", active=False)
        recent_date = datetime.now() - timedelta(days=5)
        ioc = IOC.objects.create(name="1.2.3.4", type="ip", scanner=True, last_seen=recent_date)
        ioc.general_honeypot.add(hp)

        cutoff = datetime.now() - timedelta(days=30)
        result = list(self.repo.get_recent_scanners(cutoff))

        values = [r["value"] for r in result]
        self.assertNotIn("1.2.3.4", values)

    def test_bulk_update_scores_with_custom_batch_size(self):
        ioc1 = IOC.objects.create(name="1.2.3.4", type="ip", recurrence_probability=0.0)
        ioc2 = IOC.objects.create(name="5.6.7.8", type="ip", recurrence_probability=0.0)

        ioc1.recurrence_probability = 0.75
        ioc2.recurrence_probability = 0.85

        result = self.repo.bulk_update_scores([ioc1, ioc2], ["recurrence_probability"], batch_size=1)

        self.assertEqual(result, 2)
        updated1 = IOC.objects.get(name="1.2.3.4")
        updated2 = IOC.objects.get(name="5.6.7.8")
        self.assertEqual(updated1.recurrence_probability, 0.75)
        self.assertEqual(updated2.recurrence_probability, 0.85)


class TestScoringIntegration(CustomTestCase):
    """Integration tests for scoring jobs using IocRepository."""

    def setUp(self):
        self.repo = IocRepository()

    def test_update_scores_with_repository(self):
        """Test UpdateScores class works with injected repository."""
        import pandas as pd

        from greedybear.cronjobs.scoring.scoring_jobs import UpdateScores

        # Create test data with M2M honeypot relationships
        cowrie_hp, _ = GeneralHoneypot.objects.get_or_create(name="Cowrie", defaults={"active": True})
        log4pot_hp, _ = GeneralHoneypot.objects.get_or_create(name="Log4Pot", defaults={"active": True})

        ioc1 = IOC.objects.create(
            name="10.1.2.3",
            type="ip",
            scanner=True,
            recurrence_probability=0.0,
        )
        ioc1.general_honeypot.add(cowrie_hp)

        ioc2 = IOC.objects.create(
            name="10.5.6.7",
            type="ip",
            scanner=True,
            recurrence_probability=0.0,
        )
        ioc2.general_honeypot.add(log4pot_hp)

        # Create score dataframe
        df = pd.DataFrame(
            {
                "value": ["10.1.2.3", "10.5.6.7"],
                "recurrence_probability": [0.75, 0.85],
                "expected_interactions": [10.0, 15.0],
            }
        )

        # Inject repository and run update
        job = UpdateScores(ioc_repo=self.repo)
        result = job.update_db(df)

        # Verify our IOCs were updated (may be more due to test fixtures)
        self.assertGreaterEqual(result, 2)
        updated1 = IOC.objects.get(name="10.1.2.3")
        updated2 = IOC.objects.get(name="10.5.6.7")
        self.assertEqual(updated1.recurrence_probability, 0.75)
        self.assertEqual(updated2.recurrence_probability, 0.85)

    def test_update_scores_resets_missing_iocs(self):
        """Test UpdateScores resets scores for IOCs not in the dataframe."""
        import pandas as pd

        from greedybear.cronjobs.scoring.scoring_jobs import UpdateScores

        # Create test data with M2M honeypot relationships - one IOC will be missing from df
        cowrie_hp, _ = GeneralHoneypot.objects.get_or_create(name="Cowrie", defaults={"active": True})
        log4pot_hp, _ = GeneralHoneypot.objects.get_or_create(name="Log4Pot", defaults={"active": True})

        ioc1 = IOC.objects.create(
            name="10.2.3.4",
            type="ip",
            scanner=True,
            recurrence_probability=0.9,
        )
        ioc1.general_honeypot.add(cowrie_hp)

        ioc2 = IOC.objects.create(
            name="10.6.7.8",
            type="ip",
            scanner=True,
            recurrence_probability=0.8,
        )
        ioc2.general_honeypot.add(log4pot_hp)

        # DataFrame only has one IOC
        df = pd.DataFrame(
            {
                "value": ["10.2.3.4"],
                "recurrence_probability": [0.75],
                "expected_interactions": [10.0],
            }
        )

        job = UpdateScores(ioc_repo=self.repo)
        job.update_db(df)

        # First should be updated, second should be reset to 0
        updated1 = IOC.objects.get(name="10.2.3.4")
        updated2 = IOC.objects.get(name="10.6.7.8")
        self.assertEqual(updated1.recurrence_probability, 0.75)
        self.assertEqual(updated2.recurrence_probability, 0.0)  # Reset

    def test_get_current_data_with_repository(self):
        """Test get_current_data utility function works with repository."""
        from greedybear.cronjobs.scoring.utils import get_current_data

        recent_date = datetime.now() - timedelta(days=5)
        IOC.objects.create(name="1.2.3.4", type="ip", scanner=True, cowrie=True, last_seen=recent_date)

        result = get_current_data(days_lookback=30, ioc_repo=self.repo)

        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        values = [r["value"] for r in result]
        self.assertIn("1.2.3.4", values)

    def test_get_data_by_pks_with_repository(self):
        """Test get_data_by_pks utility function works with repository."""
        from greedybear.cronjobs.scoring.utils import get_data_by_pks

        ioc = IOC.objects.create(name="1.2.3.4", type="ip")

        result = get_data_by_pks({ioc.pk}, ioc_repo=self.repo)

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["value"], "1.2.3.4")

    def test_update_scores_with_mock_repository(self):
        """Test UpdateScores can be fully mocked for unit testing."""
        import pandas as pd

        from greedybear.cronjobs.scoring.scoring_jobs import UpdateScores

        # Create mock repository
        mock_repo = Mock()
        mock_ioc = Mock()
        mock_ioc.name = "1.2.3.4"
        mock_ioc.recurrence_probability = 0.0
        mock_repo.get_scanners_for_scoring.return_value = [mock_ioc]
        mock_repo.bulk_update_scores.return_value = 1

        # Create score dataframe
        df = pd.DataFrame(
            {
                "value": ["1.2.3.4"],
                "recurrence_probability": [0.75],
                "expected_interactions": [10.0],
            }
        )

        # Inject mock and verify it's used
        job = UpdateScores(ioc_repo=mock_repo)
        result = job.update_db(df)

        # Verify repository methods were called
        mock_repo.get_scanners_for_scoring.assert_called_once()
        mock_repo.bulk_update_scores.assert_called_once()
        self.assertEqual(result, 1)


class TestIocRepositoryCleanup(CustomTestCase):
    """Tests for cleanup-related methods in IocRepository."""

    def setUp(self):
        self.repo = IocRepository()

    def test_delete_old_iocs_deletes_old_records(self):
        old_date = datetime.now() - timedelta(days=40)
        recent_date = datetime.now() - timedelta(days=5)

        IOC.objects.create(name="1.2.3.4", type="ip", last_seen=old_date)
        IOC.objects.create(name="5.6.7.8", type="ip", last_seen=recent_date)

        cutoff = datetime.now() - timedelta(days=30)
        deleted_count = self.repo.delete_old_iocs(cutoff)

        self.assertEqual(deleted_count, 1)
        self.assertFalse(IOC.objects.filter(name="1.2.3.4").exists())
        self.assertTrue(IOC.objects.filter(name="5.6.7.8").exists())

    def test_delete_old_iocs_returns_zero_when_none_old(self):
        recent_date = datetime.now() - timedelta(days=5)
        IOC.objects.create(name="1.2.3.4", type="ip", last_seen=recent_date)

        cutoff = datetime.now() - timedelta(days=30)
        deleted_count = self.repo.delete_old_iocs(cutoff)

        self.assertEqual(deleted_count, 0)

    def test_update_ioc_reputation_updates_existing(self):
        IOC.objects.create(name="1.2.3.4", type="ip", ip_reputation="")

        result = self.repo.update_ioc_reputation("1.2.3.4", "mass scanner")

        self.assertTrue(result)
        updated = IOC.objects.get(name="1.2.3.4")
        self.assertEqual(updated.ip_reputation, "mass scanner")

    def test_update_ioc_reputation_returns_false_for_missing(self):
        result = self.repo.update_ioc_reputation("9.9.9.9", "mass scanner")
        self.assertFalse(result)
