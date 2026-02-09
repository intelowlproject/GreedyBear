from datetime import datetime, timedelta

from django.db import IntegrityError

from greedybear.cronjobs.repositories import CowrieSessionRepository
from greedybear.models import IOC, CommandSequence, CowrieCredential, CowrieSession

from . import CustomTestCase


class TestCowrieSessionRepository(CustomTestCase):
    def setUp(self):
        self.repo = CowrieSessionRepository()

    def test_get_or_create_session_creates_new(self):
        source_ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        result = self.repo.get_or_create_session(session_id="123456", source=source_ioc)
        self.assertIsNotNone(result)
        self.assertEqual(result.session_id, int("123456", 16))
        self.assertEqual(result.source, source_ioc)

    def test_get_or_create_session_returns_existing(self):
        existing_session_id = "ffffffffffff"
        source = self.cowrie_session.source
        result = self.repo.get_or_create_session(existing_session_id, source=source)
        self.assertEqual(result.pk, int(existing_session_id, 16))
        self.assertTrue(result.login_attempt)

    def test_get_or_create_raises_on_invalid_session_id(self):
        session_id = "gggggggggggg"
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        with self.assertRaises(ValueError):
            self.repo.get_or_create_session(session_id, source=source)

    def test_save_session_persists_to_database(self):
        source_ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        session = CowrieSession(session_id=12345, source=source_ioc)
        result = self.repo.save_session(session)
        self.assertIsNotNone(result.pk)
        self.assertTrue(CowrieSession.objects.filter(session_id=12345).exists())

    def test_save_session_updates_existing(self):
        existing_session_id = "ffffffffffff"
        source = self.cowrie_session.source
        session = self.repo.get_or_create_session(existing_session_id, source=source)

        original_interaction_count = session.interaction_count
        session.interaction_count = 10
        result = self.repo.save_session(session)
        self.assertEqual(result.interaction_count, 10)
        self.assertEqual(
            CowrieSession.objects.get(session_id=int(existing_session_id, 16)).interaction_count,
            10,
        )

        session.interaction_count = original_interaction_count
        result = self.repo.save_session(session)
        self.assertEqual(result.interaction_count, original_interaction_count)
        self.assertEqual(
            CowrieSession.objects.get(session_id=int(existing_session_id, 16)).interaction_count,
            original_interaction_count,
        )

    def test_get_command_sequence_by_hash_returns_existing(self):
        existing = self.command_sequence
        result = self.repo.get_command_sequence_by_hash(existing.commands_hash)
        self.assertIsNotNone(result)
        self.assertEqual(result.pk, existing.pk)
        self.assertEqual(result.commands_hash, existing.commands_hash)

    def test_get_command_sequence_by_hash_returns_none_for_missing(self):
        result = self.repo.get_command_sequence_by_hash("nonexistent")
        self.assertIsNone(result)

    def test_save_command_sequence_persists_to_database(self):
        cmd_seq = CommandSequence(
            commands=["ls", "pwd", "whoami"],
            commands_hash="def456",
        )
        result = self.repo.save_command_sequence(cmd_seq)
        self.assertIsNotNone(result.pk)
        self.assertTrue(CommandSequence.objects.filter(commands_hash="def456").exists())

    def test_save_command_sequence_updates_existing(self):
        existing = self.command_sequence
        existing.last_seen = datetime(2025, 1, 2)
        self.repo.save_command_sequence(existing)
        updated = CommandSequence.objects.get(commands_hash=existing.commands_hash)
        self.assertEqual(updated.last_seen.date(), datetime(2025, 1, 2).date())

    def test_get_or_create_session_with_hex_session_id(self):
        session_id = "abc123"
        source_ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        result = self.repo.get_or_create_session(session_id=session_id, source=source_ioc)
        self.assertEqual(result.session_id, int(session_id, 16))

    def test_command_sequence_unique_hash_constraint(self):
        existing = self.command_sequence
        with self.assertRaises(IntegrityError):
            CommandSequence.objects.create(
                commands=["different", "commands"],
                commands_hash=existing.commands_hash,
            )


class TestCowrieSessionRepositoryCleanup(CustomTestCase):
    """Tests for cleanup-related methods in CowrieSessionRepository."""

    def setUp(self):
        self.repo = CowrieSessionRepository()

    def test_delete_old_command_sequences(self):
        old_date = datetime.now() - timedelta(days=40)
        recent_date = datetime.now() - timedelta(days=5)

        CommandSequence.objects.create(commands=["ls"], commands_hash="old_hash", last_seen=old_date)
        CommandSequence.objects.create(commands=["pwd"], commands_hash="recent_hash", last_seen=recent_date)

        cutoff = datetime.now() - timedelta(days=30)
        deleted_count = self.repo.delete_old_command_sequences(cutoff)

        self.assertEqual(deleted_count, 1)
        self.assertFalse(CommandSequence.objects.filter(commands_hash="old_hash").exists())
        self.assertTrue(CommandSequence.objects.filter(commands_hash="recent_hash").exists())

    def test_delete_incomplete_sessions(self):
        source = IOC.objects.create(name="1.2.3.4", type="ip")

        CowrieSession.objects.create(session_id=123, source=source, start_time=None)
        CowrieSession.objects.create(session_id=456, source=source, start_time=datetime.now())

        deleted_count = self.repo.delete_incomplete_sessions()

        self.assertEqual(deleted_count, 1)
        self.assertFalse(CowrieSession.objects.filter(session_id=123).exists())
        self.assertTrue(CowrieSession.objects.filter(session_id=456).exists())

    def test_delete_sessions_without_login(self):
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        old_date = datetime.now() - timedelta(days=40)
        recent_date = datetime.now() - timedelta(days=5)

        # Old session without login
        CowrieSession.objects.create(session_id=111, source=source, start_time=old_date, login_attempt=False)
        # Recent session without login
        CowrieSession.objects.create(session_id=222, source=source, start_time=recent_date, login_attempt=False)
        # Old session with login
        CowrieSession.objects.create(session_id=333, source=source, start_time=old_date, login_attempt=True)

        cutoff = datetime.now() - timedelta(days=30)
        deleted_count = self.repo.delete_sessions_without_login(cutoff)

        self.assertEqual(deleted_count, 1)
        self.assertFalse(CowrieSession.objects.filter(session_id=111).exists())
        self.assertTrue(CowrieSession.objects.filter(session_id=222).exists())
        self.assertTrue(CowrieSession.objects.filter(session_id=333).exists())

    def test_delete_sessions_without_commands(self):
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        old_date = datetime.now() - timedelta(days=40)

        # Session without commands
        CowrieSession.objects.create(session_id=777, source=source, start_time=old_date)
        # Session with commands
        session_with_cmd = CowrieSession.objects.create(session_id=888, source=source, start_time=old_date)
        cmd_seq = CommandSequence.objects.create(commands=["ls"], commands_hash="hash1")
        session_with_cmd.commands = cmd_seq
        session_with_cmd.save()

        cutoff = datetime.now() - timedelta(days=30)
        deleted_count = self.repo.delete_sessions_without_commands(cutoff)

        self.assertEqual(deleted_count, 1)
        self.assertFalse(CowrieSession.objects.filter(session_id=777).exists())
        self.assertTrue(CowrieSession.objects.filter(session_id=888).exists())


class TestCowrieCredentialRepository(CustomTestCase):
    """Tests for credential-related methods in CowrieSessionRepository."""

    def setUp(self):
        self.repo = CowrieSessionRepository()

    def test_save_credential_creates_new(self):
        """Test save_credential creates a new credential and links to session."""
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        session = CowrieSession.objects.create(session_id=11111, source=source)

        created = self.repo.save_credential(session, "admin", "password123")

        self.assertTrue(created)
        self.assertEqual(session.credentials.count(), 1)
        cred = session.credentials.first()
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.password, "password123")

    def test_save_credential_reuses_existing(self):
        """Test save_credential reuses existing credential when duplicate."""
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        session1 = CowrieSession.objects.create(session_id=22222, source=source)
        session2 = CowrieSession.objects.create(session_id=33333, source=source)

        # Create via first session
        created1 = self.repo.save_credential(session1, "root", "toor")
        # Link same credential to second session
        created2 = self.repo.save_credential(session2, "root", "toor")

        self.assertTrue(created1)
        self.assertFalse(created2)

        # Both sessions should share the same credential object
        cred1 = session1.credentials.first()
        cred2 = session2.credentials.first()
        self.assertEqual(cred1.id, cred2.id)

    def test_save_credentials_creates_multiple(self):
        """Test save_credentials creates multiple credentials for a session."""
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        session = CowrieSession.objects.create(session_id=44444, source=source)

        credentials_list = [
            ("user1", "pass1"),
            ("user2", "pass2"),
            ("user3", "pass3"),
        ]
        created_count = self.repo.save_credentials(session, credentials_list)

        self.assertEqual(created_count, 3)
        self.assertEqual(session.credentials.count(), 3)

    def test_save_credentials_deduplicates(self):
        """Test save_credentials deduplicates identical credentials."""
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        session = CowrieSession.objects.create(session_id=55555, source=source)

        # List with duplicates
        credentials_list = [
            ("admin", "admin"),
            ("admin", "admin"),
            ("root", "root"),
        ]
        created_count = self.repo.save_credentials(session, credentials_list)

        # Only 2 unique credentials created
        self.assertEqual(created_count, 2)
        # But session has all 3 links (add() is called 3 times, but M2M auto-dedupes)
        self.assertEqual(session.credentials.count(), 2)

    def test_save_credentials_returns_zero_for_all_existing(self):
        """Test save_credentials returns 0 when all credentials already exist."""
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        session1 = CowrieSession.objects.create(session_id=66666, source=source)
        session2 = CowrieSession.objects.create(session_id=77777, source=source)

        # Create credentials via first session
        self.repo.save_credentials(session1, [("a", "b"), ("c", "d")])

        # Link same credentials to second session
        created_count = self.repo.save_credentials(session2, [("a", "b"), ("c", "d")])

        self.assertEqual(created_count, 0)
        self.assertEqual(session2.credentials.count(), 2)

    def test_delete_orphan_credentials_removes_unlinked(self):
        """Test delete_orphan_credentials removes credentials with no sessions."""
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        session = CowrieSession.objects.create(session_id=88888, source=source)

        # Create credential linked to session
        linked_cred = CowrieCredential.objects.create(username="linked", password="pass")
        session.credentials.add(linked_cred)

        # Create orphan credential (not linked to any session)
        orphan_cred = CowrieCredential.objects.create(username="orphan", password="pass")

        deleted_count = self.repo.delete_orphan_credentials()

        self.assertEqual(deleted_count, 1)
        self.assertTrue(CowrieCredential.objects.filter(id=linked_cred.id).exists())
        self.assertFalse(CowrieCredential.objects.filter(id=orphan_cred.id).exists())

    def test_delete_orphan_credentials_after_session_delete(self):
        """Test orphan cleanup works after session deletion."""
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        session = CowrieSession.objects.create(session_id=99999, source=source)

        # Create and link credential
        cred = CowrieCredential.objects.create(username="temp", password="temp")
        session.credentials.add(cred)
        cred_id = cred.id

        # Credential exists and is linked
        self.assertTrue(CowrieCredential.objects.filter(id=cred_id).exists())

        # Delete session
        session.delete()

        # Credential still exists (M2M doesn't cascade delete)
        self.assertTrue(CowrieCredential.objects.filter(id=cred_id).exists())

        # Now it's orphaned, cleanup should remove it
        deleted_count = self.repo.delete_orphan_credentials()

        self.assertEqual(deleted_count, 1)
        self.assertFalse(CowrieCredential.objects.filter(id=cred_id).exists())

    def test_delete_orphan_credentials_preserves_shared(self):
        """Test orphan cleanup preserves credentials shared across sessions."""
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        session1 = CowrieSession.objects.create(session_id=111111, source=source)
        session2 = CowrieSession.objects.create(session_id=222222, source=source)

        # Create credential linked to both sessions
        shared_cred = CowrieCredential.objects.create(username="shared", password="pass")
        session1.credentials.add(shared_cred)
        session2.credentials.add(shared_cred)
        shared_cred_id = shared_cred.id

        # Delete one session
        session1.delete()

        # Credential should NOT be deleted (still linked to session2)
        deleted_count = self.repo.delete_orphan_credentials()
        self.assertEqual(deleted_count, 0)
        self.assertTrue(CowrieCredential.objects.filter(id=shared_cred_id).exists())

        # Delete second session
        session2.delete()

        # Now it's orphaned
        deleted_count = self.repo.delete_orphan_credentials()
        self.assertEqual(deleted_count, 1)
        self.assertFalse(CowrieCredential.objects.filter(id=shared_cred_id).exists())
