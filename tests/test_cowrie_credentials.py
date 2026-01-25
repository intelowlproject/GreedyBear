from datetime import datetime

from django.db import IntegrityError

from greedybear.cronjobs.extraction.strategies.cowrie import CowrieExtractionStrategy
from greedybear.cronjobs.repositories import CowrieSessionRepository, IocRepository, SensorRepository

# Use TransactionTestCase to test database constraints like unique_together properly handles rollback if needed,
# although TestCase usually handles it with savepoints. Standard TestCase is faster.
from greedybear.models import IOC, CowrieCredential, CowrieSession

from . import CustomTestCase


class CowrieCredentialModelTestCase(CustomTestCase):
    def test_credential_creation(self):
        """Test that we can create a credential linked to a session."""
        # Use existing session from setUpTestData or create new
        session = self.cowrie_session

        cred = CowrieCredential.objects.create(session=session, username="newuser", password="newpassword")
        self.assertEqual(cred.username, "newuser")
        self.assertEqual(cred.password, "newpassword")
        self.assertEqual(cred.session, session)

    def test_unique_constraint(self):
        """Test that (session, username, password) must be unique."""
        session = self.cowrie_session

        # 'root' | 'root' already exists from setUpTestData
        with self.assertRaises(IntegrityError):
            CowrieCredential.objects.create(session=session, username="root", password="root")

    def test_multiple_creds_same_session(self):
        """Test that a session can have multiple different credentials."""
        session = self.cowrie_session

        CowrieCredential.objects.create(session=session, username="u1", password="p1")
        CowrieCredential.objects.create(session=session, username="u2", password="p2")

        self.assertEqual(session.credential_set.count(), 3)  # 1 from setup + 2 new


class CowrieStrategyIntegrationTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.ioc_repo = IocRepository()
        self.sensor_repo = SensorRepository()
        self.session_repo = CowrieSessionRepository()
        self.strategy = CowrieExtractionStrategy(honeypot="Cowrie", ioc_repo=self.ioc_repo, sensor_repo=self.sensor_repo, session_repo=self.session_repo)

    def test_extract_login_success(self):
        """Test extraction of a successful login creates a credential."""
        # Clean up existing sessions to have a clean slate for this test?
        # Or just use a fresh unique IP for the scanner.
        scanner_ip = "1.2.3.4"

        # Pre-process hits as the pipeline does (converting _source to dict usually handled by elastic client)
        # The strategy expects a list of dicts. The pipeline does hit.to_dict().
        # Let's assume the list pass to extract_from_hits is simple dicts.

        simple_hits = [
            {
                "src_ip": scanner_ip,
                "timestamp": datetime.now(),
                "session": "aabbccddeeff",
                "eventid": "cowrie.login.success",
                "username": "admin",
                "password": "password123",
                "message": "login attempt",
                "duration": 1.0,
            }
        ]

        self.strategy.extract_from_hits(simple_hits)

        # Check IOC created
        ioc = IOC.objects.get(name=scanner_ip)
        self.assertIsNotNone(ioc)

        # Check Session created
        session = CowrieSession.objects.get(session_id=int("aabbccddeeff", 16))
        self.assertIsNotNone(session)

        # Check Credential created
        creds = CowrieCredential.objects.filter(session=session)
        self.assertEqual(creds.count(), 1)
        self.assertEqual(creds.first().username, "admin")
        self.assertEqual(creds.first().password, "password123")

        # Check backward compatibility ArrayField -> No longer populated
        self.assertEqual(len(session.credentials), 0)

    def test_extract_login_failed_multiple(self):
        """Test extraction of multiple failed logins in same session."""
        scanner_ip = "5.6.7.8"
        session_id_hex = "1234567890ab"

        simple_hits = [
            {
                "src_ip": scanner_ip,
                "timestamp": datetime.now(),
                "session": session_id_hex,
                "eventid": "cowrie.login.failed",
                "username": "root",
                "password": "123",
                "message": "failed",
            },
            {
                "src_ip": scanner_ip,
                "timestamp": datetime.now(),
                "session": session_id_hex,
                "eventid": "cowrie.login.failed",
                "username": "root",
                "password": "456",
                "message": "failed",
            },
        ]

        self.strategy.extract_from_hits(simple_hits)

        session = CowrieSession.objects.get(session_id=int(session_id_hex, 16))

        # Should have 2 credentials
        self.assertEqual(session.credential_set.count(), 2)

        usernames = sorted([c.username for c in session.credential_set.all()])
        passwords = sorted([c.password for c in session.credential_set.all()])

        self.assertEqual(usernames, ["root", "root"])
        self.assertEqual(passwords, ["123", "456"])

        # The ArrayField on the session is no longer populated
        self.assertEqual(len(session.credentials), 0)

    def test_duplicate_credentials_deduplication(self):
        """Test that identical credentials in the same session are not duplicated in DB."""
        scanner_ip = "9.9.9.9"
        session_id_hex = "abcdef123456"

        # Same credential repeated in logs
        simple_hits = [
            {
                "src_ip": scanner_ip,
                "timestamp": datetime.now(),
                "session": session_id_hex,
                "eventid": "cowrie.login.failed",
                "username": "user",
                "password": "pass",
                "message": "failed",
            },
            {
                "src_ip": scanner_ip,
                "timestamp": datetime.now(),
                "session": session_id_hex,
                "eventid": "cowrie.login.failed",
                "username": "user",
                "password": "pass",
                "message": "failed again",
            },
        ]

        self.strategy.extract_from_hits(simple_hits)

        session = CowrieSession.objects.get(session_id=int(session_id_hex, 16))

        # Should have ONLY 1 credential record per unique pair
        self.assertEqual(session.credential_set.count(), 1)
        cred = session.credential_set.first()
        self.assertEqual(cred.username, "user")
        self.assertEqual(cred.password, "pass")

        # The ArrayField on the session is no longer populated
        self.assertEqual(len(session.credentials), 0)

    def test_null_character_normalization(self):
        """Test that null chars are replaced."""
        scanner_ip = "11.11.11.11"
        session_id_hex = "cccccccccccc"

        simple_hits = [
            {
                "src_ip": scanner_ip,
                "timestamp": datetime.now(),
                "session": session_id_hex,
                "eventid": "cowrie.login.failed",
                "username": "us\x00er",
                "password": "pa\x00ss",
                "message": "failed",
            }
        ]

        self.strategy.extract_from_hits(simple_hits)

        session = CowrieSession.objects.get(session_id=int(session_id_hex, 16))
        cred = session.credential_set.first()

        self.assertEqual(cred.username, "us[NUL]er")
        self.assertEqual(cred.password, "pa[NUL]ss")
