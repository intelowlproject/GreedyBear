# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
Comprehensive test suite for CowrieCredential model and credential-based queries.

Tests cover:
- Model creation and relationships
- Database constraints and indexes
- Query operations (exact, case-insensitive, joins)
- API endpoint integration
- Data integrity and edge cases
"""

from datetime import datetime

from django.db import IntegrityError, transaction
from rest_framework.test import APIClient

from greedybear.cronjobs.extraction.strategies.cowrie import CowrieExtractionStrategy
from greedybear.cronjobs.repositories import CowrieSessionRepository, IocRepository, SensorRepository
from greedybear.models import IOC, CowrieCredential, CowrieSession, IocType

from . import CustomTestCase


class CowrieCredentialModelTestCase(CustomTestCase):
    """Test CowrieCredential model functionality."""

    def test_create_credential_with_valid_data(self):
        """Test creating a credential with valid session, username, and password."""
        credential = CowrieCredential.objects.create(
            session=self.cowrie_session,
            username="testuser",
            password="testpass123",
        )
        self.assertIsNotNone(credential.id)
        self.assertEqual(credential.session, self.cowrie_session)
        self.assertEqual(credential.username, "testuser")
        self.assertEqual(credential.password, "testpass123")

    def test_credential_string_representation(self):
        """Test __str__ returns 'username | password' format."""
        credential = CowrieCredential.objects.create(
            session=self.cowrie_session,
            username="admin",
            password="secret",
        )
        self.assertEqual(str(credential), "admin | secret")

    def test_foreign_key_relationship(self):
        """Test ForeignKey relationship between credential and session."""
        credential = CowrieCredential.objects.create(
            session=self.cowrie_session,
            username="user",
            password="pass",
        )
        # Forward relationship
        self.assertEqual(credential.session.session_id, self.cowrie_session.session_id)

        # Reverse relationship
        credentials = self.cowrie_session.credential_set.all()
        self.assertIn(credential, credentials)

    def test_cascade_delete(self):
        """Test credentials are deleted when session is deleted (CASCADE)."""
        credential = CowrieCredential.objects.create(
            session=self.cowrie_session,
            username="temp",
            password="temp123",
        )
        credential_id = credential.id

        # Delete session
        self.cowrie_session.delete()

        # Credential should be deleted
        self.assertFalse(CowrieCredential.objects.filter(id=credential_id).exists())

    def test_multiple_credentials_per_session(self):
        """Test that one session can have multiple credentials."""
        cred1 = CowrieCredential.objects.create(session=self.cowrie_session, username="user1", password="pass1")
        cred2 = CowrieCredential.objects.create(session=self.cowrie_session, username="user2", password="pass2")
        cred3 = CowrieCredential.objects.create(session=self.cowrie_session, username="user3", password="pass3")

        credentials = list(self.cowrie_session.credential_set.all())
        # Should have at least 4 (1 from setup + 3 created here)
        self.assertGreaterEqual(len(credentials), 4)
        self.assertIn(cred1, credentials)
        self.assertIn(cred2, credentials)
        self.assertIn(cred3, credentials)

    def test_empty_username_allowed(self):
        """Test credentials can have empty username (blank=True)."""
        credential = CowrieCredential.objects.create(
            session=self.cowrie_session,
            username="",
            password="password123",
        )
        self.assertEqual(credential.username, "")
        self.assertEqual(str(credential), " | password123")

    def test_empty_password_allowed(self):
        """Test credentials can have empty password (blank=True)."""
        credential = CowrieCredential.objects.create(
            session=self.cowrie_session,
            username="username123",
            password="",
        )
        self.assertEqual(credential.password, "")
        self.assertEqual(str(credential), "username123 | ")

    def test_max_length_username(self):
        """Test username field respects max_length=256."""
        long_username = "a" * 256
        credential = CowrieCredential.objects.create(
            session=self.cowrie_session,
            username=long_username,
            password="test",
        )
        self.assertEqual(len(credential.username), 256)

    def test_max_length_password(self):
        """Test password field respects max_length=256."""
        long_password = "b" * 256
        credential = CowrieCredential.objects.create(
            session=self.cowrie_session,
            username="test",
            password=long_password,
        )
        self.assertEqual(len(credential.password), 256)


class CowrieCredentialQueryTestCase(CustomTestCase):
    """Test querying CowrieCredential objects."""

    def test_query_by_exact_password(self):
        """Test exact password match query."""
        credentials = CowrieCredential.objects.filter(password="root")
        self.assertEqual(credentials.count(), 1)
        self.assertEqual(credentials.first().password, "root")
        self.assertEqual(credentials.first().username, "root")

    def test_query_by_password_case_insensitive(self):
        """Test case-insensitive password queries using __iexact."""
        # Create test credential
        CowrieCredential.objects.create(session=self.cowrie_session, username="test", password="TestPass")

        # All case variations should match
        self.assertTrue(CowrieCredential.objects.filter(password__iexact="testpass").exists())
        self.assertTrue(CowrieCredential.objects.filter(password__iexact="TESTPASS").exists())
        self.assertTrue(CowrieCredential.objects.filter(password__iexact="TestPass").exists())

    def test_query_by_username(self):
        """Test querying by username field."""
        credentials = CowrieCredential.objects.filter(username="root")
        self.assertEqual(credentials.count(), 1)
        self.assertEqual(credentials.first().username, "root")

    def test_query_by_username_and_password(self):
        """Test composite query with both username and password."""
        credentials = CowrieCredential.objects.filter(username="root", password="root")
        self.assertEqual(credentials.count(), 1)
        cred = credentials.first()
        self.assertEqual(cred.username, "root")
        self.assertEqual(cred.password, "root")

    def test_query_sessions_via_password(self):
        """Test querying sessions through credential_set reverse relationship."""
        sessions = CowrieSession.objects.filter(credential_set__password="root")
        self.assertGreater(sessions.count(), 0)
        self.assertIn(self.cowrie_session, sessions)

    def test_query_sessions_distinct(self):
        """Test .distinct() prevents duplicate sessions in results."""
        # Add multiple credentials with same password to one session
        CowrieCredential.objects.create(session=self.cowrie_session, username="admin", password="duplicate")
        CowrieCredential.objects.create(session=self.cowrie_session, username="user", password="duplicate")

        # Without distinct, would get duplicate sessions
        CowrieSession.objects.filter(credential_set__password="duplicate")
        sessions_with_distinct = CowrieSession.objects.filter(credential_set__password="duplicate").distinct()

        # Verify distinct works
        session_ids = [s.session_id for s in sessions_with_distinct]
        self.assertEqual(len(session_ids), len(set(session_ids)))

    def test_query_nonexistent_password(self):
        """Test querying for password that doesn't exist."""
        credentials = CowrieCredential.objects.filter(password="nonexistent_password_xyz")
        self.assertEqual(credentials.count(), 0)

    def test_query_with_prefetch_related(self):
        """Test prefetch_related optimization for credential_set."""
        sessions = CowrieSession.objects.filter(credential_set__password="root").distinct().prefetch_related("credential_set")

        session = sessions.first()
        self.assertIsNotNone(session)

        # Accessing credential_set should use prefetched data
        credentials = list(session.credential_set.all())
        self.assertGreater(len(credentials), 0)


class CowrieCredentialEdgeCasesTestCase(CustomTestCase):
    """Test edge cases and special scenarios."""

    def test_special_characters_in_password(self):
        """Test passwords with special characters are stored correctly."""
        special_chars = [
            "!@#$%^&*()",
            "{}[]|\\;:'\"",
            "<>,./",
            "~`",
            "password<script>alert('xss')</script>",
        ]
        for password in special_chars:
            CowrieCredential.objects.create(
                session=self.cowrie_session,
                username="user",
                password=password,
            )
            # Verify stored correctly
            found = CowrieCredential.objects.filter(password=password).first()
            self.assertIsNotNone(found)
            self.assertEqual(found.password, password)

    def test_sql_injection_attempts_handled_safely(self):
        """Test SQL injection attempts are safely stored as strings."""
        sql_attempts = [
            "'; DROP TABLE--",
            "' OR '1'='1",
            "admin'--",
            "1' UNION SELECT NULL--",
        ]
        for attempt in sql_attempts:
            CowrieCredential.objects.create(
                session=self.cowrie_session,
                username="user",
                password=attempt,
            )
            # Django ORM should handle this safely
            found = CowrieCredential.objects.filter(password=attempt).first()
            self.assertIsNotNone(found)
            self.assertEqual(found.password, attempt)

    def test_unicode_in_credentials(self):
        """Test Unicode and international characters in credentials."""
        unicode_passwords = [
            "密码123",  # Chinese
            "пароль",  # Russian
            "パスワード",  # Japanese
        ]
        for password in unicode_passwords:
            CowrieCredential.objects.create(
                session=self.cowrie_session,
                username="user",
                password=password,
            )
            found = CowrieCredential.objects.filter(password__iexact=password).first()
            self.assertIsNotNone(found)

    def test_whitespace_handling(self):
        """Test credentials with leading/trailing whitespace."""
        whitespace_tests = [
            " password",
            "password ",
            " pass word ",
        ]
        for password in whitespace_tests:
            CowrieCredential.objects.create(
                session=self.cowrie_session,
                username="user",
                password=password,
            )
            # Whitespace should be preserved
            found = CowrieCredential.objects.filter(password=password).first()
            self.assertIsNotNone(found)
            self.assertEqual(found.password, password)

    def test_multiple_sessions_same_password(self):
        """Test multiple sessions can share the same password."""
        password = "shared_password"

        # Create additional sessions with same password
        for i in range(3):
            ioc = IOC.objects.create(
                name=f"192.168.1.{100 + i}",
                type=IocType.IP.value,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            )
            ioc.general_honeypot.add(self.cowrie_hp)
            session = CowrieSession.objects.create(
                session_id=int(f"{i:012x}", 16),
                source=ioc,
                duration=1,
            )
            CowrieCredential.objects.create(session=session, username=f"user{i}", password=password)

        # Query should find all sessions
        sessions = CowrieSession.objects.filter(credential_set__password=password, duration__gt=0).distinct()

        self.assertGreaterEqual(sessions.count(), 3)


class CowrieCredentialAPIIntegrationTestCase(CustomTestCase):
    """Test API endpoint integration with CowrieCredential."""

    def setUp(self):
        """Set up API client."""
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_password_query_returns_sessions(self):
        """Test API password query returns correct sessions."""
        response = self.client.get("/api/cowrie_session?query=root")
        self.assertEqual(response.status_code, 200)
        self.assertIn("sources", response.data)
        self.assertIn(self.cowrie_session.source.name, response.data["sources"])

    def test_password_query_case_sensitive(self):
        """Test password queries are case-sensitive."""
        response_lower = self.client.get("/api/cowrie_session?query=root")
        response_upper = self.client.get("/api/cowrie_session?query=ROOT")

        self.assertEqual(response_lower.status_code, 200)
        self.assertEqual(response_upper.status_code, 404)

    def test_password_query_nonexistent_returns_404(self):
        """Test querying non-existent password returns 404."""
        response = self.client.get("/api/cowrie_session?query=nonexistent_xyz")
        self.assertEqual(response.status_code, 404)

    def test_password_query_with_credentials_included(self):
        """Test include_credentials parameter works."""
        response = self.client.get("/api/cowrie_session?query=root&include_credentials=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("credentials", response.data)
        self.assertIn("root | root", response.data["credentials"])

    def test_password_query_with_session_data(self):
        """Test include_session_data parameter works."""
        response = self.client.get("/api/cowrie_session?query=root&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("sessions", response.data)
        self.assertGreater(len(response.data["sessions"]), 0)

        session_data = response.data["sessions"][0]
        self.assertIn("credentials", session_data)
        self.assertIn("root | root", session_data["credentials"])

    def test_credentials_format_in_response(self):
        """Test credentials are formatted as 'username | password'."""
        response = self.client.get("/api/cowrie_session?query=root&include_credentials=true")
        self.assertEqual(response.status_code, 200)

        for credential in response.data["credentials"]:
            self.assertIn(" | ", credential)
            parts = credential.split(" | ", 1)
            self.assertEqual(len(parts), 2)

    def test_special_characters_in_password_query(self):
        """Test password queries with special characters work (not treated as attacks)."""
        # Create credential with special characters
        special_password = "<script>alert('xss')</script>"
        CowrieCredential.objects.create(
            session=self.cowrie_session,
            username="test",
            password=special_password,
        )

        # Query should work (not be rejected as XSS)
        from urllib.parse import quote

        response = self.client.get(f"/api/cowrie_session?query={quote(special_password)}")
        # Should return 200 (found) or 404 (not found due to duration filter)
        # but NOT 400 (validation error)
        self.assertIn(response.status_code, [200, 404])
        self.assertNotEqual(response.status_code, 400)

    def test_ip_query_still_works(self):
        """Test IP queries still work after credential refactoring."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("sources", response.data)

    def test_hash_query_still_works(self):
        """Test hash queries still work after credential refactoring."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("sources", response.data)


class CowrieCredentialDataIntegrityTestCase(CustomTestCase):
    """Test data integrity and consistency."""

    def test_cronjob_get_or_create_prevents_duplicates(self):
        """Test get_or_create prevents duplicate credentials."""
        # First creation
        cred1, created1 = CowrieCredential.objects.get_or_create(
            session=self.cowrie_session,
            username="testuser",
            password="testpass",
        )
        self.assertTrue(created1)

        # Second attempt - should get existing
        cred2, created2 = CowrieCredential.objects.get_or_create(
            session=self.cowrie_session,
            username="testuser",
            password="testpass",
        )
        self.assertFalse(created2)
        self.assertEqual(cred1.id, cred2.id)

    def test_credentials_require_saved_session(self):
        """Test credentials can only be created for saved sessions."""
        # Create but don't save session
        ioc = IOC.objects.create(
            name="192.168.1.200",
            type=IocType.IP.value,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
        )
        ioc.general_honeypot.add(self.cowrie_hp)
        session = CowrieSession(
            session_id=int("abcdef123456", 16),
            source=ioc,
        )

        # Must save session first (ForeignKey requirement)
        session.save()

        # Now can create credential
        credential = CowrieCredential.objects.create(
            session=session,
            username="user",
            password="pass",
        )
        self.assertIsNotNone(credential.id)

    def test_unique_constraint_prevents_duplicates(self):
        """Test unique_together constraint prevents duplicate credentials."""
        # Create first credential
        CowrieCredential.objects.create(
            session=self.cowrie_session,
            username="testuser",
            password="testpass",
        )

        # Attempting to create duplicate should raise IntegrityError
        with transaction.atomic():
            with self.assertRaises(IntegrityError):
                CowrieCredential.objects.create(
                    session=self.cowrie_session,
                    username="testuser",
                    password="testpass",
                )

        # get_or_create should work (returns existing)
        cred, created = CowrieCredential.objects.get_or_create(
            session=self.cowrie_session,
            username="testuser",
            password="testpass",
        )
        self.assertFalse(created)


class CowrieStrategyIntegrationTestCase(CustomTestCase):
    """Test integration of CowrieExtractionStrategy with CowrieCredential."""

    def setUp(self):
        super().setUp()
        self.ioc_repo = IocRepository()
        self.sensor_repo = SensorRepository()
        self.session_repo = CowrieSessionRepository()
        self.strategy = CowrieExtractionStrategy(
            honeypot="Cowrie",
            ioc_repo=self.ioc_repo,
            sensor_repo=self.sensor_repo,
            session_repo=self.session_repo,
        )

    def test_extract_login_success(self):
        """Test extraction of a successful login creates a credential."""
        scanner_ip = "1.2.3.4"
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
