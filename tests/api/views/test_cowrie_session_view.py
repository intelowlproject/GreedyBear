from django.test import override_settings
from rest_framework.test import APIClient

from tests import CustomTestCase


class CowrieSessionViewTestCase(CustomTestCase):
    """Test cases for the cowrie_session_view."""

    def setUp(self):
        # setup client
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    # # # # # Basic IP Query Test # # # # #
    def test_ip_address_query(self):
        """Test view with a valid IP address query."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)

    def test_ip_address_query_with_similar(self):
        """Test view with a valid IP address query including similar sequences."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_similar=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)
        self.assertEqual(len(response.data["sources"]), 2)

    def test_ip_address_query_with_credentials(self):
        """Test view with a valid IP address query including credentials."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)
        self.assertEqual(len(response.data["credentials"]), 1)
        self.assertEqual(response.data["credentials"][0], "root | root")

    def test_ip_address_query_with_sessions(self):
        """Test view with a valid IP address query including session data."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertIn("sessions", response.data)
        self.assertEqual(len(response.data["sessions"]), 1)
        self.assertIn("time", response.data["sessions"][0])
        self.assertEqual(response.data["sessions"][0]["duration"], 1.234)
        self.assertEqual(response.data["sessions"][0]["source"], "140.246.171.141")
        self.assertEqual(response.data["sessions"][0]["interactions"], 5)
        self.assertEqual(response.data["sessions"][0]["credentials"][0], "root | root")
        self.assertEqual(response.data["sessions"][0]["commands"], "cd foo\nls -la")

    def test_ip_address_query_with_all(self):
        """Test view with a valid IP address query including everything."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_similar=true&include_credentials=true&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertIn("credentials", response.data)
        self.assertIn("sessions", response.data)

    # # # # # Basic Hash Query Test # # # # #
    def test_hash_query(self):
        """Test view with a valid hash query."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)

    def test_hash_query_with_all(self):
        """Test view with a valid hash query including everything."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}&include_similar=true&include_credentials=true&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertIn("credentials", response.data)
        self.assertIn("sessions", response.data)
        self.assertEqual(len(response.data["sources"]), 2)

    # # # # # IP Address Validation Tests # # # # #
    def test_nonexistent_ip_address(self):
        """Test that view returns 404 for IP with no sequences."""
        response = self.client.get("/api/cowrie_session?query=10.0.0.1")
        self.assertEqual(response.status_code, 404)

    def test_ipv6_address_query(self):
        """Test view with a valid IPv6 address query."""
        response = self.client.get("/api/cowrie_session?query=2001:db8::1")
        self.assertEqual(response.status_code, 404)

    def test_invalid_ip_format(self):
        """Test that malformed IP addresses are rejected."""
        response = self.client.get("/api/cowrie_session?query=999.999.999.999")
        self.assertEqual(response.status_code, 400)

    def test_ip_with_cidr_notation(self):
        """Test that CIDR notation is rejected."""
        response = self.client.get("/api/cowrie_session?query=192.168.1.0/24")
        self.assertEqual(response.status_code, 400)

    # # # # # Parameter Validation Tests # # # # #
    def test_missing_query_parameter(self):
        """Test that view returns BadRequest when query parameter is missing."""
        response = self.client.get("/api/cowrie_session")
        self.assertEqual(response.status_code, 400)

    def test_invalid_query_parameter(self):
        """Test that view returns BadRequest when query parameter is invalid."""
        response = self.client.get("/api/cowrie_session?query=invalid-input}")
        self.assertEqual(response.status_code, 400)

    def test_include_credentials_invalid_value(self):
        """Test that invalid boolean values default to false."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=maybe")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("credentials", response.data)

    def test_case_insensitive_boolean_parameters(self):
        """Test that boolean parameters accept various case formats."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=TRUE")
        self.assertEqual(response.status_code, 200)
        self.assertIn("credentials", response.data)

        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=True")
        self.assertEqual(response.status_code, 200)
        self.assertIn("credentials", response.data)

    # # # # # Hash Validation Tests # # # # #
    def test_nonexistent_hash(self):
        """Test that view returns 404 for nonexistent hash."""
        response = self.client.get(f"/api/cowrie_session?query={'f' * 64}")
        self.assertEqual(response.status_code, 404)

    def test_hash_wrong_length(self):
        """Test that hashes with incorrect length are rejected."""
        response = self.client.get("/api/cowrie_session?query=" + "a" * 32)  # 32 chars instead of 64
        self.assertEqual(response.status_code, 400)

    def test_hash_invalid_characters(self):
        """Test that hashes with invalid characters are rejected."""
        invalid_hash = "g" * 64  # 'g' is not a valid hex character
        response = self.client.get(f"/api/cowrie_session?query={invalid_hash}")
        self.assertEqual(response.status_code, 400)

    def test_hash_case_insensitive(self):
        """Test that hash queries are case-insensitive."""
        response_lower = self.client.get(f"/api/cowrie_session?query={self.hash.lower()}")
        response_upper = self.client.get(f"/api/cowrie_session?query={self.hash.upper()}")
        self.assertEqual(response_lower.status_code, response_upper.status_code)

    # # # # # Special Characters & Encoding Tests # # # # #
    def test_query_with_url_encoding(self):
        """Test that URL-encoded queries work correctly."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141%20")
        # Should either work or return 400, not crash
        self.assertIn(response.status_code, [200, 400, 404])

    # # # # # License Tests # # # # #
    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_ip_query_with_license(self):
        """Test that license is included when FEEDS_LICENSE is populated."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.data)
        self.assertEqual(response.data["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_ip_query_without_license(self):
        """Test that license is not included when FEEDS_LICENSE is empty."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.data)

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_hash_query_with_license(self):
        """Test that license is included when FEEDS_LICENSE is populated."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.data)
        self.assertEqual(response.data["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_hash_query_without_license(self):
        """Test that license is not included when FEEDS_LICENSE is empty."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.data)

    def test_query_with_special_characters(self):
        """Test handling of queries with special characters."""
        response = self.client.get("/api/cowrie_session?query=<script>alert('xss')</script>")
        self.assertEqual(response.status_code, 400)

    # # # # # Authentication & Authorization Tests # # # # #
    def test_unauthenticated_request(self):
        """Test that unauthenticated requests are rejected."""
        client = APIClient()  # No authentication
        response = client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 401)

    def test_regular_user_access(self):
        """Test that regular (non-superuser) authenticated users can access."""
        client = APIClient()
        client.force_authenticate(user=self.regular_user)
        response = client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
