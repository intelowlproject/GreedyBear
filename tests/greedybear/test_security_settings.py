# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.conf import settings
from django.test import SimpleTestCase


class SecuritySettingsTests(SimpleTestCase):
    def test_content_type_nosniff_enabled(self):
        """SECURE_CONTENT_TYPE_NOSNIFF should always be True."""
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)

    def test_x_frame_options_deny(self):
        """X_FRAME_OPTIONS should be DENY to block all framing."""
        self.assertEqual(settings.X_FRAME_OPTIONS, "DENY")

    def test_ssl_redirect_not_set(self):
        """SECURE_SSL_REDIRECT must not be enabled (TLS terminates at nginx)."""
        self.assertFalse(getattr(settings, "SECURE_SSL_REDIRECT", False))

    def test_cookie_security_matches_environment(self):
        """Cookies should only be marked secure in production."""
        is_production = getattr(settings, "STAGE_PRODUCTION", False)
        
        # Test SESSION_COOKIE_SECURE
        session_secure = getattr(settings, "SESSION_COOKIE_SECURE", False)
        self.assertEqual(session_secure, is_production)
        
        # Test CSRF_COOKIE_SECURE
        csrf_secure = getattr(settings, "CSRF_COOKIE_SECURE", False)
        self.assertEqual(csrf_secure, is_production)
