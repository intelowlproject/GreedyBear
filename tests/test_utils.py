# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from ipaddress import ip_address

from django.test import SimpleTestCase

from greedybear.utils import is_ip_address, is_non_global_ip, is_sha256hash, is_valid_domain


class UtilsTestCase(SimpleTestCase):
    def test_is_ip_address(self):
        # Valid IPv4
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("8.8.8.8"))
        # Valid IPv6
        self.assertTrue(is_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
        self.assertTrue(is_ip_address("::1"))
        # Invalid IP
        self.assertFalse(is_ip_address("256.256.256.256"))
        self.assertFalse(is_ip_address("not_an_ip"))
        self.assertFalse(is_ip_address(""))

    def test_is_valid_domain(self):
        # Valid domains
        self.assertTrue(is_valid_domain("example.com"))
        self.assertTrue(is_valid_domain("sub.example.co.uk"))
        self.assertTrue(is_valid_domain("valid-domain.org"))

        # Invalid domains (empty)
        self.assertFalse(is_valid_domain(""))

        # Invalid domains (STIX injection characters)
        self.assertFalse(is_valid_domain("example.com'"))
        self.assertFalse(is_valid_domain('example.com"'))
        self.assertFalse(is_valid_domain("example.com\\"))
        self.assertFalse(is_valid_domain("example.com\n"))
        self.assertFalse(is_valid_domain("example.com\r"))

    def test_is_sha256hash(self):
        # Valid SHA-256
        self.assertTrue(is_sha256hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        self.assertTrue(is_sha256hash("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"))
        # Invalid SHA-256
        self.assertFalse(is_sha256hash("not_a_hash"))
        self.assertFalse(is_sha256hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"))  # 63 chars
        self.assertFalse(is_sha256hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555"))  # 65 chars
        self.assertFalse(is_sha256hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4g49b934ca495991b7852b855"))  # Invalid char 'g'
        self.assertFalse(is_sha256hash(""))

    def test_is_non_global_ip(self):
        self.assertTrue(is_non_global_ip(ip_address("127.0.0.1")))
        self.assertTrue(is_non_global_ip(ip_address("10.0.0.1")))
        self.assertTrue(is_non_global_ip(ip_address("169.254.1.1")))
        self.assertTrue(is_non_global_ip(ip_address("224.0.0.1")))
        self.assertTrue(is_non_global_ip(ip_address("240.0.0.1")))
        self.assertTrue(is_non_global_ip(ip_address("::1")))
        self.assertTrue(is_non_global_ip(ip_address("fc00::1")))

        self.assertFalse(is_non_global_ip(ip_address("8.8.8.8")))
        self.assertFalse(is_non_global_ip(ip_address("2001:4860:4860::8888")))
