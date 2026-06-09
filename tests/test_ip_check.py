"""Tests for checks/ip_check.py"""

import unittest
from checks.ip_check import check_ip_url


class TestIpCheck(unittest.TestCase):

    def test_ipv4_url_triggers(self):
        result = check_ip_url("http://192.168.1.1/login")
        self.assertTrue(result["triggered"])
        self.assertGreater(result["score"], 0)

    def test_ipv4_with_port_triggers(self):
        result = check_ip_url("http://10.0.0.1:8080/admin")
        self.assertTrue(result["triggered"])

    def test_normal_domain_does_not_trigger(self):
        result = check_ip_url("https://google.com")
        self.assertFalse(result["triggered"])
        self.assertEqual(result["score"], 0)

    def test_subdomain_does_not_trigger(self):
        result = check_ip_url("https://mail.google.com/inbox")
        self.assertFalse(result["triggered"])

    def test_localhost_does_not_trigger(self):
        # 'localhost' is not a numeric IP
        result = check_ip_url("http://localhost:5000/")
        self.assertFalse(result["triggered"])


if __name__ == "__main__":
    unittest.main()
