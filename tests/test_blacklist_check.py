"""Tests for checks/blacklist_check.py"""

import os
import tempfile
import unittest
from checks.blacklist_check import check_blacklist


class TestBlacklistCheck(unittest.TestCase):

    def setUp(self):
        """Create a temporary blacklist file for testing."""
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        self.tmp.write("# Test blacklist\n")
        self.tmp.write("known-phishing-site.com\n")
        self.tmp.write("evil-domain.net\n")
        self.tmp.close()
        self.blacklist_path = self.tmp.name

    def tearDown(self):
        os.unlink(self.blacklist_path)

    def test_blacklisted_domain_triggers(self):
        result = check_blacklist(
            "https://known-phishing-site.com/steal-creds",
            blacklist_path=self.blacklist_path,
        )
        self.assertTrue(result["triggered"])
        self.assertGreater(result["score"], 0)

    def test_safe_domain_does_not_trigger(self):
        result = check_blacklist(
            "https://google.com",
            blacklist_path=self.blacklist_path,
        )
        self.assertFalse(result["triggered"])
        self.assertEqual(result["score"], 0)

    def test_subdomain_of_blacklisted_does_not_trigger(self):
        # The check is exact-match on hostname; subdomains are NOT auto-matched
        result = check_blacklist(
            "https://sub.known-phishing-site.com",
            blacklist_path=self.blacklist_path,
        )
        self.assertFalse(result["triggered"])

    def test_missing_blacklist_file_does_not_crash(self):
        result = check_blacklist(
            "https://google.com",
            blacklist_path="/nonexistent/path/blacklist.txt",
        )
        self.assertFalse(result["triggered"])

    def test_comment_lines_are_ignored(self):
        result = check_blacklist(
            "https://test blacklist",
            blacklist_path=self.blacklist_path,
        )
        self.assertFalse(result["triggered"])


if __name__ == "__main__":
    unittest.main()
