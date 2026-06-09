"""Tests for checks/length_check.py"""

import unittest
from checks.length_check import check_url_length, LENGTH_THRESHOLD


class TestLengthCheck(unittest.TestCase):

    def test_short_url_does_not_trigger(self):
        result = check_url_length("https://google.com")
        self.assertFalse(result["triggered"])
        self.assertEqual(result["score"], 0)

    def test_url_at_threshold_does_not_trigger(self):
        url = "https://example.com/" + "a" * (LENGTH_THRESHOLD - len("https://example.com/"))
        self.assertEqual(len(url), LENGTH_THRESHOLD)
        result = check_url_length(url)
        self.assertFalse(result["triggered"])

    def test_url_over_threshold_triggers(self):
        url = "https://example.com/" + "a" * 100
        self.assertGreater(len(url), LENGTH_THRESHOLD)
        result = check_url_length(url)
        self.assertTrue(result["triggered"])
        self.assertGreater(result["score"], 0)

    def test_very_long_url_triggers(self):
        url = "http://legitimate-looking-domain.com/" + "x" * 200
        result = check_url_length(url)
        self.assertTrue(result["triggered"])


if __name__ == "__main__":
    unittest.main()
