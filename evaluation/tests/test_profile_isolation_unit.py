#!/usr/bin/env python3
"""
Unit tests for Profile Isolation probe classification logic.
Tests fail-closed requirements:
- HTTP 404/403 -> PROTECTED
- HTTP 2xx -> EXPOSED
- HTTP 405 -> METHOD_MISMATCH_EXPOSED (never classified as protected)
- None/Exception -> OFFLINE
- Non-protected status codes fail overall check
"""

import unittest
from pathlib import Path
import sys

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR))

import test_profile_isolation as iso


class ProfileIsolationClassificationTests(unittest.TestCase):
    def test_404_and_403_are_protected(self):
        self.assertEqual(iso.classify_probe_result(404), "PROTECTED")
        self.assertEqual(iso.classify_probe_result(403), "PROTECTED")

    def test_200_and_2xx_are_exposed(self):
        self.assertEqual(iso.classify_probe_result(200), "EXPOSED")
        self.assertEqual(iso.classify_probe_result(201), "EXPOSED")
        self.assertEqual(iso.classify_probe_result(204), "EXPOSED")

    def test_405_is_not_protected(self):
        result = iso.classify_probe_result(405)
        self.assertEqual(result, "METHOD_MISMATCH_EXPOSED")
        self.assertNotEqual(result, "PROTECTED")

    def test_offline_is_offline(self):
        self.assertEqual(iso.classify_probe_result(None), "OFFLINE")

    def test_other_codes_are_rejected(self):
        self.assertEqual(iso.classify_probe_result(500), "REJECTED_HTTP_500")
        self.assertEqual(iso.classify_probe_result(400), "REJECTED_HTTP_400")

    def test_spec_declares_http_methods(self):
        for item in iso.TEST_ENDPOINTS_SPEC:
            self.assertIn(item["method"], ("GET", "POST", "PUT", "DELETE"))
            self.assertTrue(item["path"].startswith("/api/test"))
            if item["method"] == "POST":
                self.assertIsNotNone(item["body"])


if __name__ == "__main__":
    unittest.main()
