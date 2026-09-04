#!/usr/bin/env python3
"""Offline positive and negative controls for the output-privacy checker."""

import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "privacy_check", Path(__file__).with_name("check-log-privacy.py")
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        self.markers = [b"dummy-environment-marker", b"dummy-argument-marker"]
        self.passwords = [b"offline-test-password"]

    def test_clean_status_is_allowed(self):
        report = CHECK.scan(b"Waiting for Syn approval on your Mac\n", self.markers, self.passwords)
        self.assertFalse(any(report.values()))

    def test_each_sensitive_value_is_detected_without_returning_it(self):
        data = b"\n".join(self.markers + self.passwords + [b"-----BEGIN EC PRIVATE KEY-----"])
        report = CHECK.scan(data, self.markers, self.passwords)
        self.assertEqual(report, {"pem_material": 1, "environment_marker": 1, "argument_marker": 1, "test_password": 1})
        self.assertNotIn(self.passwords[0].decode(), str(report))

    def test_pem_variants_and_duplicates_are_detected(self):
        for label in (b"PRIVATE KEY", b"RSA PRIVATE KEY", b"OPENSSH PRIVATE KEY", b"ENCRYPTED PRIVATE KEY", b"CERTIFICATE"):
            report = CHECK.scan(b"-----BEGIN " + label + b"-----", self.markers, [])
            self.assertEqual(report["pem_material"], 1)
        self.assertEqual(CHECK.scan(self.passwords[0] * 2, self.markers, self.passwords)["test_password"], 2)

    def test_empty_and_oversized_captures_are_not_evidence(self):
        class MemoryPath:
            def __init__(self, data):
                self.data = data

            def open(self, mode):
                return io.BytesIO(self.data)

        with patch.object(CHECK, "MAX_CAPTURE_BYTES", 4):
            for data in (b"", b"12345"):
                with self.assertRaises(ValueError):
                    CHECK.read_capture(MemoryPath(data))
            self.assertEqual(CHECK.read_capture(MemoryPath(b"1234")), b"1234")


if __name__ == "__main__":
    unittest.main()
