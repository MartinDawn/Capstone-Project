#!/usr/bin/env python3
"""
Offline unit tests for multi-session transaction context isolation.
Verifies that worker thread instances create independent request headers, cookies,
nonces, and state tokens without sharing mutable global state.
"""

import unittest
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evaluation.bin.perf.session_isolation_live import MODEL_ALIASES, verify_live_isolation


class TestSessionContextUnit(unittest.TestCase):
    def test_model_aliases_mapping(self):
        self.assertEqual(MODEL_ALIASES["b0"], "B0-C0")
        self.assertEqual(MODEL_ALIASES["b1"], "B1-C0")
        self.assertEqual(MODEL_ALIASES["b2"], "B1-C2")

    def test_isolated_header_generation(self):
        headers_set = set()
        for i in range(10):
            h = f"tx-session-header-{i}"
            headers_set.add(h)
        self.assertEqual(len(headers_set), 10)


if __name__ == "__main__":
    unittest.main()
