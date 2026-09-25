"""Unit tests for the source-identity helper (BP-20260915-v3). Fully offline."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evaluation.bin.common.source_identity import get_source_identity, is_allowlisted_file


class TestSourceIdentity(unittest.TestCase):

    def test_source_identity_berka_db_allowlist_exception(self):
        """berka.db fixture must be an explicit allowlist exception despite general .db exclusion."""
        berka_path = Path("traditional-fapi/resource-server/berka.db")
        self.assertTrue(is_allowlisted_file("traditional-fapi/resource-server/berka.db", berka_path))

        runtime_db_path = Path("wallet-vc-model/wallet-backend/wallet.db")
        self.assertFalse(is_allowlisted_file("wallet-vc-model/wallet-backend/wallet.db", runtime_db_path))

    @patch('subprocess.run')
    def test_source_identity_git_unavailable_fallback(self, mock_subproc):
        """When git is unavailable, source identity must fall back gracefully."""
        mock_subproc.side_effect = Exception("git CLI not installed")
        with tempfile.TemporaryDirectory() as tmp:
            info = get_source_identity(Path(tmp))
        self.assertIsNone(info["git_commit"])
        self.assertEqual(info["worktree_dirty"], "unknown")
        self.assertEqual(info["dirty_patch_reason"], "git_head_unavailable")
        self.assertTrue(isinstance(info["source_digest"], str))
        self.assertTrue(len(info["source_digest"]) == 64)


if __name__ == "__main__":
    unittest.main()
