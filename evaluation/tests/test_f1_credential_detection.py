#!/usr/bin/env python3
"""
Unit tests for F1 Scope VC issuance fresh credential detection and regression against stale credential reuse.
"""

import json
import unittest
from unittest.mock import patch, MagicMock
import urllib.error

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evaluation.bin.common import ais_flows as benchmark_runner


class F1CredentialDetectionTests(unittest.TestCase):

    def test_stale_credential_rejected_when_no_fresh_vc_issued(self):
        """
        Regression Test for Requirement 5:
        If Wallet already has a Scope VC from a previous run/iteration, but the current
        OID4VCI callback does not result in a new fresh credential being stored,
        the iteration MUST FAIL with F1_STALE_CREDENTIAL_ERROR and NOT accept the stale VC.
        """
        existing_vc = {
            "type": "AuthorizationCredential",
            "jti": "urn:uuid:existing-vc-1111",
            "sdJwt": "header.payload.sig~disc1~disc2~"
        }

        def mock_urlopen(req, *args, **kwargs):
            url = req.full_url if hasattr(req, 'full_url') else str(req)
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.reason = 'OK'
            mock_resp.headers = MagicMock()
            mock_resp.headers.as_bytes.return_value = b""
            mock_resp.__enter__.return_value = mock_resp

            if url.endswith("/api/vcs"):
                mock_resp.read.return_value = json.dumps({"vcs": [existing_vc]}).encode('utf-8')
                return mock_resp
            elif url.endswith("/api/receive-offer"):
                mock_resp.read.return_value = json.dumps({"sessionId": "sess-123"}).encode('utf-8')
                return mock_resp
            elif url.endswith("/api/start-auth"):
                mock_resp.read.return_value = json.dumps({"authUrl": "http://localhost:8080/auth?code=mock_code"}).encode('utf-8')
                return mock_resp
            elif "callback" in url:
                mock_resp.read.return_value = b"OK"
                return mock_resp
            raise ValueError(f"Unhandled mock URL: {url}")

        mock_opener = MagicMock()
        mock_auth_resp = MagicMock()
        mock_auth_resp.headers.get.return_value = "http://localhost:5000/callback?code=test-code&state=test-state"
        mock_auth_resp.read.return_value = b""
        mock_opener.open.return_value = mock_auth_resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen), \
             patch("urllib.request.build_opener", return_value=mock_opener):
            with self.assertRaises(RuntimeError) as ctx:
                benchmark_runner.execute_vdam_f1_oid4vci_flow(
                    wallet_url="http://localhost:5000",
                    keycloak_host="localhost",
                    timeout=5
                )
            self.assertIn("F1_STALE_CREDENTIAL_ERROR", str(ctx.exception))

    def test_fresh_credential_accepted_when_new_vc_issued(self):
        """
        Verifies that when a truly new Scope VC with a novel JTI is issued,
        it is accepted and correlated.
        """
        existing_vc = {
            "type": "AuthorizationCredential",
            "jti": "urn:uuid:old-vc-0000",
            "sdJwt": "old.old.old~"
        }
        fresh_vc = {
            "type": "AuthorizationCredential",
            "jti": "urn:uuid:fresh-vc-9999",
            "sdJwt": "header.eyJzdWIiOiJ0ZXN0dXNlciIsImhvbGRlcl9jZXJ0X3JlZiI6ImJpbmQtMTIzIn0.sig~"
        }

        call_count = {"vcs": 0}

        def mock_urlopen(req, *args, **kwargs):
            url = req.full_url if hasattr(req, 'full_url') else str(req)
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.reason = 'OK'
            mock_resp.headers = MagicMock()
            mock_resp.headers.as_bytes.return_value = b""
            mock_resp.__enter__.return_value = mock_resp

            if url.endswith("/api/vcs"):
                call_count["vcs"] += 1
                if call_count["vcs"] == 1:
                    mock_resp.read.return_value = json.dumps({"vcs": [existing_vc]}).encode('utf-8')
                else:
                    mock_resp.read.return_value = json.dumps({"vcs": [existing_vc, fresh_vc]}).encode('utf-8')
                return mock_resp
            elif url.endswith("/api/receive-offer"):
                mock_resp.read.return_value = json.dumps({"sessionId": "sess-123"}).encode('utf-8')
                return mock_resp
            elif url.endswith("/api/start-auth"):
                mock_resp.read.return_value = json.dumps({"authUrl": "http://localhost:8080/auth?code=mock_code"}).encode('utf-8')
                return mock_resp
            elif "callback" in url:
                mock_resp.read.return_value = b"OK"
                return mock_resp
            elif "/api/test/bindings/bind-123" in url:
                mock_resp.read.return_value = json.dumps({"record_id": "bind-123", "status": "ACTIVE"}).encode('utf-8')
                return mock_resp
            raise ValueError(f"Unhandled mock URL: {url}")

        mock_opener = MagicMock()
        mock_auth_resp = MagicMock()
        mock_auth_resp.headers.get.return_value = "http://localhost:5000/callback?code=test-code&state=test-state"
        mock_auth_resp.read.return_value = b""
        mock_opener.open.return_value = mock_auth_resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen), \
             patch("urllib.request.build_opener", return_value=mock_opener):
            res = benchmark_runner.execute_vdam_f1_oid4vci_flow(
                wallet_url="http://localhost:5000",
                keycloak_host="localhost",
                timeout=5,
                issuer_url="http://localhost:7000"
            )
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["jti"], "urn:uuid:fresh-vc-9999")


if __name__ == "__main__":
    unittest.main()
