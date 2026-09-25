#!/usr/bin/env python3
"""
Profile Isolation and Security Boundary Test.
Verifies that test-assistance endpoints (/api/test/*) are unreachable or reject requests
when the SUT microservices are running in standard production/default profile (without conformance profile).

Requirements:
- Probes endpoints with their exact canonical HTTP method and minimal valid request body.
- Passes ONLY when test endpoints are confirmed disabled/not found (HTTP 404 or 403 Forbidden).
- HTTP 2xx is classified as EXPOSED and triggers a test failure.
- HTTP 405 is classified as METHOD_MISMATCH_EXPOSED (not a pass, since endpoint exists).
- Service OFFLINE is classified as INCONCLUSIVE/OFFLINE and returns non-zero exit code.
- Produces machine-readable JSON output and exits with non-zero code on any failure/exposure/offline.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


TEST_ENDPOINTS_SPEC = [
    {
        "service": "Bank Issuer",
        "path": "/api/test/sign-artifact",
        "port": 7000,
        "method": "POST",
        "body": {"payload": {"test": "probe"}, "typ": "JWT"},
    },
    {
        "service": "Bank Issuer",
        "path": "/api/test/bindings/dummy-ref",
        "port": 7000,
        "method": "GET",
        "body": None,
    },
    {
        "service": "Bank Issuer",
        "path": "/api/test/typed-authority/policy",
        "port": 7000,
        "method": "GET",
        "body": None,
    },
    {
        "service": "Bank Issuer",
        "path": "/api/test/typed-authority/policy",
        "port": 7000,
        "method": "POST",
        "body": {"test": "probe"},
    },
    {
        "service": "TPP",
        "path": "/api/test/sign-artifact",
        "port": 3000,
        "method": "POST",
        "body": {"payload": {"test": "probe"}, "typ": "JWT"},
    },
    {
        "service": "Wallet",
        "path": "/api/test/sign-artifact",
        "port": 5000,
        "method": "POST",
        "body": {"payload": {"test": "probe"}, "typ": "JWT"},
    },
]


def classify_probe_result(status_code: int | None, error: Exception | None = None) -> str:
    """
    Classifies the probe outcome according to fail-closed security boundary rules:
    - PROTECTED: HTTP 404 (Not Found) or 403 (Forbidden) - endpoint disabled or blocked by profile.
    - EXPOSED: HTTP 2xx - endpoint is actively answering requests in production mode (CRITICAL FAIL).
    - METHOD_MISMATCH_EXPOSED: HTTP 405 - endpoint exists on server but method disallowed (NOT a pass).
    - REJECTED_OTHER: HTTP 400, 401, 500, etc. - endpoint exists and processed request to some degree.
    - OFFLINE: Connection refused, timeout, or network error - service cannot be verified.
    """
    if status_code is None:
        return "OFFLINE"
    if 200 <= status_code < 300:
        return "EXPOSED"
    if status_code in (403, 404):
        return "PROTECTED"
    if status_code == 405:
        return "METHOD_MISMATCH_EXPOSED"
    return f"REJECTED_HTTP_{status_code}"


def probe_endpoint(spec: dict, host: str = "localhost", timeout: float = 3.0) -> dict:
    url = f"http://{host}:{spec['port']}{spec['path']}"
    method = spec.get("method", "GET")
    data = None
    headers = {}
    if spec.get("body") is not None:
        data = json.dumps(spec["body"]).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            classification = classify_probe_result(resp.status)
            return {
                "service": spec["service"],
                "url": url,
                "method": method,
                "status_code": resp.status,
                "classification": classification,
                "passed": classification == "PROTECTED",
                "error": None,
            }
    except urllib.error.HTTPError as err:
        classification = classify_probe_result(err.code, err)
        return {
            "service": spec["service"],
            "url": url,
            "method": method,
            "status_code": err.code,
            "classification": classification,
            "passed": classification == "PROTECTED",
            "error": f"HTTP {err.code}: {err.reason}",
        }
    except Exception as exc:
        classification = classify_probe_result(None, exc)
        return {
            "service": spec["service"],
            "url": url,
            "method": method,
            "status_code": None,
            "classification": classification,
            "passed": False,
            "error": str(exc),
        }


def check_all_test_endpoints(host: str = "localhost", timeout: float = 3.0) -> dict:
    probes = []
    for spec in TEST_ENDPOINTS_SPEC:
        res = probe_endpoint(spec, host=host, timeout=timeout)
        probes.append(res)

    exposed_count = sum(1 for p in probes if p["classification"] == "EXPOSED")
    offline_count = sum(1 for p in probes if p["classification"] == "OFFLINE")
    other_fail_count = sum(1 for p in probes if not p["passed"] and p["classification"] not in ("EXPOSED", "OFFLINE"))
    all_passed = all(p["passed"] for p in probes)

    summary_status = "PASS" if all_passed else ("OFFLINE" if offline_count > 0 else "FAIL")

    return {
        "overall_status": summary_status,
        "all_passed": all_passed,
        "counts": {
            "total": len(probes),
            "protected": sum(1 for p in probes if p["passed"]),
            "exposed": exposed_count,
            "offline": offline_count,
            "other_failures": other_fail_count,
        },
        "probes": probes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Profile isolation and test endpoint exposure checker")
    parser.add_argument("--host", default="localhost", help="Target microservice host (default: localhost)")
    parser.add_argument("--timeout", type=float, default=3.0, help="HTTP request timeout in seconds")
    parser.add_argument("--json-output", help="Optional path to write JSON results to")
    args = parser.parse_args()

    results = check_all_test_endpoints(host=args.host, timeout=args.timeout)

    print(f"\nProfile Isolation Test - Target: {args.host}")
    print("=" * 70)
    for p in results["probes"]:
        status_tag = "[OK: PROTECTED]" if p["passed"] else f"[FAIL: {p['classification']}]"
        code_str = f"HTTP {p['status_code']}" if p["status_code"] else "NO_RESPONSE"
        print(f"  {status_tag:<22} {p['method']:<4} {p['url']:<48} ({code_str})")
        if p["error"] and not p["passed"]:
            print(f"       Detail: {p['error']}")

    print("=" * 70)
    print(f"Overall Result: {results['overall_status']} (Protected: {results['counts']['protected']}/{results['counts']['total']})")

    if args.json_output:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_output)), exist_ok=True)
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

    if not results["all_passed"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
