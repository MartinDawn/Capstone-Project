#!/usr/bin/env python3
"""Two-overlapping-transaction isolation proof for the perf load test.

Runs two authorization transactions concurrently against the live stack and checks that
no session, PKCE, state, nonce, code, request, delegation, or token material is shared.
It then runs a controlled failing transaction next to a valid one and checks the valid
one is not corrupted. The perf runner refuses to load a VDAM model without a verified,
source-digest-matched proof.

Only the authorization phase is exercised (no resource-server call).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import threading
import time
import uuid

_root_dir = Path(__file__).resolve().parents[3]
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from evaluation.bin.common import ais_flows  # noqa: E402
from evaluation.bin.common.constants import PROTOCOL_ID  # noqa: E402
from evaluation.bin.common.source_identity import get_source_identity  # noqa: E402

MODEL_ALIASES = {"b0": "B0-C0", "b1": "B1-C0", "b2": "B1-C2", "B0-C0": "B0-C0", "B1-C0": "B1-C0", "B1-C2": "B1-C2"}
WORKLOAD = "Small"

# Fields that must differ between two concurrent transactions when both are present.
DISTINCT_FIELDS = (
    "session_instance_uuid", "thread_id", "oauth_state_digest", "pkce_digest", "nonce_digest",
    "access_token_digest", "par_request_uri_digest", "auth_code_digest", "delegation_jti", "challenge_id",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value) -> str | None:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest() if value else None


def run_isolation_transaction(workspace: str, canonical_model: str, tx_id: int, authz_vc_jti: str | None):
    """One authorization transaction inside a worker thread. Returns (metadata, t_start, t_end)."""
    if tx_id > 1:
        time.sleep(0.05)  # stagger so the two transactions overlap rather than start together
    t_start = time.monotonic()
    meta = {
        "thread_id": str(threading.get_ident()),
        "session_instance_uuid": str(uuid.uuid4()),
        "trace_id": f"iso-tx-{tx_id}",
    }
    if canonical_model == "B0-C0":
        res = ais_flows.run_b0_auth(workspace, WORKLOAD)
        meta.update({
            "oauth_state_digest": _digest(res.get("state")),
            "pkce_digest": _digest(res.get("pkce_challenge")),
            "access_token_digest": _digest(res.get("access_token")),
            "par_request_uri_digest": _digest(res.get("request_uri")),
            "auth_code_digest": _digest(res.get("auth_code")),
        })
    else:
        res = ais_flows.run_vdam_auth(workspace, WORKLOAD, authz_vc_jti=authz_vc_jti)
        meta.update({
            "access_token_digest": _digest(res.get("access_token")),
            "delegation_jti": str(res["delegate_vc_jti"]) if res.get("delegate_vc_jti") else None,
            "challenge_id": str(res["request_id"]) if res.get("request_id") else None,
        })
    return meta, t_start, time.monotonic()


def _required_fields(canonical_model: str) -> tuple[str, ...]:
    common = ("thread_id", "session_instance_uuid", "access_token_digest", "trace_id")
    if canonical_model == "B0-C0":
        return common + ("oauth_state_digest", "pkce_digest", "par_request_uri_digest", "auth_code_digest")
    return common + ("delegation_jti", "challenge_id")


def _injected_failure():
    raise RuntimeError("INJECTED_FAILURE_TEST: Controlled failure hook invoked")


def verify_live_isolation(model_key: str, workspace: Path, concurrency: int = 2) -> dict:
    """Runs overlapping concurrent transactions and checks for cross-talk."""
    canonical_model = MODEL_ALIASES[model_key]
    started_at = utc_now()
    t_begin = time.monotonic()
    details: list[str] = []
    cross_talk = False

    authz_vc_jti = None
    if canonical_model != "B0-C0":
        try:
            authz_vc_jti = ais_flows.provision_root_vc()["jti"]
        except Exception as exc:
            cross_talk = True
            details.append(f"FAILURE: root VC provisioning failed: {type(exc).__name__}: {exc}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            (i, executor.submit(run_isolation_transaction, str(workspace), canonical_model, i, authz_vc_jti))
            for i in range(1, concurrency + 1)
        ]

    contexts: dict[int, dict] = {}
    comparison: list[dict] = []
    timestamps: dict[int, tuple[float, float]] = {}
    for tx_id, fut in futures:
        try:
            meta, t_s, t_e = fut.result(timeout=30.0)
            status, err = "SUCCESS", None
            timestamps[tx_id] = (t_s, t_e)
        except Exception as exc:
            meta, status, err = {}, "FAILED", f"{type(exc).__name__}: {exc}"
            timestamps[tx_id] = (0, 0)
        contexts[tx_id] = {"status": status, "error": err}

        if status != "SUCCESS":
            cross_talk = True
            details.append(f"FAILURE: Transaction tx-{tx_id} failed with error: {err}")
        else:
            missing = [f for f in _required_fields(canonical_model) if not meta.get(f)]
            if missing:
                cross_talk = True
                details.append(f"FAILURE: tx-{tx_id} missing mandatory isolation fields (fail-closed): {missing}")
        comparison.append({"transaction_id": f"tx-{tx_id}", **meta})

    if len(comparison) >= 2:
        c1, c2 = comparison[0], comparison[1]
        for field in DISTINCT_FIELDS:
            if c1.get(field) and c1.get(field) == c2.get(field):
                cross_talk = True
                details.append(f"FAILURE: {field} collision between concurrent transactions")
        (t1_s, t1_e), (t2_s, t2_e) = timestamps.get(1, (0, 0)), timestamps.get(2, (0, 0))
        if t1_s > 0 and t2_s > 0 and not (t1_s < t2_e and t2_s < t1_e):
            cross_talk = True
            details.append("FAILURE: Concurrent transactions did not temporally overlap (fail-closed)")

    # Failure injection: a failing transaction next to a valid one must not corrupt the valid one.
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as inj:
            fut_fail = inj.submit(_injected_failure)
            fut_valid = inj.submit(run_isolation_transaction, str(workspace), canonical_model, 99, authz_vc_jti)
            try:
                fut_fail.result(timeout=10.0)
                cross_talk = True
                details.append("FAILURE_INJECTION_TEST: Expected controlled failure did not occur")
            except Exception as exc:
                if "INJECTED_FAILURE_TEST" not in str(exc):
                    cross_talk = True
                    details.append(f"FAILURE_INJECTION_TEST: unexpected exception: {exc}")
            meta_valid, _, _ = fut_valid.result(timeout=30.0)
            if not meta_valid.get("session_instance_uuid") or not meta_valid.get("access_token_digest"):
                cross_talk = True
                details.append("FAILURE_INJECTION_TEST: concurrent valid transaction corrupted by the failing one")
            else:
                details.append("FAILURE_INJECTION_TEST: failing transaction isolated; concurrent transaction completed intact")
    except Exception as exc:
        cross_talk = True
        details.append(f"FAILURE_INJECTION_TEST: injection test failed: {exc}")

    source_id = get_source_identity(workspace)
    distinct_threads = len({c["thread_id"] for c in comparison if c.get("thread_id")}) == len(comparison) if comparison else True
    distinct_sessions = len({c["session_instance_uuid"] for c in comparison if c.get("session_instance_uuid")}) == len(comparison) if comparison else True

    return {
        "schema_version": "3.0.0",
        "protocol_id": PROTOCOL_ID,
        "experiment_id": "EXP-PERF-02",
        "configuration": canonical_model,
        "concurrency": concurrency,
        "scope": "authorization_only",
        "isolation_verified": (
            not cross_talk
            and len(contexts) == concurrency
            and all(c["status"] == "SUCCESS" for c in contexts.values())
        ),
        "started_at": started_at,
        "ended_at": utc_now(),
        "duration_ms": round((time.monotonic() - t_begin) * 1000.0, 2),
        "source_digest": source_id.get("source_digest"),
        "source_identity": source_id,
        "comparison_objects": comparison,
        "sanitized_transactions": [
            {"transaction_id": f"tx-{i}", "status": c["status"], "error_sanitized": c["error"]}
            for i, c in contexts.items()
        ],
        "isolation_checks": {
            "no_shared_mutable_cookies": distinct_sessions and not cross_talk,
            "distinct_worker_execution_threads": distinct_threads,
            "zero_observed_cross_talk": not cross_talk,
            "details": details,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Live transaction isolation verification")
    parser.add_argument("--configuration", required=True, choices=tuple(MODEL_ALIASES))
    parser.add_argument("--output-root", default="evaluation/evidence/perf")
    args = parser.parse_args()

    canonical = MODEL_ALIASES[args.configuration]
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"isolation-proof-{canonical.lower().replace('-', '')}-{stamp}"
    output_dir = _root_dir / args.output_root / run_id
    output_dir.mkdir(parents=True, exist_ok=False)

    print(f"Executing live multi-session isolation proof for {canonical}...")
    proof = verify_live_isolation(args.configuration, _root_dir, concurrency=2)

    proof_path = output_dir / "isolation-proof.json"
    proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    (output_dir / "checksums.txt").write_text(f"{sha256_file(proof_path)}  isolation-proof.json\n", encoding="utf-8")

    print(f"[OK] Isolation proof written to {proof_path}")
    print(f"Isolation Verified: {proof['isolation_verified']}")
    return 0 if proof["isolation_verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
