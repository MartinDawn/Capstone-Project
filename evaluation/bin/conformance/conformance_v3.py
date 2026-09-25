#!/usr/bin/env python3
"""Run one BP-20260915-v3 conformance package without result carry-forward."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import traceback
import urllib.request

_root_dir = Path(__file__).resolve().parents[3]
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from evaluation.bin.conformance import conformance_runner as legacy
from evaluation.bin.common.source_identity import calculate_source_tree_hash


PROTOCOL_ID = "BP-20260915-v3"
CONFIGURATIONS = ("B0-C0", "B1-C0", "B1-C2")
ORACLE_MATH_CASE_IDS = (
    "VD-F02",
    "VD-F03",
    "VD-F04",
    "VD-F05",
    "VD-F06",
    "VD-N05-DisjointAccounts",
    "VD-N05-InvertedValidity",
    "VD-N05-DisjointFields",
    "VD-N05-ZeroHistory",
    "VD-N05-ZeroPageSize",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_digest(workspace: Path, configuration: str) -> str:
    """The one canonical source-tree digest (evaluation.bin.common.source_identity), not a
    conformance-local recomputation: run_cost.py's final-approval gate compares a conformance run's
    recorded source_digest against its own, so the two must be the same function over the same tree.
    `configuration` is unused; kept for call-site compatibility.
    """
    return calculate_source_tree_hash(workspace)


def digest_paths(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.as_posix()):
        if not path.is_file():
            raise FileNotFoundError(f"Required evidence input does not exist: {path}")
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def read_case_ids(path: Path) -> list[str]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    case_ids = [str(row["case_id"]) for row in rows]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError(f"Duplicate case IDs in {path}")
    return case_ids


def required_catalog(workspace: Path, configuration: str) -> list[dict]:
    tests = workspace / "evaluation" / "tests"
    fixtures = workspace / "evaluation" / "fixtures" / "data"
    catalog: list[dict] = []

    def add(suite: str, tier: str, case_ids: list[str]) -> None:
        catalog.extend(
            {
                "catalog_key": f"{tier}:{case_id}",
                "suite": suite,
                "tier": tier,
                "case_id": case_id,
                "required": True,
                "applicable": True,
            }
            for case_id in case_ids
        )

    if configuration == "B0-C0":
        add("B0_FAPI_Baseline", "SUT_CONFORMANCE", read_case_ids(tests / "b0_cases.json"))
        return catalog

    add(
        "Boundary_Matrix_20",
        "ORACLE_UNIT",
        read_case_ids(fixtures / "boundary_20_vd_f05.json"),
    )
    add("VDAM_Oracle_Math", "ORACLE_UNIT", list(ORACLE_MATH_CASE_IDS))
    if configuration == "B1-C2":
        add(
            "Hybrid_PQC_Verification",
            "CRYPTOGRAPHIC_UNIT",
            read_case_ids(tests / "hybrid_cases.json"),
        )
    add("VDAM_Valid_SUT", "SUT_CONFORMANCE", read_case_ids(tests / "vdam_valid_cases.json"))
    add("VDAM_Negative_SUT", "SUT_CONFORMANCE", read_case_ids(tests / "vdam_negative_cases.json"))
    return catalog


def catalog_key(record: dict) -> str:
    return f"{record.get('tier')}:{record.get('case_id')}"


def complete_required_results(
    results: list[dict], catalog: list[dict], configuration: str, run_id: str
) -> list[dict]:
    observed: dict[str, int] = {}
    for row in results:
        key = catalog_key(row)
        observed[key] = observed.get(key, 0) + 1

    completed = list(results)
    for item in catalog:
        key = item["catalog_key"]
        count = observed.get(key, 0)
        if count > 0:
            continue
        completed.append(
            normalize_record(
                {
                    "suite": item["suite"],
                    "tier": item["tier"],
                    "case_id": item["case_id"],
                    "status": "NOT_RUN",
                    "actual_decision": "NOT_RUN",
                    "reason": "REQUIRED_CASE_MISSING",
                    "required": True,
                    "applicable": True,
                },
                configuration,
                run_id,
            )
        )
    return completed


def gate_disposition(results: list[dict], catalog: list[dict]) -> tuple[str, list[str]]:
    required_keys = {item["catalog_key"] for item in catalog if item["required"] and item["applicable"]}
    rows_by_key: dict[str, list[dict]] = {key: [] for key in required_keys}
    for row in results:
        key = catalog_key(row)
        if key in rows_by_key:
            rows_by_key[key].append(row)

    blockers: list[str] = []
    for key in sorted(required_keys):
        rows = rows_by_key[key]
        if len(rows) != 1:
            blockers.append(f"{key}:RESULT_COUNT_{len(rows)}")
        elif rows[0].get("status") != "PASS":
            blockers.append(f"{key}:{rows[0].get('status', 'MISSING')}")

    if not blockers:
        return ("pass", [])
    if any(row.get("status") == "PASS" for row in results):
        return ("partial", blockers)
    return ("partial", blockers)


def git_identity(workspace: Path) -> dict:
    def run(*arguments: str) -> str | None:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=workspace,
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.stdout.strip() if completed.returncode == 0 else None

    return {
        "commit": run("rev-parse", "HEAD"),
        "dirty": bool(run("status", "--porcelain")),
    }


def suite_plan(configuration: str, include_quantum: bool):
    if configuration == "B0-C0":
        return [("B0_FAPI_Baseline", "SUT_CONFORMANCE", legacy.run_b0_conformance)]
    suites = [
        ("Boundary_Matrix_20", "ORACLE_UNIT", legacy.run_boundary_20_conformance),
        ("VDAM_Oracle_Math", "ORACLE_UNIT", legacy.run_vdam_oracle_math_conformance),
    ]
    if configuration == "B1-C2" and include_quantum:
        suites.append(("Hybrid_PQC_Verification", "CRYPTOGRAPHIC_UNIT", legacy.run_hybrid_crypto_conformance))
    suites.extend(
        [
            ("VDAM_Valid_SUT", "SUT_CONFORMANCE", legacy.run_vdam_valid_sut_conformance),
            ("VDAM_Negative_SUT", "SUT_CONFORMANCE", legacy.run_vdam_negative_sut_conformance),
        ]
    )
    return suites


def normalize_record(record: dict, configuration: str, run_id: str) -> dict:
    normalized = dict(record)
    normalized["protocol_id"] = PROTOCOL_ID
    normalized["run_id"] = run_id
    normalized["configuration"] = configuration
    status = str(normalized.get("status", "INCONCLUSIVE")).upper()
    if status not in {"PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN"}:
        status = "INCONCLUSIVE"
    normalized["execution_status"] = "not_run" if status == "NOT_RUN" else "executed"
    normalized["outcome"] = None if status == "NOT_RUN" else status.lower()
    normalized["status"] = status
    return normalized


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def append_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", required=True, choices=CONFIGURATIONS)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-root", default="evaluation/evidence/conformance")
    parser.add_argument(
        "--include-quantum",
        action="store_true",
        help="Run the HY-* provider-backed suite for B1-C2. The suite is otherwise recorded as deferred.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    # Process-local build identity for source-driven suite adapters.
    os.environ["CONFORMANCE_CONFIGURATION"] = args.configuration
    os.environ["CONFORMANCE_RUN_ID"] = args.run_id
    workspace = Path(__file__).resolve().parents[3]
    output_root = Path(args.output_root)
    if not output_root.is_absolute():
        output_root = workspace / output_root
    run_dir = output_root / args.run_id
    if run_dir.exists():
        raise SystemExit(f"Refusing to overwrite existing run directory: {run_dir}")
    run_dir.mkdir(parents=True)

    started_at = utc_now()
    catalog = required_catalog(workspace, args.configuration)
    catalog_digest = hashlib.sha256(
        json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    fixture_paths = [
        workspace / "evaluation" / "tests" / "b0_cases.json",
        workspace / "evaluation" / "tests" / "vdam_valid_cases.json",
        workspace / "evaluation" / "tests" / "vdam_negative_cases.json",
        workspace / "evaluation" / "tests" / "hybrid_cases.json",
        workspace / "evaluation" / "fixtures" / "data" / "boundary_20_vd_f05.json",
        workspace / "evaluation" / "manifests" / "semantic-contract.json",
    ]
    command = " ".join(shlex.quote(item) for item in sys.argv)
    manifest_path = run_dir / "manifest.json"
    cases_path = run_dir / "cases.jsonl"
    traces_path = run_dir / "traces.jsonl"
    initial_manifest = {
        "schema_version": "3.1.0",
        "protocol_id": PROTOCOL_ID,
        "experiment_id": "EXP-CONF-01",
        "experiment_purpose": "smoke",
        "run_id": args.run_id,
        "configuration": args.configuration,
        "state": "RUNNING",
        "started_at": started_at,
        "ended_at": None,
        "source_digest": source_digest(workspace, args.configuration),
        "fixture_digest": digest_paths(fixture_paths),
        "catalog_digest": catalog_digest,
        "required_catalog": catalog,
        "source_identity": git_identity(workspace),
        "runtime_profile": os.environ.get("SPRING_PROFILES_ACTIVE"),
        "command": command,
        "result_counts": None,
        "gate_disposition": "pending",
        "gate_blockers": [],
        "result_carry_forward": False,
    }
    write_json(manifest_path, initial_manifest)
    write_jsonl(cases_path, [])
    write_jsonl(traces_path, [])

    traces: list[dict] = []
    results: list[dict] = []
    summaries: list[dict] = []

    for suite_name, tier, runner in suite_plan(args.configuration, args.include_quantum):
        suite_traces: list[dict] = []
        try:
            suite_results = runner(str(workspace), suite_traces)
        except Exception as exc:
            suite_results = [
                {
                    "case_id": f"{suite_name}-EXECUTION",
                    "tier": tier,
                    "status": "FAIL",
                    "actual_decision": "ABORT",
                    "reason": f"SUITE_EXECUTION_ERROR: {type(exc).__name__}: {exc}",
                    "traceback": traceback.format_exc(),
                }
            ]
        normalized_results = [
            normalize_record(row, args.configuration, args.run_id) for row in suite_results
        ]
        for trace in suite_traces:
            normalized_trace = dict(trace)
            normalized_trace.update(
                protocol_id=PROTOCOL_ID,
                run_id=args.run_id,
                configuration=args.configuration,
            )
            traces.append(normalized_trace)
        results.extend(normalized_results)
        append_jsonl(cases_path, normalized_results)
        append_jsonl(traces_path, [trace for trace in traces[-len(suite_traces):]] if suite_traces else [])
    completed_results = complete_required_results(results, catalog, args.configuration, args.run_id)
    completion_rows = completed_results[len(results):]
    if completion_rows:
        append_jsonl(cases_path, completion_rows)
    results = completed_results

    summaries = []
    suite_order = list(dict.fromkeys((item["suite"], item["tier"]) for item in catalog))
    for suite_name, tier in suite_order:
        suite_rows = [row for row in results if row.get("suite") == suite_name and row.get("tier") == tier]
        counts = {
            status: sum(row["status"] == status for row in suite_rows)
            for status in ("PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN")
        }
        summaries.append(
            {
                "suite": suite_name,
                "tier": tier,
                "configuration": args.configuration,
                "total_cases": len(suite_rows),
                "passed_cases": counts["PASS"],
                "failed_cases": counts["FAIL"],
                "inconclusive_cases": counts["INCONCLUSIVE"],
                "not_run_cases": counts["NOT_RUN"],
            }
        )

    totals = {
        status: sum(row["status"] == status for row in results)
        for status in ("PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN")
    }
    summaries.append(
        {
            "suite": "TOTAL",
            "tier": "ALL_TIERS",
            "configuration": args.configuration,
            "total_cases": len(results),
            "passed_cases": totals["PASS"],
            "failed_cases": totals["FAIL"],
            "inconclusive_cases": totals["INCONCLUSIVE"],
            "not_run_cases": totals["NOT_RUN"],
        }
    )

    with (run_dir / "conformance-summary.csv").open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summaries[0]))
        writer.writeheader()
        writer.writerows(summaries)

    if "post-restart" not in args.run_id:
        checkpoint_dir = workspace / "evaluation" / "state"
        checkpoint_file = checkpoint_dir / f"durability_checkpoint_{args.configuration}.json"
        if checkpoint_file.exists():
            try:
                with checkpoint_file.open("r", encoding="utf-8") as f:
                    chk = json.load(f)
                b_ref = chk.get("binding_ref")
                if b_ref:
                    issuer_host = os.environ.get("BANK_HOST", "127.0.0.1")
                    issuer_url = os.environ.get("VDAM_ISSUER_URL", f"http://{issuer_host}:7000")
                    with urllib.request.urlopen(f"{issuer_url}/api/test/bindings/{b_ref}", timeout=5) as resp:
                        cur_b = json.loads(resp.read().decode("utf-8"))
                    chk["binding_version"] = cur_b.get("binding_version")
                    chk["holder_subject"] = cur_b.get("holder_subject")
                    chk["holder_jwk"] = cur_b.get("holder_jwk")
                    with checkpoint_file.open("w", encoding="utf-8") as f:
                        json.dump(chk, f)
            except Exception:
                pass

    disposition, gate_blockers = gate_disposition(results, catalog)
    manifest = {
        **initial_manifest,
        "state": "COMPLETE",
        "ended_at": utc_now(),
        "result_counts": totals,
        "gate_disposition": disposition,
        "gate_blockers": gate_blockers,
        "quantum_suite": {
            "included": bool(args.configuration == "B1-C2" and args.include_quantum),
            "deferred_case_ids": (
                []
                if args.configuration != "B1-C2" or args.include_quantum
                else [
                    "HY-F01",
                    "HY-N01",
                    "HY-N02",
                    "HY-N03-CorruptClassical",
                    "HY-N03-CorruptPQC",
                    "HY-N04",
                    "HY-N05",
                ]
            ),
            "deferred_reason": (
                None
                if args.configuration != "B1-C2" or args.include_quantum
                else "DEFERRED_BY_USER_SCOPE"
            ),
        },
    }
    write_json(manifest_path, manifest)

    checksum_paths = [
        manifest_path,
        cases_path,
        traces_path,
        run_dir / "conformance-summary.csv",
    ]
    with (run_dir / "checksums.txt").open("x", encoding="utf-8", newline="\n") as handle:
        for path in checksum_paths:
            handle.write(f"{sha256_file(path)}  {path.name}\n")

    print(json.dumps({"run_dir": str(run_dir), "counts": totals, "gate": manifest["gate_disposition"], "blockers": gate_blockers}))
    # Runner contract: a required failure, an inconclusive required case or a missing required result must
    # leave a non-zero exit code. Exit 0 means every required case in the catalog passed.
    return 0 if disposition == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
