#!/usr/bin/env python3
"""Sequential authorization-cost runner (BP-20260922-v6, docs/EVALUATION_PROTOCOL.md section 3).

Measures the latency and the application-level wire bytes of one authorization at a time: exactly one
active business transaction per runner process. There is no load generation, no saturation search,
and no CPU, memory, or storage collection.

Measured boundary: the first authorization request through access-token issuance.
  B0-C0        the complete FAPI 2.0 path (PKCE, PAR, mTLS, Keycloak login and consent, token exchange)
  B1-C0/C2     F2-F4 for every attempt, with a Root/Scope VC provisioned before the measured batch

The B1 F1 issuance is measured once per batch and reported on its own; it is never added to the
repeated-authorization observations.

Each (workload, batch, model) is one window: stop every stack, start the model, provision the Root VC
(B1), run the warm-up attempts (excluded), run the measured attempts, stop every stack. The model order
of a paired block follows the deterministic pairing plan. A failed attempt is recorded and never
replaced by a retry.

    python evaluation/bin/perf/run_cost.py --config evaluation/configs/cost-local.json --purpose smoke --dry-run
    python evaluation/bin/perf/run_cost.py --config evaluation/configs/cost-vm.json --purpose smoke \
        --campaign-id smoke-cost-001 --execute

Workloads, models, batch count, attempts per batch, and warm-up attempts come from the command line or
the configuration `cost` block; the source needs no edit between campaigns. A final run needs an
approved, frozen configuration (see evaluation/bin/common/cost_protocol.py).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import shutil
import sys
import threading
from typing import Optional

_root_dir = Path(__file__).resolve().parents[3]
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from evaluation.bin.common import cost_protocol as protocol  # noqa: E402
from evaluation.bin.common import cost_stats  # noqa: E402
from evaluation.bin.common.constants import COST_PROTOCOL_ID, MODEL_ALIASES  # noqa: E402
from evaluation.bin.common.orchestrator import (  # noqa: E402
    Orchestrator,
    default_campaign_id,
    load_config,
    utc_now,
    validate_config,
)
from evaluation.bin.common.source_identity import get_sut_commits, sha256_of_file  # noqa: E402

FAMILY = "cost"
EXPERIMENT_ID = "EXP-COST-01"
SCHEMA_VERSION = "4.0.0"
MEASUREMENT_BOUNDARY = "first authorization request through access-token issuance"

BATCH_SUMMARY_COLUMNS = [
    "protocol_id", "campaign_id", "run_id", "paired_block_id", "batch", "configuration", "workload", "mode",
    "attempted", "succeeded", "failed", "failure_denominator", "failure_rate_pct",
    "median_ms", "mean_ms", "stdev_ms", "min_ms", "max_ms", "p95_ms", "p99_ms",
    "median_wire_bytes", "mean_wire_bytes", "wire_samples",
    "f1_outcome", "f1_latency_ms", "f1_wire_bytes", "f1_root_vc_bytes",
]
CAMPAIGN_SUMMARY_COLUMNS = [
    "protocol_id", "campaign_id", "configuration", "workload", "mode", "batches", "attempted", "succeeded",
    "failed", "failure_denominator", "failure_rate_pct",
    "median_ms", "mean_ms", "stdev_ms", "min_ms", "max_ms", "p95_ms", "p99_ms",
    "median_wire_bytes", "mean_wire_bytes", "wire_samples",
]
F1_COLUMNS = [
    "protocol_id", "campaign_id", "run_id", "paired_block_id", "batch", "configuration", "workload",
    "outcome", "latency_ms", "wire_bytes", "root_vc_bytes", "root_vc_sha256", "step_latency_ms",
    "step_wire_bytes", "failure_reason", "start_timestamp", "end_timestamp",
]

_STAGE_KEYWORDS = (
    ("initiate", "par"), ("par ", "par"), ("request-delegate", "request_delegate"),
    ("fetch-tpp-request", "fetch_request"), ("approve-delegate", "approve_delegate"),
    ("login", "browser_authorization"), ("consent", "browser_authorization"), ("authorize", "browser_authorization"),
    ("token", "token_exchange"), ("timed out", "timeout"), ("timeout", "timeout"),
)


class FlowFailure(RuntimeError):
    """A flow failed. `stage` names the protocol step when it is known."""

    def __init__(self, stage: str, reason: str):
        super().__init__(reason)
        self.stage = stage


def classify_failure(exc: BaseException) -> str:
    """Best-effort protocol step of a failure, from the message the source flows raise."""
    text = str(exc).lower()
    for keyword, stage in _STAGE_KEYWORDS:
        if keyword in text:
            return stage
    return "unspecified"


# ---------------------------------------------------------------------------
# Flow adapters
# ---------------------------------------------------------------------------

class FlowAdapter:
    """What the runner needs from the source-defined flows. Tests replace it with a mock."""

    def provision_root_vc(self) -> dict:
        """Runs F1 and returns {'jti','credential','digest','f1_ms','f1_wire','f1_step_ms','f1_step_wire'}."""
        raise NotImplementedError

    def authorize(self, model: str, workload: str, root_vc: Optional[dict]) -> dict:
        """Runs one authorization. Returns latency_ms, wire_bytes, step_wire, access_token_issued, transaction_id."""
        raise NotImplementedError


class LiveFlowAdapter(FlowAdapter):
    """Drives the real services through the flows shared with the conformance runner."""

    def __init__(self, workspace: Path):
        from evaluation.bin.common import ais_flows
        self._flows = ais_flows
        self._base_dir = str(workspace)

    def provision_root_vc(self) -> dict:
        return self._flows.provision_root_vc()

    def authorize(self, model: str, workload: str, root_vc: Optional[dict]) -> dict:
        if model == "B0-C0":
            res = self._flows.run_b0_auth(self._base_dir, workload)
            return {
                "latency_ms": res["par_ms"] + res["auth_ms"] + res["token_ms"],
                "wire_bytes": res["par_wire"] + res["auth_wire"] + res["token_wire"],
                "step_wire": {"par": res["par_wire"], "browser_authorization": res["auth_wire"],
                              "token_exchange": res["token_wire"]},
                "access_token_issued": bool(res.get("access_token")),
                "transaction_id": res.get("state"),
            }
        if not root_vc:
            raise FlowFailure("precondition", "a B1 authorization needs a provisioned Root/Scope VC")
        res = self._flows.run_vdam_auth(self._base_dir, workload, root_vc["jti"])
        return {
            "latency_ms": res["auth_ms"],
            "wire_bytes": res["auth_wire"],
            "step_wire": {protocol.B1_STEP_NAMES[k]: v for k, v in res["step_wire"].items()},
            "access_token_issued": bool(res.get("access_token")),
            "transaction_id": res.get("request_id"),
        }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class CostRunner(Orchestrator):
    family = FAMILY

    def __init__(self, workspace, config, config_path, config_digest, campaign_id, *, purpose: str, settings: dict,
                 adapter: FlowAdapter, pairing_plan: dict, resume: bool = False):
        super().__init__(workspace, config, config_path, config_digest, campaign_id,
                         resume=resume, models=settings["models"])
        self.purpose = purpose
        self.settings = settings
        self.adapter = adapter
        self.pairing_plan = pairing_plan
        self.protocol_digest = protocol.protocol_digest(workspace)
        self.sut_commits = get_sut_commits(workspace)
        # One transaction at a time. A second acquisition while one is active is a programming error.
        self._transaction_lock = threading.Lock()

    # -- environment ------------------------------------------------------

    def apply_environment(self) -> None:
        """In-process flows read the same hosts the lifecycle subprocesses get."""
        os.environ.update(self.config.get("command_environment", {}))

    # -- one attempt ------------------------------------------------------

    def run_attempt(self, model: str, workload: str, root_vc: Optional[dict]) -> dict:
        """One transaction. Never retries: a failure is returned as a FAILED record."""
        if not self._transaction_lock.acquire(blocking=False):
            raise RuntimeError("a second transaction was started while another was active")
        started = utc_now()
        try:
            result = self.adapter.authorize(model, workload, root_vc)
            failure_stage = failure_reason = ""
            outcome = protocol.OUTCOME_SUCCESS
            if not result.get("access_token_issued"):
                outcome, failure_stage = protocol.OUTCOME_FAILED, "token_issuance"
                failure_reason = "the flow returned no access token"
        except Exception as exc:  # recorded, never retried
            result = {}
            outcome = protocol.OUTCOME_FAILED
            failure_stage = getattr(exc, "stage", None) or classify_failure(exc)
            failure_reason = f"{type(exc).__name__}: {protocol.sanitize_reason(exc)}"
        finally:
            self._transaction_lock.release()
        ended = utc_now()
        ok = outcome == protocol.OUTCOME_SUCCESS
        return {
            "transaction_id": result.get("transaction_id") or "",
            "start_timestamp": started,
            "end_timestamp": ended,
            "latency_ms": round(float(result["latency_ms"]), 3) if ok else "",
            "outcome": outcome,
            "failure_stage": failure_stage,
            "failure_reason": failure_reason,
            "access_token_issued": bool(result.get("access_token_issued")) and ok,
            "authorization_wire_bytes": int(result["wire_bytes"]) if ok else "",
            "step_wire_bytes": json.dumps(result.get("step_wire", {}), sort_keys=True) if ok else "",
        }

    # -- one window -------------------------------------------------------

    def run_window(self, workload: str, batch: int, model: str, position: int, order: list[str]) -> None:
        alias = MODEL_ALIASES[model]
        run_id = protocol.run_id_for(self.campaign_id, workload, model, batch)
        block_id = protocol.paired_block_id(self.campaign_id, workload, batch)
        run_dir = self.run_dir(run_id)
        label = f"{workload.lower()}-{alias}-b{batch:02d}"

        if self.resume and (run_dir / "manifest.json").exists():
            print(f"[{model} {workload} b{batch}] already completed; preserving evidence")
            self.dispositions.append(self._disposition(json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))))
            return

        run_dir.mkdir(parents=True, exist_ok=False)
        fixture_digest = protocol.fixture_digest(self.workspace, workload)
        common = {
            "protocol_id": COST_PROTOCOL_ID, "campaign_id": self.campaign_id, "run_id": run_id,
            "paired_block_id": block_id, "batch": batch, "configuration": model, "workload": workload,
            "mode": self.settings["mode"], "source_digest": self.source_identity.get("source_digest"),
            "configuration_digest": self.config_digest, "fixture_digest": fixture_digest,
        }

        window_started = utc_now()
        f1_row: Optional[dict] = None
        root_vc: Optional[dict] = None
        warmups: list[dict] = []
        measured: list[dict] = []
        blocked_reason: Optional[str] = None
        try:
            self.stop_all(f"pre-stop-{label}")
            self.start_model(model)
            fingerprint = self.campaign_dir / "fingerprints" / f"{alias}.json"
            if fingerprint.exists():
                shutil.copyfile(fingerprint, run_dir / "fingerprint.json")

            if model != "B0-C0":
                f1_row, root_vc = self.provision_f1(common)
                if root_vc is None:
                    blocked_reason = f"F1_PROVISIONING_FAILED: {f1_row['failure_reason']}"

            if blocked_reason is None:
                for index in range(1, self.settings["warmup_attempts"] + 1):
                    warmups.append({**common, "attempt": index, **self.run_attempt(model, workload, root_vc)})
                for index in range(1, self.settings["attempts_per_batch"] + 1):
                    measured.append({**common, "attempt": index, **self.run_attempt(model, workload, root_vc)})
        except Exception as exc:
            blocked_reason = f"WINDOW_ABORTED: {type(exc).__name__}: {protocol.sanitize_reason(exc)}"
        finally:
            try:
                self.stop_all(f"post-stop-{label}")
            except Exception as exc:
                self.dispositions.append({
                    "stage": "cleanup", "configuration": model, "run_id": run_id,
                    "status": "failed", "reason": protocol.sanitize_reason(exc),
                })

        self.write_attempts(run_dir / "attempts.csv", measured)
        self.write_attempts(run_dir / "warmup-attempts.csv", warmups)
        if f1_row is not None:
            self.write_rows(run_dir / "f1.csv", F1_COLUMNS, [f1_row])

        manifest = self.build_manifest(
            common, order, position, window_started, measured, warmups, f1_row, blocked_reason)
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.seal_run_dir(run_dir)
        self.dispositions.append(self._disposition(manifest))

    def provision_f1(self, common: dict) -> tuple[dict, Optional[dict]]:
        """Measures F1 once for the batch. Returns the report row and the Root VC (None when F1 failed)."""
        started = utc_now()
        root_vc = None
        row = {**common, "start_timestamp": started, "failure_reason": "", "outcome": protocol.OUTCOME_FAILED,
               "latency_ms": "", "wire_bytes": "", "root_vc_bytes": "", "root_vc_sha256": "",
               "step_latency_ms": "", "step_wire_bytes": ""}
        try:
            root_vc = self.adapter.provision_root_vc()
            credential = root_vc["credential"]
            row.update({
                "outcome": protocol.OUTCOME_SUCCESS,
                "latency_ms": round(float(root_vc["f1_ms"]), 3),
                "wire_bytes": int(root_vc["f1_wire"]),
                "root_vc_bytes": len(credential.encode("utf-8")),
                "root_vc_sha256": root_vc.get("digest", ""),
                "step_latency_ms": json.dumps({k: round(v, 3) for k, v in (root_vc.get("f1_step_ms") or {}).items()}, sort_keys=True),
                "step_wire_bytes": json.dumps(root_vc.get("f1_step_wire") or {}, sort_keys=True),
            })
        except Exception as exc:
            root_vc = None
            row["failure_reason"] = f"{type(exc).__name__}: {protocol.sanitize_reason(exc)}"
        row["end_timestamp"] = utc_now()
        return row, root_vc

    # -- evidence ---------------------------------------------------------

    @staticmethod
    def write_rows(path: Path, columns: list[str], rows: list[dict]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

    def write_attempts(self, path: Path, rows: list[dict]) -> None:
        self.write_rows(path, protocol.ATTEMPT_COLUMNS, rows)

    def build_manifest(self, common: dict, order: list[str], position: int, started: str, measured: list[dict],
                       warmups: list[dict], f1_row: Optional[dict], blocked_reason: Optional[str]) -> dict:
        summary = summarize_attempts(measured)
        if blocked_reason:
            status = "BLOCKED"
        elif summary["failed"] > 0:
            status = "DEGRADED"
        else:
            status = "COMPLETED"
        return {
            "schema_version": SCHEMA_VERSION,
            "experiment_id": EXPERIMENT_ID,
            "experiment_purpose": self.purpose,
            **{k: common[k] for k in ("protocol_id", "campaign_id", "run_id", "paired_block_id", "batch",
                                      "configuration", "workload", "mode")},
            "scope": "authorization_only",
            "measurement_boundary": MEASUREMENT_BOUNDARY,
            "concurrency": 1,
            "driver": "python_sequential",
            "latency_clock": "time.perf_counter_ns (monotonic); wall-clock timestamps are provenance only",
            "model_order_in_block": order,
            "position_in_block": position,
            "settings": {k: self.settings[k] for k in ("batches", "attempts_per_batch", "warmup_attempts")},
            "protocol_digest": self.protocol_digest,
            "configuration_digest": common["configuration_digest"],
            "fixture_digest": common["fixture_digest"],
            "source_digest": common["source_digest"],
            "source_identity": self.source_identity,
            "sut_commits": self.sut_commits,
            "environment": self.config.get("environment"),
            "fingerprint": self.fingerprint_reference(common["run_id"]),
            "started_at": started,
            "ended_at": utc_now(),
            "status": status,
            "reason": blocked_reason,
            "warmup_attempts_recorded": len(warmups),
            "metrics": summary,
            "f1": (
                {"outcome": f1_row["outcome"], "latency_ms": f1_row["latency_ms"], "wire_bytes": f1_row["wire_bytes"],
                 "root_vc_bytes": f1_row["root_vc_bytes"], "reported_separately": True}
                if f1_row else {"applicable": False}
            ),
        }

    def fingerprint_reference(self, run_id: str) -> Optional[dict]:
        path = self.run_dir(run_id) / "fingerprint.json"
        digest = sha256_of_file(path)
        return {"file": "fingerprint.json", "sha256": digest} if digest else None

    @staticmethod
    def _disposition(manifest: dict) -> dict:
        blocked = manifest["status"] == "BLOCKED"
        return {
            "stage": "cost", "configuration": manifest["configuration"], "workload": manifest["workload"],
            "batch": manifest["batch"], "run_id": manifest["run_id"],
            "status": "blocked" if blocked else "executed",
            "run_outcome": manifest["status"], "reason": manifest.get("reason"),
        }

    # -- campaign ---------------------------------------------------------

    def execute(self) -> None:
        self.initialize()
        self.apply_environment()
        self.notes.append(
            f"purpose={self.purpose}; workloads={self.settings['workloads']}; models={self.settings['models']}; "
            f"batches={self.settings['batches']}; attempts_per_batch={self.settings['attempts_per_batch']}; "
            f"warmup_attempts={self.settings['warmup_attempts']}; mode={self.settings['mode']}; "
            f"boundary={MEASUREMENT_BOUNDARY}; concurrency=1; F1 reported separately"
        )
        try:
            self.stop_all("initial-stop-all")
            for workload in self.settings["workloads"]:
                for batch in range(1, self.settings["batches"] + 1):
                    order = protocol.model_order(self.pairing_plan, workload, batch, self.settings["models"])
                    print(f"\n--- {workload} paired block {batch}/{self.settings['batches']}: {' -> '.join(order)} ---")
                    for position, model in enumerate(order, start=1):
                        try:
                            self.run_window(workload, batch, model, position, order)
                        except Exception as exc:
                            self.dispositions.append({
                                "stage": "cost", "configuration": model, "workload": workload, "batch": batch,
                                "run_id": None, "status": "failed",
                                "reason": f"{type(exc).__name__}: {protocol.sanitize_reason(exc)}",
                            })
            write_campaign_summaries(self.evidence_root, self.campaign_dir, self.campaign_id)
        except Exception as exc:
            self.dispositions.append({
                "stage": "cost", "configuration": "all", "run_id": None, "status": "failed",
                "reason": f"{type(exc).__name__}: {protocol.sanitize_reason(exc)}",
            })
        finally:
            try:
                self.stop_all("final-stop-all")
            except Exception as exc:
                self.dispositions.append({
                    "stage": "cleanup", "configuration": "all", "run_id": None, "status": "failed",
                    "reason": protocol.sanitize_reason(exc),
                })
            self.write_handoff()


# ---------------------------------------------------------------------------
# Aggregation (also used on its own by tests and the analysis)
# ---------------------------------------------------------------------------

def read_csv_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def summarize_attempts(rows: list[dict]) -> dict:
    """Counts and statistics of measured attempts.

    Latency statistics use successful attempts only, and the failure count is reported beside them. Every
    rate names its denominator.
    """
    attempted = len(rows)
    ok = [r for r in rows if r["outcome"] == protocol.OUTCOME_SUCCESS]
    failed = attempted - len(ok)
    latency = [float(r["latency_ms"]) for r in ok]
    wire = [float(r["authorization_wire_bytes"]) for r in ok if r.get("authorization_wire_bytes") not in ("", None)]
    stats = cost_stats.describe(latency)
    return {
        "attempted": attempted,
        "succeeded": len(ok),
        "failed": failed,
        "failure_denominator": attempted,
        "failure_rate_pct": round(100.0 * failed / attempted, 4) if attempted else None,
        "median_ms": stats["median"], "mean_ms": stats["mean"], "stdev_ms": stats["stdev"],
        "min_ms": stats["min"], "max_ms": stats["max"], "p95_ms": stats["p95"], "p99_ms": stats["p99"],
        "median_wire_bytes": cost_stats.percentile(wire, 50), "mean_wire_bytes": cost_stats.mean(wire),
        "wire_samples": len(wire),
    }


def collect_campaign_runs(evidence_root: Path, campaign_id: str) -> list[dict]:
    """Manifests of every run of one campaign, in a stable order. Never picks a campaign implicitly."""
    runs = []
    for manifest_path in sorted(evidence_root.glob(f"{campaign_id}-*/manifest.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("campaign_id") == campaign_id and manifest.get("experiment_id") == EXPERIMENT_ID:
            runs.append({"manifest": manifest, "dir": manifest_path.parent})
    return runs


def write_campaign_summaries(evidence_root: Path, campaign_dir: Path, campaign_id: str) -> None:
    """attempts.csv, batch-summary.csv, and campaign-summary.csv from the run packages on disk."""
    runs = collect_campaign_runs(evidence_root, campaign_id)
    all_attempts: list[dict] = []
    batch_rows: list[dict] = []
    grouped: dict[tuple[str, str], list[dict]] = {}
    batches_seen: dict[tuple[str, str], set] = {}

    for run in runs:
        manifest, directory = run["manifest"], run["dir"]
        attempts = read_csv_rows(directory / "attempts.csv")
        all_attempts.extend(attempts)
        summary = summarize_attempts(attempts)
        f1 = manifest.get("f1") or {}
        batch_rows.append({
            **{k: manifest[k] for k in ("protocol_id", "campaign_id", "run_id", "paired_block_id", "batch",
                                        "configuration", "workload", "mode")},
            **summary,
            "f1_outcome": f1.get("outcome", "NOT_APPLICABLE"),
            "f1_latency_ms": f1.get("latency_ms", ""), "f1_wire_bytes": f1.get("wire_bytes", ""),
            "f1_root_vc_bytes": f1.get("root_vc_bytes", ""),
        })
        key = (manifest["configuration"], manifest["workload"])
        grouped.setdefault(key, []).extend(attempts)
        batches_seen.setdefault(key, set()).add(manifest["batch"])

    campaign_rows = []
    for (model, workload), attempts in sorted(grouped.items()):
        campaign_rows.append({
            "protocol_id": COST_PROTOCOL_ID, "campaign_id": campaign_id, "configuration": model,
            "workload": workload, "mode": protocol.MODES[0], "batches": len(batches_seen[(model, workload)]),
            **summarize_attempts(attempts),
        })

    CostRunner.write_rows(campaign_dir / "attempts.csv", protocol.ATTEMPT_COLUMNS, all_attempts)
    CostRunner.write_rows(campaign_dir / "batch-summary.csv", BATCH_SUMMARY_COLUMNS, batch_rows)
    CostRunner.write_rows(campaign_dir / "campaign-summary.csv", CAMPAIGN_SUMMARY_COLUMNS, campaign_rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--purpose", required=True, choices=protocol.PURPOSES)
    parser.add_argument("--campaign-id")
    parser.add_argument("--models", nargs="+", choices=tuple(MODEL_ALIASES))
    parser.add_argument("--workloads", nargs="+", choices=protocol.WORKLOADS)
    parser.add_argument("--batches", type=int)
    parser.add_argument("--attempts-per-batch", type=int)
    parser.add_argument("--warmup-attempts", type=int)
    parser.add_argument("--resume", action="store_true")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    return parser


def main(argv: Optional[list[str]] = None, workspace: Path = _root_dir, adapter: Optional[FlowAdapter] = None) -> int:
    args = build_parser().parse_args(argv)

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = workspace / config_path
    config, digest = load_config(config_path)

    errors = validate_config(config, args.purpose, FAMILY)
    # A dry run of a final configuration must still describe every cell, so approval problems are
    # reported as blockers there instead of stopping the description.
    approval_errors = [e for e in errors if e.startswith("final execution requires")]
    config_errors = [e for e in errors if e not in approval_errors]
    if config_errors:
        for error in config_errors:
            print(f"CONFIGURATION_ERROR: {error}", file=sys.stderr)
        return 2

    try:
        settings = protocol.resolve_settings(args.purpose, config, {
            "models": args.models, "workloads": args.workloads, "batches": args.batches,
            "attempts_per_batch": args.attempts_per_batch, "warmup_attempts": args.warmup_attempts,
        })
        pairing_plan = protocol.load_pairing_plan(workspace)
    except (protocol.ProtocolError, OSError, ValueError) as exc:
        print(f"CONFIGURATION_ERROR: {exc}", file=sys.stderr)
        return 2

    schedule = protocol.build_schedule(settings, pairing_plan, args.purpose)

    if args.dry_run:
        blockers = list(approval_errors)
        if args.purpose == "final":
            from evaluation.bin.common.source_identity import get_source_identity
            blockers = sorted(set(blockers + protocol.validate_final_approval(
                workspace, config, get_source_identity(workspace), settings["models"])))
        print(json.dumps({
            "protocol_id": COST_PROTOCOL_ID,
            "experiment_id": EXPERIMENT_ID,
            "purpose": args.purpose,
            "evidence_root": f"evaluation/evidence/{FAMILY}",
            "config_digest": digest,
            "settings": settings,
            "measured_attempts_total": len(schedule) * settings["attempts_per_batch"],
            "warmup_attempts_total": len(schedule) * settings["warmup_attempts"],
            "window_count": len(schedule),
            "final_execution_blockers": blockers if args.purpose == "final" else [],
            "schedule": schedule,
        }, indent=2))
        return 0

    if args.purpose == "final":
        from evaluation.bin.common.source_identity import get_source_identity
        blockers = approval_errors + protocol.validate_final_approval(
            workspace, config, get_source_identity(workspace), settings["models"])
        if blockers:
            for blocker in blockers:
                print(f"FINAL_EXECUTION_BLOCKED: {blocker}", file=sys.stderr)
            return 2

    campaign_id = args.campaign_id or default_campaign_id(FAMILY, args.purpose)
    runner = CostRunner(
        workspace, config, config_path, digest, campaign_id, purpose=args.purpose, settings=settings,
        adapter=adapter or LiveFlowAdapter(workspace), pairing_plan=pairing_plan, resume=args.resume)
    runner.execute()
    failed = any(item["status"] in {"failed", "blocked"} for item in runner.dispositions)
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
