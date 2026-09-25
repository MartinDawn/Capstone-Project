#!/usr/bin/env python3
"""Exploratory saturation probe for the authorization load test. NOT protocol evidence.

REINSTATED by BP-20260922-v5 (decision DEC-020) as a calibration aid for E-LOAD (evaluation/bin/perf/run_perf.py).
It remains exploratory: its output is never pooled with E-COST, E-ARTIFACT, or E-LOAD protocol evidence,
whatever the protocol revision. Use it to find candidate offered-rate levels before a pilot, and to
diagnose the reinstated tooling's known defects (BLK-013) without spending a protocol window on it.

Purpose: find, quickly, the offered rate at which each model stops keeping up, so that one can
choose the levels for the pilot and final campaigns. It is a planning aid only.

How it differs from run_perf.py:
  * One service start and ONE k6 run per model. The k6 run climbs a ladder of offered rates
    (k6/probe_load.js); run_perf.py restarts the stack for every rate and batch.
  * Each rung is short and there is a single batch, so the numbers are indicative, not statistics.
  * The run aborts itself when a rung crosses a stop threshold.
  * Output goes to evaluation/evidence/perf-probe/<campaign-id>/, marked
    `evidence_class: exploratory_not_protocol_evidence`. Analysis must never pool it with
    pilot or final runs.

What stays the same: the lifecycle (stop, start, readiness, fingerprint check, isolation proof,
root VC provisioning, sequential preflight) and the transactions themselves (auth_load.js is
imported unchanged), so a rung exercises the real source-defined flow, not a shortcut.

Usage:

    python evaluation/bin/perf/probe_saturation.py \
        --config evaluation/configs/perf-vm.json --models B1-C2 --execute

    python evaluation/bin/perf/probe_saturation.py --config evaluation/configs/perf-vm.json --dry-run
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import shutil
import sys
import time

_root_dir = Path(__file__).resolve().parents[3]
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from evaluation.bin.common import ais_flows  # noqa: E402
from evaluation.bin.common.orchestrator import (  # noqa: E402
    MODEL_ALIASES,
    PROTOCOL_ID,
    load_config,
    utc_now,
)
from evaluation.bin.perf import run_perf  # noqa: E402

PROBE_ROOT_NAME = "perf-probe"
PROBE_SCRIPT = Path(__file__).resolve().parent / "k6" / "probe_load.js"
EVIDENCE_CLASS = "exploratory_not_protocol_evidence"

DEFAULT_RATES = [1, 5, 10, 25, 50, 100, 200]

# A rung is SATURATED when it fails more than MAX_FAIL_PCT of its arrivals or completes less than
# MIN_THROUGHPUT_RATIO of the offered rate. It is GENERATOR_LIMITED when k6 ran out of virtual
# users, which means the load client (not necessarily the system under test) is the limit.
MIN_THROUGHPUT_RATIO = 0.90


def rung_name(index: int, rate: int) -> str:
    return f"step_{index:02d}_r{rate}"


def build_rungs(rates: list[int], step_seconds: int) -> list[dict]:
    return [{"name": rung_name(i, r), "rate": r, "duration": step_seconds} for i, r in enumerate(rates, start=1)]


def estimated_k6_seconds(rungs: list[dict], warmup_s: int, drain_s: int) -> int:
    return warmup_s + drain_s + sum(r["duration"] + drain_s for r in rungs)


# ---------------------------------------------------------------------------
# Summary parsing
# ---------------------------------------------------------------------------

def metric_values(summary: dict, name: str) -> dict:
    return (summary.get("metrics", {}).get(name) or {}).get("values") or {}


def rung_metrics(summary: dict, rung: dict, max_fail_pct: float) -> dict:
    """Turns the exported per-rung sub-metrics into one row."""
    name, rate, duration = rung["name"], rung["rate"], rung["duration"]
    ok = int(metric_values(summary, f"auth_ok{{phase:{name}}}").get("count", 0))
    failed = int(metric_values(summary, f"auth_fail{{phase:{name}}}").get("count", 0))
    dropped = int(metric_values(summary, f"dropped_iterations{{scenario:{name}}}").get("count", 0))
    latency = metric_values(summary, f"auth_duration{{phase:{name}}}")

    scheduled = rate * duration
    completed = ok + failed
    started = max(scheduled - dropped, completed)
    unfinished = started - completed
    reached = (ok + failed + dropped) > 0
    row = {
        "step": name,
        "offered_rate_tps": rate,
        "duration_s": duration,
        "scheduled": scheduled,
        "started": started if reached else 0,
        "success": ok,
        "failed": failed,
        "unfinished": unfinished if reached else 0,
        "not_started": dropped,
        "throughput_tps": round(ok / duration, 3) if reached else None,
        "error_pct": round(100.0 * (failed + unfinished) / started, 2) if reached and started else None,
        "p50_ms": round(latency["med"], 1) if latency.get("count") else None,
        "p95_ms": round(latency["p(95)"], 1) if latency.get("count") else None,
        "p99_ms": round(latency["p(99)"], 1) if latency.get("count") else None,
    }
    row["verdict"] = verdict(row, rate, max_fail_pct, reached)
    return row


def verdict(row: dict, rate: int, max_fail_pct: float, reached: bool) -> str:
    if not reached:
        return "NOT_REACHED"
    if row["not_started"] > 0:
        return "GENERATOR_LIMITED"
    if (row["error_pct"] or 0) > max_fail_pct or (row["throughput_tps"] or 0) < MIN_THROUGHPUT_RATIO * rate:
        return "SATURATED"
    return "OK"


def summarize_knee(rows: list[dict]) -> dict:
    """The knee is the first rung that is not OK; the last OK rung before it is the safe level."""
    last_ok = None
    knee = None
    for row in rows:
        if row["verdict"] == "OK":
            last_ok = row
        elif row["verdict"] != "NOT_REACHED":
            knee = row
            break
    baseline = next((r["p95_ms"] for r in rows if r["verdict"] == "OK" and r["p95_ms"]), None)
    for row in rows:
        row["p95_vs_first_ok"] = (
            round(row["p95_ms"] / baseline, 2) if baseline and row.get("p95_ms") else None
        )
    return {
        "last_ok_rate_tps": last_ok["offered_rate_tps"] if last_ok else None,
        "knee_rate_tps": knee["offered_rate_tps"] if knee else None,
        "knee_verdict": knee["verdict"] if knee else None,
        "knee_reached": knee is not None,
    }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class ProbeRunner(run_perf.PerfRunner):
    """Reuses the perf runner's lifecycle; only the k6 script, summary and output root differ."""

    def __init__(self, *args, rates, step_seconds, warmup_s, drain_s, max_fail_pct, stop_p95_ms,
                 max_vus, pre_allocated_vus, cooldown_s, workload=None, **kwargs):
        # The ladder rates (this method's `rates`) are a probe-only concept (ascending TPS rungs
        # climbed in one k6 run) and must not be confused with PerfRunner.rates (the list of
        # offered-rate levels run_perf.py measures as separate windows); PerfRunner still needs its
        # own `rates`/`workload` kwargs satisfied, so pass placeholders it never actually uses here.
        super().__init__(*args, rates=[float(r) for r in rates],
                          workload=workload or run_perf.DEFAULT_WORKLOAD, **kwargs)
        # Probe output never shares a root with protocol evidence.
        self.evidence_root = self.workspace / "evaluation" / "evidence" / PROBE_ROOT_NAME
        self.campaign_dir = self.evidence_root / self.campaign_id
        self.log_dir = self.campaign_dir / "logs"
        self.effective_config_path = self.campaign_dir / "effective-config.json"
        self.rungs = build_rungs(rates, step_seconds)
        self.warmup_s = warmup_s
        self.drain_s = drain_s
        self.max_fail_pct = max_fail_pct
        self.stop_p95_ms = stop_p95_ms
        self.max_vus = max_vus
        self.pre_allocated_vus = pre_allocated_vus
        self.cooldown_s = cooldown_s
        self.model_results: list[dict] = []

    def find_isolation_proof(self, model: str) -> Path | None:
        """Isolation proofs are shared with the protocol runs, so look in the perf evidence root."""
        protocol_root = self.workspace / "evaluation" / "evidence" / run_perf.FAMILY
        original = self.evidence_root
        self.evidence_root = protocol_root
        try:
            return super().find_isolation_proof(model)
        finally:
            self.evidence_root = original

    def ensure_isolation_proof(self, model: str) -> Path | None:
        proof = self.find_isolation_proof(model)
        if proof:
            return proof
        # Same command the perf runner uses; it writes the proof to the perf evidence root so the
        # protocol runs can reuse it.
        self.run_command(
            [sys.executable, "-m", "evaluation.bin.perf.session_isolation_live",
             "--configuration", model, "--output-root", f"evaluation/evidence/{run_perf.FAMILY}"],
            f"isolation-proof-{MODEL_ALIASES[model]}",
            allowed_exit_codes={0, 2},
        )
        return self.find_isolation_proof(model)

    def probe_environment(self, model: str, run_id: str, root_vc: dict | None) -> dict[str, str]:
        # probe_load.js ignores OFFERED_RATE_TPS (it reads PROBE_STEPS instead), so the rate value
        # passed here is a placeholder only.
        env = self.k6_environment(model, run_id, root_vc, self.rungs[0]["rate"] if self.rungs else 0)
        env.update({
            "PROBE_STEPS": json.dumps(self.rungs),
            "PROBE_WARMUP_S": str(self.warmup_s),
            "PROBE_DRAIN_S": str(self.drain_s),
            "PROBE_MAX_FAIL_PCT": str(self.max_fail_pct),
            "PROBE_STOP_P95_MS": str(self.stop_p95_ms),
            "PROBE_MAX_VUS": str(self.max_vus),
            "PROBE_PRE_ALLOCATED_VUS": str(self.pre_allocated_vus),
        })
        return env

    def probe_model(self, model: str) -> None:
        alias = MODEL_ALIASES[model]
        run_id = f"{self.campaign_id}-probe-{alias}"
        run_dir = self.run_dir(run_id)

        def blocked(reason: str) -> None:
            print(f"[{model}] BLOCKED: {reason}")
            self.dispositions.append({
                "stage": "probe", "configuration": model, "run_id": run_id,
                "status": "blocked", "reason": reason,
            })

        self.stop_all(f"reset-stop-{alias}")
        self.start_model(model)

        proof_path = None
        root_vc = None
        if model != "B0-C0":
            proof_path = self.ensure_isolation_proof(model)
            if not proof_path:
                return blocked("ISOLATION_PROOF_MISSING_OR_NOT_VERIFIED")
            try:
                root_vc = ais_flows.provision_root_vc()
            except Exception as exc:
                return blocked(f"ROOT_VC_PROVISIONING_FAILED: {type(exc).__name__}: {exc}")

        # The first login of a user must never overlap another login (Keycloak consent race), and
        # the probe must not spend a ladder on a broken path.
        try:
            self.preflight_authorization(model, root_vc)
        except Exception as exc:
            return blocked(f"PREFLIGHT_AUTHORIZATION_FAILED: {type(exc).__name__}: {str(exc)[:300]}")

        run_dir.mkdir(parents=True, exist_ok=False)
        command = [self.k6_bin, "run", "--quiet", "--no-usage-report", PROBE_SCRIPT.as_posix()]
        timeout = estimated_k6_seconds(self.rungs, self.warmup_s, self.drain_s) + 120
        started_at = utc_now()
        exit_code, stop_reason = self.run_k6(command, self.probe_environment(model, run_id, root_vc), run_id, timeout)
        ended_at = utc_now()

        summary_path = run_dir / "k6-summary.json"
        rows: list[dict] = []
        reason = None
        if not summary_path.exists():
            reason = "K6_SUMMARY_MISSING"
        else:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            rows = [rung_metrics(summary, rung, self.max_fail_pct) for rung in self.rungs]
        knee = summarize_knee(rows) if rows else {}

        # k6 exits 99 when a stop threshold aborted the run. That is the probe's intended stop, not a fault.
        if stop_reason:
            status = "STOPPED_SAFETY"
            reason = reason or stop_reason
        elif reason or exit_code not in (0, 99):
            status = "FAILED"
            reason = reason or f"K6_EXIT_{exit_code}"
        else:
            status = "STOPPED_BY_THRESHOLD" if exit_code == 99 else "LADDER_COMPLETED"

        manifest = {
            "schema_version": "3.0.0",
            "protocol_id": PROTOCOL_ID,
            "evidence_class": EVIDENCE_CLASS,
            "experiment_purpose": "probe",
            "campaign_id": self.campaign_id,
            "run_id": run_id,
            "configuration": model,
            "workload": self.workload,
            "scope": "authorization_only",
            "driver": "k6",
            "k6_version": self.k6_version,
            "ladder": self.rungs,
            "warmup_s": self.warmup_s,
            "drain_s": self.drain_s,
            "stop_rules": {"max_fail_pct": self.max_fail_pct, "stop_p95_ms": self.stop_p95_ms,
                           "min_throughput_ratio": MIN_THROUGHPUT_RATIO},
            "vu_pool": {"pre_allocated": self.pre_allocated_vus, "max": self.max_vus},
            "source_digest": self.source_identity.get("source_digest"),
            "isolation_proof": proof_path.relative_to(self.workspace).as_posix() if proof_path else None,
            "root_vc_digest": root_vc["digest"] if root_vc else None,
            "started_at": started_at,
            "ended_at": ended_at,
            "k6_exit_status": exit_code,
            "status": status,
            "reason": reason,
            "knee": knee,
            "rungs": rows,
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.seal_run_dir(run_dir)
        self.model_results.append(manifest)
        self.dispositions.append({
            "stage": "probe", "configuration": model, "run_id": run_id,
            "status": "executed" if status in ("LADDER_COMPLETED", "STOPPED_BY_THRESHOLD") else "failed",
            "reason": reason or status,
        })
        print_model_table(model, status, rows, knee)

        print(f"Enforcing cooldown ({self.cooldown_s}s)...")
        time.sleep(self.cooldown_s)

    def write_probe_summary(self) -> None:
        columns = [
            "configuration", "step", "offered_rate_tps", "duration_s", "scheduled", "started", "success",
            "failed", "unfinished", "not_started", "throughput_tps", "error_pct",
            "p50_ms", "p95_ms", "p99_ms", "p95_vs_first_ok", "verdict",
        ]
        with (self.campaign_dir / "probe-summary.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for result in self.model_results:
                for row in result["rungs"]:
                    writer.writerow({"configuration": result["configuration"], **{k: row.get(k) for k in columns[1:]}})
        lines = [f"# Saturation probe: {self.campaign_id}", "",
                 f"Evidence class: `{EVIDENCE_CLASS}`. Do not pool with pilot or final runs.", ""]
        for result in self.model_results:
            knee = result["knee"]
            lines.append(
                f"- {result['configuration']}: status {result['status']}, last OK rate "
                f"{knee.get('last_ok_rate_tps')} TPS, first non-OK rate {knee.get('knee_rate_tps')} TPS "
                f"({knee.get('knee_verdict')})"
            )
        (self.campaign_dir / "probe-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def execute(self) -> None:
        self.initialize()
        self.apply_environment()
        self.notes.append(
            f"evidence_class={EVIDENCE_CLASS}; ladder={[r['rate'] for r in self.rungs]} TPS; "
            f"step={self.rungs[0]['duration']}s; warmup={self.warmup_s}s; drain={self.drain_s}s; "
            f"workload={self.workload}; scope=authorization_only; driver=k6"
        )
        try:
            self.locate_k6()
            for model in self.models:
                try:
                    self.probe_model(model)
                except Exception as exc:
                    self.dispositions.append({
                        "stage": "probe", "configuration": model, "run_id": None,
                        "status": "failed", "reason": f"{type(exc).__name__}: {exc}",
                    })
            self.write_probe_summary()
        except Exception as exc:
            self.dispositions.append({
                "stage": "probe", "configuration": "all", "run_id": None,
                "status": "failed", "reason": f"{type(exc).__name__}: {exc}",
            })
        finally:
            try:
                self.stop_all("post-stop-all")
            except Exception as exc:
                self.dispositions.append({
                    "stage": "cleanup", "configuration": "all", "run_id": None,
                    "status": "failed", "reason": str(exc),
                })
            self.write_handoff()


def print_model_table(model: str, status: str, rows: list[dict], knee: dict) -> None:
    print(f"\n=== {model}: {status} ===")
    header = f"{'rate':>6} {'ok':>5} {'fail':>5} {'unfin':>5} {'drop':>5} {'tput':>7} {'err%':>6} {'p50':>8} {'p95':>8} {'p99':>8}  verdict"
    print(header)
    for r in rows:
        cell = lambda v, w: f"{'-' if v is None else v:>{w}}"
        print(f"{r['offered_rate_tps']:>6} {r['success']:>5} {r['failed']:>5} {r['unfinished']:>5} {r['not_started']:>5} "
              f"{cell(r['throughput_tps'], 7)} {cell(r['error_pct'], 6)} {cell(r['p50_ms'], 8)} "
              f"{cell(r['p95_ms'], 8)} {cell(r['p99_ms'], 8)}  {r['verdict']}")
    print(f"last OK rate: {knee.get('last_ok_rate_tps')} TPS; first non-OK rate: {knee.get('knee_rate_tps')} TPS "
          f"({knee.get('knee_verdict')})")


def default_probe_campaign_id() -> str:
    return "probe-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--campaign-id")
    parser.add_argument("--models", nargs="+", choices=tuple(MODEL_ALIASES),
                        help="Subset of configurations. Probing only B1-C2 first is the fastest option.")
    parser.add_argument("--rates", nargs="+", type=int, default=DEFAULT_RATES,
                        help="Ascending offered rates in TPS (default: %(default)s).")
    parser.add_argument("--workload", help="Defaults to configuration load.workloads[0], else "
                                            f"{run_perf.DEFAULT_WORKLOAD!r}.")
    parser.add_argument("--step-seconds", type=int, default=30, help="Seconds per rung (default: %(default)s).")
    parser.add_argument("--warmup-seconds", type=int, default=15, help="Warm-up at the first rate (default: %(default)s).")
    parser.add_argument("--drain-seconds", type=int, default=10,
                        help="Grace period after each rung; keep it above the expected latency (default: %(default)s).")
    parser.add_argument("--max-fail-pct", type=float, default=10.0,
                        help="Abort and mark SATURATED above this failure percent (default: %(default)s).")
    parser.add_argument("--stop-p95-ms", type=float, default=15000.0,
                        help="Abort when a rung's p95 exceeds this (default: %(default)s).")
    parser.add_argument("--max-vus", type=int, default=run_perf.MAX_VUS,
                        help="k6 virtual-user ceiling (default: %(default)s).")
    parser.add_argument("--pre-allocated-vus", type=int, default=300,
                        help="VUs k6 creates before the run. Growing the pool mid-run drops arrivals, which "
                             "looks like saturation, so keep it above rate x latency (default: %(default)s).")
    parser.add_argument("--cooldown-seconds", type=int, default=15)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    if args.rates != sorted(set(args.rates)) or min(args.rates) < 1:
        print("CONFIGURATION_ERROR: --rates must be strictly ascending positive integers", file=sys.stderr)
        return 2

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = _root_dir / config_path
    config, digest = load_config(config_path)
    models = args.models or config["models"]
    workload = run_perf.resolve_workload(config, args.workload)
    rungs = build_rungs(args.rates, args.step_seconds)
    k6_seconds = estimated_k6_seconds(rungs, args.warmup_seconds, args.drain_seconds)

    if args.dry_run:
        print(json.dumps({
            "evidence_class": EVIDENCE_CLASS,
            "evidence_root": f"evaluation/evidence/{PROBE_ROOT_NAME}",
            "config_digest": digest,
            "k6_found": bool(os.environ.get("K6_BIN") or shutil.which("k6")),
            "models": models,
            "workload": workload,
            "ladder": rungs,
            "warmup_s": args.warmup_seconds,
            "drain_s": args.drain_seconds,
            "estimated_k6_seconds_per_model": k6_seconds,
            "per_model_steps": ["stop_all", "start", "isolation_proof (B1 only)", "provision_root_vc (B1 only)",
                                "preflight_authorization", "k6_ladder", "cooldown"],
        }, indent=2))
        return 0

    campaign_id = args.campaign_id or default_probe_campaign_id()
    runner = ProbeRunner(
        _root_dir, config, config_path, digest, campaign_id, models=models,
        rates=args.rates, workload=workload, step_seconds=args.step_seconds, warmup_s=args.warmup_seconds,
        drain_s=args.drain_seconds, max_fail_pct=args.max_fail_pct, stop_p95_ms=args.stop_p95_ms,
        max_vus=args.max_vus, pre_allocated_vus=args.pre_allocated_vus, cooldown_s=args.cooldown_seconds,
    )
    runner.execute()
    failed = any(item["status"] in {"failed", "blocked"} for item in runner.dispositions)
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
