#!/usr/bin/env python3
"""E-LOAD perf runner: authorization latency and throughput under offered load (k6).

REINSTATED by BP-20260922-v5 (decision DEC-020), reversing the BP-20260921-v4 retirement. Blocked from
producing `pilot`/`final` evidence until a live isolation proof exists for B1-C0/B1-C2 (BLK-004) and the
known reinstated-prototype defects are closed (BLK-013); see docs/EVALUATION_PROTOCOL.md section 3.4. Smoke and
`--dry-run` may be used to inspect the schedule and diagnose defects without contacting live services.

One execution measures every offered rate in `--rates` (or the configuration's `load.rates_tps`) for the
three models, in interleaved paired blocks (B0, B1-C0, B1-C2, B0, ...) for the batch count of the chosen
profile. Only the authorization phase is measured, from the first authorization request to access-token
issuance. F1 (root VC issuance) is provisioned outside the measured window, and the
resource server is never called. No CPU, memory, or storage is measured.

Per offered rate and model the result reports p50, p95, p99, throughput, and error rate,
computed on samples pooled over all valid batches.

No source edit is needed to measure another rate or workload; they come from `--rates`/`--workload` or
the configuration's `load` block:

    python evaluation/bin/perf/run_perf.py \
        --config evaluation/configs/perf-local.json \
        --purpose pilot --rates 1 5 10 --workload Small --campaign-id pilot-perf-001 --execute

Artifact and network sizes are measured once, separately, by bin/artifacts/measure_artifacts.py.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

_root_dir = Path(__file__).resolve().parents[3]
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from evaluation.bin.common import ais_flows  # noqa: E402
from evaluation.bin.common.constants import COST_PROTOCOL_ID  # noqa: E402
from evaluation.bin.common.orchestrator import (  # noqa: E402
    MODEL_ALIASES,
    Orchestrator,
    default_campaign_id,
    load_config,
    sha256_file,
    utc_now,
    validate_config,
)
from evaluation.bin.common.source_identity import get_source_identity  # noqa: E402

FAMILY = "perf"
EXPERIMENT_ID = "EXP-LOAD-01"

# Default offered-load levels (TPS) and workload used when neither --rates/--workload nor the
# configuration's `load` block supply them. Every level is measured in the same campaign; no source
# edit is required to add or change a level.
DEFAULT_RATES_TPS = [1.0]
# Workload is no longer a comparison dimension (decision DEC-023, 2026-09-22): Medium is the one
# workload used everywhere.
DEFAULT_WORKLOAD = "Medium"

# ---------------------------------------------------------------------------
# Tunables that stay module constants: window shape, VU pool, and driver behavior. Offered rate and
# workload are configuration/CLI-driven (see resolve_rates/resolve_workload below).
# ---------------------------------------------------------------------------

# Per-purpose window shape. "final" is the authoritative one; smoke and pilot are the same
# code path with shorter windows.
PROFILES = {
    "smoke": {"batches": 1, "warmup_s": 5,  "warmup_drain_s": 5,  "measure_s": 10,  "drain_s": 5,  "cooldown_s": 5},
    "pilot": {"batches": 1, "warmup_s": 10, "warmup_drain_s": 10, "measure_s": 30,  "drain_s": 10, "cooldown_s": 30},
    # 20/10/60/20/20, batches=2: matches docs/EVALUATION_PROTOCOL.md section 3.4 (updated 2026-09-22, decision
    # DEC-025, superseding DEC-021's 3-batch/100s window). The stack is started once per (model, batch)
    # and every offered-rate level runs in that one lifetime (see run_model_batch/run_rate_window
    # below); only batch-to-batch independence is the bootstrap's resampling unit
    # (analysis.resampling_unit: paired_block), so restarting between rate levels of the same batch is
    # not required for statistical validity. 2 batches, like 3, stays below
    # min_paired_blocks_for_stable_interval (5), so the analysis labels the interval "descriptive"
    # either way; shortening measure_s only widens within-block noise, it does not change that label.
    "final": {"batches": 2, "warmup_s": 20, "warmup_drain_s": 10, "measure_s": 60, "drain_s": 20, "cooldown_s": 20},
}

# k6 virtual-user pool. Arrivals that find no free VU are counted as dropped_iterations
# (generator limited or system saturated).
PRE_ALLOCATED_VUS = 50
MAX_VUS = 1000

# Keep the (large, gzipped) raw k6 point stream next to the compact per-run results.
KEEP_RAW_K6_OUTPUT = False

K6_SCRIPT = Path(__file__).resolve().parent / "k6" / "auth_load.js"


# ---------------------------------------------------------------------------
# Offered-rate / workload resolution (configuration/CLI-driven; no source edit between campaigns)
# ---------------------------------------------------------------------------

def resolve_rates(config: dict, cli_rates: list[float] | None) -> list[float]:
    """CLI --rates, else configuration load.rates_tps, else DEFAULT_RATES_TPS. Never empty."""
    if cli_rates:
        rates = list(cli_rates)
    else:
        rates = (config.get("load", {}) or {}).get("rates_tps") or DEFAULT_RATES_TPS
    rates = [float(r) for r in rates]
    if not rates:
        raise ValueError("at least one offered rate is required (--rates or configuration load.rates_tps)")
    return rates


def resolve_workload(config: dict, cli_workload: str | None) -> str:
    """CLI --workload, else the first configured load.workloads entry, else DEFAULT_WORKLOAD."""
    if cli_workload:
        return cli_workload
    workloads = (config.get("load", {}) or {}).get("workloads") or []
    return workloads[0] if workloads else DEFAULT_WORKLOAD


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def percentile(sorted_values: list[float], pct: float) -> float | None:
    """Linear-interpolated percentile of an already sorted list."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * pct / 100.0
    lo = int(k)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def latency_stats(durations: list[float]) -> dict:
    values = sorted(durations)
    r = lambda v: None if v is None else round(v, 3)
    return {
        "p50_ms": r(percentile(values, 50)),
        "p95_ms": r(percentile(values, 95)),
        "p99_ms": r(percentile(values, 99)),
        "min_ms": r(values[0]) if values else None,
        "max_ms": r(values[-1]) if values else None,
    }


def parse_k6_points(raw_path: Path) -> dict:
    """Streams k6's gzipped JSON output and keeps only the metrics this experiment needs."""
    wanted = ('"auth_duration"', '"auth_ok"', '"auth_fail"', '"dropped_iterations"')
    durations: list[tuple[str, float]] = []
    counts = {"ok": {}, "fail": {}, "dropped": {}}
    fail_stages: dict[str, int] = {}
    opener = gzip.open if raw_path.suffix == ".gz" else open
    with opener(raw_path, "rt", encoding="utf-8") as handle:
        for line in handle:
            if '"type":"Point"' not in line or not any(w in line for w in wanted):
                continue
            rec = json.loads(line)
            metric, data = rec["metric"], rec["data"]
            tags = data.get("tags") or {}
            phase = tags.get("phase") or tags.get("scenario")
            value = data["value"]
            if metric == "auth_duration" and phase == "measure":
                durations.append((data.get("time", ""), float(value)))
            elif metric == "auth_ok":
                counts["ok"][phase] = counts["ok"].get(phase, 0) + int(value)
            elif metric == "auth_fail":
                counts["fail"][phase] = counts["fail"].get(phase, 0) + int(value)
                if phase == "measure":
                    stage = tags.get("stage", "unknown")
                    fail_stages[stage] = fail_stages.get(stage, 0) + int(value)
            elif metric == "dropped_iterations":
                counts["dropped"][phase] = counts["dropped"].get(phase, 0) + int(value)
    return {"durations": durations, "counts": counts, "fail_stages": fail_stages}


def compute_window_metrics(parsed: dict, rate: int, measure_s: int) -> dict:
    """Turns raw k6 counters into the per-window accounting and headline metrics."""
    ok = parsed["counts"]["ok"].get("measure", 0)
    failed = parsed["counts"]["fail"].get("measure", 0)
    dropped = parsed["counts"]["dropped"].get("measure", 0)
    scheduled = rate * measure_s
    completed = ok + failed
    # k6's constant-arrival-rate can start one boundary iteration beyond rate * duration, so the
    # nominal schedule is only a lower bound for what was actually started.
    expected_started = max(scheduled - dropped, 0)
    started = max(expected_started, completed)
    unfinished = started - completed
    metrics = {
        "scheduled": scheduled,
        "started": started,
        "not_started": dropped,
        "success": ok,
        "failed": failed,
        "unfinished": unfinished,
        "boundary_iterations": max(completed - expected_started, 0),
        "failed_by_stage": parsed["fail_stages"],
        "throughput_tps": round(ok / measure_s, 4) if measure_s else None,
        "error_rate_pct": round(100.0 * (failed + unfinished) / started, 4) if started else None,
    }
    metrics.update(latency_stats([v for _, v in parsed["durations"]]))
    metrics["counter_invariant_ok"] = completed > 0
    return metrics


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class PerfRunner(Orchestrator):
    family = FAMILY

    def __init__(self, *args, rates: list[float], workload: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.profile = PROFILES[self.config["experiment_purpose"]]
        self.rates = rates
        self.workload = workload
        self.k6_bin: str | None = None
        self.k6_version: str | None = None
        self.window_results: list[dict] = []

    # -- environment ------------------------------------------------------

    def locate_k6(self) -> None:
        self.k6_bin = os.environ.get("K6_BIN") or shutil.which("k6")
        if not self.k6_bin:
            raise RuntimeError("k6 was not found. Install k6 or set K6_BIN to its full path.")
        out = subprocess.run([self.k6_bin, "version"], capture_output=True, text=True, check=False)
        self.k6_version = (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else "unknown"

    def apply_environment(self) -> None:
        """In-process flows (F1 provisioning) read the same hosts the subprocesses get."""
        os.environ.update(self.config.get("command_environment", {}))

    def k6_environment(self, model: str, run_id: str, root_vc: dict | None, rate: float) -> dict[str, str]:
        p = self.profile
        hosts = ais_flows.perf_hosts()
        env = os.environ.copy()
        env.update(self.config.get("command_environment", {}))
        env.update({
            "MODEL": model,
            "OFFERED_RATE_TPS": str(rate),
            "WARMUP_SECONDS": str(p["warmup_s"]),
            "WARMUP_DRAIN_SECONDS": str(p["warmup_drain_s"]),
            "MEASUREMENT_SECONDS": str(p["measure_s"]),
            "DRAIN_SECONDS": str(p["drain_s"]),
            "PRE_ALLOCATED_VUS": str(PRE_ALLOCATED_VUS),
            "MAX_VUS": str(MAX_VUS),
            "BANK_HOST": hosts["bank_host"],
            "KEYCLOAK_HOST": hosts["keycloak_host"],
            "TPP_HOST": hosts["tpp_host"],
            "WALLET_HOST": hosts["wallet_host"],
            "TPP_URL": hosts["tpp_url"],
            "WALLET_URL": hosts["wallet_url"],
            "SUMMARY_PATH": (self.run_dir(run_id) / "k6-summary.json").as_posix(),
        })
        base_dir = str(self.workspace)
        if model == "B0-C0":
            params = ais_flows.b0_auth_params(base_dir, self.workload)
            env.update({
                "B0_SCOPE": params["scope"],
                "B0_TPP_URL": hosts["b0_tpp_url"],
                "B0_USERNAME": ais_flows.B0_USERNAME,
                "B0_PASSWORD": ais_flows.B0_PASSWORD,
            })
        else:
            env["VDAM_SCOPES"] = json.dumps(ais_flows.vdam_auth_scopes(base_dir, self.workload))
            env["AUTHZ_VC_JTI"] = root_vc["jti"] if root_vc else ""
        return env

    # -- isolation proof --------------------------------------------------

    def find_isolation_proof(self, model: str) -> Path | None:
        """Newest verified proof for this model whose source digest matches the current tree."""
        current = get_source_identity(self.workspace).get("source_digest", "unknown")
        if not self.evidence_root.exists():
            return None
        slug = model.lower().replace("-", "")
        for item in sorted(self.evidence_root.glob(f"isolation-proof-{slug}-*"), reverse=True):
            candidate = item / "isolation-proof.json"
            if not candidate.exists():
                continue
            try:
                proof = json.loads(candidate.read_text(encoding="utf-8"))
            except Exception:
                continue
            digest_ok = current == "unknown" or proof.get("source_digest") == current
            if proof.get("isolation_verified") and proof.get("configuration") == model and digest_ok:
                return candidate
        return None

    def ensure_isolation_proof(self, model: str) -> Path | None:
        proof = self.find_isolation_proof(model)
        if proof:
            return proof
        self.run_command(
            [sys.executable, "-m", "evaluation.bin.perf.session_isolation_live",
             "--configuration", model, "--output-root", f"evaluation/evidence/{FAMILY}"],
            f"isolation-proof-{MODEL_ALIASES[model]}",
            allowed_exit_codes={0, 2},
        )
        return self.find_isolation_proof(model)

    # -- k6 supervision ---------------------------------------------------

    def run_k6(self, command: list[str], env: dict[str, str], run_id: str, timeout: float) -> tuple[int, str | None]:
        """Runs k6 with a hard process deadline; kills the whole process tree on expiry."""
        command_id = f"CMD-{len(self.commands) + 1:04d}"
        started = utc_now()
        log_path = self.log_dir / f"{command_id}-{run_id}.log"
        stop_reason = None
        with log_path.open("w", encoding="utf-8") as log:
            log.write(f"Executing under process supervision: {' '.join(command)}\n")
            log.flush()
            proc = subprocess.Popen(command, cwd=self.workspace, env=env, stdout=log, stderr=subprocess.STDOUT, text=True)
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_reason = "PROCESS_DEADLINE_EXCEEDED"
                log.write(f"\n[SUPERVISOR] deadline {timeout}s exceeded; terminating process tree\n")
                log.flush()
                try:
                    proc.terminate()
                    proc.wait(timeout=5.0)
                except Exception:
                    pass
                if proc.poll() is None:
                    if os.name == "nt":
                        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False)
                    else:
                        proc.kill()
                    proc.wait()
                exit_code = 124
        self.commands.append({
            "command_id": command_id,
            "campaign_id": self.campaign_id,
            "working_directory": ".",
            "command": " ".join(command),
            "started_at": started,
            "ended_at": utc_now(),
            "exit_status": exit_code,
            "log_path": log_path.relative_to(self.workspace).as_posix(),
        })
        return exit_code, stop_reason

    # -- one window -------------------------------------------------------

    def preflight_authorization(self, model: str, root_vc: dict | None) -> None:
        """Run one complete authorization, alone, and require an access token."""
        base_dir = str(self.workspace)
        if model == "B0-C0":
            result = ais_flows.run_b0_auth(base_dir, self.workload)
        else:
            result = ais_flows.run_vdam_auth(base_dir, self.workload, authz_vc_jti=root_vc["jti"] if root_vc else None)
        if not result.get("access_token"):
            raise RuntimeError("the preflight authorization returned no access token")
        print(f"[{model}] preflight authorization OK")

    def run_model_batch(self, model: str, batch: int) -> None:
        """Starts the stack once for this (model, batch) and runs every offered-rate level in that one
        lifetime; only stops/restarts between batches. See the note on PROFILES['final'] above."""
        p = self.profile
        alias = MODEL_ALIASES[model]

        def blocked_all(reason: str) -> None:
            for rate in self.rates:
                print(f"[{model} r{rate} b{batch}] BLOCKED: {reason}")
                self.dispositions.append({
                    "stage": "perf", "configuration": model, "offered_rate_tps": rate, "batch": batch,
                    "run_id": None, "status": "blocked", "reason": reason,
                })

        self.stop_all(f"reset-stop-{alias}-b{batch:02d}")
        self.start_model(model)

        proof_path = None
        root_vc = None
        if model != "B0-C0":
            proof_path = self.ensure_isolation_proof(model)
            if not proof_path:
                return blocked_all("ISOLATION_PROOF_MISSING_OR_NOT_VERIFIED")
            try:
                root_vc = ais_flows.provision_root_vc()
            except Exception as exc:
                return blocked_all(f"ROOT_VC_PROVISIONING_FAILED: {type(exc).__name__}: {exc}")

        # One sequential authorization before any load. Keycloak stores the user's consent on the first login and
        # concurrent first logins can create duplicate consent rows that break every later login, so the first
        # login must never overlap another. It also proves the whole path works before a window is spent on it.
        try:
            self.preflight_authorization(model, root_vc)
        except Exception as exc:
            return blocked_all(f"PREFLIGHT_AUTHORIZATION_FAILED: {type(exc).__name__}: {str(exc)[:300]}")

        for rate in self.rates:
            try:
                self.run_rate_window(model, batch, rate, proof_path, root_vc)
            except Exception as exc:
                print(f"[{model} r{rate} b{batch}] FAILED: {type(exc).__name__}: {exc}")
                self.dispositions.append({
                    "stage": "perf", "configuration": model, "offered_rate_tps": rate, "batch": batch,
                    "run_id": None, "status": "failed", "reason": f"{type(exc).__name__}: {exc}",
                })

        print(f"Enforcing cooldown ({p['cooldown_s']}s)...")
        time.sleep(p["cooldown_s"])

    def run_rate_window(self, model: str, batch: int, rate: float, proof_path: Path | None,
                        root_vc: dict | None) -> None:
        """One offered-rate level within an already-started (model, batch) lifetime."""
        p = self.profile
        alias = MODEL_ALIASES[model]
        rate_slug = f"{rate:g}".replace(".", "p")
        run_id = f"{self.campaign_id}-perf-{alias}-r{rate_slug}-b{batch:02d}"
        paired_block_id = f"{self.campaign_id}-r{rate_slug}-pb{batch:02d}"
        run_dir = self.run_dir(run_id)

        if self.resume and (run_dir / "manifest.json").exists():
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            print(f"[{model} r{rate} b{batch}] already completed; preserving evidence")
            self.record_result(manifest)
            return

        run_dir.mkdir(parents=True, exist_ok=False)
        raw_path = run_dir / "k6-raw.json.gz"
        command = [self.k6_bin, "run", "--quiet", "--no-usage-report", "--out", f"json={raw_path.as_posix()}",
                   K6_SCRIPT.as_posix()]
        timeout = p["warmup_s"] + p["warmup_drain_s"] + p["measure_s"] + p["drain_s"] + 60
        started_at = utc_now()
        exit_code, stop_reason = self.run_k6(command, self.k6_environment(model, run_id, root_vc, rate), run_id, timeout)
        ended_at = utc_now()

        metrics: dict = {}
        reason = None
        if not raw_path.exists():
            reason = "K6_OUTPUT_MISSING"
        else:
            try:
                parsed = parse_k6_points(raw_path)
                metrics = compute_window_metrics(parsed, rate, p["measure_s"])
                self.write_durations(run_dir, parsed["durations"])
            except Exception as exc:
                reason = f"K6_OUTPUT_UNPARSEABLE: {type(exc).__name__}: {exc}"
            if not KEEP_RAW_K6_OUTPUT:
                raw_path.unlink(missing_ok=True)

        if stop_reason == "PROCESS_DEADLINE_EXCEEDED":
            measurement_status, run_outcome = "INVALID_MEASUREMENT", "STOPPED_SAFETY"
            reason = reason or stop_reason
        elif reason or exit_code != 0 or not metrics.get("counter_invariant_ok"):
            measurement_status, run_outcome = "INVALID_MEASUREMENT", "DEGRADED"
            reason = reason or (f"K6_EXIT_{exit_code}" if exit_code != 0 else "COUNTER_INVARIANT_FAILED")
        else:
            measurement_status = "VALID"
            if metrics["not_started"] > 0:
                run_outcome = "GENERATOR_LIMITED"
            elif metrics["failed"] > 0 or metrics["unfinished"] > 0:
                run_outcome = "DEGRADED"
            else:
                run_outcome = "COMPLETED"

        manifest = {
            "schema_version": "4.0.0",
            "protocol_id": COST_PROTOCOL_ID,
            "experiment_id": EXPERIMENT_ID,
            "experiment_purpose": self.config["experiment_purpose"],
            "campaign_id": self.campaign_id,
            "run_id": run_id,
            "paired_block_id": paired_block_id,
            "batch": batch,
            "configuration": model,
            "workload": self.workload,
            "mode": "repeated",
            "scope": "authorization_only",
            "driver": "k6",
            "k6_version": self.k6_version,
            "scheduler": "constant_arrival_rate_open_loop",
            "offered_rate_tps": rate,
            "window": {k: p[k] for k in ("warmup_s", "warmup_drain_s", "measure_s", "drain_s", "cooldown_s")},
            "vu_pool": {"pre_allocated": PRE_ALLOCATED_VUS, "max": MAX_VUS},
            "source_digest": self.source_identity.get("source_digest"),
            "source_identity": self.source_identity,
            "isolation_proof": proof_path.relative_to(self.workspace).as_posix() if proof_path else None,
            "root_vc_digest": root_vc["digest"] if root_vc else None,
            "started_at": started_at,
            "ended_at": ended_at,
            "k6_exit_status": exit_code,
            "stop_reason": stop_reason,
            "measurement_status": measurement_status,
            "run_outcome": run_outcome,
            "reason": reason,
            "metrics": metrics,
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.seal_run_dir(run_dir)
        self.record_result(manifest)

    @staticmethod
    def write_durations(run_dir: Path, durations: list[tuple[str, float]]) -> None:
        with (run_dir / "durations.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["time_utc", "duration_ms"])
            writer.writerows(durations)

    def record_result(self, manifest: dict) -> None:
        self.window_results.append(manifest)
        self.dispositions.append({
            "stage": "perf",
            "configuration": manifest["configuration"],
            "batch": manifest["batch"],
            "run_id": manifest["run_id"],
            "measurement_status": manifest["measurement_status"],
            "run_outcome": manifest["run_outcome"],
            "status": "executed" if manifest["measurement_status"] == "VALID" else "blocked",
            "reason": manifest.get("reason"),
        })

    # -- aggregation ------------------------------------------------------

    def write_summaries(self) -> None:
        """perf-summary.csv pools samples over valid batches; the per-batch file keeps each window."""
        summary_cols = [
            "protocol_id", "campaign_id", "configuration", "workload", "offered_rate_tps",
            "batches_total", "batches_valid", "scheduled", "started", "success", "failed",
            "unfinished", "not_started", "throughput_tps", "error_rate_pct",
            "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms",
        ]
        batch_cols = [
            "run_id", "configuration", "batch", "offered_rate_tps", "measurement_status", "run_outcome",
            "scheduled", "started", "success", "failed", "unfinished", "not_started",
            "throughput_tps", "error_rate_pct", "p50_ms", "p95_ms", "p99_ms",
        ]
        measure_s = self.profile["measure_s"]

        with (self.campaign_dir / "perf-summary-per-batch.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=batch_cols)
            writer.writeheader()
            for m in self.window_results:
                writer.writerow({
                    "run_id": m["run_id"], "configuration": m["configuration"], "batch": m["batch"],
                    "offered_rate_tps": m["offered_rate_tps"], "measurement_status": m["measurement_status"],
                    "run_outcome": m["run_outcome"],
                    **{k: (m.get("metrics") or {}).get(k) for k in batch_cols[6:]},
                })

        rows = []
        for model in self.models:
            for rate in self.rates:
                windows = [m for m in self.window_results
                           if m["configuration"] == model and m["offered_rate_tps"] == rate]
                valid = [m for m in windows if m["measurement_status"] == "VALID"]
                if not windows:
                    continue
                pooled: list[float] = []
                for m in valid:
                    durations_file = self.run_dir(m["run_id"]) / "durations.csv"
                    if durations_file.exists():
                        with durations_file.open(encoding="utf-8") as handle:
                            pooled.extend(float(r["duration_ms"]) for r in csv.DictReader(handle))
                total = lambda key: sum((m["metrics"] or {}).get(key, 0) for m in valid)
                started = total("started")
                rows.append({
                    "protocol_id": COST_PROTOCOL_ID, "campaign_id": self.campaign_id, "configuration": model,
                    "workload": self.workload, "offered_rate_tps": rate,
                    "batches_total": len(windows), "batches_valid": len(valid),
                    "scheduled": total("scheduled"), "started": started, "success": total("success"),
                    "failed": total("failed"), "unfinished": total("unfinished"), "not_started": total("not_started"),
                    "throughput_tps": round(total("success") / (len(valid) * measure_s), 4) if valid else None,
                    "error_rate_pct": round(100.0 * (total("failed") + total("unfinished")) / started, 4) if started else None,
                    **(latency_stats(pooled) if pooled else {k: None for k in ("p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms")}),
                })
        with (self.campaign_dir / "perf-summary.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=summary_cols)
            writer.writeheader()
            writer.writerows(rows)

    # -- campaign ---------------------------------------------------------

    def execute(self) -> None:
        self.initialize()
        self.apply_environment()
        self.notes.append(
            f"offered_rate_levels_tps={self.rates}, batches={self.profile['batches']}, workload={self.workload}, "
            "scope=authorization_only, driver=k6"
        )
        try:
            self.locate_k6()
            for batch in range(1, self.profile["batches"] + 1):
                print(f"\n--- Paired block {batch}/{self.profile['batches']}, rates {self.rates} TPS ---")
                for model in self.models:
                    try:
                        self.run_model_batch(model, batch)
                    except Exception as exc:
                        self.dispositions.append({
                            "stage": "perf", "configuration": model, "batch": batch, "run_id": None,
                            "status": "failed", "reason": f"{type(exc).__name__}: {exc}",
                        })
            self.write_summaries()
        except Exception as exc:
            self.dispositions.append({
                "stage": "perf", "configuration": "all", "run_id": None,
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


def build_schedule(models: list[str], purpose: str, rates: list[float], workload: str) -> list[dict]:
    """One entry per (batch, model): the stack starts once and every offered-rate level in `rates` runs
    in that one lifetime (see PerfRunner.run_model_batch), so `rate_windows` lists the repeated k6
    invocations while stop_all/start/preflight/cooldown appear exactly once."""
    profile = PROFILES[purpose]
    schedule: list[dict] = []
    for batch in range(1, profile["batches"] + 1):
        for model in models:
            prep_steps = ["stop_all", "start"]
            if model != "B0-C0":
                prep_steps += ["isolation_proof", "provision_root_vc"]
            prep_steps += ["preflight_authorization"]
            schedule.append({
                "batch": batch, "configuration": model, "workload": workload,
                "prep_steps": prep_steps,
                "rate_windows": [{"offered_rate_tps": rate, "steps": ["k6_warmup", "k6_measure"]} for rate in rates],
                "final_step": "cooldown",
                "window": {k: profile[k] for k in ("warmup_s", "warmup_drain_s", "measure_s", "drain_s", "cooldown_s")},
            })
    return schedule


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--purpose", required=True, choices=tuple(PROFILES))
    parser.add_argument("--campaign-id")
    parser.add_argument("--models", nargs="+", choices=tuple(MODEL_ALIASES),
                        help="Subset of configurations. Defaults to every model in the configuration.")
    parser.add_argument("--rates", nargs="+", type=float,
                        help="Offered rates in TPS, measured in one campaign. "
                             "Defaults to configuration load.rates_tps, else DEFAULT_RATES_TPS.")
    parser.add_argument("--workload", help="Defaults to configuration load.workloads[0], else DEFAULT_WORKLOAD.")
    parser.add_argument("--resume", action="store_true")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = _root_dir / config_path
    config, digest = load_config(config_path)
    errors = validate_config(config, args.purpose, FAMILY)
    if errors:
        for error in errors:
            print(f"CONFIGURATION_ERROR: {error}", file=sys.stderr)
        return 2

    models = args.models or config["models"]
    try:
        rates = resolve_rates(config, args.rates)
    except ValueError as exc:
        print(f"CONFIGURATION_ERROR: {exc}", file=sys.stderr)
        return 2
    workload = resolve_workload(config, args.workload)

    if args.dry_run:
        print(json.dumps({
            "protocol_id": COST_PROTOCOL_ID,
            "experiment_family": FAMILY,
            "experiment_id": EXPERIMENT_ID,
            "evidence_root": f"evaluation/evidence/{FAMILY}",
            "config_digest": digest,
            "k6_found": bool(os.environ.get("K6_BIN") or shutil.which("k6")),
            "offered_rate_levels_tps": rates,
            "workload": workload,
            "schedule": build_schedule(models, args.purpose, rates, workload),
        }, indent=2))
        return 0

    campaign_id = args.campaign_id or default_campaign_id(FAMILY, args.purpose)
    runner = PerfRunner(_root_dir, config, config_path, digest, campaign_id, resume=args.resume, models=models,
                         rates=rates, workload=workload)
    runner.execute()
    failed = any(item["status"] in {"failed", "blocked"} for item in runner.dispositions)
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
