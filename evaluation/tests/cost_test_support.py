"""Shared, fully offline helpers for the cost-evaluation tests: a throw-away workspace, mock flows, and
synthetic evidence with known values. Nothing here starts Docker or contacts a service."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import shutil
import sys
import threading

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evaluation.bin.common import cost_protocol as protocol  # noqa: E402
from evaluation.bin.common.constants import COST_PROTOCOL_ID  # noqa: E402
from evaluation.bin.artifacts import measure_artifacts  # noqa: E402
from evaluation.bin.perf import run_cost  # noqa: E402

MODELS = ["B0-C0", "B1-C0", "B1-C2"]
# Workload is fixed to Medium everywhere (decision DEC-023); kept as a list of one so every test that
# iterates WORKLOADS still works unchanged.
WORKLOADS = ["Medium"]


def make_workspace(root: Path) -> Path:
    """A minimal workspace: the real pairing plan and protocol manifest, stub fixtures, and a config."""
    workspace = Path(root)
    manifests = workspace / "evaluation" / "manifests"
    manifests.mkdir(parents=True)
    for name in ("pairing-plan.json", "benchmark-protocol.json"):
        shutil.copyfile(_ROOT / "evaluation" / "manifests" / name, manifests / name)
    fixtures = workspace / "evaluation" / "fixtures" / "data"
    fixtures.mkdir(parents=True)
    for workload in WORKLOADS:
        (fixtures / f"workload_{workload.lower()}.json").write_text(
            json.dumps({"workload": workload, "permissions": ["ReadAccountsDetail"]}), encoding="utf-8")
    return workspace


def write_config(workspace: Path, purpose: str = "smoke", **extra) -> Path:
    config = {
        "schema_version": "3.0.0",
        "protocol_id": COST_PROTOCOL_ID,
        "experiment_purpose": purpose,
        "environment": "test",
        "models": MODELS,
        "lifecycle": {
            "stop_all_commands": [["echo", "stop"]],
            "start_commands": {model: [["echo", "start", model]] for model in MODELS},
        },
        "approval": {"state": "proposed", "decision_id": None, "frozen_digest": None},
    }
    config.update(extra)
    path = workspace / "evaluation" / "configs" / f"cost-{purpose}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def patch_lifecycle(cls, log: list):
    """Replaces the Docker lifecycle of a runner class with a call log for the duration of a `with` block."""
    from contextlib import ExitStack
    from unittest import mock

    stack = ExitStack()
    stack.enter_context(mock.patch.object(cls, "stop_all", lambda runner, label: log.append(("stop", label))))
    stack.enter_context(mock.patch.object(cls, "start_model", lambda runner, model: log.append(("start", model))))
    return stack


class MockCostAdapter(run_cost.FlowAdapter):
    """Scripted flows. Records every call and the highest number of simultaneously active transactions."""

    def __init__(self, latency=100.0, wire=1000, fail_on=(), f1_fails=False, warmup_latency=None, log=None):
        self.latency = latency
        self.warmup_latency = warmup_latency
        self.wire = wire
        self.fail_on = set(fail_on)  # 1-based positions among all authorize calls
        self.f1_fails = f1_fails
        self.calls = 0
        self.f1_calls = 0
        self.active = 0
        self.max_active = 0
        self.log = log if log is not None else []
        self._lock = threading.Lock()

    def provision_root_vc(self):
        self.f1_calls += 1
        self.log.append(("f1",))
        if self.f1_fails:
            raise RuntimeError("F1 login failed")
        return {"jti": "jti-1", "credential": "aaa.bbb.ccc~disclosure", "digest": "d" * 64,
                "f1_ms": 5000.0, "f1_wire": 7000,
                "f1_step_ms": {"offer": 1.0}, "f1_step_wire": {"offer": 700, "start_auth": 300}}

    def authorize(self, model, workload, root_vc):
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.calls += 1
            position = self.calls
        try:
            self.log.append(("authorize", model, workload))
            if position in self.fail_on:
                raise RuntimeError("TPP token exchange failed with HTTP 500")
            latency = self.latency
            if self.warmup_latency is not None and position <= self.warmup_count:
                latency = self.warmup_latency
            return {"latency_ms": latency + position, "wire_bytes": self.wire,
                    "step_wire": {"a": self.wire // 2, "b": self.wire - self.wire // 2},
                    "access_token_issued": True, "transaction_id": f"tx-{position}"}
        finally:
            with self._lock:
                self.active -= 1

    warmup_count = 0


class MockArtifactSource(measure_artifacts.ArtifactSource):
    SECRET = "SECRET-TOKEN-MARKER"

    def __init__(self):
        self.collected: list[tuple] = []

    def provision_root_vc(self):
        return {"jti": "jti-1", "credential": f"h.p.s~{self.SECRET}", "digest": "d" * 64,
                "f1_ms": 1.0, "f1_wire": 900, "f1_step_ms": {}, "f1_step_wire": {"offer": 400, "callback": 500}}

    def collect(self, model, workload, sample, root_vc):
        self.collected.append((model, workload, sample))
        if model == "B0-C0":
            artifacts = [
                {"name": "access_token", "type": "application/jwt", "content": f"h.p.{self.SECRET}"},
                {"name": "par_request_object", "type": "application/jwt", "content": None, "reason": "NOT_OBSERVABLE"},
            ]
            steps = {"par": 100, "browser_authorization": 200, "token_exchange": 300}
        else:
            artifacts = [
                {"name": "scope_vc", "type": "application/sd-jwt", "content": root_vc["credential"]},
                {"name": "delegation_vc", "type": "application/sd-jwt", "content": "0c9bb1d2-jti-not-a-credential"},
                {"name": "pop_access_token", "type": "application/jwt", "content": f"h.p.{self.SECRET}"},
            ]
            steps = {"request_delegate": 10, "fetch_request": 20, "approve_delegate": 30, "token_exchange": 40}
        return {"artifacts": artifacts, "wire_steps": steps}


# ---------------------------------------------------------------------------
# Synthetic evidence for the analysis tests
# ---------------------------------------------------------------------------

def write_cost_run(evidence_root: Path, campaign: str, workload: str, model: str, batch: int, latencies,
                   purpose="final", failed=0, wire=1000, digests=None, protocol_id=COST_PROTOCOL_ID) -> Path:
    digests = {"source_digest": "src", "configuration_digest": "cfg", "protocol_digest": "prt",
               "fixture_digest": f"fx-{workload}", **(digests or {})}
    alias = {"B0-C0": "b0", "B1-C0": "b1", "B1-C2": "b2"}[model]
    run_id = f"{campaign}-{workload.lower()}-{alias}-b{batch:02d}"
    block = f"{campaign}-{workload.lower()}-pb{batch:02d}"
    directory = evidence_root / run_id
    directory.mkdir(parents=True)
    rows = []
    for index, latency in enumerate(latencies, start=1):
        rows.append({"protocol_id": protocol_id, "campaign_id": campaign, "run_id": run_id, "paired_block_id": block,
                     "batch": batch, "attempt": index, "configuration": model, "workload": workload,
                     "mode": "repeated_authorization", "transaction_id": f"t{index}", "outcome": "SUCCESS",
                     "latency_ms": latency, "access_token_issued": True, "authorization_wire_bytes": wire,
                     "step_wire_bytes": json.dumps({"a": wire // 2, "b": wire - wire // 2})})
    for index in range(failed):
        rows.append({"protocol_id": protocol_id, "campaign_id": campaign, "run_id": run_id, "paired_block_id": block,
                     "batch": batch, "attempt": len(latencies) + index + 1, "configuration": model,
                     "workload": workload, "mode": "repeated_authorization", "outcome": "FAILED",
                     "failure_stage": "token_exchange", "failure_reason": "HTTP 500", "access_token_issued": False})
    with (directory / "attempts.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=protocol.ATTEMPT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    manifest = {
        "protocol_id": protocol_id, "experiment_id": run_cost.EXPERIMENT_ID, "experiment_purpose": purpose,
        "campaign_id": campaign, "run_id": run_id, "paired_block_id": block, "batch": batch,
        "configuration": model, "workload": workload, "mode": "repeated_authorization", **digests,
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def write_artifact_run(evidence_root: Path, campaign: str, workload: str, model: str, rows, purpose="final",
                       digests=None) -> Path:
    digests = {"source_digest": "src", "configuration_digest": "cfg", "protocol_digest": "prt",
               "fixture_digest": f"fx-{workload}", **(digests or {})}
    run_id = f"{campaign}-artifacts-{workload.lower()}-{model.lower()}"
    directory = evidence_root / run_id
    directory.mkdir(parents=True)
    with (directory / "artifact-measurements.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=measure_artifacts.ARTIFACT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    with (directory / "network-measurements.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=measure_artifacts.NETWORK_COLUMNS)
        writer.writeheader()
    manifest = {"protocol_id": COST_PROTOCOL_ID, "experiment_id": measure_artifacts.EXPERIMENT_ID,
                "experiment_purpose": purpose, "campaign_id": campaign, "run_id": run_id, "configuration": model,
                "workload": workload, **digests}
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory
