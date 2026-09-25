#!/usr/bin/env python3
"""Artifact-size and application-level wire-byte measurement (BP-20260922-v6, docs/EVALUATION_PROTOCOL.md section 4).

For every (workload, model) it runs the source-defined authorization and records:

  * the exact serialized size (UTF-8 bytes) and SHA-256 of every authorization artifact that is
    observable at a client-facing boundary, or an explicit UNAVAILABLE disposition with the reason;
  * the application-level authorization wire bytes of every named step and their total. A step's value
    is the request bytes plus the response bytes of that exchange, each counted once. Server-to-server
    traffic, TLS record overhead, retransmission, and link-layer framing are outside this metric.
  * for B1, the F1 issuance separately: the size of the Root/Scope VC and the wire bytes of each F1 step.

The Delegation VC is the credential itself. The Wallet's `approve-delegate` reply carries only its JTI,
so the credential is read from the Wallet's existing `GET /api/delegate-vcs/{requestId}` endpoint after
the measured flow, outside the wire-byte accounting. A JTI is never accepted as a credential size.

Manifests and CSV files hold sizes and digests only, never an artifact itself.

    python evaluation/bin/artifacts/measure_artifacts.py --config evaluation/configs/cost-local.json \
        --purpose smoke --dry-run
    python evaluation/bin/artifacts/measure_artifacts.py --config evaluation/configs/cost-vm.json \
        --purpose smoke --campaign-id smoke-artifacts-001 --execute
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Optional

_root_dir = Path(__file__).resolve().parents[3]
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from evaluation.bin.common import cost_protocol as protocol  # noqa: E402
from evaluation.bin.common import packet_capture  # noqa: E402
from evaluation.bin.common.constants import BASELINE_ALIASES, COST_PROTOCOL_ID, MODEL_ALIASES  # noqa: E402
from evaluation.bin.common.orchestrator import (  # noqa: E402
    Orchestrator,
    default_campaign_id,
    load_config,
    utc_now,
    validate_config,
)
from evaluation.bin.common.source_identity import get_sut_commits  # noqa: E402

FAMILY = "artifacts"
EXPERIMENT_ID = "EXP-COST-02"
SCHEMA_VERSION = "4.0.0"
NETWORK_LAYER = "ApplicationLevelAuthorizationWireBytes"

ARTIFACT_COLUMNS = [
    "run_id", "window_id", "model", "workload", "sample", "artifact_name", "artifact_type",
    "size_bytes", "sha256_digest", "availability", "missing_reason", "measurement_method", "timestamp",
]
NETWORK_COLUMNS = ["run_id", "model", "workload", "sample", "layer", "phase", "step", "wire_bytes", "timestamp"]

AVAILABLE = "AVAILABLE"
UNAVAILABLE = "UNAVAILABLE"

B1_STEP_NAMES = protocol.B1_STEP_NAMES


# ---------------------------------------------------------------------------
# Pure measurement helpers (unit tested without any service)
# ---------------------------------------------------------------------------

def _looks_like_jws(segment: str) -> bool:
    parts = segment.split(".")
    return len(parts) == 3 and all(part != "" for part in parts[:2])


def is_serialized_credential(artifact_type: str, content: str) -> bool:
    """True when `content` has the shape its type promises.

    A JWT has three dot-separated segments. An SD-JWT is a JWT followed by `~`-separated disclosures. A bare
    identifier such as a JTI has neither, so it can never pass as a credential.
    """
    if artifact_type == "application/jwt":
        return _looks_like_jws(content)
    if artifact_type == "application/sd-jwt":
        return _looks_like_jws(content.split("~", 1)[0])
    return True


def sd_jwt_components(sd_jwt: str) -> tuple:
    """Splits an SD-JWT into (issuer JWT, disclosures, trailing key-binding JWT or None).

    The key-binding JWT is the last `~` segment when it is itself a JWS. A presentation that ends in `~`
    has no key binding. The parts are read from the serialized text, never rebuilt.
    """
    parts = sd_jwt.split("~")
    issuer_jwt, rest = parts[0], parts[1:]
    key_binding = None
    if rest and rest[-1] != "" and _looks_like_jws(rest[-1]):
        key_binding, rest = rest[-1], rest[:-1]
    return issuer_jwt, [part for part in rest if part], key_binding


def measurement_row(run_id: str, window_id: str, model: str, workload: str, sample: int, name: str,
                    artifact_type: str, content, missing_reason: Optional[str] = None) -> dict:
    """One artifact-measurement row. Never estimates: an unobservable artifact is reported as UNAVAILABLE."""
    base = {
        "run_id": run_id, "window_id": window_id, "model": model, "workload": workload, "sample": sample,
        "artifact_name": name, "artifact_type": artifact_type, "timestamp": utc_now(),
    }
    if content is None or content == "":
        return {**base, "size_bytes": "", "sha256_digest": "", "availability": UNAVAILABLE,
                "missing_reason": missing_reason or "ARTIFACT_NOT_RETURNED", "measurement_method": "not_measured"}
    text = content if isinstance(content, str) else content.decode("utf-8")
    if not is_serialized_credential(artifact_type, text):
        return {**base, "size_bytes": "", "sha256_digest": "", "availability": UNAVAILABLE,
                "missing_reason": "VALUE_IS_AN_IDENTIFIER_NOT_A_SERIALIZED_CREDENTIAL",
                "measurement_method": "rejected_identifier"}
    raw = text.encode("utf-8")
    return {**base, "size_bytes": len(raw), "sha256_digest": hashlib.sha256(raw).hexdigest(),
            "availability": AVAILABLE, "missing_reason": "", "measurement_method": "utf8_serialized_bytes"}


def wire_rows(run_id: str, model: str, workload: str, sample: int, phase: str, steps: dict,
              total_name: str) -> list[dict]:
    """One row per named step plus one total row. The total is the plain sum, so no exchange is counted twice."""
    stamp = utc_now()
    rows = [{"run_id": run_id, "model": model, "workload": workload, "sample": sample, "layer": NETWORK_LAYER,
             "phase": phase, "step": name, "wire_bytes": int(value), "timestamp": stamp}
            for name, value in steps.items()]
    rows.append({"run_id": run_id, "model": model, "workload": workload, "sample": sample, "layer": NETWORK_LAYER,
                 "phase": phase, "step": total_name, "wire_bytes": sum(int(v) for v in steps.values()),
                 "timestamp": stamp})
    return rows


# ---------------------------------------------------------------------------
# Sources of observations
# ---------------------------------------------------------------------------

class ArtifactSource:
    """One sample: the artifacts and the wire steps of a single authorization. Tests replace it."""

    def collect(self, model: str, workload: str, sample: int, root_vc: Optional[dict]) -> dict:
        """Returns {'artifacts': [{'name','type','content','reason'}], 'wire_steps': {...}}."""
        raise NotImplementedError

    def provision_root_vc(self) -> dict:
        raise NotImplementedError


class LiveArtifactSource(ArtifactSource):
    def __init__(self, workspace: Path):
        from evaluation.bin.common import ais_flows
        self._flows = ais_flows
        self._base_dir = str(workspace)

    def provision_root_vc(self) -> dict:
        return self._flows.provision_root_vc()

    def collect(self, model: str, workload: str, sample: int, root_vc: Optional[dict]) -> dict:
        if model == "B0-C0":
            res = self._flows.run_b0_auth(self._base_dir, workload)
            return {
                "artifacts": [
                    {"name": "par_request_uri", "type": "text/uri-list", "content": res.get("request_uri")},
                    {"name": "par_request_object", "type": "application/jwt", "content": None,
                     "reason": "NOT_OBSERVABLE_AT_CLIENT_BOUNDARY_ONLY_THE_REQUEST_URI_IS_RETURNED"},
                    {"name": "authorization_code", "type": "text/plain", "content": res.get("auth_code")},
                    {"name": "access_token", "type": "application/jwt", "content": res.get("access_token")},
                ],
                "wire_steps": {"par": res["par_wire"], "browser_authorization": res["auth_wire"],
                               "token_exchange": res["token_wire"]},
            }

        if not root_vc:
            raise RuntimeError("a B1 sample needs the Root/Scope VC provisioned by F1")
        res = self._flows.run_vdam_auth(self._base_dir, workload, root_vc["jti"])
        hosts = self._flows.perf_hosts()
        # Read-only lookup after the measured flow; it is not part of the wire-byte accounting.
        held = self._flows.fetch_delegate_artifacts(hosts["wallet_url"], res["request_id"])
        delegation_vc = held.get("delegate_vc")
        _, _, key_binding_jwt = sd_jwt_components(delegation_vc) if delegation_vc else (None, [], None)
        return {
            "artifacts": [
                {"name": "scope_vc", "type": "application/sd-jwt", "content": root_vc["credential"]},
                {"name": "delegation_vc", "type": "application/sd-jwt", "content": delegation_vc,
                 "reason": "WALLET_DID_NOT_RETURN_THE_DELEGATION_VC"},
                # A component of the delegation VC (its trailing key-binding JWT). Its bytes are already
                # inside the delegation_vc size, so the two rows must never be added together.
                {"name": "delegation_vc_key_binding_jwt", "type": "application/jwt", "content": key_binding_jwt,
                 "reason": "DELEGATION_VC_HAS_NO_TRAILING_KEY_BINDING_JWT"},
                # The root VC as the Wallet presents it (selected disclosures only, no key binding). It is the
                # `authorization_vc` claim that the TPP later places inside its presentation, not that presentation.
                {"name": "root_vc_presentation", "type": "application/sd-jwt", "content": held.get("authorization_vc"),
                 "reason": "WALLET_DID_NOT_RETURN_THE_ROOT_PRESENTATION"},
                {"name": "das_encrypted_package", "type": "application/jose", "content": held.get("das_encrypted_package"),
                 "reason": "WALLET_DID_NOT_RETURN_THE_DAS_PACKAGE"},
                # The Verifiable Presentation itself: the JWT the TPP signs at F4 and posts to the Bank as the
                # `assertion` of the token request. It travels TPP to Bank and no client-facing endpoint returns it.
                {"name": "tpp_vp_assertion", "type": "application/jwt", "content": None,
                 "reason": "BUILT_BY_THE_TPP_AND_SENT_TO_THE_BANK_SERVER_TO_SERVER_NOT_RETURNED_TO_THE_CLIENT"},
                {"name": "pop_access_token", "type": "application/jwt", "content": res.get("access_token")},
            ],
            "wire_steps": {B1_STEP_NAMES[k]: v for k, v in res["step_wire"].items()},
        }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class ArtifactMeasurer(Orchestrator):
    family = FAMILY

    def __init__(self, workspace, config, config_path, config_digest, campaign_id, *, purpose: str, settings: dict,
                 source: ArtifactSource, capture_local_network: bool = False):
        super().__init__(workspace, config, config_path, config_digest, campaign_id, models=settings["models"])
        self.purpose = purpose
        self.settings = settings
        self.source = source
        self.capture_local_network = capture_local_network
        self.protocol_digest = protocol.protocol_digest(workspace)
        self.sut_commits = get_sut_commits(workspace)

    def measure(self, workload: str, model: str) -> dict:
        alias = MODEL_ALIASES[model]
        run_id = f"{self.campaign_id}-artifacts-{workload.lower()}-{alias}"
        window_id = f"{workload.lower()}-{alias}"
        run_dir = self.run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=False)
        fingerprint = self.campaign_dir / "fingerprints" / f"{alias}.json"
        if fingerprint.exists():
            shutil.copyfile(fingerprint, run_dir / "fingerprint.json")

        artifacts: list[dict] = []
        network: list[dict] = []
        f1_report: Optional[dict] = None
        root_vc: Optional[dict] = None

        if model != "B0-C0":
            root_vc = self.source.provision_root_vc()
            f1_report = {
                "root_vc_bytes": len(root_vc["credential"].encode("utf-8")),
                "wire_bytes": int(root_vc["f1_wire"]),
                "step_wire_bytes": {k: int(v) for k, v in (root_vc.get("f1_step_wire") or {}).items()},
            }

        raw_capture_report: Optional[dict] = None
        gateway_containers = packet_capture.LOCAL_GATEWAY_CONTAINERS.get(model)
        do_capture = self.capture_local_network and gateway_containers is not None
        active_capture = None
        capture_error = None
        if do_capture:
            try:
                active_capture = packet_capture.capture_pair(
                    gateway_containers["tpp"], gateway_containers["bank"],
                    run_dir / "pcap", label=f"{alias}-{workload.lower()}")
            except packet_capture.CaptureError as exc:
                capture_error = str(exc)

        try:
            for sample in range(1, self.settings["samples"] + 1):
                observed = self.source.collect(model, workload, sample, root_vc)
                for item in observed["artifacts"]:
                    artifacts.append(measurement_row(
                        run_id, window_id, model, workload, sample, item["name"], item["type"],
                        item.get("content"), item.get("reason")))
                network.extend(wire_rows(run_id, model, workload, sample, "authorization", observed["wire_steps"],
                                         "total_authorization"))
                if f1_report and f1_report["step_wire_bytes"]:
                    network.extend(wire_rows(run_id, model, workload, sample, "F1_issuance",
                                             f1_report["step_wire_bytes"], "total_f1"))
        finally:
            # The capture sidecar must never be left running, even when collect() raises.
            if active_capture is not None:
                try:
                    raw_capture_report = packet_capture.stop_pair(active_capture)
                except packet_capture.CaptureError as exc:
                    capture_error = str(exc)
            if do_capture and raw_capture_report is None:
                raw_capture_report = {"error": capture_error or "capture not started"}

        self.write_rows(run_dir / "artifact-measurements.csv", ARTIFACT_COLUMNS, artifacts)
        self.write_rows(run_dir / "network-measurements.csv", NETWORK_COLUMNS, network)

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "protocol_id": COST_PROTOCOL_ID,
            "experiment_id": EXPERIMENT_ID,
            "experiment_purpose": self.purpose,
            "campaign_id": self.campaign_id,
            "run_id": run_id,
            "configuration": model,
            "workload": workload,
            "samples": self.settings["samples"],
            "scope": "authorization_only",
            "network_boundary": (
                "application-level authorization wire bytes: request plus response bytes of each named "
                "client-facing step; server-to-server traffic, TLS record overhead, retransmission, and "
                "link-layer framing are excluded"
            ),
            "f1_reported_separately": f1_report is not None,
            "protocol_digest": self.protocol_digest,
            "configuration_digest": self.config_digest,
            "fixture_digest": protocol.fixture_digest(self.workspace, workload),
            "source_digest": self.source_identity.get("source_digest"),
            "source_identity": self.source_identity,
            "sut_commits": self.sut_commits,
            "environment": self.config.get("environment"),
            "created_at": utc_now(),
            "artifacts": summarize_artifacts(artifacts),
            "wire_bytes": summarize_wire(network),
            "f1": f1_report,
            "raw_packet_capture_local": raw_capture_report,
            "raw_packet_capture_boundary": (
                "LOCAL Docker only, diagnostic (never pooled with application-level wire bytes or with "
                "VM evidence): real captured bytes (TCP/IP + TLS ciphertext) on the TPP gateway and Bank "
                "gateway containers' own interface for this window, via a network-namespace-sharing "
                "tcpdump sidecar. No TLS decryption; payload content is never read or stored. See "
                "docs/EVALUATION_PROTOCOL.md section 4.3 and decision DEC-022."
            ) if do_capture else None,
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.seal_run_dir(run_dir)
        return manifest

    @staticmethod
    def write_rows(path: Path, columns: list[str], rows: list[dict]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

    def execute(self) -> None:
        self.initialize()
        os.environ.update(self.config.get("command_environment", {}))
        self.notes.append(
            f"purpose={self.purpose}; workloads={self.settings['workloads']}; models={self.settings['models']}; "
            f"samples={self.settings['samples']}; sizes and digests only, no artifact content is stored"
        )
        try:
            self.stop_all("initial-stop-all")
            for workload in self.settings["workloads"]:
                for model in self.settings["models"]:
                    label = f"{workload.lower()}-{MODEL_ALIASES[model]}"
                    try:
                        self.stop_all(f"pre-stop-{label}")
                        self.start_model(model)
                        manifest = self.measure(workload, model)
                        self.dispositions.append({
                            "stage": "artifacts", "configuration": model, "workload": workload,
                            "run_id": manifest["run_id"], "status": "executed", "reason": None,
                        })
                    except Exception as exc:
                        self.dispositions.append({
                            "stage": "artifacts", "configuration": model, "workload": workload, "run_id": None,
                            "status": "failed", "reason": f"{type(exc).__name__}: {protocol.sanitize_reason(exc)}",
                        })
                    finally:
                        try:
                            self.stop_all(f"post-stop-{label}")
                        except Exception as exc:
                            self.dispositions.append({
                                "stage": "cleanup", "configuration": model, "run_id": None, "status": "failed",
                                "reason": protocol.sanitize_reason(exc),
                            })
        finally:
            self.write_handoff()


def summarize_artifacts(rows: list[dict]) -> list[dict]:
    """Per artifact: availability and the observed sizes. No content and no digest of a reusable secret."""
    summary: dict[str, dict] = {}
    for row in rows:
        entry = summary.setdefault(row["artifact_name"], {
            "artifact_name": row["artifact_name"], "availability": row["availability"],
            "missing_reason": row["missing_reason"], "sizes_bytes": [],
        })
        if row["availability"] == AVAILABLE:
            entry["sizes_bytes"].append(row["size_bytes"])
        elif entry["availability"] == AVAILABLE and not entry["sizes_bytes"]:
            entry["availability"], entry["missing_reason"] = row["availability"], row["missing_reason"]
    return list(summary.values())


def summarize_wire(rows: list[dict]) -> dict:
    """Wire bytes by phase and step of the first sample (later samples are in the CSV)."""
    result: dict[str, dict] = {}
    for row in rows:
        if row["sample"] != 1:
            continue
        result.setdefault(row["phase"], {})[row["step"]] = row["wire_bytes"]
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def resolve_artifact_settings(purpose: str, config: dict, cli: dict) -> dict:
    """Workloads and models follow the cost rules; `samples` comes from the CLI, then config, then 1."""
    base = protocol.resolve_settings(purpose, config, {k: cli.get(k) for k in ("models", "workloads")})
    section = config.get("artifacts", {}) or {}
    samples = cli.get("samples") if cli.get("samples") is not None else section.get("samples", 1)
    if not isinstance(samples, int) or isinstance(samples, bool) or samples < 1:
        raise protocol.ProtocolError("samples must be an integer of at least 1")
    if purpose == "final" and cli.get("samples") is not None and cli["samples"] != section.get("samples", 1):
        raise protocol.ProtocolError("a final run must use the frozen configuration; refused override: samples")
    return {"workloads": base["workloads"], "models": base["models"], "samples": samples}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--purpose", required=True, choices=protocol.PURPOSES)
    parser.add_argument("--campaign-id")
    parser.add_argument("--models", nargs="+", choices=tuple(MODEL_ALIASES))
    parser.add_argument("--workloads", nargs="+", choices=protocol.WORKLOADS)
    parser.add_argument("--samples", type=int, help="authorizations per (workload, model); default 1")
    parser.add_argument("--capture-local-network", action="store_true",
                        help="LOCAL only: also raw-capture the TPP and Bank gateway containers' own "
                             "network interface for this window (docs/EVALUATION_PROTOCOL.md section 4.3, DEC-022). "
                             "Refused unless configuration.environment == 'local'.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    return parser


def main(argv: Optional[list[str]] = None, workspace: Path = _root_dir, source: Optional[ArtifactSource] = None) -> int:
    args = build_parser().parse_args(argv)
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = workspace / config_path
    config, digest = load_config(config_path)

    errors = validate_config(config, args.purpose, FAMILY)
    approval_errors = [e for e in errors if e.startswith("final execution requires")]
    config_errors = [e for e in errors if e not in approval_errors]
    if config_errors:
        for error in config_errors:
            print(f"CONFIGURATION_ERROR: {error}", file=sys.stderr)
        return 2
    try:
        settings = resolve_artifact_settings(args.purpose, config, {
            "models": args.models, "workloads": args.workloads, "samples": args.samples})
    except protocol.ProtocolError as exc:
        print(f"CONFIGURATION_ERROR: {exc}", file=sys.stderr)
        return 2

    if args.capture_local_network and config.get("environment") != "local":
        print("CONFIGURATION_ERROR: --capture-local-network requires configuration.environment == 'local'",
              file=sys.stderr)
        return 2

    if args.dry_run:
        blockers: list[str] = []
        if args.purpose == "final":
            from evaluation.bin.common.source_identity import get_source_identity
            blockers = sorted(set(approval_errors + protocol.validate_final_approval(
                workspace, config, get_source_identity(workspace), settings["models"])))
        print(json.dumps({
            "protocol_id": COST_PROTOCOL_ID, "experiment_id": EXPERIMENT_ID, "purpose": args.purpose,
            "evidence_root": f"evaluation/evidence/{FAMILY}", "config_digest": digest, "settings": settings,
            "final_execution_blockers": blockers,
            "schedule": [
                {"workload": w, "configuration": m, "baseline": BASELINE_ALIASES[m],
                 "steps": ["stop_all", "start"] + (["provision_root_vc_f1"] if m != "B0-C0" else [])
                          + [f"authorize x{settings['samples']}", "capture_artifacts", "stop_all"]}
                for w in settings["workloads"] for m in settings["models"]
            ],
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

    campaign_id = args.campaign_id or default_campaign_id("artifacts", args.purpose)
    measurer = ArtifactMeasurer(workspace, config, config_path, digest, campaign_id, purpose=args.purpose,
                                settings=settings, source=source or LiveArtifactSource(workspace),
                                capture_local_network=args.capture_local_network)
    measurer.execute()
    failed = any(item["status"] in {"failed", "blocked"} for item in measurer.dispositions)
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
