#!/usr/bin/env python3
"""Shared orchestration base for the independent conformance and perf runners.

Each experiment family has its own entry point and its own evidence root:

    evaluation/evidence/conformance/
    evaluation/evidence/perf/

This module holds only what both share: configuration loading and validation,
Docker lifecycle control through manage.ps1 / manage.sh, logged subprocess execution,
and the immutable campaign handoff package.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shlex
import ssl
import subprocess
import sys
import time
import urllib.request

_root_dir = Path(__file__).resolve().parents[3]
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from evaluation.bin.common.constants import (  # noqa: E402
    BASELINE_ALIASES,
    EVIDENCE_FAMILIES,
    MODEL_ALIASES,
    PROTOCOL_ID,
    PROTOCOL_IDS_BY_FAMILY,
)
from evaluation.bin.common import fingerprint  # noqa: E402
from evaluation.bin.common.source_identity import get_source_identity  # noqa: E402

__all__ = [
    "PROTOCOL_ID",
    "MODEL_ALIASES",
    "BASELINE_ALIASES",
    "Orchestrator",
    "utc_now",
    "sha256_bytes",
    "sha256_file",
    "load_config",
    "validate_config",
    "expand_command",
    "display_command",
]


# Readiness endpoints are the HTTPS proxies, which use development certificates.
_READINESS_TLS = ssl._create_unverified_context()

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def load_config(path: Path) -> tuple[dict, str]:
    raw = Path(path).read_bytes()
    config = json.loads(raw.decode("utf-8"))
    return config, sha256_bytes(raw)


def validate_config(config: dict, purpose: str, family: str) -> list[str]:
    """Validate the fields the given experiment family actually reads.

    Both runners share the same configuration files. The perf runner keeps its tunables
    (offered rate, batches, durations) as constants at the top of run_perf.py, so only the
    common protocol, models, lifecycle, and approval fields are validated here.
    """
    if family not in EVIDENCE_FAMILIES:
        raise ValueError(f"Unknown evidence family: {family}")

    errors: list[str] = []
    expected_protocol = PROTOCOL_IDS_BY_FAMILY[family]
    if config.get("protocol_id") != expected_protocol:
        errors.append(f"protocol_id must be {expected_protocol}")
    if config.get("experiment_purpose") != purpose:
        errors.append("CLI purpose must match experiment_purpose in the configuration")
    models = config.get("models")
    if not isinstance(models, list) or set(models) != set(MODEL_ALIASES):
        errors.append("models must contain B0-C0, B1-C0, and B1-C2 exactly once")

    lifecycle = config.get("lifecycle", {})
    if not lifecycle.get("stop_all_commands") and not lifecycle.get("stop_all_command"):
        errors.append("lifecycle stop_all_commands is required")
    if not lifecycle.get("start_commands") and not lifecycle.get("start_command"):
        errors.append("lifecycle start_commands is required")

    if purpose == "final":
        approval = config.get("approval", {})
        if approval.get("state") != "frozen":
            errors.append("final execution requires approval.state=frozen")
        if not approval.get("decision_id") or not approval.get("frozen_digest"):
            errors.append("final execution requires a decision ID and frozen digest")

    return errors


def expand_command(template: list[str], values: dict[str, str]) -> list[str]:
    return [part.format(**values) for part in template]


def display_command(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


class Orchestrator:
    """Base class for a single-family campaign.

    Subclasses implement `run_family()` and set `family` to one of
    "conformance" or "perf". All evidence is confined to
    evaluation/evidence/<family>/.
    """

    family: str = ""

    def __init__(
        self,
        workspace: Path,
        config: dict,
        config_path: Path,
        config_digest: str,
        campaign_id: str,
        resume: bool = False,
        models: list[str] | None = None,
    ):
        if not self.family:
            raise ValueError("Orchestrator subclasses must set `family`")
        self.workspace = workspace
        self.config = config
        self.config_path = config_path
        self.config_digest = config_digest
        self.campaign_id = campaign_id
        self.resume = resume
        self.models = models or config["models"]
        self.evidence_root = workspace / "evaluation" / "evidence" / self.family
        self.campaign_dir = self.evidence_root / campaign_id
        self.log_dir = self.campaign_dir / "logs"
        self.effective_config_path = self.campaign_dir / "effective-config.json"
        self.commands: list[dict] = []
        self.dispositions: list[dict] = []
        self.notes: list[str] = []
        self.source_identity = get_source_identity(workspace)

    # -- evidence package -------------------------------------------------

    def run_dir(self, run_id: str) -> Path:
        return self.evidence_root / run_id

    def initialize(self) -> None:
        if self.campaign_dir.exists():
            if not self.resume:
                raise RuntimeError(f"Refusing to overwrite campaign: {self.campaign_dir}")
            if not self.effective_config_path.exists():
                self.effective_config_path.write_bytes(self.config_path.read_bytes())
            if not self.log_dir.exists():
                self.log_dir.mkdir(parents=True)
        else:
            self.log_dir.mkdir(parents=True)
            self.effective_config_path.write_bytes(self.config_path.read_bytes())

        if self.resume and self.log_dir.exists():
            for log_file in sorted(self.log_dir.glob("CMD-*.log")):
                parts = log_file.stem.split("-", 2)
                if len(parts) >= 2:
                    self.commands.append(
                        {
                            "command_id": f"{parts[0]}-{parts[1]}",
                            "campaign_id": self.campaign_id,
                            "working_directory": ".",
                            "command": f"Existing execution log: {log_file.name}",
                            "started_at": utc_now(),
                            "ended_at": utc_now(),
                            "exit_status": 0,
                            "log_path": log_file.relative_to(self.workspace).as_posix(),
                        }
                    )

    # -- command execution ------------------------------------------------

    def run_command(
        self, command: list[str], label: str, allowed_exit_codes: set[int] | None = None
    ) -> int:
        allowed = allowed_exit_codes or {0}
        command_id = f"CMD-{len(self.commands) + 1:04d}"
        log_path = self.log_dir / f"{command_id}-{label}.log"
        started = utc_now()
        with log_path.open("w", encoding="utf-8", newline="\n") as log:
            command_environment = os.environ.copy()
            command_environment.update(self.config.get("command_environment", {}))
            result = subprocess.run(
                command,
                cwd=self.workspace,
                env=command_environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
        self.commands.append(
            {
                "command_id": command_id,
                "campaign_id": self.campaign_id,
                "working_directory": ".",
                "command": display_command(command),
                "started_at": started,
                "ended_at": utc_now(),
                "exit_status": result.returncode,
                "log_path": log_path.relative_to(self.workspace).as_posix(),
            }
        )
        if result.returncode not in allowed:
            raise RuntimeError(f"Command {command_id} failed with exit status {result.returncode}")
        return result.returncode

    # -- Docker lifecycle -------------------------------------------------

    def stop_all(self, label: str) -> None:
        commands = self.config["lifecycle"].get("stop_all_commands")
        if commands is None:
            commands = [self.config["lifecycle"]["stop_all_command"]]
        for index, template in enumerate(commands, start=1):
            self.run_command(expand_command(template, {}), f"{label}-host{index}")

    def start_model(self, model: str) -> None:
        commands_by_model = self.config["lifecycle"].get("start_commands")
        templates = commands_by_model.get(model) if commands_by_model else None
        if templates is None:
            templates = [self.config["lifecycle"]["start_command"]]
        for index, template in enumerate(templates, start=1):
            command = expand_command(template, {"baseline": BASELINE_ALIASES[model]})
            self.run_command(command, f"start-{MODEL_ALIASES[model]}-role{index}")
        wait_seconds = int(self.config["lifecycle"].get("startup_wait_seconds", 0))
        if wait_seconds:
            time.sleep(wait_seconds)
        self.await_readiness(model)
        self.verify_environment(model)

    def verify_environment(self, model: str) -> None:
        """Compare what is actually running with the resource table; a mismatch stops the run.

        Enabled by `lifecycle.fingerprint_hosts`: [{"name": ..., "docker": [<prefix that runs docker>]}].
        Writes fingerprints/<model>.json into the campaign directory. It checks configuration only.
        """
        hosts = self.config["lifecycle"].get("fingerprint_hosts")
        if not hosts:
            self.notes.append(f"{model}: environment fingerprint skipped (no lifecycle.fingerprint_hosts)")
            return
        manifest = fingerprint.load_manifest()
        snapshots: dict = {}
        problems: list[str] = []
        for host in hosts:
            snapshot = fingerprint.collect_host(host["docker"])
            snapshots[host["name"]] = snapshot
            problems.extend(fingerprint.runtime_check(model, host["name"], snapshot, manifest))
        path = self.campaign_dir / "fingerprints" / f"{MODEL_ALIASES[model]}.json"
        fingerprint.write_fingerprint(path, model, snapshots, problems)
        if problems:
            raise RuntimeError(f"Environment fingerprint mismatch for {model} (see {path}): " + "; ".join(problems[:5]))
        print(f"[{model} Fingerprint] resource table and image digests match")

    def await_readiness(self, model: str) -> None:
        readiness_urls = self.config["lifecycle"].get("readiness_urls_by_model", {}).get(model, [])
        readiness_timeout = int(self.config["lifecycle"].get("readiness_timeout_seconds", 120))
        deadline = time.monotonic() + readiness_timeout
        pending = list(readiness_urls)
        last_log = 0.0
        while pending and time.monotonic() < deadline:
            next_pending = []
            for url in pending:
                try:
                    with urllib.request.urlopen(url, timeout=3, context=_READINESS_TLS) as response:
                        if response.status != 200:
                            next_pending.append(url)
                except Exception as exc:
                    if time.monotonic() - last_log > 10:
                        print(f"[{model} Readiness] Waiting for {url}... ({type(exc).__name__}: {exc})")
                        last_log = time.monotonic()
                    next_pending.append(url)
            pending = next_pending
            if pending:
                time.sleep(1)
        if pending:
            raise RuntimeError("Readiness timeout for: " + ", ".join(pending))
        print(f"[{model} Readiness] All endpoints READY!")

    def services_ready(self, model: str) -> bool:
        readiness_urls = self.config["lifecycle"].get("readiness_urls_by_model", {}).get(model, [])
        if not readiness_urls:
            return False
        try:
            for url in readiness_urls:
                with urllib.request.urlopen(url, timeout=3, context=_READINESS_TLS) as response:
                    if response.status != 200:
                        return False
            return True
        except Exception:
            return False

    # -- per-run sealing --------------------------------------------------

    def seal_run_dir(self, run_dir: Path) -> None:
        """Write checksums.txt covering every other file in an immutable run package."""
        lines = []
        for item in sorted(run_dir.iterdir(), key=lambda p: p.name):
            if item.is_file() and item.name != "checksums.txt":
                lines.append(f"{sha256_file(item)}  {item.name}")
        (run_dir / "checksums.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # -- handoff ----------------------------------------------------------

    def _relative_to_workspace(self, path: Path) -> str:
        try:
            return path.relative_to(self.workspace).as_posix()
        except ValueError:
            return path.as_posix()  # configuration kept outside the repository

    def write_handoff(self) -> None:
        try:
            source_id_info = get_source_identity(self.workspace)
        except Exception:
            source_id_info = {
                "git_commit": None,
                "worktree_dirty": "unknown",
                "source_digest": "unknown",
                "dirty_patch_digest": None,
                "dirty_patch_reason": "git_head_unavailable",
            }

        manifest = {
            "schema_version": "3.0.0",
            "protocol_id": PROTOCOL_IDS_BY_FAMILY[self.family],
            "experiment_family": self.family,
            "campaign_id": self.campaign_id,
            "experiment_purpose": self.config["experiment_purpose"],
            "configuration_path": self._relative_to_workspace(self.config_path),
            "configuration_digest": self.config_digest,
            "source_digest": source_id_info.get("source_digest"),
            "source_identity": source_id_info,
            "created_at": utc_now(),
            "notes": self.notes,
            "commands": self.commands,
            "dispositions": self.dispositions,
        }
        manifest_path = self.campaign_dir / "campaign-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        command_path = self.campaign_dir / "commands.jsonl"
        command_path.write_text(
            "".join(json.dumps(record, sort_keys=True) + "\n" for record in self.commands),
            encoding="utf-8",
        )

        handoff_path = self.campaign_dir / "handoff.md"
        lines = [
            f"# {self.family.upper()} campaign handoff: {self.campaign_id}",
            "",
            f"- Protocol: `{PROTOCOL_IDS_BY_FAMILY[self.family]}`",
            f"- Experiment family: `{self.family}`",
            f"- Purpose: `{self.config['experiment_purpose']}`",
            f"- Configuration digest: `{self.config_digest}`",
            f"- Evidence root: `{self._relative_to_workspace(self.evidence_root)}/`",
            f"- Final measurements: {'produced under the frozen approved configuration' if self.config['experiment_purpose'] == 'final' else 'not authorized by this ' + self.config['experiment_purpose'] + ' handoff'}",
            "",
        ]
        if self.notes:
            lines.extend(["## Notes", ""])
            lines.extend(f"- {note}" for note in self.notes)
            lines.append("")
        lines.extend(["## Dispositions", ""])
        for item in self.dispositions:
            status_str = item.get("status") or (
                f"{item.get('measurement_status', 'VALID')}/{item.get('run_outcome', 'COMPLETED')}"
            )
            lines.append(
                f"- {item.get('configuration', 'all')} / {item.get('stage', 'stage')}: {status_str}"
                + (f" — {item['reason']}" if item.get("reason") else "")
            )
        handoff_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        checked = [
            self.effective_config_path,
            manifest_path,
            command_path,
            handoff_path,
            *sorted(self.log_dir.glob("*.log")),
        ]
        if self.evidence_root.exists():
            for run_dir in sorted(self.evidence_root.iterdir(), key=lambda p: p.name):
                if run_dir.is_dir() and run_dir.name.startswith(self.campaign_id):
                    for f_item in sorted(run_dir.rglob("*"), key=lambda p: p.as_posix()):
                        if f_item.is_file():
                            checked.append(f_item)

        checksum_lines = []
        for path in checked:
            if path.name == "checksums.txt":
                continue
            try:
                rel = path.relative_to(self.campaign_dir).as_posix()
            except ValueError:
                rel = path.relative_to(self.workspace).as_posix()
            checksum_lines.append(f"{sha256_file(path)}  {rel}")
        checksum_lines.sort()
        (self.campaign_dir / "checksums.txt").write_text(
            "\n".join(checksum_lines) + "\n", encoding="utf-8"
        )


def default_campaign_id(family: str, purpose: str) -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{purpose}-{family}-{stamp}"
