#!/usr/bin/env python3
"""Standalone BP-v3 E-CONF runner.

Runs the conformance suite only. It never touches E-COST or E-LOAD, and every
artefact it produces stays under evaluation/evidence/conformance/.

    python evaluation/bin/conformance/run_conformance.py \
        --config evaluation/configs/conformance-local.json \
        --purpose smoke --campaign-id smoke-conf-001 --execute
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_root_dir = Path(__file__).resolve().parents[3]
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from evaluation.bin.common.orchestrator import (  # noqa: E402
    MODEL_ALIASES,
    PROTOCOL_ID,
    Orchestrator,
    default_campaign_id,
    expand_command,
    load_config,
    validate_config,
)

FAMILY = "conformance"


class ConformanceRunner(Orchestrator):
    family = FAMILY

    def run_conformance(self, model: str) -> bool:
        run_id = f"{self.campaign_id}-conf-{MODEL_ALIASES[model]}"
        values = {"configuration": model, "run_id": run_id}
        conformance = self.config.get("conformance", {})
        command_template = conformance.get("command")
        command = expand_command(command_template, values) if command_template else [
            sys.executable, "evaluation/bin/conformance/conformance_v3.py",
            "--configuration", model,
            "--run-id", run_id,
        ]
        if model == "B1-C2" and conformance.get("include_quantum_for_b1_c2"):
            command.append("--include-quantum")
        exit_code = self.run_command(command, f"conformance-{MODEL_ALIASES[model]}", {0, 2})

        collect_template = conformance.get("collect_command")
        if collect_template:
            self.run_command(expand_command(collect_template, values), f"collect-{MODEL_ALIASES[model]}")

        blocking_findings = conformance.get("blocking_findings_by_model", {}).get(model, [])
        passed = exit_code == 0 and not blocking_findings
        blocked_reason = None
        if exit_code != 0:
            blocked_reason = "G3 conformance did not pass"
        elif blocking_findings:
            blocked_reason = "Unresolved critical findings: " + ", ".join(blocking_findings)
        self.dispositions.append(
            {
                "stage": "conformance",
                "configuration": model,
                "run_id": run_id,
                "status": "accepted" if passed else "blocked",
                "reason": blocked_reason,
            }
        )
        return passed

    def execute(self) -> None:
        self.initialize()
        for model in self.models:
            conf_run_id = f"{self.campaign_id}-conf-{MODEL_ALIASES[model]}"
            conf_dir = self.run_dir(conf_run_id)
            conf_done = (conf_dir / "cases.jsonl").exists() and (conf_dir / "manifest.json").exists()

            if self.resume and conf_done:
                print(f"[{model}] Conformance already completed ({conf_run_id}). Preserving evidence.")
                self.dispositions.append(
                    {
                        "stage": "conformance",
                        "configuration": model,
                        "run_id": conf_run_id,
                        "status": "accepted",
                        "reason": None,
                    }
                )
                continue

            try:
                if self.resume and self.services_ready(model):
                    print(f"[{model}] Services are already running and ready. Continuing...")
                else:
                    self.stop_all(f"pre-stop-{MODEL_ALIASES[model]}")
                    self.start_model(model)
                self.run_conformance(model)
            except Exception as exc:
                self.dispositions.append(
                    {
                        "stage": "lifecycle",
                        "configuration": model,
                        "run_id": None,
                        "status": "failed",
                        "reason": str(exc),
                    }
                )
            finally:
                try:
                    self.stop_all(f"post-stop-{MODEL_ALIASES[model]}")
                except Exception as exc:
                    self.dispositions.append(
                        {
                            "stage": "cleanup",
                            "configuration": model,
                            "run_id": None,
                            "status": "failed",
                            "reason": str(exc),
                        }
                    )
        self.write_handoff()


def build_schedule(models: list[str]) -> list[dict]:
    schedule: list[dict] = []
    for model in models:
        schedule.append({"configuration": model, "action": "stop_all"})
        schedule.append({"configuration": model, "action": "start"})
        schedule.append({"configuration": model, "action": "E-CONF"})
        schedule.append({"configuration": model, "action": "stop_all"})
    return schedule


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--purpose", required=True, choices=("smoke", "pilot", "final"))
    parser.add_argument("--campaign-id")
    parser.add_argument(
        "--models", nargs="+", choices=tuple(MODEL_ALIASES),
        help="Subset of configurations to run. Defaults to every model in the configuration.",
    )
    parser.add_argument("--resume", action="store_true")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    workspace = Path(__file__).resolve().parents[3]
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = workspace / config_path
    config, digest = load_config(config_path)
    errors = validate_config(config, args.purpose, FAMILY)
    if errors:
        for error in errors:
            print(f"CONFIGURATION_ERROR: {error}", file=sys.stderr)
        return 2

    models = args.models or config["models"]

    if args.dry_run:
        print(json.dumps(
            {
                "protocol_id": PROTOCOL_ID,
                "experiment_family": FAMILY,
                "evidence_root": f"evaluation/evidence/{FAMILY}",
                "config_digest": digest,
                "schedule": build_schedule(models),
            },
            indent=2,
        ))
        return 0

    campaign_id = args.campaign_id or default_campaign_id(FAMILY, args.purpose)
    runner = ConformanceRunner(
        workspace, config, config_path, digest, campaign_id, resume=args.resume, models=models
    )
    runner.execute()
    failed = any(item["status"] in {"failed", "blocked"} for item in runner.dispositions)
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
