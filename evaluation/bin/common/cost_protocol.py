"""Protocol contract for the sequential cost evaluation (BP-20260922-v6, docs/EVALUATION_PROTOCOL.md).

Holds everything that is a decision of the protocol rather than of one runner: the run profiles, how
the CLI, the configuration, and the profile combine, the deterministic paired model order, the frozen
digest, and the fail-closed guard that a final run must pass. It performs no I/O against services.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Optional

from evaluation.bin.common.constants import BASELINE_ALIASES, COST_PROTOCOL_ID, MODEL_ALIASES
from evaluation.bin.common.source_identity import canonical_json_digest, sha256_of_file

# Workload is no longer a comparison dimension (decision DEC-023, 2026-09-22): the evaluation uses one
# common workload, Medium, everywhere. The tuple stays a tuple (not a bare string) so resolve_settings'
# validation logic is unchanged; it just has one valid member now instead of three.
WORKLOADS = ("Medium",)
MODES = ("repeated_authorization",)
PURPOSES = ("smoke", "pilot", "final")

# Batches, measured attempts per batch, and warm-up attempts per batch (docs/EVALUATION_PROTOCOL.md section 3.1).
PROFILES = {
    "smoke": {"batches": 1, "attempts_per_batch": 2, "warmup_attempts": 1},
    "pilot": {"batches": 1, "attempts_per_batch": 5, "warmup_attempts": 2},
    "final": {"batches": 5, "attempts_per_batch": 10, "warmup_attempts": 2},
}

ATTEMPT_COLUMNS = [
    "protocol_id", "campaign_id", "run_id", "paired_block_id", "batch", "attempt",
    "configuration", "workload", "mode", "transaction_id", "start_timestamp", "end_timestamp",
    "latency_ms", "outcome", "failure_stage", "failure_reason", "access_token_issued",
    "authorization_wire_bytes", "step_wire_bytes", "source_digest", "configuration_digest", "fixture_digest",
]

# Names of the B1 steps as the source flow reports them, mapped to the protocol's step names.
B1_STEP_NAMES = {
    "request_delegate": "request_delegate",
    "fetch_request": "fetch_request",
    "approve_delegate": "approve_delegate",
    "token": "token_exchange",
}

OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_FAILED = "FAILED"

MANIFEST_DIR = Path("evaluation") / "manifests"
PROTOCOL_MANIFEST = MANIFEST_DIR / "benchmark-protocol.json"
PAIRING_PLAN = MANIFEST_DIR / "pairing-plan.json"

# Fields of the protocol manifest that record the approval itself and therefore cannot be part of
# the digest that the approval freezes.
_APPROVAL_FIELDS = ("state", "approved_by", "approved_at", "frozen_digest")


class ProtocolError(ValueError):
    """The requested run violates the protocol contract."""


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def resolve_settings(purpose: str, config: dict, cli: dict) -> dict:
    """Combines CLI values, the configuration `cost` block, and the built-in profile.

    Precedence is CLI, then configuration, then the profile of the purpose. Nothing needs editing in
    the source between campaigns. A final run refuses any override that changes the frozen values.
    """
    if purpose not in PROFILES:
        raise ProtocolError(f"purpose must be one of {PURPOSES}")
    section = config.get("cost", {}) or {}
    defaults = {
        "batches": PROFILES[purpose]["batches"],
        "attempts_per_batch": PROFILES[purpose]["attempts_per_batch"],
        "warmup_attempts": PROFILES[purpose]["warmup_attempts"],
        "workloads": list(WORKLOADS),
        "models": list(config.get("models") or MODEL_ALIASES),
    }
    from_config = {key: section[key] for key in defaults if section.get(key) is not None}
    settings = {**defaults, **from_config}

    overrides = {key: value for key, value in cli.items() if key in defaults and value is not None}
    if purpose == "final":
        changed = {key: value for key, value in overrides.items() if value != settings[key]}
        if changed:
            raise ProtocolError(
                "a final run must use the frozen configuration; refused command-line overrides: "
                + ", ".join(sorted(changed))
            )
    settings.update(overrides)

    for key in ("batches", "attempts_per_batch"):
        if not isinstance(settings[key], int) or isinstance(settings[key], bool) or settings[key] < 1:
            raise ProtocolError(f"{key} must be an integer of at least 1")
    if not isinstance(settings["warmup_attempts"], int) or isinstance(settings["warmup_attempts"], bool) \
            or settings["warmup_attempts"] < 0:
        raise ProtocolError("warmup_attempts must be an integer of at least 0")

    unknown_workloads = [w for w in settings["workloads"] if w not in WORKLOADS]
    if unknown_workloads or not settings["workloads"]:
        raise ProtocolError(f"workloads must be a non-empty subset of {WORKLOADS}; got {settings['workloads']}")
    unknown_models = [m for m in settings["models"] if m not in MODEL_ALIASES]
    if unknown_models or not settings["models"]:
        raise ProtocolError(f"models must be a non-empty subset of {tuple(MODEL_ALIASES)}; got {settings['models']}")
    if len(set(settings["workloads"])) != len(settings["workloads"]) or len(set(settings["models"])) != len(settings["models"]):
        raise ProtocolError("workloads and models must not repeat")
    settings["mode"] = MODES[0]
    return settings


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------

def load_pairing_plan(workspace: Path) -> dict:
    return json.loads((workspace / PAIRING_PLAN).read_text(encoding="utf-8"))


def model_order(pairing_plan: dict, workload: str, batch: int, models: list[str]) -> list[str]:
    """Deterministic model order of one paired block.

    The permutation rotates with the workload index and the 1-based batch number, so every comparator
    appears first, in the middle, and last across blocks. Only the selected models are kept, in the
    order the permutation gives them.
    """
    permutations = pairing_plan["model_order_permutations"]
    workload_index = WORKLOADS.index(workload)
    permutation = permutations[(workload_index + batch - 1) % len(permutations)]
    return [model for model in permutation if model in models]


def paired_block_id(campaign_id: str, workload: str, batch: int) -> str:
    return f"{campaign_id}-{workload.lower()}-pb{batch:02d}"


def run_id_for(campaign_id: str, workload: str, model: str, batch: int) -> str:
    return f"{campaign_id}-{workload.lower()}-{MODEL_ALIASES[model]}-b{batch:02d}"


def build_schedule(settings: dict, pairing_plan: dict, purpose: str) -> list[dict]:
    """Every measurement window in execution order. Used by the dry run and by the runner itself."""
    schedule: list[dict] = []
    for workload in settings["workloads"]:
        for batch in range(1, settings["batches"] + 1):
            for position, model in enumerate(model_order(pairing_plan, workload, batch, settings["models"]), start=1):
                steps = ["stop_all", "start"]
                if model != "B0-C0":
                    steps.append("provision_root_vc_f1 (measured separately)")
                steps += [
                    f"warmup x{settings['warmup_attempts']} (excluded)",
                    f"measured x{settings['attempts_per_batch']} (one active transaction)",
                    "stop_all",
                ]
                schedule.append({
                    "workload": workload, "batch": batch, "position_in_block": position, "configuration": model,
                    "baseline": BASELINE_ALIASES[model], "mode": settings["mode"], "purpose": purpose,
                    "steps": steps,
                })
    return schedule


# ---------------------------------------------------------------------------
# Identity and approval
# ---------------------------------------------------------------------------

def fixture_digest(workspace: Path, workload: str) -> Optional[str]:
    return sha256_of_file(workspace / "evaluation" / "fixtures" / "data" / f"workload_{workload.lower()}.json")


def protocol_digest(workspace: Path) -> Optional[str]:
    """Digest of the protocol manifest without the fields that record the approval."""
    path = workspace / PROTOCOL_MANIFEST
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return canonical_json_digest({k: v for k, v in manifest.items() if k not in _APPROVAL_FIELDS})


def compute_frozen_digest(workspace: Path, config: dict) -> str:
    """The digest that an approval freezes.

    Covers the protocol manifest, the configuration without its approval block, the pairing plan, and
    the workload fixtures. Changing any of them after the approval changes the digest.
    """
    body = {
        "protocol": protocol_digest(workspace),
        "configuration": canonical_json_digest({k: v for k, v in config.items() if k != "approval"}),
        "pairing_plan": sha256_of_file(workspace / PAIRING_PLAN),
        "fixtures": {w: fixture_digest(workspace, w) for w in WORKLOADS},
    }
    return canonical_json_digest(body)


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def validate_final_approval(workspace: Path, config: dict, identity: dict, models: list[str]) -> list[str]:
    """Reasons a final run must not start. An empty list means the run may proceed.

    A final run fails closed: it needs an approval frozen to the current inputs, an exact source
    identity, and passing conformance evidence for the exact evaluated source.
    """
    errors: list[str] = []
    approval = config.get("approval") or {}
    if config.get("protocol_id") != COST_PROTOCOL_ID:
        errors.append(f"protocol_id must be {COST_PROTOCOL_ID}")
    if approval.get("state") != "frozen":
        errors.append("final execution requires approval.state=frozen")
    if not approval.get("decision_id"):
        errors.append("final execution requires a decision ID (approval.decision_id)")
    frozen = approval.get("frozen_digest")
    if not frozen:
        errors.append("final execution requires approval.frozen_digest")
    elif frozen != compute_frozen_digest(workspace, config):
        errors.append("approval.frozen_digest does not match the current protocol, configuration, pairing plan, and fixtures")

    manifest = _read_json(workspace / PROTOCOL_MANIFEST) or {}
    if manifest.get("protocol_id") != COST_PROTOCOL_ID:
        errors.append(f"the protocol manifest must declare {COST_PROTOCOL_ID}")
    if manifest.get("state") != "frozen":
        errors.append("the protocol manifest must be in state frozen")
    elif manifest.get("frozen_digest") != frozen:
        errors.append("the protocol manifest frozen_digest differs from approval.frozen_digest")

    if not identity.get("git_commit"):
        errors.append("the evaluation repository commit is unavailable; commit the evaluated source first")
    dirty = identity.get("worktree_dirty")
    if dirty != "false":
        allowed = approval.get("allowed_dirty_patch_digest")
        if dirty != "true" or not identity.get("dirty_patch_digest"):
            errors.append("the worktree state is unknown, so the exact patch digest cannot be recorded")
        elif allowed != identity["dirty_patch_digest"]:
            errors.append("the worktree is dirty and its patch digest is not the approved one")

    conformance = approval.get("conformance_run_ids") or {}
    source_digest = identity.get("source_digest")
    for model in models:
        run_id = conformance.get(model)
        if not run_id:
            errors.append(f"approval.conformance_run_ids has no passing conformance run for {model}")
            continue
        recorded = _read_json(workspace / "evaluation" / "evidence" / "conformance" / run_id / "manifest.json")
        if not recorded:
            errors.append(f"conformance run {run_id} for {model} is not present in the evidence")
        elif recorded.get("configuration") != model or recorded.get("gate_disposition") != "pass" \
                or recorded.get("state") != "COMPLETE":
            errors.append(f"conformance run {run_id} is not a completed passing run of {model}")
        elif recorded.get("source_digest") != source_digest:
            errors.append(f"conformance run {run_id} was produced for a different source digest than the evaluated one")
    return errors


# ---------------------------------------------------------------------------
# Failure text
# ---------------------------------------------------------------------------

_LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-\.~+/=]{40,}")


def sanitize_reason(text: Any, limit: int = 240) -> str:
    """Failure text safe to store: long token-like strings are redacted and the length is bounded."""
    cleaned = _LONG_TOKEN.sub("<redacted>", str(text)).replace("\r", " ").replace("\n", " ")
    return cleaned[:limit]
