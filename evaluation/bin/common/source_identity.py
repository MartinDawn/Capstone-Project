"""
Source identity calculation module for E-COST measurement pipeline.
Provides SHA-256 tree hashing over allowlisted source files and static fixtures.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
from typing import Any, Dict, Optional

ALLOWLIST_EXTENSIONS = {
    ".py", ".java", ".js", ".ts", ".json", ".sh", ".ps1", ".yml", ".yaml",
    ".properties", ".xml", ".conf", ".csv", ".jsonl", ".crt", ".pem"
}

ALLOWLIST_FILENAMES = {
    "pom.xml", "package.json", "package-lock.json", "Dockerfile"
}

EXPLICIT_ALLOWLIST_FIXTURES = {
    "traditional-fapi/resource-server/berka.db"
}

# Excluded only at these exact workspace-root-relative locations. None of these is evaluated source:
# evaluation/configs and evaluation/manifests are approval/protocol bookkeeping (every config file
# already gets its own configuration_digest via sha256_of_file at run time, benchmark-protocol.json
# has its own field-excluding protocol_digest(), pairing-plan.json and the workload fixtures are
# hashed individually into compute_frozen_digest); evaluation/state holds generated run state (the
# durability checkpoints, rewritten by every conformance execution's VD-N06 rollback/version cases).
# Hashing any of their raw bytes into source_digest meant that recording an approval or a run's own
# checkpoint churn - both necessarily edits inside one of these directories - changed source_digest
# itself, so no conformance run's recorded digest could ever match the tree state right after
# freezing it or running it: a genuine circular dependency, not a safeguard.
ROOTED_EXCLUDED_DIRS = {
    "evaluation/evidence", "evaluation/results", "evaluation/configs", "evaluation/manifests",
    "evaluation/state",
}

# Excluded wherever they occur, at any nesting depth: every Maven module has its own target/, every
# Node package its own node_modules/, and a nested .git would only ever be a submodule checkout.
EXCLUDED_DIR_NAMES = {"target", "node_modules", ".git"}


def _is_excluded_path(rel_path_posix: str) -> bool:
    for exc in ROOTED_EXCLUDED_DIRS:
        if rel_path_posix == exc or rel_path_posix.startswith(exc + "/"):
            return True
    return any(part in EXCLUDED_DIR_NAMES for part in rel_path_posix.split("/"))


def is_allowlisted_file(rel_path_posix: str, full_path: Path) -> bool:
    # Explicit fixture check
    if rel_path_posix in EXPLICIT_ALLOWLIST_FIXTURES:
        return True

    # Exclude directories
    if _is_excluded_path(rel_path_posix):
        return False

    # Exclude private key files
    if full_path.suffix.lower() == ".key":
        return False

    name = full_path.name
    if name in ALLOWLIST_FILENAMES:
        return True

    ext = full_path.suffix.lower()
    if ext in ALLOWLIST_EXTENSIONS:
        if ext in (".crt", ".pem"):
            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
                if "PRIVATE KEY" in content:
                    return False
            except Exception:
                return False
        return True

    return False


def calculate_source_tree_hash(workspace: Path) -> str:
    hasher = hashlib.sha256()
    matched_files = []

    for root, dirs, files in os.walk(workspace):
        rel_root = Path(root).relative_to(workspace).as_posix()
        if rel_root != ".":
            if _is_excluded_path(rel_root):
                dirs.clear()
                continue

        for file_name in files:
            full_path = Path(root) / file_name
            rel_path = full_path.relative_to(workspace).as_posix()
            if is_allowlisted_file(rel_path, full_path):
                matched_files.append((rel_path, full_path))

    matched_files.sort(key=lambda x: x[0])

    for rel_path, full_path in matched_files:
        try:
            content = full_path.read_bytes()
            hasher.update(rel_path.encode("utf-8") + b"\n" + content)
        except Exception:
            pass

    return hasher.hexdigest()


def _dirty_patch_digest(workspace: Path) -> Optional[str]:
    """Digest of every uncommitted change: staged and unstaged edits against HEAD plus untracked files.

    `git diff` alone misses staged changes and untracked files, so two different dirty trees could
    share a digest. Returns None when git cannot produce the diff.
    """
    res_diff = subprocess.run(
        ["git", "diff", "HEAD", "--binary"],
        cwd=workspace, capture_output=True, check=False
    )
    if res_diff.returncode != 0:
        return None
    hasher = hashlib.sha256()
    hasher.update(res_diff.stdout)
    res_untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=workspace, capture_output=True, check=False
    )
    if res_untracked.returncode != 0:
        return None
    for raw in sorted(p for p in res_untracked.stdout.split(b"\x00") if p):
        rel = raw.decode("utf-8", errors="replace")
        try:
            content = (workspace / rel).read_bytes()
        except OSError:
            content = b"<unreadable>"
        hasher.update(b"\nuntracked:" + rel.encode("utf-8") + b"\n" + hashlib.sha256(content).digest())
    return hasher.hexdigest()


def get_source_identity(workspace: Path) -> Dict[str, Any]:
    tree_hash = calculate_source_tree_hash(workspace)

    git_commit = None
    worktree_dirty = "unknown"
    dirty_patch_digest = None
    dirty_patch_reason = "git_head_unavailable"

    git_dir = workspace / ".git"
    if git_dir.exists():
        try:
            res_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=workspace, capture_output=True, text=True, check=False
            )
            if res_commit.returncode == 0 and res_commit.stdout.strip():
                git_commit = res_commit.stdout.strip()
                dirty_patch_reason = ""

                res_status = subprocess.run(
                    ["git", "status", "--porcelain"],
                    cwd=workspace, capture_output=True, text=True, check=False
                )
                if res_status.returncode == 0:
                    status_out = res_status.stdout.strip()
                    worktree_dirty = "true" if status_out else "false"
                    if status_out:
                        dirty_patch_digest = _dirty_patch_digest(workspace)
        except Exception:
            pass

    return {
        "git_commit": git_commit,
        "worktree_dirty": worktree_dirty,
        "source_digest": tree_hash,
        "dirty_patch_digest": dirty_patch_digest,
        "dirty_patch_reason": dirty_patch_reason
    }


# Directory of each evaluated implementation inside the evaluation repository.
SUT_DIRECTORIES = {
    "B0-C0": "traditional-fapi",
    "B1-C0": "wallet-vc-model-classical",
    "B1-C2": "wallet-vc-model",
}


def get_sut_commits(workspace: Path) -> Dict[str, Dict[str, Any]]:
    """Commit of each evaluated implementation, where it is separately accessible.

    The three implementations normally live in the evaluation repository, so they share its commit.
    A directory that is its own git repository (for example a submodule) reports its own HEAD.
    """
    result: Dict[str, Dict[str, Any]] = {}
    for model, directory in SUT_DIRECTORIES.items():
        path = workspace / directory
        entry: Dict[str, Any] = {"directory": directory, "commit": None, "scope": "unavailable"}
        if (path / ".git").exists():
            res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout.strip():
                entry.update({"commit": res.stdout.strip(), "scope": "own_repository"})
        elif path.exists():
            entry["scope"] = "evaluation_repository"
        result[model] = entry
    return result


def sha256_of_file(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def canonical_json_digest(value: Any) -> str:
    """SHA-256 of a JSON value serialized with sorted keys and no insignificant whitespace."""
    import json
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
