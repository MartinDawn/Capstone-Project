#!/usr/bin/env python3
"""Environment fairness checks: one resource table, one image per role, verified at start-up.

Two checks share the table in evaluation/manifests/resource-limits.json:

* static audit  - the compose files of the three baselines are compared with the table and with
                  each other (same limits per role, same runtime image where the roles are comparable);
* runtime check - after a baseline is started, `docker inspect` of every running container is compared
                  with the table. Limits, pinned image digests, OOM kills and restarts are recorded in
                  fingerprints/<model>.json and any mismatch stops the run.

It verifies configuration only. It does not sample CPU or memory usage.

Command line (static audit):
    python evaluation/bin/common/fingerprint.py --audit
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

_root_dir = Path(__file__).resolve().parents[3]
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

MANIFEST_PATH = _root_dir / "evaluation" / "manifests" / "resource-limits.json"

# Every compose file a baseline can be started from: the per-role files used on the VMs and,
# for B0, the single-host file used locally (the B1 single-host files only include the role files).
COMPOSE_FILES = {
    "B0-C0": ["traditional-fapi/docker-compose.bank.yml", "traditional-fapi/docker-compose.tpp.yml",
              "traditional-fapi/docker-compose.yml"],
    "B1-C0": ["wallet-vc-model-classical/bank/docker-compose.yml", "wallet-vc-model-classical/tpp/docker-compose.yml",
              "wallet-vc-model-classical/wallet/docker-compose.yml"],
    "B1-C2": ["wallet-vc-model/pqc-bank/docker-compose.yml", "wallet-vc-model/pqc-tpp/docker-compose.yml",
              "wallet-vc-model/pqc-wallet/docker-compose.yml"],
}
MIB = 1024 * 1024


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_memory_bytes(value) -> int:
    """Compose renders memory either as an integer of bytes or as text such as '1536M'."""
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().lower()
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmg]?)b?", text)
    if not match:
        raise ValueError(f"unrecognised memory value: {value!r}")
    factor = {"": 1, "k": 1024, "m": MIB, "g": 1024 * MIB}[match.group(2)]
    return int(float(match.group(1)) * factor)


def last_from(dockerfile: Path) -> str | None:
    """Base image of the final (runtime) stage of a Dockerfile."""
    last = None
    for line in dockerfile.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"\s*FROM\s+(\S+)", line, re.IGNORECASE)
        if match:
            last = match.group(1)
    return last


def compose_services(workspace: Path, compose_relative: str) -> dict[str, dict]:
    """Resolved services of one compose file (limits, image, runtime base image)."""
    compose = workspace / compose_relative
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose), "config", "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker compose config failed for {compose_relative}: {result.stderr.strip()[:300]}")
    services = {}
    for name, spec in json.loads(result.stdout).get("services", {}).items():
        limits = ((spec.get("deploy") or {}).get("resources") or {}).get("limits") or {}
        base = None
        build = spec.get("build")
        if build:
            context = Path(build["context"] if isinstance(build, dict) else build)
            dockerfile = context / (build.get("dockerfile", "Dockerfile") if isinstance(build, dict) else "Dockerfile")
            if dockerfile.exists():
                base = last_from(dockerfile)
        services[name] = {
            "image": spec.get("image"),
            "runtime_base": base,
            "cpus": float(spec.get("cpus") or limits.get("cpus") or 0),
            "memory_bytes": parse_memory_bytes(spec.get("mem_limit") or limits.get("memory")),
            "deploy_memory_bytes": parse_memory_bytes(limits.get("memory")),
            "deploy_cpus": float(limits.get("cpus") or 0),
        }
    return services


def static_audit(workspace: Path, manifest: dict) -> tuple[list[dict], list[str]]:
    """Compare every baseline's compose files with the table and with each other."""
    rows: list[dict] = []
    problems: list[str] = []
    by_role: dict[str, dict[str, dict]] = {}
    for model, files in COMPOSE_FILES.items():
        for compose_relative in files:
            for service, spec in compose_services(workspace, compose_relative).items():
                role = manifest["service_roles"].get(service)
                if role is None:
                    problems.append(f"{model}/{service}: service has no role in service_roles")
                    continue
                expected = manifest["roles"][role]
                rows.append({"model": model, "service": service, "role": role, **spec})
                by_role.setdefault(role, {})[model] = spec
                if abs(spec["cpus"] - expected["cpus"]) > 1e-9 or abs(spec["deploy_cpus"] - expected["cpus"]) > 1e-9:
                    problems.append(f"{model}/{service}: cpus {spec['cpus']}/{spec['deploy_cpus']} != {expected['cpus']}")
                want = expected["memory_mib"] * MIB
                if spec["memory_bytes"] != want or spec["deploy_memory_bytes"] != want:
                    problems.append(
                        f"{model}/{service}: memory {spec['memory_bytes'] // MIB}/{spec['deploy_memory_bytes'] // MIB} MiB "
                        f"!= {expected['memory_mib']} MiB")
                image = spec["image"]
                if image and "@sha256:" not in image:
                    problems.append(f"{model}/{service}: image {image} is not pinned by digest")
                if spec["runtime_base"] and "@sha256:" not in spec["runtime_base"]:
                    problems.append(f"{model}/{service}: runtime base {spec['runtime_base']} is not pinned by digest")
    for role, models in manifest.get("equal_across", {}).items():
        values = {}
        for model in models:
            spec = by_role.get(role, {}).get(model)
            if spec:
                values[model] = spec["image"] or spec["runtime_base"]
        if len(set(values.values())) > 1:
            problems.append(f"role {role} differs across baselines: {values}")
    return rows, problems


# -- runtime ---------------------------------------------------------------

def _docker(prefix: list[str], *args: str) -> str:
    result = subprocess.run([*prefix, *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join([*prefix, *args])[:120]} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def collect_host(prefix: list[str]) -> dict:
    """`docker inspect` of every running container plus basic host facts. `prefix` is e.g. ['docker'] or ['ssh', ..., 'docker']."""
    # `--format=json` needs no braces, which the local shell and ssh would otherwise rewrite.
    names = [json.loads(line)["Names"] for line in _docker(prefix, "ps", "--format=json").splitlines() if line.strip()]
    containers = []
    if names:
        for item in json.loads(_docker(prefix, "inspect", *names)):
            host_config = item["HostConfig"]
            labels = item["Config"].get("Labels") or {}
            containers.append({
                "name": item["Name"].lstrip("/"),
                "service": labels.get("com.docker.compose.service"),
                "image": item["Config"]["Image"],
                "image_id": item["Image"],
                "nano_cpus": host_config.get("NanoCpus", 0),
                "memory_bytes": host_config.get("Memory", 0),
                "memory_swap_bytes": host_config.get("MemorySwap", 0),
                "oom_killed": item["State"].get("OOMKilled", False),
                "restart_count": item.get("RestartCount", 0),
                "env": sorted(e.split("=", 1)[0] + "=" + e.split("=", 1)[1]
                              for e in (item["Config"].get("Env") or [])
                              if re.match(r"(JAVA_|JDK_JAVA_|NODE_OPTIONS|KC_LOG|SPRING_PROFILES)", e)),
            })
    info = json.loads(_docker(prefix, "info", "--format=json"))
    return {
        "containers": containers,
        "docker": {
            "server_version": info.get("ServerVersion"),
            "ncpu": info.get("NCPU"),
            "mem_total_bytes": info.get("MemTotal"),
            "cgroup_version": info.get("CgroupVersion"),
        },
    }


def runtime_check(model: str, host_name: str, snapshot: dict, manifest: dict) -> list[str]:
    problems: list[str] = []
    for container in snapshot["containers"]:
        service = container["service"]
        role = manifest["service_roles"].get(service)
        if role is None:
            continue  # not one of the baseline's services (for example another tool's container)
        expected = manifest["roles"][role]
        label = f"{model}@{host_name}/{container['name']}"
        if container["nano_cpus"] != round(expected["cpus"] * 1e9):
            problems.append(f"{label}: NanoCpus {container['nano_cpus']} != {round(expected['cpus'] * 1e9)}")
        if container["memory_bytes"] != expected["memory_mib"] * MIB:
            problems.append(f"{label}: memory {container['memory_bytes'] // MIB} MiB != {expected['memory_mib']} MiB")
        if container["oom_killed"]:
            problems.append(f"{label}: container was OOM-killed")
        if container["restart_count"]:
            problems.append(f"{label}: restarted {container['restart_count']} time(s)")
        if expected.get("pinned_image") and "@sha256:" not in container["image"]:
            problems.append(f"{label}: image {container['image']} is not pinned by digest")
    return problems


def write_fingerprint(path: Path, model: str, snapshots: dict, problems: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "model": model,
        "resource_table": str(MANIFEST_PATH.relative_to(_root_dir).as_posix()),
        "hosts": snapshots,
        "problems": problems,
        "status": "MATCH" if not problems else "MISMATCH",
    }, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Static fairness audit of the three baselines' compose files")
    parser.add_argument("--audit", action="store_true", required=True)
    parser.parse_args()
    manifest = load_manifest()
    rows, problems = static_audit(_root_dir, manifest)
    for row in rows:
        print(f"{row['model']:6s} {row['service']:22s} {row['role']:10s} cpus={row['cpus']:<4} "
              f"mem={row['memory_bytes'] // MIB:>5} MiB  image={row['image'] or ('build:' + str(row['runtime_base']))}")
    print()
    if problems:
        print(f"{len(problems)} problem(s):")
        for p in problems:
            print("  -", p)
        return 1
    print("Fairness audit passed: limits and images match the table and are equal across baselines where comparable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
