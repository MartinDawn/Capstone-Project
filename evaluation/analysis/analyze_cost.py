#!/usr/bin/env python3
"""Deterministic analysis of the sequential cost evidence (BP-20260921-v4, docs/EVALUATION_PROTOCOL.md section 5).

The analysis takes explicit campaign IDs and/or run IDs. It never picks the newest directory. It
validates that the selected runs are comparable, refuses to mix smoke or pilot evidence into a final
aggregate, keeps failed, unavailable, and inconclusive dispositions visible, and writes machine-readable
CSV/JSON plus LaTeX tables generated from the numbers, never typed by hand.

    python evaluation/analysis/analyze_cost.py --campaign-id final-cost-001 --analysis-id final-cost-001-a1
    python evaluation/analysis/analyze_cost.py --campaign-id smoke-cost-001 --analysis-id diag-001 --allow-diagnostic

Paired comparisons (A - B): architecture cost B1-C0 - B0-C0, hybrid migration cost B1-C2 - B1-C0, and total
observed change B1-C2 - B0-C0. The resampling unit is the paired block: each block contributes its per-model
median latency (or mean wire bytes), and blocks are drawn with replacement using the seed and replicate
count recorded in the protocol (20260921 and 10,000 by default).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Optional

_root_dir = Path(__file__).resolve().parents[2]
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from evaluation.bin.common import cost_stats  # noqa: E402
from evaluation.bin.common.constants import COST_PROTOCOL_ID, COST_SEED, MODEL_ALIASES  # noqa: E402
from evaluation.bin.common.cost_protocol import MODES, OUTCOME_SUCCESS  # noqa: E402
from evaluation.bin.common.orchestrator import utc_now  # noqa: E402
from evaluation.bin.perf.run_cost import EXPERIMENT_ID as COST_EXPERIMENT_ID  # noqa: E402
from evaluation.bin.artifacts.measure_artifacts import EXPERIMENT_ID as ARTIFACT_EXPERIMENT_ID  # noqa: E402

DEFAULT_COMPARISONS = [
    {"id": "architecture_cost", "minuend": "B1-C0", "subtrahend": "B0-C0"},
    {"id": "hybrid_migration_cost", "minuend": "B1-C2", "subtrahend": "B1-C0"},
    {"id": "total_observed_change", "minuend": "B1-C2", "subtrahend": "B0-C0"},
]
MIN_TAIL_SAMPLES = 100
MIN_TAIL_BLOCKS = 10
MIN_STABLE_BLOCKS = 5

LATENCY_COLUMNS = [
    "protocol_id", "analysis_id", "analysis_class", "configuration", "workload", "mode", "batches",
    "attempted", "succeeded", "failed", "failure_denominator", "failure_rate_pct",
    "median_ms", "mean_ms", "stdev_ms", "min_ms", "max_ms", "p95_ms", "p99_ms", "tail_label",
]
F1_COLUMNS = [
    "protocol_id", "analysis_id", "configuration", "workload", "batches", "succeeded", "failed",
    "median_latency_ms", "mean_latency_ms", "median_wire_bytes", "median_root_vc_bytes",
]
WIRE_COLUMNS = [
    "protocol_id", "analysis_id", "source", "configuration", "workload", "phase", "step", "samples",
    "median_bytes", "mean_bytes", "min_bytes", "max_bytes",
]
ARTIFACT_COLUMNS = [
    "protocol_id", "analysis_id", "configuration", "workload", "artifact_name", "artifact_type",
    "availability", "samples", "available_samples", "size_median_bytes", "size_min_bytes", "size_max_bytes",
    "missing_reason",
]
PAIRED_COLUMNS = [
    "protocol_id", "analysis_id", "comparison_id", "minuend", "subtrahend", "workload", "metric", "unit",
    "blocks_total", "blocks_valid", "excluded_blocks", "replicates", "seed", "confidence_level",
    "absolute_effect", "absolute_ci_low", "absolute_ci_high",
    "relative_effect", "relative_ci_low", "relative_ci_high", "stability", "disposition",
]


class AnalysisError(ValueError):
    """The selected evidence cannot be analysed as requested."""


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------

def read_csv_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _load_manifest(directory: Path) -> Optional[dict]:
    path = directory / "manifest.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def load_selected_runs(evidence_roots, campaign_ids: list[str], run_ids: list[str]) -> list[dict]:
    """Loads exactly the requested runs from the cost and artifact evidence roots.

    An unknown ID is an error, never a silent skip. `evidence_roots` is one path or a list of paths.
    """
    roots = [evidence_roots] if isinstance(evidence_roots, Path) else list(evidence_roots)
    if not campaign_ids and not run_ids:
        raise AnalysisError("select evidence explicitly with --campaign-id and/or --run-id; nothing is chosen implicitly")
    selected: dict[str, dict] = {}

    for campaign_id in campaign_ids:
        found = 0
        for root in roots:
            for manifest_path in sorted(root.glob(f"{campaign_id}-*/manifest.json")):
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if manifest.get("campaign_id") != campaign_id:
                    continue  # a longer campaign ID that merely starts with the requested one
                if manifest.get("experiment_id") in (COST_EXPERIMENT_ID, ARTIFACT_EXPERIMENT_ID):
                    selected[manifest["run_id"]] = {"manifest": manifest, "dir": manifest_path.parent}
                    found += 1
        if not found:
            raise AnalysisError(f"campaign {campaign_id} has no cost or artifact runs under "
                                + ", ".join(str(r) for r in roots))

    for run_id in run_ids:
        manifest, directory = None, None
        for root in roots:
            manifest = _load_manifest(root / run_id)
            if manifest is not None:
                directory = root / run_id
                break
        if manifest is None:
            raise AnalysisError(f"run {run_id} was not found under " + ", ".join(str(r) for r in roots))
        if manifest.get("experiment_id") not in (COST_EXPERIMENT_ID, ARTIFACT_EXPERIMENT_ID):
            raise AnalysisError(f"run {run_id} is not a cost or artifact run")
        selected[manifest["run_id"]] = {"manifest": manifest, "dir": directory}

    return [selected[key] for key in sorted(selected)]


def validate_selection(runs: list[dict], allow_diagnostic: bool) -> str:
    """Returns the analysis class, "final" or "diagnostic", or raises AnalysisError.

    Rejects protocol, source, configuration, fixture, or mode mismatches, and never lets smoke or pilot
    evidence enter a final aggregate.
    """
    if not runs:
        raise AnalysisError("no runs selected")
    problems: list[str] = []

    protocols = {r["manifest"].get("protocol_id") for r in runs}
    if protocols != {COST_PROTOCOL_ID}:
        problems.append(f"every run must be under {COST_PROTOCOL_ID}; found {sorted(map(str, protocols))}")

    purposes = {r["manifest"].get("experiment_purpose") for r in runs}
    if purposes == {"final"}:
        analysis_class = "final"
    elif "final" in purposes:
        raise AnalysisError("smoke or pilot evidence must not enter a final aggregate; "
                            f"the selection mixes purposes {sorted(map(str, purposes))}")
    elif purposes <= {"smoke", "pilot"}:
        if not allow_diagnostic:
            raise AnalysisError(f"the selection has {sorted(purposes)} evidence only; a final analysis refuses it. "
                                "Pass --allow-diagnostic for a diagnostic analysis")
        analysis_class = "diagnostic"
    else:
        raise AnalysisError(f"unknown experiment purposes: {sorted(map(str, purposes))}")

    for key, label in (("source_digest", "source digest"), ("configuration_digest", "configuration digest"),
                       ("protocol_digest", "protocol digest")):
        values = {r["manifest"].get(key) for r in runs}
        if len(values) > 1:
            problems.append(f"the runs were produced by different {label}s ({len(values)} distinct)")

    fixtures: dict[str, set] = {}
    for r in runs:
        fixtures.setdefault(r["manifest"].get("workload"), set()).add(r["manifest"].get("fixture_digest"))
    for workload, digests in fixtures.items():
        if len(digests) > 1:
            problems.append(f"workload {workload} has more than one fixture digest")

    modes = {r["manifest"].get("mode") for r in runs if r["manifest"].get("experiment_id") == COST_EXPERIMENT_ID}
    if modes and modes != {MODES[0]}:
        problems.append(f"only {MODES[0]} runs can be compared; found {sorted(map(str, modes))}")

    if problems:
        raise AnalysisError("; ".join(problems))
    return analysis_class


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _fmt(value):
    if value is None or value == "":
        return ""
    if isinstance(value, float):
        return repr(round(value, 6))
    return value


def cost_runs(runs: list[dict]) -> list[dict]:
    return [r for r in runs if r["manifest"].get("experiment_id") == COST_EXPERIMENT_ID]


def artifact_runs(runs: list[dict]) -> list[dict]:
    return [r for r in runs if r["manifest"].get("experiment_id") == ARTIFACT_EXPERIMENT_ID]


def _successful(attempts: list[dict]) -> list[dict]:
    return [a for a in attempts if a["outcome"] == OUTCOME_SUCCESS]


def group_attempts(runs: list[dict]) -> dict:
    """{(model, workload): {'attempts': [...], 'batches': set, 'f1': [...]}} from the selected cost runs."""
    grouped: dict[tuple, dict] = {}
    for run in cost_runs(runs):
        manifest, directory = run["manifest"], run["dir"]
        entry = grouped.setdefault((manifest["configuration"], manifest["workload"]),
                                   {"attempts": [], "batches": set(), "f1": []})
        entry["attempts"].extend(read_csv_rows(directory / "attempts.csv"))
        entry["batches"].add(manifest["batch"])
        entry["f1"].extend(read_csv_rows(directory / "f1.csv"))
    return grouped


def latency_summary(grouped: dict, analysis_id: str, analysis_class: str) -> list[dict]:
    rows = []
    for (model, workload), entry in sorted(grouped.items()):
        attempts = entry["attempts"]
        ok = _successful(attempts)
        stats = cost_stats.describe([float(a["latency_ms"]) for a in ok])
        failed = len(attempts) - len(ok)
        tail = "descriptive" if len(ok) < MIN_TAIL_SAMPLES or len(entry["batches"]) < MIN_TAIL_BLOCKS else "estimated"
        rows.append({
            "protocol_id": COST_PROTOCOL_ID, "analysis_id": analysis_id, "analysis_class": analysis_class,
            "configuration": model, "workload": workload, "mode": MODES[0], "batches": len(entry["batches"]),
            "attempted": len(attempts), "succeeded": len(ok), "failed": failed,
            "failure_denominator": len(attempts),
            "failure_rate_pct": round(100.0 * failed / len(attempts), 4) if attempts else None,
            "median_ms": stats["median"], "mean_ms": stats["mean"], "stdev_ms": stats["stdev"],
            "min_ms": stats["min"], "max_ms": stats["max"], "p95_ms": stats["p95"], "p99_ms": stats["p99"],
            "tail_label": tail,
        })
    return rows


def f1_summary(grouped: dict, analysis_id: str) -> list[dict]:
    rows = []
    for (model, workload), entry in sorted(grouped.items()):
        if not entry["f1"]:
            continue
        ok = [r for r in entry["f1"] if r["outcome"] == OUTCOME_SUCCESS]
        rows.append({
            "protocol_id": COST_PROTOCOL_ID, "analysis_id": analysis_id, "configuration": model,
            "workload": workload, "batches": len(entry["f1"]), "succeeded": len(ok),
            "failed": len(entry["f1"]) - len(ok),
            "median_latency_ms": cost_stats.percentile([float(r["latency_ms"]) for r in ok], 50),
            "mean_latency_ms": cost_stats.mean([float(r["latency_ms"]) for r in ok]),
            "median_wire_bytes": cost_stats.percentile([float(r["wire_bytes"]) for r in ok], 50),
            "median_root_vc_bytes": cost_stats.percentile([float(r["root_vc_bytes"]) for r in ok], 50),
        })
    return rows


def wire_summary(runs: list[dict], grouped: dict, analysis_id: str) -> list[dict]:
    """Per-step and total application-level wire bytes, from the attempts and from the artifact runs."""
    rows = []
    for (model, workload), entry in sorted(grouped.items()):
        ok = _successful(entry["attempts"])
        per_step: dict[str, list[float]] = {}
        for attempt in ok:
            if attempt.get("step_wire_bytes"):
                for step, value in json.loads(attempt["step_wire_bytes"]).items():
                    per_step.setdefault(step, []).append(float(value))
        per_step["total_authorization"] = [float(a["authorization_wire_bytes"]) for a in ok
                                           if a.get("authorization_wire_bytes") not in ("", None)]
        for step, values in per_step.items():
            rows.append(_wire_row(analysis_id, "cost_attempts", model, workload, "authorization", step, values))

    artifact_groups: dict[tuple, list[float]] = {}
    for run in artifact_runs(runs):
        for row in read_csv_rows(run["dir"] / "network-measurements.csv"):
            key = (row["model"], row["workload"], row["phase"], row["step"])
            artifact_groups.setdefault(key, []).append(float(row["wire_bytes"]))
    for (model, workload, phase, step), values in sorted(artifact_groups.items()):
        rows.append(_wire_row(analysis_id, "artifact_measurement", model, workload, phase, step, values))
    return rows


def _wire_row(analysis_id, source, model, workload, phase, step, values) -> dict:
    return {
        "protocol_id": COST_PROTOCOL_ID, "analysis_id": analysis_id, "source": source, "configuration": model,
        "workload": workload, "phase": phase, "step": step, "samples": len(values),
        "median_bytes": cost_stats.percentile(values, 50), "mean_bytes": cost_stats.mean(values),
        "min_bytes": min(values) if values else None, "max_bytes": max(values) if values else None,
    }


def artifact_summary(runs: list[dict], analysis_id: str) -> list[dict]:
    """Availability and sizes per artifact. An artifact that was ever unobservable stays visible as such."""
    groups: dict[tuple, list[dict]] = {}
    for run in artifact_runs(runs):
        for row in read_csv_rows(run["dir"] / "artifact-measurements.csv"):
            groups.setdefault((row["model"], row["workload"], row["artifact_name"], row["artifact_type"]), []).append(row)
    rows = []
    for (model, workload, name, kind), items in sorted(groups.items()):
        available = [r for r in items if r["availability"] == "AVAILABLE"]
        sizes = [float(r["size_bytes"]) for r in available]
        if len(available) == len(items):
            availability = "AVAILABLE"
        elif available:
            availability = "PARTIAL"
        else:
            availability = "UNAVAILABLE"
        reasons = sorted({r["missing_reason"] for r in items if r["missing_reason"]})
        rows.append({
            "protocol_id": COST_PROTOCOL_ID, "analysis_id": analysis_id, "configuration": model,
            "workload": workload, "artifact_name": name, "artifact_type": kind, "availability": availability,
            "samples": len(items), "available_samples": len(available),
            "size_median_bytes": cost_stats.percentile(sizes, 50),
            "size_min_bytes": min(sizes) if sizes else None, "size_max_bytes": max(sizes) if sizes else None,
            "missing_reason": ";".join(reasons),
        })
    return rows


# ---------------------------------------------------------------------------
# Paired comparisons
# ---------------------------------------------------------------------------

def block_values(runs: list[dict]) -> dict:
    """{(workload, paired_block_id): {model: {'latency': median_ms, 'wire': mean_bytes}}} over successful attempts."""
    blocks: dict[tuple, dict] = {}
    for run in cost_runs(runs):
        manifest = run["manifest"]
        ok = _successful(read_csv_rows(run["dir"] / "attempts.csv"))
        if not ok:
            blocks.setdefault((manifest["workload"], manifest["paired_block_id"]), {})[manifest["configuration"]] = None
            continue
        latency = cost_stats.percentile([float(a["latency_ms"]) for a in ok], 50)
        wire_values = [float(a["authorization_wire_bytes"]) for a in ok if a["authorization_wire_bytes"] != ""]
        blocks.setdefault((manifest["workload"], manifest["paired_block_id"]), {})[manifest["configuration"]] = {
            "latency": latency, "wire": cost_stats.mean(wire_values),
        }
    return blocks


def paired_comparisons(runs: list[dict], comparisons: list[dict], analysis_id: str, seed: int, replicates: int,
                       confidence: float) -> tuple[list[dict], list[str]]:
    blocks = block_values(runs)
    workloads = sorted({workload for workload, _ in blocks})
    rows: list[dict] = []
    warnings: list[str] = []
    metrics = (("latency", "latency_block_median", "ms"), ("wire", "wire_bytes_block_mean", "bytes"))

    for comparison in comparisons:
        minuend, subtrahend = comparison["minuend"], comparison["subtrahend"]
        for workload in workloads:
            block_ids = sorted(bid for (w, bid) in blocks if w == workload)
            valid, excluded = [], []
            for bid in block_ids:
                pair = blocks[(workload, bid)]
                a, b = pair.get(minuend), pair.get(subtrahend)
                if minuend not in pair or subtrahend not in pair:
                    excluded.append(f"{bid}:missing_model")
                elif a is None or b is None:
                    excluded.append(f"{bid}:no_successful_attempts")
                else:
                    valid.append(bid)
            for key, metric, unit in metrics:
                base = {
                    "protocol_id": COST_PROTOCOL_ID, "analysis_id": analysis_id, "comparison_id": comparison["id"],
                    "minuend": minuend, "subtrahend": subtrahend, "workload": workload, "metric": metric,
                    "unit": unit, "blocks_total": len(block_ids), "blocks_valid": len(valid),
                    "excluded_blocks": ";".join(excluded), "replicates": replicates, "seed": seed,
                    "confidence_level": confidence,
                }
                if not valid:
                    rows.append({**base, "stability": "not_computed", "disposition": "INCONCLUSIVE_NO_VALID_PAIRS"})
                    warnings.append(f"{comparison['id']} / {workload}: no valid paired block; the comparison is inconclusive")
                    continue
                result = cost_stats.paired_block_bootstrap(
                    [blocks[(workload, b)][minuend][key] for b in valid],
                    [blocks[(workload, b)][subtrahend][key] for b in valid],
                    seed=seed, replicates=replicates, confidence=confidence)
                stable = len(valid) >= MIN_STABLE_BLOCKS
                rows.append({
                    **base,
                    **{k: result[k] for k in ("absolute_effect", "absolute_ci_low", "absolute_ci_high",
                                              "relative_effect", "relative_ci_low", "relative_ci_high")},
                    "stability": "adequate" if stable else "insufficient_blocks",
                    "disposition": "COMPUTED" if not excluded else "COMPUTED_WITH_EXCLUDED_BLOCKS",
                })
                if key == "latency":
                    if not stable:
                        warnings.append(
                            f"{comparison['id']} / {workload}: {len(valid)} valid paired block(s), fewer than "
                            f"{MIN_STABLE_BLOCKS}; the interval is not stable")
                    if excluded:
                        warnings.append(f"{comparison['id']} / {workload}: excluded blocks {', '.join(excluded)}")
    return rows, warnings


# ---------------------------------------------------------------------------
# LaTeX
# ---------------------------------------------------------------------------

_LATEX_ESCAPES = {
    "\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_",
    "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
}


def latex_escape(value) -> str:
    return "".join(_LATEX_ESCAPES.get(ch, ch) for ch in str(value))


def _num(value, digits: int = 1) -> str:
    if value in (None, ""):
        return "--"
    return f"{float(value):,.{digits}f}".replace(",", "{,}")


def latex_table(caption: str, label: str, header: list[str], body: list[list[str]], note: str = "",
                text_columns: int = 2) -> str:
    columns = "l" * text_columns + "r" * (len(header) - text_columns)
    lines = [
        r"\begin{table}[htbp]", r"\centering", f"\\caption{{{latex_escape(caption)}}}", f"\\label{{{label}}}",
        f"\\begin{{tabular}}{{{columns}}}", r"\hline",
        " & ".join(latex_escape(h) for h in header) + r" \\", r"\hline",
    ]
    for row in body:
        lines.append(" & ".join(row) + r" \\")
    lines += [r"\hline", r"\end{tabular}"]
    if note:
        lines.append(f"\\par\\smallskip{{\\footnotesize {latex_escape(note)}}}")
    lines.append(r"\end{table}")
    return "\n".join(lines) + "\n"


def latency_table(rows: list[dict]) -> str:
    body = [[latex_escape(r["workload"]), latex_escape(r["configuration"]), f"{r['succeeded']}/{r['attempted']}",
             _num(r["median_ms"]), _num(r["mean_ms"]), _num(r["stdev_ms"]), _num(r["p95_ms"]), _num(r["p99_ms"])]
            for r in rows]
    return latex_table(
        "Sequential authorization latency (ms), successful attempts", "tab:evaluation-latency",
        ["Workload", "Configuration", "Succeeded/attempted", "Median", "Mean", "SD", "p95", "p99"], body,
        "p95 and p99 are descriptive when the sample or the number of independent blocks is small.", text_columns=3)


def artifact_table(rows: list[dict]) -> str:
    body = [[latex_escape(r["workload"]), latex_escape(r["configuration"]), latex_escape(r["artifact_name"]),
             latex_escape(r["availability"]), _num(r["size_median_bytes"], 0)] for r in rows]
    return latex_table("Serialized artifact sizes (bytes)", "tab:evaluation-artifacts",
                       ["Workload", "Configuration", "Artifact", "Availability", "Median size"], body,
                       "UNAVAILABLE artifacts are not observable at a client-facing boundary and are never estimated.",
                       text_columns=4)


def wire_table(rows: list[dict]) -> str:
    body = [[latex_escape(r["workload"]), latex_escape(r["configuration"]), latex_escape(f"{r['phase']}/{r['step']}"),
             _num(r["median_bytes"], 0), _num(r["mean_bytes"], 1)] for r in rows]
    return latex_table("Application-level authorization wire bytes", "tab:evaluation-wire-bytes",
                       ["Workload", "Configuration", "Step", "Median", "Mean"], body,
                       "Request plus response bytes per client-facing step; TLS record overhead and server-to-server "
                       "traffic are excluded.", text_columns=3)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _fmt(row.get(k)) for k in columns})


def limitations_text(analysis_class: str, runs: list[dict], latency_rows: list[dict], artifact_rows: list[dict],
                     warnings: list[str]) -> str:
    lines = ["# Limitations of this analysis", ""]
    if analysis_class == "diagnostic":
        lines += ["- **Diagnostic analysis.** The selected evidence is smoke or pilot evidence. It must not populate "
                  "final result tables.", ""]
    lines += [
        "## Scope",
        "- Sequential, single-active-transaction cost only. No load, saturation, maximum-throughput, production "
        "capacity, availability, or scalability claim follows from these numbers.",
        "- CPU, RAM, storage, packet-level bandwidth, and network capture were not measured.",
        "- Latency covers the first authorization request through access-token issuance. B1 F1 issuance is reported "
        "separately and is not part of any repeated-authorization latency.",
        "- Application-level wire bytes are the request plus the response bytes of each named client-facing step. "
        "TLS record overhead, retransmission, link-layer framing, and server-to-server traffic are excluded. "
        "Request and response bytes are not reported separately.",
        "- B0-C0 and the two B1 configurations use different identity providers and TPP implementations. The "
        "architecture-cost and total-change comparisons therefore include implementation differences as well as "
        "protocol differences. Only B1-C2 minus B1-C0 changes the cryptographic profile alone.",
        "- Latency depends on the network path between the client machine and the servers.",
        "",
        "## Statistics",
        "- Latency statistics use successful attempts only. The failure count and its denominator are shown beside "
        "every rate.",
        f"- p95 and p99 are labelled descriptive below {MIN_TAIL_SAMPLES} successful samples or {MIN_TAIL_BLOCKS} "
        "independent blocks.",
        f"- A paired-block interval is marked insufficient below {MIN_STABLE_BLOCKS} valid paired blocks. Intervals "
        "from few blocks are unstable even when computed.",
        "",
    ]
    failures = [r for r in latency_rows if r["failed"]]
    if failures:
        lines.append("## Failed attempts")
        lines += [f"- {r['configuration']} / {r['workload']}: {r['failed']} of {r['failure_denominator']} attempts failed"
                  for r in failures]
        lines.append("")
    unavailable = sorted({(r["configuration"], r["artifact_name"], r["missing_reason"]) for r in artifact_rows
                          if r["availability"] != "AVAILABLE"})
    if unavailable:
        lines.append("## Artifacts not fully observable")
        lines += [f"- {model}: {name} ({reason or 'partially observable'})" for model, name, reason in unavailable]
        lines.append("")
    if warnings:
        lines.append("## Warnings raised by this analysis")
        lines += [f"- {w}" for w in warnings]
        lines.append("")
    return "\n".join(lines)


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_protocol_analysis_settings(workspace: Path) -> dict:
    """Comparisons, seed, and replicate count from the protocol manifest, with the documented defaults."""
    try:
        manifest = json.loads((workspace / "evaluation" / "manifests" / "benchmark-protocol.json").read_text(encoding="utf-8"))
        section = manifest.get("analysis", {})
    except (OSError, ValueError):
        section = {}
    return {
        "comparisons": section.get("comparisons") or DEFAULT_COMPARISONS,
        "seed": int(section.get("bootstrap_seed", COST_SEED)),
        "replicates": int(section.get("bootstrap_replicates", cost_stats.DEFAULT_BOOTSTRAP_REPLICATES)),
        "confidence": float(section.get("confidence_level", cost_stats.DEFAULT_CONFIDENCE_LEVEL)),
    }


def run_analysis(workspace: Path, analysis_id: str, campaign_ids: list[str], run_ids: list[str],
                 allow_diagnostic: bool = False, evidence_root: Optional[Path] = None,
                 artifact_root: Optional[Path] = None, results_root: Optional[Path] = None) -> Path:
    evidence_root = evidence_root or workspace / "evaluation" / "evidence" / "cost"
    artifact_root = artifact_root or workspace / "evaluation" / "evidence" / "artifacts"
    results_root = results_root or workspace / "evaluation" / "results"
    out_dir = results_root / analysis_id
    if out_dir.exists():
        raise AnalysisError(f"refusing to overwrite an existing analysis: {out_dir}")

    runs = load_selected_runs([evidence_root, artifact_root], campaign_ids, run_ids)
    analysis_class = validate_selection(runs, allow_diagnostic)
    settings = load_protocol_analysis_settings(workspace)

    grouped = group_attempts(runs)
    latency_rows = latency_summary(grouped, analysis_id, analysis_class)
    f1_rows = f1_summary(grouped, analysis_id)
    wire_rows = wire_summary(runs, grouped, analysis_id)
    artifact_rows = artifact_summary(runs, analysis_id)
    paired_rows, warnings = paired_comparisons(
        runs, settings["comparisons"], analysis_id, settings["seed"], settings["replicates"], settings["confidence"])

    if analysis_class == "diagnostic":
        warnings.insert(0, "diagnostic analysis of smoke or pilot evidence; not eligible for final result tables")
    for row in latency_rows:
        if row["tail_label"] == "descriptive":
            warnings.append(f"{row['configuration']} / {row['workload']}: p95 and p99 are descriptive "
                            f"({row['succeeded']} successful samples over {row['batches']} block(s))")
        if row["failed"]:
            warnings.append(f"{row['configuration']} / {row['workload']}: {row['failed']} of "
                            f"{row['failure_denominator']} attempts failed and are counted, not replaced")
    for row in artifact_rows:
        if row["availability"] != "AVAILABLE":
            warnings.append(f"{row['configuration']} / {row['workload']}: artifact {row['artifact_name']} is "
                            f"{row['availability']} ({row['missing_reason'] or 'partial'})")

    out_dir.mkdir(parents=True)
    (out_dir / "tables").mkdir()
    write_csv(out_dir / "latency-summary.csv", LATENCY_COLUMNS, latency_rows)
    write_csv(out_dir / "f1-summary.csv", F1_COLUMNS, f1_rows)
    write_csv(out_dir / "wire-summary.csv", WIRE_COLUMNS, wire_rows)
    write_csv(out_dir / "artifact-summary.csv", ARTIFACT_COLUMNS, artifact_rows)
    write_csv(out_dir / "paired-comparisons.csv", PAIRED_COLUMNS, paired_rows)
    (out_dir / "tables" / "evaluation-latency.tex").write_text(latency_table(latency_rows), encoding="utf-8", newline="\n")
    (out_dir / "tables" / "evaluation-artifacts.tex").write_text(artifact_table(artifact_rows), encoding="utf-8", newline="\n")
    (out_dir / "tables" / "evaluation-wire-bytes.tex").write_text(
        wire_table([r for r in wire_rows if r["source"] == "cost_attempts"] or wire_rows), encoding="utf-8", newline="\n")
    (out_dir / "limitations.md").write_text(
        limitations_text(analysis_class, runs, latency_rows, artifact_rows, warnings), encoding="utf-8", newline="\n")

    manifest = {
        "schema_version": "1.0.0",
        "protocol_id": COST_PROTOCOL_ID,
        "analysis_id": analysis_id,
        "analysis_class": analysis_class,
        "created_at": utc_now(),
        "selection": {"campaign_ids": campaign_ids, "run_ids": run_ids},
        "inputs": [
            {"run_id": r["manifest"]["run_id"], "campaign_id": r["manifest"]["campaign_id"],
             "experiment_id": r["manifest"]["experiment_id"], "purpose": r["manifest"]["experiment_purpose"],
             "configuration": r["manifest"]["configuration"], "workload": r["manifest"]["workload"],
             "manifest_sha256": sha256_path(r["dir"] / "manifest.json")}
            for r in runs
        ],
        "digests": {
            "source_digest": sorted({r["manifest"].get("source_digest") for r in runs}),
            "configuration_digest": sorted({str(r["manifest"].get("configuration_digest")) for r in runs}),
            "protocol_digest": sorted({str(r["manifest"].get("protocol_digest")) for r in runs}),
        },
        "bootstrap": {"seed": settings["seed"], "replicates": settings["replicates"],
                      "confidence_level": settings["confidence"], "resampling_unit": "paired_block"},
        "comparisons": settings["comparisons"],
        "thresholds": {"min_tail_samples": MIN_TAIL_SAMPLES, "min_tail_blocks": MIN_TAIL_BLOCKS,
                       "min_stable_blocks": MIN_STABLE_BLOCKS},
        "warnings": warnings,
        "outputs": sorted(str(p.relative_to(out_dir).as_posix()) for p in out_dir.rglob("*") if p.is_file()),
    }
    (out_dir / "analysis-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")

    lines = []
    for path in sorted(out_dir.rglob("*"), key=lambda p: p.relative_to(out_dir).as_posix()):
        if path.is_file() and path.name != "checksums.txt":
            lines.append(f"{sha256_path(path)}  {path.relative_to(out_dir).as_posix()}")
    (out_dir / "checksums.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return out_dir


def main(argv: Optional[list[str]] = None, workspace: Path = _root_dir) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--campaign-id", nargs="+", default=[], help="explicit campaign IDs (every run of each)")
    parser.add_argument("--run-id", nargs="+", default=[], help="explicit run IDs")
    parser.add_argument("--analysis-id", required=True)
    parser.add_argument("--allow-diagnostic", action="store_true",
                        help="permit smoke or pilot evidence; the result is labelled diagnostic")
    args = parser.parse_args(argv)
    try:
        out_dir = run_analysis(workspace, args.analysis_id, args.campaign_id, args.run_id, args.allow_diagnostic)
    except AnalysisError as exc:
        print(f"ANALYSIS_REFUSED: {exc}", file=sys.stderr)
        return 2
    print(f"analysis written to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
