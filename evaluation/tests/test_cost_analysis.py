"""Tests of the explicit-run cost analysis on synthetic evidence with known values (BP-20260922-v6)."""

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cost_test_support import make_workspace, write_artifact_run, write_cost_run  # noqa: E402
from evaluation.analysis import analyze_cost as ac  # noqa: E402
from evaluation.bin.common import cost_stats  # noqa: E402


def read_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


class AnalysisCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workspace = make_workspace(Path(self._tmp.name))
        self.evidence = self.workspace / "evaluation" / "evidence" / "cost"
        self.evidence.mkdir(parents=True)
        self.artifact_evidence = self.workspace / "evaluation" / "evidence" / "artifacts"
        self.artifact_evidence.mkdir(parents=True)

    def analyse(self, analysis_id="a1", campaigns=("cmp",), runs=(), diagnostic=False):
        return ac.run_analysis(self.workspace, analysis_id, list(campaigns), list(runs), allow_diagnostic=diagnostic)

    def write_blocks(self, campaign="cmp", workload="Small", blocks=5, **kwargs):
        """Model latencies with known block medians: B0 = 100, B1-C0 = 160, B1-C2 = 200 (plus a per-block shift)."""
        for batch in range(1, blocks + 1):
            shift = batch  # the same shift in every model, so the paired differences are constant
            write_cost_run(self.evidence, campaign, workload, "B0-C0", batch, [100 + shift] * 3, **kwargs)
            write_cost_run(self.evidence, campaign, workload, "B1-C0", batch, [160 + shift] * 3, **kwargs)
            write_cost_run(self.evidence, campaign, workload, "B1-C2", batch, [200 + shift] * 3, **kwargs)


class TestSelection(AnalysisCase):

    def test_evidence_must_be_selected_explicitly(self):
        self.write_blocks()
        with self.assertRaises(ac.AnalysisError) as raised:
            ac.run_analysis(self.workspace, "a1", [], [])
        self.assertIn("explicitly", str(raised.exception))

    def test_an_unknown_campaign_or_run_is_an_error(self):
        self.write_blocks()
        with self.assertRaises(ac.AnalysisError):
            self.analyse(campaigns=("nope",))
        with self.assertRaises(ac.AnalysisError):
            self.analyse(campaigns=(), runs=("cmp-small-b0-b99",))

    def test_a_campaign_id_that_is_only_a_prefix_is_not_selected(self):
        self.write_blocks(campaign="cmp")
        self.write_blocks(campaign="cmp2", blocks=1)
        out_dir = self.analyse(campaigns=("cmp",))
        manifest = json.loads((out_dir / "analysis-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual({i["campaign_id"] for i in manifest["inputs"]}, {"cmp"})

    def test_explicit_run_ids_select_only_those_runs(self):
        self.write_blocks()
        out_dir = self.analyse(campaigns=(), runs=("cmp-small-b0-b01", "cmp-small-b1-b01"))
        manifest = json.loads((out_dir / "analysis-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(i["run_id"] for i in manifest["inputs"]), ["cmp-small-b0-b01", "cmp-small-b1-b01"])

    def test_mismatches_are_rejected(self):
        write_cost_run(self.evidence, "cmp", "Small", "B0-C0", 1, [1, 2], digests={"source_digest": "one"})
        write_cost_run(self.evidence, "cmp", "Small", "B1-C0", 1, [1, 2], digests={"source_digest": "two"})
        with self.assertRaises(ac.AnalysisError) as raised:
            self.analyse()
        self.assertIn("source digest", str(raised.exception))

    def test_configuration_protocol_and_fixture_mismatches_are_rejected(self):
        for key, expected in (("configuration_digest", "configuration digest"), ("protocol_digest", "protocol digest")):
            with self.subTest(key=key):
                inner = tempfile.TemporaryDirectory()
                self.addCleanup(inner.cleanup)
                evidence = Path(inner.name)
                write_cost_run(evidence, "cmp", "Small", "B0-C0", 1, [1], digests={key: "x"})
                write_cost_run(evidence, "cmp", "Small", "B1-C0", 1, [1], digests={key: "y"})
                runs = ac.load_selected_runs(evidence, ["cmp"], [])
                with self.assertRaises(ac.AnalysisError) as raised:
                    ac.validate_selection(runs, False)
                self.assertIn(expected, str(raised.exception))
        inner = tempfile.TemporaryDirectory()
        self.addCleanup(inner.cleanup)
        write_cost_run(Path(inner.name), "cmp", "Small", "B0-C0", 1, [1], digests={"fixture_digest": "fx-a"})
        write_cost_run(Path(inner.name), "cmp", "Small", "B1-C0", 1, [1], digests={"fixture_digest": "fx-b"})
        with self.assertRaises(ac.AnalysisError) as raised:
            ac.validate_selection(ac.load_selected_runs(Path(inner.name), ["cmp"], []), False)
        self.assertIn("fixture digest", str(raised.exception))

    def test_another_protocol_revision_is_rejected(self):
        write_cost_run(self.evidence, "cmp", "Small", "B0-C0", 1, [1], protocol_id="BP-20260915-v3")
        with self.assertRaises(ac.AnalysisError) as raised:
            self.analyse()
        self.assertIn("BP-20260922-v6", str(raised.exception))

    def test_smoke_and_pilot_are_excluded_from_final_aggregates(self):
        self.write_blocks(campaign="fin", blocks=1, purpose="final")
        self.write_blocks(campaign="smk", blocks=1, purpose="smoke")
        with self.assertRaises(ac.AnalysisError) as raised:
            self.analyse(campaigns=("fin", "smk"), diagnostic=True)  # even a diagnostic flag cannot mix them
        self.assertIn("must not enter a final aggregate", str(raised.exception))

    def test_smoke_only_needs_the_diagnostic_flag_and_is_labelled(self):
        self.write_blocks(campaign="smk", blocks=2, purpose="smoke")
        with self.assertRaises(ac.AnalysisError):
            self.analyse("a-refused", campaigns=("smk",))
        out_dir = self.analyse("a-diag", campaigns=("smk",), diagnostic=True)
        manifest = json.loads((out_dir / "analysis-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["analysis_class"], "diagnostic")
        self.assertIn("diagnostic", (out_dir / "limitations.md").read_text(encoding="utf-8").lower())
        self.assertEqual({r["analysis_class"] for r in read_rows(out_dir / "latency-summary.csv")}, {"diagnostic"})

    def test_final_evidence_is_analysed_as_final(self):
        self.write_blocks(blocks=2)
        manifest = json.loads((self.analyse() / "analysis-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["analysis_class"], "final")

    def test_output_directory_is_immutable(self):
        self.write_blocks(blocks=1)
        self.analyse("once")
        with self.assertRaises(ac.AnalysisError):
            self.analyse("once")


class TestStatistics(AnalysisCase):

    def test_descriptive_statistics_of_known_values(self):
        write_cost_run(self.evidence, "cmp", "Small", "B0-C0", 1, [10, 20, 30, 40, 50])
        row = read_rows(self.analyse() / "latency-summary.csv")[0]
        self.assertEqual((row["attempted"], row["succeeded"], row["failed"]), ("5", "5", "0"))
        self.assertEqual(float(row["median_ms"]), 30.0)
        self.assertEqual(float(row["mean_ms"]), 30.0)
        self.assertAlmostEqual(float(row["stdev_ms"]), 15.811388, places=5)
        self.assertEqual((float(row["min_ms"]), float(row["max_ms"])), (10.0, 50.0))
        self.assertAlmostEqual(float(row["p95_ms"]), 48.0)
        self.assertAlmostEqual(float(row["p99_ms"]), 49.6)

    def test_percentile_edge_cases(self):
        self.assertIsNone(cost_stats.percentile([], 50))
        self.assertEqual(cost_stats.percentile([7], 99), 7)
        self.assertIsNone(cost_stats.sample_stdev([7]))

    def test_failed_attempts_are_counted_and_kept_beside_the_statistics(self):
        write_cost_run(self.evidence, "cmp", "Small", "B0-C0", 1, [10, 20, 30], failed=2)
        row = read_rows(self.analyse() / "latency-summary.csv")[0]
        self.assertEqual((row["attempted"], row["succeeded"], row["failed"], row["failure_denominator"]), ("5", "3", "2", "5"))
        self.assertEqual(float(row["failure_rate_pct"]), 40.0)
        self.assertEqual(float(row["median_ms"]), 20.0)  # over the successful attempts only
        self.assertIn("2 of 5 attempts failed", (self.evidence.parent.parent / "results" / "a1" / "limitations.md")
                      .read_text(encoding="utf-8"))

    def test_tail_percentiles_are_labelled_descriptive_for_small_samples(self):
        write_cost_run(self.evidence, "cmp", "Small", "B0-C0", 1, list(range(1, 11)))
        out_dir = self.analyse()
        self.assertEqual(read_rows(out_dir / "latency-summary.csv")[0]["tail_label"], "descriptive")
        self.assertTrue(any("p95 and p99 are descriptive" in w for w in
                            json.loads((out_dir / "analysis-manifest.json").read_text(encoding="utf-8"))["warnings"]))

    def test_tail_percentiles_are_estimated_only_with_enough_samples_and_blocks(self):
        for batch in range(1, 11):
            write_cost_run(self.evidence, "cmp", "Small", "B0-C0", batch, list(range(1, 11)))
        self.assertEqual(read_rows(self.analyse() / "latency-summary.csv")[0]["tail_label"], "estimated")

    def test_wire_statistics_per_step_and_total(self):
        write_cost_run(self.evidence, "cmp", "Small", "B0-C0", 1, [1, 2, 3], wire=1001)
        wire = {r["step"]: r for r in read_rows(self.analyse() / "wire-summary.csv")}
        self.assertEqual(float(wire["total_authorization"]["median_bytes"]), 1001.0)
        self.assertEqual(float(wire["a"]["median_bytes"]) + float(wire["b"]["median_bytes"]), 1001.0)


class TestPairedComparisons(AnalysisCase):

    def comparison(self, out_dir, comparison_id, metric="latency_block_median", workload="Small"):
        return next(r for r in read_rows(out_dir / "paired-comparisons.csv")
                    if r["comparison_id"] == comparison_id and r["metric"] == metric and r["workload"] == workload)

    def test_absolute_and_relative_effects_of_known_blocks(self):
        self.write_blocks(blocks=5)
        out_dir = self.analyse()
        arch = self.comparison(out_dir, "architecture_cost")       # B1-C0 - B0-C0 = 60 in every block
        self.assertAlmostEqual(float(arch["absolute_effect"]), 60.0)
        self.assertAlmostEqual(float(arch["relative_effect"]), 60.0 / 103.0, places=6)  # mean B0 = 103
        migration = self.comparison(out_dir, "hybrid_migration_cost")  # B1-C2 - B1-C0 = 40
        self.assertAlmostEqual(float(migration["absolute_effect"]), 40.0)
        total = self.comparison(out_dir, "total_observed_change")   # B1-C2 - B0-C0 = 100
        self.assertAlmostEqual(float(total["absolute_effect"]), 100.0)
        self.assertEqual((arch["blocks_total"], arch["blocks_valid"]), ("5", "5"))
        self.assertEqual(arch["stability"], "adequate")

    def test_constant_differences_give_a_degenerate_interval(self):
        self.write_blocks(blocks=5)
        arch = self.comparison(self.analyse(), "architecture_cost")
        self.assertAlmostEqual(float(arch["absolute_ci_low"]), 60.0)
        self.assertAlmostEqual(float(arch["absolute_ci_high"]), 60.0)

    def test_bootstrap_matches_a_hand_computed_point_estimate(self):
        result = cost_stats.paired_block_bootstrap([10, 20, 30], [5, 10, 15], seed=1, replicates=200)
        self.assertEqual(result["absolute_effect"], 10.0)
        self.assertEqual(result["relative_effect"], 1.0)
        self.assertLessEqual(result["absolute_ci_low"], 10.0 + 1e-9)
        self.assertGreaterEqual(result["absolute_ci_high"], 10.0 - 1e-9)

    def test_bootstrap_is_deterministic_and_seed_dependent(self):
        a, b = [10, 40, 25, 31, 12], [5, 30, 20, 20, 9]
        first = cost_stats.paired_block_bootstrap(a, b, seed=20260921, replicates=2000)
        second = cost_stats.paired_block_bootstrap(a, b, seed=20260921, replicates=2000)
        other = cost_stats.paired_block_bootstrap(a, b, seed=7, replicates=2000)
        self.assertEqual(first, second)
        self.assertNotEqual((first["absolute_ci_low"], first["absolute_ci_high"]),
                           (other["absolute_ci_low"], other["absolute_ci_high"]))
        self.assertLess(first["absolute_ci_low"], first["absolute_effect"] + 1e-9)
        self.assertGreater(first["absolute_ci_high"], first["absolute_effect"] - 1e-9)

    def test_the_default_seed_and_replicates_come_from_the_protocol(self):
        self.write_blocks(blocks=2)
        manifest = json.loads((self.analyse() / "analysis-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["bootstrap"]["seed"], 20260921)
        self.assertEqual(manifest["bootstrap"]["replicates"], 10000)

    def test_two_analyses_of_the_same_evidence_are_byte_identical(self):
        for batch, (b0, b1) in enumerate(((100, 150), (110, 190), (95, 140), (130, 160), (101, 155)), start=1):
            write_cost_run(self.evidence, "cmp", "Small", "B0-C0", batch, [b0, b0 + 2])
            write_cost_run(self.evidence, "cmp", "Small", "B1-C0", batch, [b1, b1 + 3])
        first = self.analyse("first")
        second = self.analyse("second")
        for name in ("paired-comparisons.csv", "latency-summary.csv", "wire-summary.csv"):
            # the analysis ID is the only value that legitimately differs between the two directories
            normalise = lambda directory: [{k: v for k, v in r.items() if k != "analysis_id"}
                                           for r in read_rows(directory / name)]
            self.assertEqual(normalise(first), normalise(second), name)
        self.assertEqual((first / "tables" / "evaluation-latency.tex").read_bytes(),
                         (second / "tables" / "evaluation-latency.tex").read_bytes())

    def test_incomplete_pairs_are_excluded_and_reported(self):
        self.write_blocks(blocks=4)
        write_cost_run(self.evidence, "cmp", "Small", "B0-C0", 5, [100, 101])  # block 5 has no B1-C0
        out_dir = self.analyse()
        arch = self.comparison(out_dir, "architecture_cost")
        self.assertEqual((arch["blocks_total"], arch["blocks_valid"]), ("5", "4"))
        self.assertIn("cmp-small-pb05:missing_model", arch["excluded_blocks"])
        self.assertEqual(arch["disposition"], "COMPUTED_WITH_EXCLUDED_BLOCKS")

    def test_a_block_without_successes_is_excluded_not_averaged(self):
        self.write_blocks(blocks=3)
        write_cost_run(self.evidence, "cmp", "Small", "B0-C0", 4, [], failed=3)
        write_cost_run(self.evidence, "cmp", "Small", "B1-C0", 4, [150, 151])
        arch = self.comparison(self.analyse(), "architecture_cost")
        self.assertEqual((arch["blocks_total"], arch["blocks_valid"]), ("4", "3"))
        self.assertIn("no_successful_attempts", arch["excluded_blocks"])

    def test_no_valid_pair_is_inconclusive(self):
        write_cost_run(self.evidence, "cmp", "Small", "B0-C0", 1, [100])
        arch = self.comparison(self.analyse(), "architecture_cost")
        self.assertEqual(arch["disposition"], "INCONCLUSIVE_NO_VALID_PAIRS")
        self.assertEqual(arch["absolute_effect"], "")

    def test_a_small_number_of_blocks_raises_a_warning(self):
        self.write_blocks(blocks=2)
        out_dir = self.analyse()
        self.assertEqual(self.comparison(out_dir, "architecture_cost")["stability"], "insufficient_blocks")
        warnings = json.loads((out_dir / "analysis-manifest.json").read_text(encoding="utf-8"))["warnings"]
        self.assertTrue(any("fewer than 5" in w for w in warnings))
        self.assertIn("fewer than 5", (out_dir / "limitations.md").read_text(encoding="utf-8"))

    def test_each_workload_is_compared_separately(self):
        self.write_blocks(workload="Small", blocks=2)
        self.write_blocks(workload="Large", blocks=2)
        rows = read_rows(self.analyse() / "paired-comparisons.csv")
        self.assertEqual({r["workload"] for r in rows}, {"Small", "Large"})


class TestArtifactsAndUnavailable(AnalysisCase):

    def artifact_row(self, name, availability, size="", reason="", model="B1-C0"):
        return {"run_id": "r", "window_id": "w", "model": model, "workload": "Small", "sample": 1, "artifact_name": name,
                "artifact_type": "application/sd-jwt", "size_bytes": size, "sha256_digest": "", "availability": availability,
                "missing_reason": reason, "measurement_method": "m", "timestamp": "t"}

    def test_unavailable_artifacts_are_preserved(self):
        write_artifact_run(self.artifact_evidence, "cmp", "Small", "B1-C0", [
            self.artifact_row("scope_vc", "AVAILABLE", 900),
            self.artifact_row("delegation_vc", "UNAVAILABLE", "", "WALLET_DID_NOT_RETURN_THE_DELEGATION_VC"),
        ])
        out_dir = self.analyse()
        rows = {r["artifact_name"]: r for r in read_rows(out_dir / "artifact-summary.csv")}
        self.assertEqual(rows["delegation_vc"]["availability"], "UNAVAILABLE")
        self.assertEqual(rows["delegation_vc"]["size_median_bytes"], "")
        self.assertEqual(rows["scope_vc"]["size_median_bytes"], "900.0")
        limitations = (out_dir / "limitations.md").read_text(encoding="utf-8")
        self.assertIn("delegation_vc", limitations)
        self.assertIn("WALLET_DID_NOT_RETURN_THE_DELEGATION_VC", limitations)
        self.assertIn("UNAVAILABLE", (out_dir / "tables" / "evaluation-artifacts.tex").read_text(encoding="utf-8"))

    def test_partial_availability_is_not_reported_as_available(self):
        write_artifact_run(self.artifact_evidence, "cmp", "Small", "B1-C0", [
            self.artifact_row("delegation_vc", "AVAILABLE", 800),
            self.artifact_row("delegation_vc", "UNAVAILABLE", "", "NOT_RETURNED"),
        ])
        row = read_rows(self.analyse() / "artifact-summary.csv")[0]
        self.assertEqual(row["availability"], "PARTIAL")
        self.assertEqual((row["samples"], row["available_samples"]), ("2", "1"))

    def test_the_required_output_files_exist_even_without_artifact_runs(self):
        self.write_blocks(blocks=2)
        out_dir = self.analyse()
        for name in ("analysis-manifest.json", "latency-summary.csv", "wire-summary.csv", "artifact-summary.csv",
                     "paired-comparisons.csv", "tables/evaluation-latency.tex", "tables/evaluation-artifacts.tex",
                     "tables/evaluation-wire-bytes.tex", "limitations.md", "checksums.txt"):
            self.assertTrue((out_dir / name).exists(), name)


class TestLatexAndOutputs(AnalysisCase):

    def test_latex_escaping(self):
        self.assertEqual(ac.latex_escape("B1_C0 & 50% #1 $x {y} ~ ^"),
                         r"B1\_C0 \& 50\% \#1 \$x \{y\} \textasciitilde{} \textasciicircum{}")
        self.assertEqual(ac.latex_escape("a\\b"), r"a\textbackslash{}b")

    def test_generated_tables_are_valid_and_derived_from_the_data(self):
        write_cost_run(self.evidence, "cmp", "Small", "B0-C0", 1, [10, 20, 30, 40, 50])
        out_dir = self.analyse()
        table = (out_dir / "tables" / "evaluation-latency.tex").read_text(encoding="utf-8")
        self.assertIn(r"\begin{tabular}{lllrrrrr}", table)
        self.assertIn("B0-C0", table)
        self.assertIn("30.0", table)       # the median, computed
        self.assertIn(r"5/5", table)
        self.assertEqual(table.count(r"\begin{table}"), table.count(r"\end{table}"))
        self.assertEqual(table.count(r"\begin{tabular}"), table.count(r"\end{tabular}"))
        for text in ("Workload", "Configuration"):
            self.assertIn(text, table)
        for name in ("evaluation-artifacts.tex", "evaluation-wire-bytes.tex"):
            content = (out_dir / "tables" / name).read_text(encoding="utf-8")
            self.assertIn(r"\begin{tabular}", content)
            self.assertNotRegex(content.replace(r"\_", ""), r"(?<!\\)_")  # every underscore is escaped

    def test_checksums_validate_every_output(self):
        import hashlib
        self.write_blocks(blocks=2)
        out_dir = self.analyse()
        listed = {}
        for line in (out_dir / "checksums.txt").read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ", 1)
            listed[name] = digest
        files = {p.relative_to(out_dir).as_posix() for p in out_dir.rglob("*") if p.is_file() and p.name != "checksums.txt"}
        self.assertEqual(set(listed), files)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((out_dir / name).read_bytes()).hexdigest(), digest, name)

    def test_the_manifest_lists_inputs_and_digests(self):
        self.write_blocks(blocks=1)
        manifest = json.loads((self.analyse() / "analysis-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["inputs"]), 3)
        self.assertTrue(all(len(i["manifest_sha256"]) == 64 for i in manifest["inputs"]))
        self.assertEqual(manifest["digests"]["source_digest"], ["src"])
        self.assertEqual([c["id"] for c in manifest["comparisons"]],
                         ["architecture_cost", "hybrid_migration_cost", "total_observed_change"])

    def test_limitations_state_the_scope_and_the_excluded_measurements(self):
        self.write_blocks(blocks=1)
        text = (self.analyse() / "limitations.md").read_text(encoding="utf-8")
        for phrase in ("No load", "CPU, RAM, storage", "F1 issuance is reported", "Only B1-C2 minus B1-C0"):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
