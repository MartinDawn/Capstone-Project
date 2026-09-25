"""Unit and integration-style tests of the sequential cost runner (BP-20260922-v6). Fully offline."""

import contextlib
import csv
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cost_test_support import (  # noqa: E402
    MODELS, WORKLOADS, MockCostAdapter, make_workspace, patch_lifecycle, write_config,
)
from evaluation.analysis import analyze_cost  # noqa: E402
from evaluation.bin.common import cost_protocol as protocol  # noqa: E402
from evaluation.bin.common.constants import COST_PROTOCOL_ID  # noqa: E402
from evaluation.bin.perf import run_cost  # noqa: E402


def read_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def quiet_main(argv, workspace, adapter=None):
    """run_cost.main with stdout and stderr captured; returns (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = run_cost.main(argv, workspace=workspace, adapter=adapter)
    return code, out.getvalue(), err.getvalue()


class TestSettings(unittest.TestCase):

    def test_profile_defaults_are_exact(self):
        self.assertEqual(protocol.PROFILES["smoke"], {"batches": 1, "attempts_per_batch": 2, "warmup_attempts": 1})
        self.assertEqual(protocol.PROFILES["pilot"], {"batches": 1, "attempts_per_batch": 5, "warmup_attempts": 2})
        self.assertEqual(protocol.PROFILES["final"], {"batches": 5, "attempts_per_batch": 10, "warmup_attempts": 2})

    def test_defaults_come_from_the_profile(self):
        settings = protocol.resolve_settings("pilot", {"models": MODELS}, {})
        self.assertEqual((settings["batches"], settings["attempts_per_batch"], settings["warmup_attempts"]), (1, 5, 2))
        self.assertEqual(settings["workloads"], WORKLOADS)
        self.assertEqual(settings["models"], MODELS)

    def test_cli_overrides_config_and_config_overrides_profile(self):
        config = {"models": MODELS, "cost": {"batches": 3, "attempts_per_batch": 4, "workloads": ["Medium"]}}
        settings = protocol.resolve_settings("smoke", config, {"attempts_per_batch": 9, "batches": None})
        self.assertEqual(settings["batches"], 3)             # configuration beats the profile
        self.assertEqual(settings["attempts_per_batch"], 9)  # CLI beats the configuration
        self.assertEqual(settings["warmup_attempts"], 1)     # profile default
        self.assertEqual(settings["workloads"], ["Medium"])

    def test_supported_models_and_workloads_are_enforced(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.resolve_settings("smoke", {"models": MODELS}, {"workloads": ["Huge"]})
        with self.assertRaises(protocol.ProtocolError):
            protocol.resolve_settings("smoke", {"models": MODELS}, {"models": ["B9-C9"]})
        with self.assertRaises(protocol.ProtocolError):
            protocol.resolve_settings("smoke", {"models": MODELS}, {"batches": 0})
        with self.assertRaises(protocol.ProtocolError):
            protocol.resolve_settings("smoke", {"models": MODELS}, {"warmup_attempts": -1})
        for workload in WORKLOADS:
            protocol.resolve_settings("smoke", {"models": MODELS}, {"workloads": [workload]})

    def test_final_refuses_overrides_that_change_the_frozen_values(self):
        config = {"models": MODELS}
        with self.assertRaises(protocol.ProtocolError):
            protocol.resolve_settings("final", config, {"batches": 2})
        settings = protocol.resolve_settings("final", config, {"batches": 5})  # equal to the frozen value
        self.assertEqual(settings["batches"], 5)


class TestPairing(unittest.TestCase):

    def setUp(self):
        self.plan = json.loads((_ROOT / "evaluation" / "manifests" / "pairing-plan.json").read_text(encoding="utf-8"))

    def test_order_is_deterministic(self):
        first = [protocol.model_order(self.plan, w, b, MODELS) for w in WORKLOADS for b in range(1, 6)]
        second = [protocol.model_order(self.plan, w, b, MODELS) for w in WORKLOADS for b in range(1, 6)]
        self.assertEqual(first, second)

    def test_every_model_takes_every_position_across_blocks(self):
        seen = {model: set() for model in MODELS}
        for workload in WORKLOADS:
            for batch in range(1, 7):
                for position, model in enumerate(protocol.model_order(self.plan, workload, batch, MODELS)):
                    seen[model].add(position)
        for model in MODELS:
            self.assertEqual(seen[model], {0, 1, 2}, model)

    def test_subset_keeps_the_permutation_order(self):
        full = protocol.model_order(self.plan, "Medium", 2, MODELS)
        subset = protocol.model_order(self.plan, "Medium", 2, ["B1-C2", "B0-C0"])
        self.assertEqual(subset, [m for m in full if m in {"B1-C2", "B0-C0"}])

    def test_dry_run_schedule_describes_every_final_cell(self):
        settings = protocol.resolve_settings("final", {"models": MODELS}, {})
        schedule = protocol.build_schedule(settings, self.plan, "final")
        self.assertEqual(len(schedule), 1 * 5 * 3)  # workloads (Medium only) x batches x models
        self.assertEqual(len({(s["workload"], s["batch"], s["configuration"]) for s in schedule}), len(schedule))
        b1 = next(s for s in schedule if s["configuration"] == "B1-C0")
        self.assertTrue(any("provision_root_vc_f1" in step for step in b1["steps"]))
        b0 = next(s for s in schedule if s["configuration"] == "B0-C0")
        self.assertFalse(any("provision_root_vc_f1" in step for step in b0["steps"]))


def build_runner(workspace, adapter, purpose="smoke", campaign="cmp-001", settings_override=None, log=None):
    config_path = write_config(workspace, purpose) if not (workspace / "evaluation" / "configs" / f"cost-{purpose}.json").exists() \
        else workspace / "evaluation" / "configs" / f"cost-{purpose}.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    settings = protocol.resolve_settings(purpose, config, settings_override or {})
    plan = protocol.load_pairing_plan(workspace)
    return run_cost.CostRunner(workspace, config, config_path, "cfgdigest", campaign, purpose=purpose,
                               settings=settings, adapter=adapter, pairing_plan=plan)


class TestRunner(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workspace = make_workspace(Path(self._tmp.name))
        self.log: list = []

    def run_campaign(self, adapter, **kwargs):
        runner = build_runner(self.workspace, adapter, **kwargs)
        with patch_lifecycle(run_cost.CostRunner, self.log):
            runner.execute()
        return runner

    def runs(self, campaign="cmp-001"):
        return sorted((self.workspace / "evaluation" / "evidence" / "cost").glob(f"{campaign}-*"))

    def test_exactly_one_active_transaction(self):
        adapter = MockCostAdapter()
        self.run_campaign(adapter, settings_override={"workloads": ["Medium"]})
        self.assertGreater(adapter.calls, 0)
        self.assertEqual(adapter.max_active, 1)

    def test_a_second_concurrent_transaction_is_refused(self):
        runner = build_runner(self.workspace, MockCostAdapter())

        class Reentrant(MockCostAdapter):
            def authorize(inner, model, workload, root_vc):
                runner.run_attempt(model, workload, root_vc)  # would be a second active transaction
                return super().authorize(model, workload, root_vc)

        runner.adapter = Reentrant()
        outer = runner.run_attempt("B0-C0", "Medium", None)
        self.assertEqual(outer["outcome"], "FAILED")
        self.assertIn("second transaction", outer["failure_reason"])
        # the guard is released afterwards, so the next transaction can run
        runner.adapter = MockCostAdapter()
        self.assertEqual(runner.run_attempt("B0-C0", "Medium", None)["outcome"], "SUCCESS")

    def test_warmup_attempts_are_excluded_from_metrics(self):
        adapter = MockCostAdapter(latency=100.0, warmup_latency=99999.0)
        adapter.warmup_count = 2  # the first two calls of the first window are warm-ups
        self.run_campaign(adapter, settings_override={"workloads": ["Medium"], "models": ["B0-C0"],
                                                     "warmup_attempts": 2, "attempts_per_batch": 3})
        run_dir = self.runs()[0]
        measured = read_rows(run_dir / "attempts.csv")
        warmups = read_rows(run_dir / "warmup-attempts.csv")
        self.assertEqual((len(measured), len(warmups)), (3, 2))
        self.assertTrue(all(float(r["latency_ms"]) > 99999 for r in warmups))
        self.assertTrue(all(float(r["latency_ms"]) < 200 for r in measured))
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["metrics"]["attempted"], 3)
        self.assertLess(manifest["metrics"]["max_ms"], 200)

    def test_failed_attempts_are_recorded_and_never_replaced(self):
        adapter = MockCostAdapter(fail_on={3})
        self.run_campaign(adapter, settings_override={"workloads": ["Medium"], "models": ["B0-C0"],
                                                     "warmup_attempts": 1, "attempts_per_batch": 4})
        rows = read_rows(self.runs()[0] / "attempts.csv")
        self.assertEqual(len(rows), 4)
        self.assertEqual(adapter.calls, 1 + 4)  # one warm-up plus four measured: no retry
        failed = [r for r in rows if r["outcome"] == "FAILED"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["access_token_issued"], "False")
        self.assertEqual(failed[0]["latency_ms"], "")
        self.assertTrue(failed[0]["failure_stage"])
        manifest = json.loads((self.runs()[0] / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual((manifest["metrics"]["attempted"], manifest["metrics"]["succeeded"], manifest["metrics"]["failed"]),
                         (4, 3, 1))
        self.assertEqual(manifest["status"], "DEGRADED")

    def test_a_flow_that_returns_no_token_is_a_failure(self):
        class NoToken(MockCostAdapter):
            def authorize(self, model, workload, root_vc):
                result = super().authorize(model, workload, root_vc)
                result["access_token_issued"] = False
                return result

        record = build_runner(self.workspace, NoToken()).run_attempt("B0-C0", "Medium", None)
        self.assertEqual(record["outcome"], "FAILED")
        self.assertEqual(record["failure_stage"], "token_issuance")

    def test_failure_text_never_stores_a_token(self):
        class Leaky(MockCostAdapter):
            def authorize(self, model, workload, root_vc):
                raise RuntimeError("token exchange failed: " + "eyJ" + "A" * 200)

        record = build_runner(self.workspace, Leaky()).run_attempt("B0-C0", "Medium", None)
        self.assertNotIn("AAAAAAAAAA", record["failure_reason"])
        self.assertIn("<redacted>", record["failure_reason"])

    def test_counts_and_denominators(self):
        rows = [{"outcome": "SUCCESS", "latency_ms": str(v), "authorization_wire_bytes": "100"} for v in (10, 20, 30, 40, 50)]
        rows.append({"outcome": "FAILED", "latency_ms": "", "authorization_wire_bytes": ""})
        summary = run_cost.summarize_attempts(rows)
        self.assertEqual((summary["attempted"], summary["succeeded"], summary["failed"]), (6, 5, 1))
        self.assertEqual(summary["failure_denominator"], 6)
        self.assertAlmostEqual(summary["failure_rate_pct"], 100 / 6, places=3)
        self.assertEqual(summary["median_ms"], 30)
        self.assertEqual(summary["mean_ms"], 30)
        self.assertAlmostEqual(summary["stdev_ms"], 15.8113883, places=5)
        self.assertAlmostEqual(summary["p95_ms"], 48.0)
        self.assertAlmostEqual(summary["p99_ms"], 49.6)
        self.assertEqual(summary["wire_samples"], 5)
        self.assertEqual(summary["median_wire_bytes"], 100)

    def test_f1_is_reported_separately_from_repeated_authorizations(self):
        adapter = MockCostAdapter(latency=100.0)
        self.run_campaign(adapter, settings_override={"workloads": ["Medium"], "models": ["B1-C0"],
                                                     "warmup_attempts": 0, "attempts_per_batch": 3})
        run_dir = self.runs()[0]
        self.assertEqual(adapter.f1_calls, 1)  # once per measured batch
        f1 = read_rows(run_dir / "f1.csv")
        self.assertEqual(len(f1), 1)
        self.assertEqual(float(f1[0]["latency_ms"]), 5000.0)
        self.assertEqual(int(f1[0]["root_vc_bytes"]), len("aaa.bbb.ccc~disclosure"))
        for row in read_rows(run_dir / "attempts.csv"):
            self.assertLess(float(row["latency_ms"]), 1000)  # F1's 5000 ms is not added to any attempt
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(manifest["f1"]["reported_separately"])

    def test_b0_has_no_f1(self):
        adapter = MockCostAdapter()
        self.run_campaign(adapter, settings_override={"workloads": ["Medium"], "models": ["B0-C0"],
                                                     "warmup_attempts": 0, "attempts_per_batch": 1})
        self.assertEqual(adapter.f1_calls, 0)
        self.assertFalse((self.runs()[0] / "f1.csv").exists())

    def test_f1_failure_blocks_the_window_without_attempts(self):
        adapter = MockCostAdapter(f1_fails=True)
        runner = self.run_campaign(adapter, settings_override={"workloads": ["Medium"], "models": ["B1-C0"]})
        manifest = json.loads((self.runs()[0] / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "BLOCKED")
        self.assertIn("F1_PROVISIONING_FAILED", manifest["reason"])
        self.assertEqual(adapter.calls, 0)
        self.assertTrue(any(d["status"] == "blocked" for d in runner.dispositions))

    def test_lifecycle_order_is_stop_start_run_stop(self):
        adapter = MockCostAdapter(log=self.log)
        self.run_campaign(adapter, settings_override={"workloads": ["Medium"], "models": ["B0-C0"],
                                                     "warmup_attempts": 1, "attempts_per_batch": 2})
        events = [entry[0] for entry in self.log]
        window = events[events.index("stop") + 1:]           # after the initial stop-all
        first_start = window.index("start")
        self.assertEqual(window[first_start - 1], "stop")     # stopped immediately before starting
        authorizations = [i for i, e in enumerate(window) if e == "authorize"]
        self.assertGreater(min(authorizations), first_start)
        self.assertEqual(window[-1], "stop")                  # and stopped again afterwards
        self.assertGreater(len([e for e in events if e == "stop"]), 2)

    def test_output_directory_is_immutable(self):
        adapter = MockCostAdapter()
        self.run_campaign(adapter, settings_override={"workloads": ["Medium"], "models": ["B0-C0"]})
        with self.assertRaises(RuntimeError):
            self.run_campaign(MockCostAdapter(), settings_override={"workloads": ["Medium"], "models": ["B0-C0"]})

    def test_manifest_and_checksums_are_generated_and_valid(self):
        self.run_campaign(MockCostAdapter(), settings_override={"workloads": ["Medium"], "models": ["B0-C0", "B1-C0"]})
        campaign_dir = self.workspace / "evaluation" / "evidence" / "cost" / "cmp-001"
        for name in ("attempts.csv", "batch-summary.csv", "campaign-summary.csv", "campaign-manifest.json",
                     "checksums.txt", "effective-config.json", "handoff.md"):
            self.assertTrue((campaign_dir / name).exists(), name)
        for run_dir in self.runs():
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            for key in ("protocol_id", "protocol_digest", "configuration_digest", "fixture_digest", "source_digest",
                        "sut_commits", "source_identity", "model_order_in_block", "paired_block_id", "settings",
                        "concurrency", "latency_clock"):
                self.assertIn(key, manifest, key)
            self.assertEqual(manifest["protocol_id"], COST_PROTOCOL_ID)
            self.assertEqual(manifest["concurrency"], 1)
            for line in (run_dir / "checksums.txt").read_text(encoding="utf-8").splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256((run_dir / name).read_bytes()).hexdigest(), digest, name)

    def test_attempt_csv_has_every_required_field(self):
        self.run_campaign(MockCostAdapter(), settings_override={"workloads": ["Medium"], "models": ["B0-C0"]})
        with (self.runs()[0] / "attempts.csv").open(encoding="utf-8") as handle:
            header = next(csv.reader(handle))
        required = ("protocol_id,campaign_id,run_id,paired_block_id,batch,attempt,configuration,workload,mode,"
                    "transaction_id,start_timestamp,end_timestamp,latency_ms,outcome,failure_stage,failure_reason,"
                    "access_token_issued,authorization_wire_bytes,source_digest,configuration_digest,fixture_digest"
                    ).split(",")
        for column in required:
            self.assertIn(column, header)

    def test_campaign_summary_aggregates_batches(self):
        self.run_campaign(MockCostAdapter(latency=100.0), settings_override={
            "workloads": ["Medium"], "models": ["B0-C0"], "batches": 2, "warmup_attempts": 0, "attempts_per_batch": 2})
        summary = read_rows(self.workspace / "evaluation" / "evidence" / "cost" / "cmp-001" / "campaign-summary.csv")
        self.assertEqual(len(summary), 1)
        self.assertEqual((summary[0]["batches"], summary[0]["attempted"], summary[0]["succeeded"]), ("2", "4", "4"))
        self.assertEqual(summary[0]["failure_denominator"], "4")


class TestFinalGuard(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workspace = make_workspace(Path(self._tmp.name))
        self.identity = {"git_commit": "c" * 40, "worktree_dirty": "false", "dirty_patch_digest": None,
                         "source_digest": "S" * 64}

    def frozen_config(self):
        config = json.loads(write_config(self.workspace, "final").read_text(encoding="utf-8"))
        evidence = self.workspace / "evaluation" / "evidence" / "conformance"
        run_ids = {}
        for model in MODELS:
            run_id = f"conf-{model.lower()}"
            (evidence / run_id).mkdir(parents=True)
            (evidence / run_id / "manifest.json").write_text(json.dumps({
                "configuration": model, "gate_disposition": "pass", "state": "COMPLETE",
                "source_digest": self.identity["source_digest"]}), encoding="utf-8")
            run_ids[model] = run_id
        config["approval"] = {"state": "frozen", "decision_id": "DEC-900", "frozen_digest": None,
                              "conformance_run_ids": run_ids}
        digest = protocol.compute_frozen_digest(self.workspace, config)
        config["approval"]["frozen_digest"] = digest
        manifest_path = self.workspace / protocol.PROTOCOL_MANIFEST
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest.update({"state": "frozen", "frozen_digest": digest})
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return config

    def test_absent_approval_is_rejected(self):
        config = json.loads(write_config(self.workspace, "final").read_text(encoding="utf-8"))
        errors = protocol.validate_final_approval(self.workspace, config, self.identity, MODELS)
        self.assertTrue(any("approval.state=frozen" in e for e in errors))
        self.assertTrue(any("decision ID" in e for e in errors))
        self.assertTrue(any("frozen_digest" in e for e in errors))

    def test_complete_approval_is_accepted(self):
        config = self.frozen_config()
        self.assertEqual(protocol.validate_final_approval(self.workspace, config, self.identity, MODELS), [])

    def test_mismatched_digest_is_rejected(self):
        config = self.frozen_config()
        config["approval"]["frozen_digest"] = "0" * 64
        errors = protocol.validate_final_approval(self.workspace, config, self.identity, MODELS)
        self.assertTrue(any("does not match" in e for e in errors))

    def test_changing_the_configuration_after_the_approval_invalidates_it(self):
        config = self.frozen_config()
        config["cost"] = {"batches": 4}
        errors = protocol.validate_final_approval(self.workspace, config, self.identity, MODELS)
        self.assertTrue(any("does not match" in e for e in errors))

    def test_changing_a_fixture_after_the_approval_invalidates_it(self):
        config = self.frozen_config()
        fixture = self.workspace / "evaluation" / "fixtures" / "data" / "workload_medium.json"
        fixture.write_text(fixture.read_text(encoding="utf-8") + " ", encoding="utf-8")
        errors = protocol.validate_final_approval(self.workspace, config, self.identity, MODELS)
        self.assertTrue(any("does not match" in e for e in errors))

    def test_unknown_or_dirty_source_fails_closed(self):
        config = self.frozen_config()
        no_commit = dict(self.identity, git_commit=None)
        self.assertTrue(any("commit" in e for e in protocol.validate_final_approval(self.workspace, config, no_commit, MODELS)))
        unknown = dict(self.identity, worktree_dirty="unknown")
        self.assertTrue(any("unknown" in e for e in protocol.validate_final_approval(self.workspace, config, unknown, MODELS)))
        dirty = dict(self.identity, worktree_dirty="true", dirty_patch_digest="p" * 64)
        self.assertTrue(any("dirty" in e for e in protocol.validate_final_approval(self.workspace, config, dirty, MODELS)))
        config["approval"]["allowed_dirty_patch_digest"] = "p" * 64
        self.assertEqual(protocol.validate_final_approval(self.workspace, config, dirty, MODELS), [])

    def test_conformance_must_pass_for_the_exact_source(self):
        config = self.frozen_config()
        other_source = dict(self.identity, source_digest="X" * 64)
        errors = protocol.validate_final_approval(self.workspace, config, other_source, MODELS)
        self.assertTrue(any("different source digest" in e for e in errors))
        config["approval"]["conformance_run_ids"]["B1-C2"] = None
        errors = protocol.validate_final_approval(self.workspace, config, self.identity, MODELS)
        self.assertTrue(any("B1-C2" in e for e in errors))

    def test_main_refuses_a_final_execution_without_approval(self):
        config_path = write_config(self.workspace, "final")
        code, _, err = quiet_main(["--config", str(config_path), "--purpose", "final", "--execute"], self.workspace,
                                  MockCostAdapter())
        self.assertEqual(code, 2)
        self.assertIn("FINAL_EXECUTION_BLOCKED", err)
        self.assertFalse((self.workspace / "evaluation" / "evidence" / "cost").exists())

    def test_final_dry_run_describes_the_cells_and_lists_the_blockers(self):
        config_path = write_config(self.workspace, "final")
        code, out, _ = quiet_main(["--config", str(config_path), "--purpose", "final", "--dry-run"], self.workspace)
        self.assertEqual(code, 0)
        described = json.loads(out)
        self.assertEqual(described["window_count"], 15)
        self.assertTrue(described["final_execution_blockers"])
        self.assertFalse((self.workspace / "evaluation" / "evidence").exists())


class TestSmokeCampaignIntegration(unittest.TestCase):
    """One complete smoke campaign over three models, one workload (Medium), with mocked flows."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workspace = make_workspace(Path(self._tmp.name))
        self.config_path = write_config(self.workspace, "smoke")
        self.log: list = []
        self.adapter = MockCostAdapter(log=self.log)
        with patch_lifecycle(run_cost.CostRunner, self.log):
            self.code, _, _ = quiet_main(
                ["--config", str(self.config_path), "--purpose", "smoke", "--campaign-id", "smk-001",
                 "--workloads", "Medium", "--execute"], self.workspace, self.adapter)
        self.evidence = self.workspace / "evaluation" / "evidence" / "cost"
        self.campaign_dir = self.evidence / "smk-001"

    def test_campaign_completes_with_one_active_transaction(self):
        self.assertEqual(self.code, 0)
        self.assertEqual(self.adapter.max_active, 1)
        runs = sorted(p for p in self.evidence.glob("smk-001-*"))
        self.assertEqual(len(runs), 3 * 1)
        # 2 measured + 1 warm-up per window, 3 windows (models x workload x batch = 3 x 1 x 1)
        self.assertEqual(self.adapter.calls, 3 * 3)

    def test_every_output_is_referenced_and_checksums_validate(self):
        campaign_manifest = json.loads((self.campaign_dir / "campaign-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(len(campaign_manifest["dispositions"]), 3)
        listed = {}
        for line in (self.campaign_dir / "checksums.txt").read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ", 1)
            listed[name] = digest
        for name in ("attempts.csv", "batch-summary.csv", "campaign-summary.csv", "campaign-manifest.json"):
            self.assertIn(name, listed)
        for run_dir in self.evidence.glob("smk-001-*"):
            for item in run_dir.iterdir():
                if item.name == "checksums.txt":
                    continue  # each run package carries its own checksum file
                self.assertIn(f"evaluation/evidence/cost/{run_dir.name}/{item.name}", listed,
                              f"{run_dir.name}/{item.name} is not covered by the checksums")
        for name, digest in listed.items():
            target = self.campaign_dir / name if (self.campaign_dir / name).exists() else self.workspace / name
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest, name)

    def test_lifecycle_stops_and_starts_around_every_window(self):
        events = [e for e in self.log if e[0] in ("stop", "start")]
        self.assertEqual([e[0] for e in events if e[0] == "start"], ["start"] * 3)
        self.assertEqual(events[0][0], "stop")
        self.assertEqual(events[-1][0], "stop")

    def test_diagnostic_analysis_accepts_it_and_final_analysis_refuses_it(self):
        out_dir = analyze_cost.run_analysis(self.workspace, "diag-001", ["smk-001"], [], allow_diagnostic=True)
        manifest = json.loads((out_dir / "analysis-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["analysis_class"], "diagnostic")
        with self.assertRaises(analyze_cost.AnalysisError):
            analyze_cost.run_analysis(self.workspace, "final-001", ["smk-001"], [], allow_diagnostic=False)


class TestLiveAdapterMapping(unittest.TestCase):
    """The live adapter turns the shared flows' results into runner records. The flows themselves are mocked."""

    def setUp(self):
        from unittest import mock
        self.adapter = run_cost.LiveFlowAdapter(_ROOT)
        self.flows = self.adapter._flows
        self._patches = mock.patch.multiple(
            self.flows,
            run_b0_auth=mock.DEFAULT, run_vdam_auth=mock.DEFAULT, provision_root_vc=mock.DEFAULT)
        self.mocks = self._patches.start()
        self.addCleanup(self._patches.stop)

    def test_b0_latency_and_wire_are_the_sum_of_the_three_steps(self):
        self.mocks["run_b0_auth"].return_value = {
            "par_ms": 10.0, "auth_ms": 20.0, "token_ms": 5.0, "par_wire": 100, "auth_wire": 700, "token_wire": 200,
            "access_token": "a.b.c", "state": "st-1"}
        result = self.adapter.authorize("B0-C0", "Medium", None)
        self.assertEqual(result["latency_ms"], 35.0)
        self.assertEqual(result["wire_bytes"], 1000)
        self.assertEqual(result["step_wire"], {"par": 100, "browser_authorization": 700, "token_exchange": 200})
        self.assertTrue(result["access_token_issued"])
        self.assertEqual(result["transaction_id"], "st-1")
        self.mocks["run_b0_auth"].assert_called_once_with(str(_ROOT), "Medium")

    def test_b1_uses_the_flow_span_and_the_protocol_step_names(self):
        self.mocks["run_vdam_auth"].return_value = {
            "auth_ms": 42.5, "auth_wire": 600, "access_token": "a.b.c", "request_id": "rq-1",
            "step_wire": {"request_delegate": 100, "fetch_request": 150, "approve_delegate": 200, "token": 150}}
        result = self.adapter.authorize("B1-C2", "Medium", {"jti": "jti-9"})
        self.assertEqual(result["latency_ms"], 42.5)
        self.assertEqual(result["step_wire"], {"request_delegate": 100, "fetch_request": 150, "approve_delegate": 200,
                                               "token_exchange": 150})
        self.assertEqual(sum(result["step_wire"].values()), result["wire_bytes"])
        self.mocks["run_vdam_auth"].assert_called_once_with(str(_ROOT), "Medium", "jti-9")
        self.assertEqual(result["transaction_id"], "rq-1")

    def test_b1_without_a_root_vc_is_a_precondition_failure(self):
        with self.assertRaises(run_cost.FlowFailure) as raised:
            self.adapter.authorize("B1-C0", "Medium", None)
        self.assertEqual(raised.exception.stage, "precondition")
        self.mocks["run_vdam_auth"].assert_not_called()

    def test_a_missing_access_token_is_reported_not_issued(self):
        self.mocks["run_b0_auth"].return_value = {
            "par_ms": 1.0, "auth_ms": 1.0, "token_ms": 1.0, "par_wire": 1, "auth_wire": 1, "token_wire": 1,
            "access_token": None, "state": "s"}
        self.assertFalse(self.adapter.authorize("B0-C0", "Medium", None)["access_token_issued"])

    def test_failure_stage_is_classified_from_the_flow_message(self):
        self.assertEqual(run_cost.classify_failure(RuntimeError("TPP initiate failed with HTTP 500")), "par")
        self.assertEqual(run_cost.classify_failure(RuntimeError("Wallet approve-delegate failed with HTTP 500")),
                         "approve_delegate")
        self.assertEqual(run_cost.classify_failure(RuntimeError("TPP token exchange failed with HTTP 400")), "token_exchange")
        self.assertEqual(run_cost.classify_failure(RuntimeError("something else")), "unspecified")


if __name__ == "__main__":
    unittest.main()
