"""Tests of artifact-size and application-wire-byte measurement (BP-20260922-v6). Fully offline."""

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

from cost_test_support import MODELS, MockArtifactSource, make_workspace, patch_lifecycle, write_config  # noqa: E402
from evaluation.analysis import analyze_cost  # noqa: E402
from evaluation.bin.artifacts import measure_artifacts as ma  # noqa: E402


def read_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def row(name, kind, content, reason=None):
    return ma.measurement_row("run", "small-b1", "B1-C0", "Medium", 1, name, kind, content, reason)


class TestArtifactRows(unittest.TestCase):

    def test_size_is_exact_utf8_bytes_and_digest_is_sha256(self):
        content = "a.b.cé€"  # two- and three-byte characters
        measured = row("access_token", "application/jwt", content)
        self.assertEqual(measured["size_bytes"], len(content.encode("utf-8")))
        self.assertNotEqual(measured["size_bytes"], len(content))
        self.assertEqual(measured["sha256_digest"], hashlib.sha256(content.encode("utf-8")).hexdigest())
        self.assertEqual(measured["availability"], "AVAILABLE")
        self.assertEqual(measured["missing_reason"], "")

    def test_jwt_and_sd_jwt_serialized_sizes(self):
        jwt = "aaa.bbb.ccc"
        self.assertEqual(row("t", "application/jwt", jwt)["size_bytes"], len(jwt))
        sd_jwt = "aaa.bbb.ccc~disclosureOne~disclosureTwo~"
        self.assertEqual(row("s", "application/sd-jwt", sd_jwt)["size_bytes"], len(sd_jwt))  # tildes are counted
        self.assertTrue(ma.is_serialized_credential("application/jwt", jwt))
        self.assertTrue(ma.is_serialized_credential("application/sd-jwt", sd_jwt))
        self.assertFalse(ma.is_serialized_credential("application/jwt", "aaa.bbb"))
        self.assertFalse(ma.is_serialized_credential("application/sd-jwt", "aaa~bbb"))

    def test_a_delegation_vc_jti_is_rejected_as_a_credential(self):
        for identifier in ("0c9bb1d2-4a1f-49aa-90d1-7b1d1f2e3c4d", "delegate_jti", "root_jti"):
            measured = row("delegation_vc", "application/sd-jwt", identifier)
            self.assertEqual(measured["availability"], "UNAVAILABLE", identifier)
            self.assertEqual(measured["size_bytes"], "")
            self.assertEqual(measured["sha256_digest"], "")
            self.assertEqual(measured["missing_reason"], "VALUE_IS_AN_IDENTIFIER_NOT_A_SERIALIZED_CREDENTIAL")

    def test_the_real_delegation_credential_is_measured(self):
        credential = "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJ4In0.c2ln~WyJzYWx0IiwiYSIsMV0~"
        measured = row("delegation_vc", "application/sd-jwt", credential)
        self.assertEqual(measured["availability"], "AVAILABLE")
        self.assertEqual(measured["size_bytes"], len(credential))

    def test_unobservable_artifacts_are_explicitly_unavailable_with_a_reason(self):
        for content in (None, ""):
            measured = row("key_binding_proof", "application/jwt", content, "NOT_RETURNED_BY_ANY_CLIENT_FACING_ENDPOINT")
            self.assertEqual(measured["availability"], "UNAVAILABLE")
            self.assertEqual(measured["missing_reason"], "NOT_RETURNED_BY_ANY_CLIENT_FACING_ENDPOINT")
            self.assertEqual(measured["size_bytes"], "")
            self.assertEqual(measured["measurement_method"], "not_measured")
        self.assertTrue(row("x", "application/jwt", None)["missing_reason"])  # a reason is always present


class TestWireBytes(unittest.TestCase):

    def test_total_is_the_sum_of_the_named_steps(self):
        rows = ma.wire_rows("run", "B1-C0", "Medium", 1, "authorization",
                            {"request_delegate": 100, "fetch_request": 200, "approve_delegate": 300, "token_exchange": 400},
                            "total_authorization")
        steps = [r for r in rows if r["step"] != "total_authorization"]
        total = next(r for r in rows if r["step"] == "total_authorization")
        self.assertEqual(len(steps), 4)
        self.assertEqual(total["wire_bytes"], 1000)
        self.assertEqual(sum(r["wire_bytes"] for r in steps), total["wire_bytes"])

    def test_no_exchange_is_counted_twice(self):
        rows = ma.wire_rows("run", "B0-C0", "Medium", 1, "authorization", {"par": 5, "browser_authorization": 7}, "total_authorization")
        self.assertEqual(sum(r["wire_bytes"] for r in rows if r["step"] != "total_authorization"), 12)
        self.assertEqual(next(r for r in rows if r["step"] == "total_authorization")["wire_bytes"], 12)  # not 24
        self.assertEqual(len({r["step"] for r in rows}), 3)

    def test_f1_wire_bytes_are_kept_apart_from_the_authorization_total(self):
        authorization = ma.wire_rows("run", "B1-C0", "Medium", 1, "authorization", {"token_exchange": 40}, "total_authorization")
        f1 = ma.wire_rows("run", "B1-C0", "Medium", 1, "F1_issuance", {"offer": 400, "callback": 500}, "total_f1")
        self.assertEqual(next(r for r in authorization if r["step"] == "total_authorization")["wire_bytes"], 40)
        self.assertEqual(next(r for r in f1 if r["step"] == "total_f1")["wire_bytes"], 900)
        self.assertEqual({r["phase"] for r in f1}, {"F1_issuance"})

    def test_b1_step_names_are_the_protocol_names(self):
        self.assertEqual(ma.B1_STEP_NAMES["token"], "token_exchange")
        self.assertEqual(set(ma.B1_STEP_NAMES.values()),
                         {"request_delegate", "fetch_request", "approve_delegate", "token_exchange"})


class TestMeasurementRun(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workspace = make_workspace(Path(self._tmp.name))
        self.config_path = write_config(self.workspace, "smoke")
        self.log: list = []
        self.source = MockArtifactSource()

    def run_main(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with patch_lifecycle(ma.ArtifactMeasurer, self.log), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ma.main(["--config", str(self.config_path), "--purpose", "smoke", "--campaign-id", "art-001",
                            "--execute", *extra], workspace=self.workspace, source=self.source)
        return code

    def evidence(self):
        return self.workspace / "evaluation" / "evidence" / "artifacts"

    def test_workload_and_model_selection_propagate(self):
        # Workload is fixed to Medium (decision DEC-023); only model and sample selection vary now.
        self.assertEqual(self.run_main("--workloads", "Medium", "--models", "B0-C0", "B1-C2", "--samples", "2"), 0)
        self.assertEqual(sorted({(m, w) for m, w, _ in self.source.collected}),
                         sorted((m, "Medium") for m in ("B0-C0", "B1-C2")))
        self.assertEqual(len(self.source.collected), 2 * 1 * 2)
        rows = read_rows(self.evidence() / "art-001-artifacts-medium-b2" / "artifact-measurements.csv")
        self.assertEqual({r["workload"] for r in rows}, {"Medium"})
        self.assertEqual({r["sample"] for r in rows}, {"1", "2"})

    def test_all_models_and_workloads_by_default(self):
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(self.source.collected), 3 * 1)
        self.assertEqual({(m) for m, _, _ in self.source.collected}, set(MODELS))

    def test_secrets_and_artifacts_are_not_written_anywhere(self):
        self.run_main()
        for path in self.workspace.rglob("*"):
            if path.is_file():
                self.assertNotIn(MockArtifactSource.SECRET.encode(), path.read_bytes(), str(path))

    def test_manifest_lists_sizes_and_unavailable_dispositions(self):
        self.run_main("--workloads", "Medium", "--models", "B0-C0", "B1-C0")
        b1 = json.loads((self.evidence() / "art-001-artifacts-medium-b1" / "manifest.json").read_text(encoding="utf-8"))
        by_name = {a["artifact_name"]: a for a in b1["artifacts"]}
        self.assertEqual(by_name["delegation_vc"]["availability"], "UNAVAILABLE")  # the mock returns a bare identifier
        self.assertEqual(by_name["scope_vc"]["availability"], "AVAILABLE")
        self.assertEqual(by_name["scope_vc"]["sizes_bytes"], [len(f"h.p.s~{MockArtifactSource.SECRET}".encode("utf-8"))])
        b0 = json.loads((self.evidence() / "art-001-artifacts-medium-b0" / "manifest.json").read_text(encoding="utf-8"))
        by_name = {a["artifact_name"]: a for a in b0["artifacts"]}
        self.assertEqual(by_name["par_request_object"]["availability"], "UNAVAILABLE")
        self.assertEqual(by_name["par_request_object"]["missing_reason"], "NOT_OBSERVABLE")

    def test_wire_and_f1_are_recorded_separately(self):
        self.run_main("--workloads", "Medium", "--models", "B1-C0")
        run_dir = self.evidence() / "art-001-artifacts-medium-b1"
        network = read_rows(run_dir / "network-measurements.csv")
        totals = {r["step"]: int(r["wire_bytes"]) for r in network if r["step"].startswith("total_")}
        self.assertEqual(totals, {"total_authorization": 100, "total_f1": 900})
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(manifest["f1_reported_separately"])
        self.assertEqual(manifest["f1"]["wire_bytes"], 900)
        self.assertEqual(manifest["f1"]["root_vc_bytes"], len(f"h.p.s~{MockArtifactSource.SECRET}".encode("utf-8")))

    def test_b0_has_no_f1_record(self):
        self.run_main("--workloads", "Medium", "--models", "B0-C0")
        manifest = json.loads((self.evidence() / "art-001-artifacts-medium-b0" / "manifest.json").read_text(encoding="utf-8"))
        self.assertFalse(manifest["f1_reported_separately"])
        self.assertIsNone(manifest["f1"])

    def test_checksums_cover_the_run_package(self):
        self.run_main("--workloads", "Medium", "--models", "B0-C0")
        run_dir = self.evidence() / "art-001-artifacts-medium-b0"
        lines = (run_dir / "checksums.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual({line.split("  ", 1)[1] for line in lines},
                         {"artifact-measurements.csv", "network-measurements.csv", "manifest.json"})

    def test_a_failing_source_is_recorded_not_hidden(self):
        class Broken(MockArtifactSource):
            def collect(self, model, workload, sample, root_vc):
                raise RuntimeError("wallet unreachable")

        self.source = Broken()
        self.assertEqual(self.run_main("--workloads", "Medium", "--models", "B0-C0"), 2)
        handoff = (self.evidence() / "art-001" / "handoff.md").read_text(encoding="utf-8")
        self.assertIn("wallet unreachable", handoff)

    def test_invalid_samples_are_rejected(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ma.main(["--config", str(self.config_path), "--purpose", "smoke", "--samples", "0", "--dry-run"],
                           workspace=self.workspace)
        self.assertEqual(code, 2)

    def test_final_run_requires_approval(self):
        config_path = write_config(self.workspace, "final")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ma.main(["--config", str(config_path), "--purpose", "final", "--execute"], workspace=self.workspace,
                           source=self.source)
        self.assertEqual(code, 2)
        self.assertIn("FINAL_EXECUTION_BLOCKED", err.getvalue())
        self.assertEqual(self.source.collected, [])

    def test_final_dry_run_lists_the_blockers_without_writing_evidence(self):
        config_path = write_config(self.workspace, "final")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ma.main(["--config", str(config_path), "--purpose", "final", "--dry-run"], workspace=self.workspace)
        self.assertEqual(code, 0)
        described = json.loads(out.getvalue())
        self.assertTrue(described["final_execution_blockers"])
        self.assertEqual(len(described["schedule"]), 3)
        self.assertFalse((self.workspace / "evaluation" / "evidence").exists())

    def test_analysis_reads_the_artifact_and_wire_evidence(self):
        self.run_main("--workloads", "Medium")
        out_dir = analyze_cost.run_analysis(self.workspace, "art-a1", ["art-001"], [], allow_diagnostic=True)
        artifacts = read_rows(out_dir / "artifact-summary.csv")
        unavailable = {(r["configuration"], r["artifact_name"]) for r in artifacts if r["availability"] == "UNAVAILABLE"}
        self.assertIn(("B1-C0", "delegation_vc"), unavailable)
        self.assertIn(("B0-C0", "par_request_object"), unavailable)
        wire = read_rows(out_dir / "wire-summary.csv")
        total = next(r for r in wire if r["configuration"] == "B1-C0" and r["step"] == "total_authorization")
        self.assertEqual(float(total["median_bytes"]), 100.0)
        limitations = (out_dir / "limitations.md").read_text(encoding="utf-8")
        self.assertIn("delegation_vc", limitations)


class TestLiveSourceMapping(unittest.TestCase):
    """LiveArtifactSource maps the shared flows' results into artifacts and named wire steps (flows mocked)."""

    def setUp(self):
        from unittest import mock
        self.source = ma.LiveArtifactSource(_ROOT)
        self.flows = self.source._flows
        patcher = mock.patch.multiple(
            self.flows, run_b0_auth=mock.DEFAULT, run_vdam_auth=mock.DEFAULT,
            fetch_delegate_artifacts=mock.DEFAULT, perf_hosts=mock.DEFAULT)
        self.mocks = patcher.start()
        self.addCleanup(patcher.stop)
        self.mocks["perf_hosts"].return_value = {"wallet_url": "https://wallet.test:3443"}

    def test_b1_reads_the_real_delegation_vc_after_the_flow(self):
        self.mocks["run_vdam_auth"].return_value = {
            "access_token": "a.b.c", "request_id": "rq-7", "delegate_vc_jti": "0c9bb1d2-jti",
            "step_wire": {"request_delegate": 1, "fetch_request": 2, "approve_delegate": 3, "token": 4}}
        self.mocks["fetch_delegate_artifacts"].return_value = {
            "delegate_vc": "h.p.s~disc", "authorization_vc": "h2.p2.s2~disc2", "das_encrypted_package": "x.y.z.u.v"}
        observed = self.source.collect("B1-C0", "Medium", 1, {"jti": "jti-1", "credential": "r.o.o~t"})
        self.mocks["fetch_delegate_artifacts"].assert_called_once_with("https://wallet.test:3443", "rq-7")
        by_name = {a["name"]: a for a in observed["artifacts"]}
        self.assertEqual(by_name["delegation_vc"]["content"], "h.p.s~disc")  # the credential, not the JTI
        self.assertNotEqual(by_name["delegation_vc"]["content"], "0c9bb1d2-jti")
        self.assertEqual(by_name["scope_vc"]["content"], "r.o.o~t")
        self.assertIsNone(by_name["tpp_vp_assertion"]["content"])   # the VP goes TPP to Bank, never to the client
        self.assertIn("SERVER_TO_SERVER", by_name["tpp_vp_assertion"]["reason"])
        self.assertEqual(by_name["root_vc_presentation"]["content"], "h2.p2.s2~disc2")
        self.assertNotIn("authorization_presentation", by_name)
        self.assertIsNone(by_name["delegation_vc_key_binding_jwt"]["content"])  # this delegation VC has no KB-JWT
        self.assertEqual(observed["wire_steps"],
                         {"request_delegate": 1, "fetch_request": 2, "approve_delegate": 3, "token_exchange": 4})

    def test_the_key_binding_jwt_is_measured_from_the_delegation_vc_not_estimated(self):
        delegation = "hdr.pay.sig~WyJzYWx0Il0~kbh.kbp.kbs"
        self.mocks["run_vdam_auth"].return_value = {"access_token": "a.b.c", "request_id": "rq", "step_wire": {"token": 4}}
        self.mocks["fetch_delegate_artifacts"].return_value = {"delegate_vc": delegation, "authorization_vc": "r.o.o~"}
        observed = self.source.collect("B1-C2", "Medium", 1, {"jti": "j", "credential": "r.o.o~t"})
        by_name = {a["name"]: a for a in observed["artifacts"]}
        self.assertEqual(by_name["delegation_vc_key_binding_jwt"]["content"], "kbh.kbp.kbs")
        self.assertEqual(by_name["delegation_vc"]["content"], delegation)

    def test_sd_jwt_components(self):
        self.assertEqual(ma.sd_jwt_components("a.b.c~d1~d2~k.b.j"), ("a.b.c", ["d1", "d2"], "k.b.j"))
        self.assertEqual(ma.sd_jwt_components("a.b.c~d1~"), ("a.b.c", ["d1"], None))      # a presentation has no KB-JWT
        self.assertEqual(ma.sd_jwt_components("a.b.c"), ("a.b.c", [], None))

    def test_a_wallet_that_returns_no_delegation_vc_is_unavailable_not_estimated(self):
        self.mocks["run_vdam_auth"].return_value = {"access_token": "a.b.c", "request_id": "rq", "step_wire": {"token": 4}}
        self.mocks["fetch_delegate_artifacts"].return_value = {}
        observed = self.source.collect("B1-C2", "Medium", 1, {"jti": "j", "credential": "r.o.o~t"})
        delegation = next(a for a in observed["artifacts"] if a["name"] == "delegation_vc")
        measured = ma.measurement_row("r", "w", "B1-C2", "Medium", 1, delegation["name"], delegation["type"],
                                      delegation["content"], delegation.get("reason"))
        self.assertEqual(measured["availability"], "UNAVAILABLE")
        self.assertEqual(measured["missing_reason"], "WALLET_DID_NOT_RETURN_THE_DELEGATION_VC")

    def test_b0_records_the_request_uri_code_token_and_step_names(self):
        self.mocks["run_b0_auth"].return_value = {
            "request_uri": "urn:ietf:params:oauth:request_uri:abc", "auth_code": "code-1", "access_token": "a.b.c",
            "par_wire": 10, "auth_wire": 20, "token_wire": 30}
        observed = self.source.collect("B0-C0", "Medium", 1, None)
        self.assertEqual({a["name"] for a in observed["artifacts"]},
                         {"par_request_uri", "par_request_object", "authorization_code", "access_token"})
        self.assertEqual(observed["wire_steps"], {"par": 10, "browser_authorization": 20, "token_exchange": 30})
        self.mocks["run_b0_auth"].assert_called_once_with(str(_ROOT), "Medium")

    def test_b1_without_a_root_vc_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.source.collect("B1-C0", "Medium", 1, None)


if __name__ == "__main__":
    unittest.main()
