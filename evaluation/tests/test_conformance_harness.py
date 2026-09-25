import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError


_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evaluation.bin.conformance import conformance_runner
from evaluation.bin.conformance import conformance_v3


def rejection(error_code, status=403, description=None):
    body = {
        "error": "access_denied",
        "error_code": error_code,
        "error_description": description or error_code,
    }
    return HTTPError(
        "https://sut.invalid/token",
        status,
        "Forbidden",
        {},
        io.BytesIO(json.dumps(body).encode("utf-8")),
    )


class SecurityRejectionTests(unittest.TestCase):
    def test_exact_rejection_code_is_accepted(self):
        accepted, reason = conformance_runner.verify_security_rejection(
            rejection("REJECT_MISMATCHED_ISSUANCE_RECORD"),
            expected_semantic_tokens=["REJECT_MISMATCHED_ISSUANCE_RECORD"],
        )

        self.assertTrue(accepted)
        self.assertEqual(
            reason,
            "SECURITY_REJECTION_VERIFIED_REJECT_MISMATCHED_ISSUANCE_RECORD",
        )

    def test_signature_failure_cannot_pass_a_binding_case(self):
        accepted, reason = conformance_runner.verify_security_rejection(
            rejection("REJECT_INVALID_ROOT_SIGNATURE"),
            expected_semantic_tokens=["REJECT_MISMATCHED_ISSUANCE_RECORD"],
        )

        self.assertFalse(accepted)
        self.assertIn("WRONG_REJECTION_CODE", reason)

    def test_generic_parser_failure_is_not_security_evidence(self):
        accepted, reason = conformance_runner.verify_security_rejection(
            rejection("REJECT_MISMATCHED_ISSUANCE_RECORD", description="syntax_error"),
            expected_semantic_tokens=["REJECT_MISMATCHED_ISSUANCE_RECORD"],
        )

        self.assertFalse(accepted)
        self.assertEqual(reason, "GENERIC_ERROR_REJECTED_SYNTAX_ERROR")


class ImmutableEvidenceTests(unittest.TestCase):
    def test_jsonl_writer_refuses_to_overwrite_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.jsonl"
            path.write_text("original\n", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                conformance_v3.write_jsonl(path, [{"status": "PASS"}])

            self.assertEqual(path.read_text(encoding="utf-8"), "original\n")

    def test_quantum_suite_requires_explicit_inclusion(self):
        deferred = [name for name, _, _ in conformance_v3.suite_plan("B1-C2", False)]
        included = [name for name, _, _ in conformance_v3.suite_plan("B1-C2", True)]

        self.assertNotIn("Hybrid_PQC_Verification", deferred)
        self.assertIn("Hybrid_PQC_Verification", included)

    def test_b0_catalog_does_not_count_vdam_oracles_as_b0_cases(self):
        workspace = Path(__file__).resolve().parents[2]
        catalog = conformance_v3.required_catalog(workspace, "B0-C0")

        self.assertEqual(len(catalog), 7)
        self.assertEqual({row["tier"] for row in catalog}, {"SUT_CONFORMANCE"})

    def test_missing_required_case_is_partial_not_blocked(self):
        workspace = Path(__file__).resolve().parents[2]
        catalog = conformance_v3.required_catalog(workspace, "B0-C0")
        one_result = conformance_v3.normalize_record(
            {
                "tier": "SUT_CONFORMANCE",
                "case_id": "B0-F01",
                "status": "PASS",
            },
            "B0-C0",
            "test-run",
        )
        completed = conformance_v3.complete_required_results(
            [one_result], catalog, "B0-C0", "test-run"
        )

        disposition, blockers = conformance_v3.gate_disposition(completed, catalog)

        self.assertEqual(disposition, "partial")
        self.assertEqual(sum(row["status"] == "NOT_RUN" for row in completed), 6)
        self.assertTrue(blockers)

    def test_empty_suite_is_partial_for_local_runs(self):
        workspace = Path(__file__).resolve().parents[2]
        catalog = conformance_v3.required_catalog(workspace, "B1-C2")
        completed = conformance_v3.complete_required_results(
            [], catalog, "B1-C2", "test-run"
        )

        disposition, blockers = conformance_v3.gate_disposition(completed, catalog)

        self.assertEqual(disposition, "partial")
        self.assertEqual(len(blockers), len(catalog))

    def test_duplicate_required_result_is_partial_until_strict_gate_is_requested(self):
        workspace = Path(__file__).resolve().parents[2]
        catalog = conformance_v3.required_catalog(workspace, "B0-C0")
        duplicate = [
            conformance_v3.normalize_record(
                {
                    "tier": "SUT_CONFORMANCE",
                    "case_id": "B0-F01",
                    "status": "PASS",
                },
                "B0-C0",
                "test-run",
            )
            for _ in range(2)
        ]
        completed = conformance_v3.complete_required_results(
            duplicate, catalog, "B0-C0", "test-run"
        )

        disposition, blockers = conformance_v3.gate_disposition(completed, catalog)

        self.assertEqual(disposition, "partial")
        self.assertIn("SUT_CONFORMANCE:B0-F01:RESULT_COUNT_2", blockers)


if __name__ == "__main__":
    unittest.main()
