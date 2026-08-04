"""Independent normative oracle for the M1 receipt and terminal matrices.

The tables below are declared literally here.  They are *not* derived from
``RECEIPT_STATE_MATRIX`` or ``TERMINAL_STATE_MATRIX``: the implementation
matrices are the objects under test, so reading them to decide which rows
should pass would make the exhaustive tests vacuous.  Every expected answer in
this module comes from these literal rows.
"""

from __future__ import annotations

from itertools import product
import unittest

from admissible.paired_runner import (
    EffectReceipt,
    RECEIPT_STATE_MATRIX,
    TERMINAL_STATE_MATRIX,
    TerminalManifest,
    receipt_process_exit_policy,
    receipt_reconciliation_required,
)
from admissible.paired_runner.schemas import RECEIPT_STATUSES, TOOL_NAMES

from tests.test_admissible_paired_runner_m1 import (
    _material_fingerprint,
    _spec,
    _terminal,
    _tool_fixture_records,
)


EFFECT_CLASSES = ("READ_ONLY", "FILE_MUTATION", "PROCESS_EXECUTION")
TOOL_CLASSIFICATION = {
    "list_files": "READ_ONLY",
    "read_file": "READ_ONLY",
    "write_file": "FILE_MUTATION",
    "run_command": "PROCESS_EXECUTION",
}

# --- literal normative receipt contract -------------------------------------
# reservation:            FORBIDDEN | ALLOWED | REQUIRED
# result_binding:         accepted result-channel tokens
# process_exit_code:      per effect classification
# reconciliation_required per effect classification
NORMATIVE_RECEIPT_ROWS = (
    {
        "status": "PROPOSED",
        "reservation": "FORBIDDEN",
        "effect_started": False,
        "effect_completed": False,
        "executed_effect": False,
        "effect_application": "NOT_APPLIED",
        "result_binding": ("NONE",),
        "outcome_known": False,
        "replay_forbidden": True,
        "process_exit_code": {"READ_ONLY": "FORBIDDEN", "FILE_MUTATION": "FORBIDDEN", "PROCESS_EXECUTION": "FORBIDDEN"},
        "reconciliation_required": {"READ_ONLY": False, "FILE_MUTATION": False, "PROCESS_EXECUTION": False},
    },
    {
        "status": "RESERVED",
        "reservation": "REQUIRED",
        "effect_started": False,
        "effect_completed": False,
        "executed_effect": False,
        "effect_application": "NOT_APPLIED",
        "result_binding": ("NONE",),
        "outcome_known": False,
        "replay_forbidden": True,
        "process_exit_code": {"READ_ONLY": "FORBIDDEN", "FILE_MUTATION": "FORBIDDEN", "PROCESS_EXECUTION": "FORBIDDEN"},
        "reconciliation_required": {"READ_ONLY": False, "FILE_MUTATION": False, "PROCESS_EXECUTION": False},
    },
    {
        "status": "STARTED",
        "reservation": "REQUIRED",
        "effect_started": True,
        "effect_completed": False,
        "executed_effect": False,
        "effect_application": "PARTIAL_OR_UNKNOWN",
        "result_binding": ("NONE",),
        "outcome_known": False,
        "replay_forbidden": True,
        "process_exit_code": {"READ_ONLY": "FORBIDDEN", "FILE_MUTATION": "FORBIDDEN", "PROCESS_EXECUTION": "FORBIDDEN"},
        "reconciliation_required": {"READ_ONLY": False, "FILE_MUTATION": True, "PROCESS_EXECUTION": True},
    },
    {
        "status": "COMPLETED",
        "reservation": "REQUIRED",
        "effect_started": True,
        "effect_completed": True,
        "executed_effect": True,
        "effect_application": "APPLIED",
        "result_binding": ("OK",),
        "outcome_known": True,
        "replay_forbidden": True,
        "process_exit_code": {"READ_ONLY": "FORBIDDEN", "FILE_MUTATION": "FORBIDDEN", "PROCESS_EXECUTION": "REQUIRED"},
        "reconciliation_required": {"READ_ONLY": False, "FILE_MUTATION": False, "PROCESS_EXECUTION": False},
    },
    {
        "status": "REFUSED",
        "reservation": "ALLOWED",
        "effect_started": False,
        "effect_completed": False,
        "executed_effect": False,
        "effect_application": "NOT_APPLIED",
        "result_binding": ("NONE", "REFUSED"),
        "outcome_known": True,
        "replay_forbidden": True,
        "process_exit_code": {"READ_ONLY": "FORBIDDEN", "FILE_MUTATION": "FORBIDDEN", "PROCESS_EXECUTION": "FORBIDDEN"},
        "reconciliation_required": {"READ_ONLY": False, "FILE_MUTATION": False, "PROCESS_EXECUTION": False},
    },
    {
        "status": "FAILED",
        "reservation": "REQUIRED",
        "effect_started": True,
        "effect_completed": True,
        "executed_effect": False,
        "effect_application": "PARTIAL_OR_UNKNOWN",
        "result_binding": ("FAILED", "EXECUTION_FAILURE"),
        "outcome_known": True,
        "replay_forbidden": True,
        "process_exit_code": {"READ_ONLY": "FORBIDDEN", "FILE_MUTATION": "FORBIDDEN", "PROCESS_EXECUTION": "ALLOWED"},
        "reconciliation_required": {"READ_ONLY": False, "FILE_MUTATION": True, "PROCESS_EXECUTION": True},
    },
    {
        "status": "CANCELLED",
        "reservation": "REQUIRED",
        "effect_started": True,
        "effect_completed": True,
        "executed_effect": False,
        "effect_application": "PARTIAL_OR_UNKNOWN",
        "result_binding": ("NONE", "EXECUTION_FAILURE"),
        "outcome_known": True,
        "replay_forbidden": True,
        "process_exit_code": {"READ_ONLY": "FORBIDDEN", "FILE_MUTATION": "FORBIDDEN", "PROCESS_EXECUTION": "ALLOWED"},
        "reconciliation_required": {"READ_ONLY": False, "FILE_MUTATION": True, "PROCESS_EXECUTION": True},
    },
    {
        "status": "TIMED_OUT",
        "reservation": "REQUIRED",
        "effect_started": True,
        "effect_completed": False,
        "executed_effect": False,
        "effect_application": "PARTIAL_OR_UNKNOWN",
        "result_binding": ("NONE", "EXECUTION_FAILURE"),
        "outcome_known": False,
        "replay_forbidden": True,
        "process_exit_code": {"READ_ONLY": "FORBIDDEN", "FILE_MUTATION": "FORBIDDEN", "PROCESS_EXECUTION": "ALLOWED"},
        "reconciliation_required": {"READ_ONLY": True, "FILE_MUTATION": True, "PROCESS_EXECUTION": True},
    },
    {
        "status": "AMBIGUOUS",
        "reservation": "REQUIRED",
        "effect_started": True,
        "effect_completed": False,
        "executed_effect": False,
        "effect_application": "PARTIAL_OR_UNKNOWN",
        "result_binding": ("NONE",),
        "outcome_known": False,
        "replay_forbidden": True,
        "process_exit_code": {"READ_ONLY": "FORBIDDEN", "FILE_MUTATION": "FORBIDDEN", "PROCESS_EXECUTION": "FORBIDDEN"},
        "reconciliation_required": {"READ_ONLY": True, "FILE_MUTATION": True, "PROCESS_EXECUTION": True},
    },
)

NORMATIVE_TERMINAL_ROWS = (
    {"task_acceptance": "ACCEPTED", "reconciliation_complete": True, "acceptance_basis": "INDEPENDENT_EVALUATOR", "final_disposition": True},
    {"task_acceptance": "REJECTED", "reconciliation_complete": True, "acceptance_basis": "INDEPENDENT_EVALUATOR", "final_disposition": True},
    {"task_acceptance": "INCONCLUSIVE", "reconciliation_complete": False, "acceptance_basis": "INDEPENDENT_EVALUATOR", "final_disposition": False},
    {"task_acceptance": "NOT_EVALUATED", "reconciliation_complete": False, "acceptance_basis": "NONE", "final_disposition": False},
)

ORACLE_BY_STATUS = {row["status"]: row for row in NORMATIVE_RECEIPT_ROWS}
RESERVATION_FP = _material_fingerprint("oracle-reservation", "test.reservation")


def _tool_bindings() -> dict[str, dict[str, object]]:
    requests, results = _tool_fixture_records()
    refused = {
        "list_files": results["list_files"].__class__.create(
            request_fingerprint=requests["list_files"].request_fingerprint, outcome="REFUSED", error_code="OUT_OF_SCOPE"
        ),
        "read_file": results["read_file"].__class__.create(
            request_fingerprint=requests["read_file"].request_fingerprint, outcome="REFUSED", error_code="OUT_OF_SCOPE"
        ),
        "write_file": results["write_file"].__class__.create(
            request_fingerprint=requests["write_file"].request_fingerprint, outcome="REFUSED", error_code="OUT_OF_SCOPE"
        ),
        "run_command": results["run_command"].__class__.create(
            request_fingerprint=requests["run_command"].request_fingerprint, outcome="REFUSED",
            process_started=False, exit_code=None, error_code="OUT_OF_SCOPE",
        ),
    }
    failed = {
        "list_files": results["list_files"].__class__.create(
            request_fingerprint=requests["list_files"].request_fingerprint, outcome="FAILED", error_code="IO_ERROR"
        ),
        "read_file": results["read_file"].__class__.create(
            request_fingerprint=requests["read_file"].request_fingerprint, outcome="FAILED", error_code="IO_ERROR"
        ),
        "write_file": results["write_file"].__class__.create(
            request_fingerprint=requests["write_file"].request_fingerprint, outcome="FAILED", error_code="IO_ERROR"
        ),
        "run_command": results["run_command"].__class__.create(
            request_fingerprint=requests["run_command"].request_fingerprint, outcome="FAILED",
            process_started=False, exit_code=None, error_code="IO_ERROR"
        ),
    }
    return {
        name: {
            "request_fingerprint": requests[name].request_fingerprint,
            "OK": results[name],
            "REFUSED": refused[name],
            "FAILED": failed[name],
        }
        for name in TOOL_NAMES
    }


BINDINGS = _tool_bindings()


def _row_result(row: dict, tool_name: str):
    """The result channel value the literal oracle row requires, if any."""

    if "NONE" in row["result_binding"]:
        return None
    if "OK" in row["result_binding"]:
        return BINDINGS[tool_name]["OK"]
    return BINDINGS[tool_name]["FAILED"]


def _create(status: str, tool_name: str, **overrides):
    binding = BINDINGS[tool_name]
    keyword: dict[str, object] = {
        "receipt_id": f"oracle-{status.lower()}-{tool_name}",
        "proposal_fingerprint": _material_fingerprint("oracle-proposal", "test.proposal"),
        "tool_name": tool_name,
        "tool_request_fingerprint": binding["request_fingerprint"],
        "status": status,
        "outcome_reason": "independent oracle fixture",
    }
    keyword.update(overrides)
    return EffectReceipt.create(**keyword)


class ReceiptOracleTests(unittest.TestCase):
    def test_oracle_is_a_separate_object_covering_every_status(self) -> None:
        self.assertIsNot(NORMATIVE_RECEIPT_ROWS, RECEIPT_STATE_MATRIX)
        self.assertEqual(tuple(ORACLE_BY_STATUS), RECEIPT_STATUSES)
        self.assertEqual(len(NORMATIVE_RECEIPT_ROWS), 9)
        for row in NORMATIVE_RECEIPT_ROWS:
            self.assertEqual(set(row["process_exit_code"]), set(EFFECT_CLASSES))
            self.assertEqual(set(row["reconciliation_required"]), set(EFFECT_CLASSES))

    def test_implementation_matrix_agrees_with_the_independent_oracle(self) -> None:
        for row in NORMATIVE_RECEIPT_ROWS:
            status = row["status"]
            rule = RECEIPT_STATE_MATRIX[status]
            self.assertEqual(rule.reservation, row["reservation"], status)
            self.assertEqual(rule.effect_started, row["effect_started"], status)
            self.assertEqual(rule.effect_completed, row["effect_completed"], status)
            self.assertEqual(rule.executed_effect, row["executed_effect"], status)
            self.assertEqual(rule.effect_application, row["effect_application"], status)
            self.assertEqual(tuple(rule.result_binding), row["result_binding"], status)
            self.assertEqual(rule.outcome_known, row["outcome_known"], status)
            self.assertEqual(rule.replay_forbidden, row["replay_forbidden"], status)
            for classification in EFFECT_CLASSES:
                self.assertEqual(
                    receipt_process_exit_policy(status, classification),
                    row["process_exit_code"][classification],
                    (status, classification),
                )
                self.assertEqual(
                    receipt_reconciliation_required(status, classification),
                    row["reconciliation_required"][classification],
                    (status, classification),
                )

    def test_every_flag_combination_of_every_status_and_tool_follows_the_oracle(self) -> None:
        examined = 0
        accepted = 0
        for row, tool_name in product(NORMATIVE_RECEIPT_ROWS, TOOL_NAMES):
            status = row["status"]
            classification = TOOL_CLASSIFICATION[tool_name]
            exit_policy = row["process_exit_code"][classification]
            for flags in product((False, True), repeat=6):
                started, completed, executed, known, replay, reconcile = flags
                examined += 1
                expected = flags == (
                    row["effect_started"],
                    row["effect_completed"],
                    row["executed_effect"],
                    row["outcome_known"],
                    row["replay_forbidden"],
                    row["reconciliation_required"][classification],
                )
                try:
                    receipt = _create(
                        status,
                        tool_name,
                        receipt_id=f"oracle-{status.lower()}-{tool_name}-{int(started)}{int(completed)}{int(executed)}",
                        reservation_fingerprint=None if row["reservation"] == "FORBIDDEN" else RESERVATION_FP,
                        effect_started=started,
                        effect_completed=completed,
                        executed_effect=executed,
                        outcome_known=known,
                        replay_forbidden=replay,
                        reconciliation_required=reconcile,
                        tool_result=_row_result(row, tool_name),
                        process_exit_code=0 if exit_policy == "REQUIRED" else None,
                    )
                except ValueError:
                    self.assertFalse(expected, f"oracle row rejected: {status}/{tool_name}/{flags}")
                else:
                    self.assertTrue(expected, f"contradictory row accepted: {status}/{tool_name}/{flags}")
                    self.assertIs(receipt.validated(), receipt)
                    accepted += 1
        self.assertEqual(examined, len(NORMATIVE_RECEIPT_ROWS) * len(TOOL_NAMES) * 64)
        self.assertEqual(accepted, len(NORMATIVE_RECEIPT_ROWS) * len(TOOL_NAMES))

    def test_reservation_and_process_exit_policies_follow_the_oracle(self) -> None:
        refusals = 0
        for row, tool_name in product(NORMATIVE_RECEIPT_ROWS, TOOL_NAMES):
            status = row["status"]
            classification = TOOL_CLASSIFICATION[tool_name]
            exit_policy = row["process_exit_code"][classification]
            base = {
                "effect_started": row["effect_started"],
                "effect_completed": row["effect_completed"],
                "executed_effect": row["executed_effect"],
                "tool_result": _row_result(row, tool_name),
            }
            if row["reservation"] == "REQUIRED":
                with self.assertRaises(ValueError, msg=f"{status}/{tool_name} accepted a missing reservation"):
                    _create(status, tool_name, reservation_fingerprint=None,
                            process_exit_code=0 if exit_policy == "REQUIRED" else None, **base)
                refusals += 1
            elif row["reservation"] == "FORBIDDEN":
                with self.assertRaises(ValueError, msg=f"{status}/{tool_name} accepted a forbidden reservation"):
                    _create(status, tool_name, reservation_fingerprint=RESERVATION_FP,
                            process_exit_code=0 if exit_policy == "REQUIRED" else None, **base)
                refusals += 1
            reservation = None if row["reservation"] == "FORBIDDEN" else RESERVATION_FP
            if exit_policy == "FORBIDDEN":
                with self.assertRaises(ValueError, msg=f"{status}/{tool_name} accepted process-exit data"):
                    _create(status, tool_name, reservation_fingerprint=reservation, process_exit_code=0, **base)
                refusals += 1
            elif exit_policy == "REQUIRED":
                with self.assertRaises(ValueError, msg=f"{status}/{tool_name} accepted a missing exit code"):
                    _create(status, tool_name, reservation_fingerprint=reservation, process_exit_code=None, **base)
                refusals += 1
        expected_refusals = sum(
            (1 if row["reservation"] in {"REQUIRED", "FORBIDDEN"} else 0)
            + (1 if row["process_exit_code"][TOOL_CLASSIFICATION[tool_name]] in {"FORBIDDEN", "REQUIRED"} else 0)
            for row, tool_name in product(NORMATIVE_RECEIPT_ROWS, TOOL_NAMES)
        )
        self.assertEqual(refusals, expected_refusals)
        self.assertEqual(refusals, 65)

    def test_result_channel_tokens_follow_the_oracle(self) -> None:
        accepted = 0
        examined = 0
        for row, tool_name in product(NORMATIVE_RECEIPT_ROWS, TOOL_NAMES):
            status = row["status"]
            classification = TOOL_CLASSIFICATION[tool_name]
            exit_policy = row["process_exit_code"][classification]
            reservation = None if row["reservation"] == "FORBIDDEN" else RESERVATION_FP
            for token in ("NONE", "OK", "REFUSED", "FAILED", "EXECUTION_FAILURE"):
                examined += 1
                tool_result = None if token in {"NONE", "EXECUTION_FAILURE"} else BINDINGS[tool_name][token]
                execution_failure = "RESULT_NOT_PRODUCED" if token == "EXECUTION_FAILURE" else None
                expected = token in row["result_binding"]
                try:
                    receipt = _create(
                        status,
                        tool_name,
                        receipt_id=f"oracle-{status.lower()}-{tool_name}-{token.lower()}",
                        reservation_fingerprint=reservation,
                        effect_started=row["effect_started"],
                        effect_completed=row["effect_completed"],
                        executed_effect=row["executed_effect"],
                        tool_result=tool_result,
                        execution_failure=execution_failure,
                        process_exit_code=0 if exit_policy == "REQUIRED" else None,
                    )
                except ValueError:
                    self.assertFalse(expected, f"oracle result token rejected: {status}/{tool_name}/{token}")
                else:
                    self.assertTrue(expected, f"unlisted result token accepted: {status}/{tool_name}/{token}")
                    self.assertEqual(receipt.result_binding, token)
                    accepted += 1
        self.assertEqual(examined, len(NORMATIVE_RECEIPT_ROWS) * len(TOOL_NAMES) * 5)
        self.assertEqual(
            accepted,
            len(TOOL_NAMES) * sum(len(row["result_binding"]) for row in NORMATIVE_RECEIPT_ROWS),
        )


class TerminalOracleTests(unittest.TestCase):
    def test_oracle_is_a_separate_object_and_agrees_with_the_matrix(self) -> None:
        self.assertIsNot(NORMATIVE_TERMINAL_ROWS, TERMINAL_STATE_MATRIX)
        self.assertEqual(
            tuple(row["task_acceptance"] for row in NORMATIVE_TERMINAL_ROWS),
            tuple(TERMINAL_STATE_MATRIX),
        )
        for row in NORMATIVE_TERMINAL_ROWS:
            rule = TERMINAL_STATE_MATRIX[row["task_acceptance"]]
            self.assertEqual(rule.reconciliation_complete, row["reconciliation_complete"])
            self.assertEqual(rule.acceptance_basis, row["acceptance_basis"])
            self.assertEqual(rule.final_disposition, row["final_disposition"])

    def test_every_terminal_combination_follows_the_oracle(self) -> None:
        specification = _spec("DIRECT", "run-oracle-terminal")
        examined = 0
        accepted = 0
        for row in NORMATIVE_TERMINAL_ROWS:
            for reconciliation_complete in (False, True):
                examined += 1
                expected = reconciliation_complete == row["reconciliation_complete"]
                try:
                    terminal = _terminal(
                        specification,
                        f"oracle-{row['task_acceptance'].lower()}-{reconciliation_complete}",
                        task_acceptance=row["task_acceptance"],
                        reconciliation_complete=reconciliation_complete,
                    )
                except ValueError:
                    self.assertFalse(expected, row["task_acceptance"])
                else:
                    self.assertTrue(expected, row["task_acceptance"])
                    self.assertIsInstance(terminal, TerminalManifest)
                    self.assertEqual(terminal.acceptance_basis, row["acceptance_basis"])
                    accepted += 1
        self.assertEqual(examined, len(NORMATIVE_TERMINAL_ROWS) * 2)
        self.assertEqual(accepted, len(NORMATIVE_TERMINAL_ROWS))


if __name__ == "__main__":
    unittest.main()
