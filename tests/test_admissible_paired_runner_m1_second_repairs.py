"""Refusal and closure tests for the second bounded M1 repair set.

Every test in this module corresponds to a reproduced false positive from the
independent closure findings M1-R06 through M1-R11, or to the positive typed
chain those repairs must still admit.  Nothing here executes an effect, starts
a process, contacts a provider, or touches an authority root.
"""

from __future__ import annotations

from dataclasses import replace
import unittest

from admissible.paired_runner import (
    CanonicalProposal,
    EffectReceipt,
    EffectReservation,
    EvaluatorSpecification,
    ExperimentSpecification,
    ListFilesRequest,
    ListFilesResult,
    ModeDecision,
    ReadFileRequest,
    ReadFileResult,
    RunCommandRequest,
    RunCommandResult,
    SessionIdentity,
    TerminalManifest,
    ToolGrammarEntry,
    ToolGrammarSpecification,
    WriteFileRequest,
    WriteFileResult,
    canonical_bytes,
    fingerprint,
    parse_canonical_json,
    written_content_fingerprint,
)
from admissible.paired_runner.schemas import (
    SCHEMA_TOOL_GRAMMAR,
    SCHEMA_TOOL_GRAMMAR_ENTRY,
    TOOL_EFFECT_CLASSIFICATIONS,
)
from admissible.paired_runner.specification import (
    CausalPredecessor,
    ClockObservation,
    derive_evaluator_identity,
    derive_tool_grammar_identity,
)
from admissible.paired_runner.tool_schemas import (
    GRAMMAR_DESCRIPTOR_FINGERPRINT_DOMAIN,
    WRITTEN_CONTENT_FINGERPRINT_DOMAIN,
)

from tests.test_admissible_paired_runner_m1 import (
    _evaluator,
    _grammar,
    _identity,
    _material_fingerprint,
    _spec,
    _terminal,
)


def _session(specification: ExperimentSpecification, suffix: str = "1") -> SessionIdentity:
    return SessionIdentity.create(
        run=specification.run_identity,
        session_id=f"session-{specification.condition.condition_id.lower()}-{suffix}",
    )


def _request_for(tool_name: str, grammar: ToolGrammarSpecification):
    grammar_fingerprint = grammar.grammar_fingerprint
    if tool_name == "list_files":
        return ListFilesRequest.create(tool_grammar_fingerprint=grammar_fingerprint, path="src", recursive=False, max_entries=4)
    if tool_name == "read_file":
        return ReadFileRequest.create(tool_grammar_fingerprint=grammar_fingerprint, path="src/main.py", max_lines=4)
    if tool_name == "write_file":
        return WriteFileRequest.create(tool_grammar_fingerprint=grammar_fingerprint, path="src/new.py", content="abcdef")
    return RunCommandRequest.create(
        tool_grammar_fingerprint=grammar_fingerprint, argv=("python", "-V"), cwd=".", timeout_ms=1000, max_output_bytes=64
    )


def _successful_result(tool_name: str, request):
    if tool_name == "list_files":
        return ListFilesResult.create(request_fingerprint=request.request_fingerprint, entries=("src/main.py",))
    if tool_name == "read_file":
        return ReadFileResult.create(request_fingerprint=request.request_fingerprint, content="print(1)\n")
    if tool_name == "write_file":
        return WriteFileResult.create(
            request_fingerprint=request.request_fingerprint,
            bytes_written=len(request.content.encode("utf-8")),
            written_content_fingerprint=written_content_fingerprint(request.content),
        )
    return RunCommandResult.create(
        request_fingerprint=request.request_fingerprint, stdout="Python 3\n", process_started=True, exit_code=0
    )


def _proposal_for(specification: ExperimentSpecification, tool_name: str, *, proposal_id: str | None = None) -> CanonicalProposal:
    return CanonicalProposal.create(
        specification=specification,
        session_identity=_session(specification),
        turn_id="turn-0",
        proposal_id=proposal_id or f"proposal-{tool_name.replace('_', '-')}",
        prompt_identity=_identity("prompt", "prompt-1"),
        tool_request=_request_for(tool_name, specification.tool_grammar),
        causal_predecessor=CausalPredecessor.root(),
        wall_clock_observation=ClockObservation.wall_clock(1_725_000_000_000),
        monotonic_observation=ClockObservation.future_runtime_placeholder(),
    )


def _decision_for(specification: ExperimentSpecification, proposal: CanonicalProposal, decision: str = "ALLOW") -> ModeDecision:
    if specification.condition.condition_id == "DIRECT":
        return ModeDecision.direct(proposal)
    return ModeDecision.governed(proposal, decision, governance_decision_reference="admissible-decision-1")


def _rebuild(body: dict, *, fingerprint_field: str, schema_id: str) -> dict:
    """Recompute a self-consistent object fingerprint after a forgery."""

    forged = {key: value for key, value in body.items() if key != fingerprint_field}
    body[fingerprint_field] = fingerprint(forged, domain=f"{schema_id}.fingerprint").to_dict()
    return body


class EvaluatorBindingTests(unittest.TestCase):
    """M1-R06: a terminal cannot accept an evaluator the experiment never bound."""

    def setUp(self) -> None:
        self.specification = _spec("DIRECT", "run-direct")

    def _terminal_with(self, evaluator: EvaluatorSpecification) -> TerminalManifest:
        return TerminalManifest.create(
            run_identity=self.specification.run_identity,
            experiment_specification_fingerprint=self.specification.specification_fingerprint,
            repository_state_fingerprint=_material_fingerprint("repo", "test.repository"),
            proposal_ledger_fingerprint=_material_fingerprint("proposals", "test.proposals"),
            effect_receipt_ledger_fingerprint=_material_fingerprint("receipts", "test.receipts"),
            budget_state_fingerprint=self.specification.common_budgets.budget_fingerprint,
            evaluator_specification_fingerprint=evaluator.evaluator_fingerprint,
            model_completion_claim="CLAIMED_COMPLETE",
            process_result="SUCCESS",
            task_acceptance="ACCEPTED",
            reconciliation_complete=True,
        )

    def test_experiment_binds_the_exact_evaluator_specification(self) -> None:
        evaluator = self.specification.evaluator_specification
        self.assertEqual(
            self.specification.evaluator_identity,
            derive_evaluator_identity(evaluator),
        )
        self.assertEqual(evaluator.environment_identity, self.specification.environment_identity)
        self.assertTrue(evaluator.independent_of_model_claim)
        self.assertTrue(evaluator.process_success_is_not_acceptance)

    def test_accepted_terminal_with_a_foreign_evaluator_is_refused(self) -> None:
        foreign = _evaluator("foreign", environment_label="environment-1")
        terminal = self._terminal_with(foreign)
        with self.assertRaises(ValueError):
            terminal.validate_for_specification(self.specification)

    def test_right_evaluator_component_with_wrong_contents_is_refused(self) -> None:
        variants = {
            "requirements": _evaluator("evaluator-1", requirements_label="other-requirements"),
            "scope": _evaluator("evaluator-1", scope_label="other-scope"),
            "test_plan": _evaluator("evaluator-1", plan_label="other-plan"),
            "version": _evaluator("evaluator-1", version="v2"),
            "environment": _evaluator("evaluator-1", environment_label="environment-2"),
        }
        for label, evaluator in variants.items():
            self.assertNotEqual(
                evaluator.evaluator_fingerprint,
                self.specification.evaluator_specification.evaluator_fingerprint,
                label,
            )
            with self.assertRaises(ValueError, msg=label):
                self._terminal_with(evaluator).validate_for_specification(self.specification)

    def test_rejected_terminal_cannot_use_an_arbitrary_evaluator_either(self) -> None:
        rejected = TerminalManifest.create(
            run_identity=self.specification.run_identity,
            experiment_specification_fingerprint=self.specification.specification_fingerprint,
            repository_state_fingerprint=_material_fingerprint("repo", "test.repository"),
            proposal_ledger_fingerprint=_material_fingerprint("proposals", "test.proposals"),
            effect_receipt_ledger_fingerprint=_material_fingerprint("receipts", "test.receipts"),
            budget_state_fingerprint=self.specification.common_budgets.budget_fingerprint,
            evaluator_specification_fingerprint=_evaluator("foreign").evaluator_fingerprint,
            model_completion_claim="CLAIMED_INCOMPLETE",
            process_result="FAILURE",
            task_acceptance="REJECTED",
            reconciliation_complete=True,
        )
        with self.assertRaises(ValueError):
            rejected.validate_for_specification(self.specification)

    def test_specification_refuses_an_evaluator_identity_that_names_another_evaluator(self) -> None:
        for forged_identity in (
            derive_evaluator_identity(_evaluator("foreign")),
            _identity("evaluator", "opaque-label"),
        ):
            with self.assertRaises(ValueError):
                replace(self.specification, evaluator_identity=forged_identity).validated()
        with self.assertRaises(ValueError):
            replace(self.specification, evaluator_specification=_evaluator("foreign")).validated()

    def test_evaluator_outside_the_experiment_environment_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            _spec("DIRECT", "run-direct", evaluator=_evaluator("evaluator-1", environment_label="other-environment"))

    def test_comparative_closure_inherits_the_exact_evaluator_binding(self) -> None:
        from admissible.paired_runner import ComparativeManifest, require_parity

        direct = _spec("DIRECT", "run-direct")
        governed = _spec("GOVERNED", "run-governed")
        parity = require_parity(direct, governed)
        governed_terminal = _terminal(governed, "governed", task_acceptance="REJECTED")
        foreign_direct_terminal = TerminalManifest.create(
            run_identity=direct.run_identity,
            experiment_specification_fingerprint=direct.specification_fingerprint,
            repository_state_fingerprint=_material_fingerprint("repo-direct", "test.repository"),
            proposal_ledger_fingerprint=_material_fingerprint("proposals-direct", "test.proposals"),
            effect_receipt_ledger_fingerprint=_material_fingerprint("receipts-direct", "test.receipts"),
            budget_state_fingerprint=direct.common_budgets.budget_fingerprint,
            evaluator_specification_fingerprint=_evaluator("foreign").evaluator_fingerprint,
            model_completion_claim="CLAIMED_COMPLETE",
            process_result="SUCCESS",
            task_acceptance="ACCEPTED",
            reconciliation_complete=True,
        )
        with self.assertRaises(ValueError):
            ComparativeManifest.create(
                direct_specification=direct,
                governed_specification=governed,
                parity_report=parity,
                direct_terminal_manifest=foreign_direct_terminal,
                governed_terminal_manifest=governed_terminal,
            )
        manifest = ComparativeManifest.create(
            direct_specification=direct,
            governed_specification=governed,
            parity_report=parity,
            direct_terminal_manifest=_terminal(direct, "direct", task_acceptance="ACCEPTED"),
            governed_terminal_manifest=governed_terminal,
        )
        self.assertIs(
            manifest.validate_for_specifications(
                direct_specification=direct, governed_specification=governed, parity_report=parity
            ),
            manifest,
        )


class ReservationReconciliationTests(unittest.TestCase):
    """M1-R07: a restored reservation cannot forge its proposal or decision."""

    def setUp(self) -> None:
        self.specification = _spec("GOVERNED", "run-governed")
        self.proposal = _proposal_for(self.specification, "write_file")
        self.decision = _decision_for(self.specification, self.proposal)
        self.reservation = EffectReservation.for_decision(
            specification=self.specification,
            reservation_id="reservation-1",
            proposal=self.proposal,
            decision=self.decision,
        )

    def _restored(self, **forged: object) -> EffectReservation:
        body = self.reservation.to_dict()
        body.update(forged)
        return EffectReservation.from_dict(
            _rebuild(body, fingerprint_field="reservation_fingerprint", schema_id="admissible.paired_runner.effect_reservation")
        )

    def test_authoritative_reconciliation_accepts_the_exact_chain(self) -> None:
        self.assertIs(
            self.reservation.validate_for_decision(self.specification, self.proposal, self.decision),
            self.reservation,
        )
        restored = EffectReservation.from_dict(parse_canonical_json(canonical_bytes(self.reservation.to_dict())))
        self.assertEqual(restored, self.reservation)
        restored.validate_for_decision(self.specification, self.proposal, self.decision)

    def test_forged_proposal_id_passes_structural_validation_but_fails_reconciliation(self) -> None:
        forged = self._restored(proposal_id="proposal-forged")
        self.assertIs(forged.validate_for_specification(self.specification), forged)
        with self.assertRaises(ValueError):
            forged.validate_for_decision(self.specification, self.proposal, self.decision)

    def test_forged_proposal_fingerprint_fails_reconciliation(self) -> None:
        other = _proposal_for(self.specification, "read_file", proposal_id="proposal-other")
        forged = self._restored(proposal_fingerprint=other.proposal_fingerprint.to_dict())
        self.assertIs(forged.validate_for_specification(self.specification), forged)
        with self.assertRaises(ValueError):
            forged.validate_for_decision(self.specification, self.proposal, self.decision)

    def test_forged_decision_fingerprint_fails_reconciliation(self) -> None:
        other_decision = ModeDecision.governed(
            self.proposal, "ALLOW", governance_decision_reference="admissible-decision-2"
        )
        forged = self._restored(mode_decision_fingerprint=other_decision.decision_fingerprint.to_dict())
        self.assertIs(forged.validate_for_specification(self.specification), forged)
        with self.assertRaises(ValueError):
            forged.validate_for_decision(self.specification, self.proposal, self.decision)

    def test_forged_condition_and_executor_identity_fail_reconciliation(self) -> None:
        other_specification = _spec("GOVERNED", "run-governed", effect_executor_label="executor-2")
        with self.assertRaises(ValueError):
            self.reservation.validate_for_decision(other_specification, self.proposal, self.decision)
        direct_specification = _spec("DIRECT", "run-direct")
        direct_proposal = _proposal_for(direct_specification, "write_file")
        with self.assertRaises(ValueError):
            self.reservation.validate_for_decision(direct_specification, direct_proposal, self.decision)

    def test_a_refusing_decision_can_never_reconcile_a_reservation(self) -> None:
        refusal = ModeDecision.governed(
            self.proposal, "REFUSE", governance_decision_reference="admissible-decision-refuse"
        )
        with self.assertRaises(ValueError):
            EffectReservation.for_decision(
                specification=self.specification,
                reservation_id="reservation-refused",
                proposal=self.proposal,
                decision=refusal,
            )
        with self.assertRaises(ValueError):
            self.reservation.validate_for_decision(self.specification, self.proposal, refusal)


class ReceiptEffectAwarenessTests(unittest.TestCase):
    """M1-R08: the receipt contract is effect-aware and bound to the chain."""

    def setUp(self) -> None:
        self.specification = _spec("DIRECT", "run-direct")
        self.proposal = _proposal_for(self.specification, "read_file")
        self.decision = _decision_for(self.specification, self.proposal)
        self.reservation = EffectReservation.for_decision(
            specification=self.specification,
            reservation_id="reservation-read",
            proposal=self.proposal,
            decision=self.decision,
        )
        self.result = _successful_result("read_file", self.proposal.tool_request)

    def _completed(self, **overrides):
        keyword = {
            "receipt_id": "receipt-read-completed",
            "proposal": self.proposal,
            "status": "COMPLETED",
            "reservation": self.reservation,
            "tool_result": self.result,
            "outcome_reason": "completed read_file without a process",
        }
        keyword.update(overrides)
        return EffectReceipt.for_proposal(**keyword)

    def test_completed_read_file_needs_no_process_exit_code(self) -> None:
        receipt = self._completed()
        self.assertIsNone(receipt.process_exit_code)
        self.assertEqual(receipt.effect_classification, "READ_ONLY")
        self.assertEqual(receipt.tool_name, "read_file")
        self.assertEqual(receipt.tool_request_fingerprint, self.proposal.tool_request.request_fingerprint)
        self.assertIs(
            receipt.validate_for_causal_chain(
                specification=self.specification,
                proposal=self.proposal,
                decision=self.decision,
                reservation=self.reservation,
            ),
            receipt,
        )

    def test_completed_read_file_refuses_a_synthetic_process_exit_code(self) -> None:
        for exit_code in (0, 1):
            with self.assertRaises(ValueError, msg=str(exit_code)):
                self._completed(process_exit_code=exit_code)

    def test_non_process_tools_never_carry_process_exit_data(self) -> None:
        for tool_name in ("list_files", "read_file", "write_file"):
            specification = _spec("DIRECT", "run-direct")
            proposal = _proposal_for(specification, tool_name)
            decision = _decision_for(specification, proposal)
            reservation = EffectReservation.for_decision(
                specification=specification, reservation_id=f"reservation-{tool_name}", proposal=proposal, decision=decision
            )
            with self.assertRaises(ValueError, msg=tool_name):
                EffectReceipt.for_proposal(
                    receipt_id=f"receipt-{tool_name}",
                    proposal=proposal,
                    status="COMPLETED",
                    reservation=reservation,
                    tool_result=_successful_result(tool_name, proposal.tool_request),
                    process_exit_code=0,
                    outcome_reason="synthetic process exit code",
                )

    def test_receipt_with_a_result_from_another_request_is_refused(self) -> None:
        other_request = ReadFileRequest.create(
            tool_grammar_fingerprint=self.specification.tool_grammar.grammar_fingerprint,
            path="src/other.py",
            max_lines=4,
        )
        foreign_result = ReadFileResult.create(request_fingerprint=other_request.request_fingerprint, content="print(2)\n")
        with self.assertRaises(ValueError):
            self._completed(tool_result=foreign_result)

    def test_receipt_with_a_result_from_another_tool_is_refused(self) -> None:
        write_request = WriteFileRequest.create(
            tool_grammar_fingerprint=self.specification.tool_grammar.grammar_fingerprint,
            path="src/new.py",
            content="abcdef",
        )
        foreign_result = _successful_result("write_file", write_request)
        with self.assertRaises(ValueError):
            self._completed(tool_result=foreign_result)

    def test_pre_effect_states_cannot_carry_a_tool_result(self) -> None:
        for status in ("PROPOSED", "RESERVED", "STARTED"):
            with self.assertRaises(ValueError, msg=status):
                self._completed(
                    receipt_id=f"receipt-{status.lower()}",
                    status=status,
                    reservation=None if status == "PROPOSED" else self.reservation,
                    tool_result=self.result,
                )

    def test_refused_receipt_cannot_claim_an_executed_effect(self) -> None:
        with self.assertRaises(ValueError):
            EffectReceipt.create(
                receipt_id="receipt-refused-executed",
                proposal_fingerprint=self.proposal.proposal_fingerprint,
                tool_name="read_file",
                tool_request_fingerprint=self.proposal.tool_request.request_fingerprint,
                status="REFUSED",
                effect_started=True,
                effect_completed=True,
                executed_effect=True,
                outcome_reason="a refusal cannot execute",
            )

    def test_failed_receipt_binds_a_failed_result_or_a_typed_execution_failure(self) -> None:
        failed_result = ReadFileResult.create(
            request_fingerprint=self.proposal.tool_request.request_fingerprint, outcome="FAILED", error_code="IO_ERROR"
        )
        typed_failure = EffectReceipt.for_proposal(
            receipt_id="receipt-failed-result",
            proposal=self.proposal,
            status="FAILED",
            reservation=self.reservation,
            tool_result=failed_result,
            outcome_reason="the tool reported a typed failure",
        )
        self.assertEqual(typed_failure.result_binding, "FAILED")
        executor_failure = EffectReceipt.for_proposal(
            receipt_id="receipt-failed-executor",
            proposal=self.proposal,
            status="FAILED",
            reservation=self.reservation,
            execution_failure="EXECUTOR_CRASHED",
            outcome_reason="the executor crashed before producing a result",
        )
        self.assertEqual(executor_failure.result_binding, "EXECUTION_FAILURE")
        with self.assertRaises(ValueError):
            EffectReceipt.for_proposal(
                receipt_id="receipt-failed-empty",
                proposal=self.proposal,
                status="FAILED",
                reservation=self.reservation,
                outcome_reason="a failure without any typed evidence",
            )

    def test_ambiguous_receipt_cannot_claim_a_known_successful_result(self) -> None:
        with self.assertRaises(ValueError):
            EffectReceipt.for_proposal(
                receipt_id="receipt-ambiguous-ok",
                proposal=self.proposal,
                status="AMBIGUOUS",
                reservation=self.reservation,
                tool_result=self.result,
                outcome_reason="ambiguity cannot know the result",
            )
        ambiguous = EffectReceipt.for_proposal(
            receipt_id="receipt-ambiguous",
            proposal=self.proposal,
            status="AMBIGUOUS",
            reservation=self.reservation,
            outcome_reason="the effect boundary was interrupted",
        )
        self.assertFalse(ambiguous.effect_completed)
        self.assertFalse(ambiguous.outcome_known)
        self.assertTrue(ambiguous.replay_forbidden)
        self.assertTrue(ambiguous.reconciliation_required)

    def test_partial_mutation_ambiguity_requires_reconciliation_and_forbids_replay(self) -> None:
        for tool_name in ("write_file", "run_command"):
            specification = _spec("DIRECT", "run-direct")
            proposal = _proposal_for(specification, tool_name)
            decision = _decision_for(specification, proposal)
            reservation = EffectReservation.for_decision(
                specification=specification, reservation_id=f"reservation-{tool_name}", proposal=proposal, decision=decision
            )
            for status in ("AMBIGUOUS", "FAILED", "CANCELLED", "TIMED_OUT", "STARTED"):
                receipt = EffectReceipt.for_proposal(
                    receipt_id=f"receipt-{tool_name}-{status.lower()}",
                    proposal=proposal,
                    status=status,
                    reservation=reservation,
                    execution_failure="RESULT_NOT_PRODUCED" if status in {"FAILED", "CANCELLED", "TIMED_OUT"} else None,
                    outcome_reason=f"{status} mutating effect",
                )
                self.assertEqual(receipt.effect_application, "PARTIAL_OR_UNKNOWN", (tool_name, status))
                self.assertTrue(receipt.reconciliation_required, (tool_name, status))
                self.assertTrue(receipt.replay_forbidden, (tool_name, status))

    def test_receipts_never_carry_task_acceptance(self) -> None:
        receipt = self._completed()
        self.assertIsNone(receipt.task_acceptance)
        body = receipt.to_dict()
        self.assertIsNone(body["task_acceptance"])
        body["task_acceptance"] = "ACCEPTED"
        with self.assertRaises(ValueError):
            EffectReceipt.from_dict(_rebuild(body, fingerprint_field="receipt_fingerprint", schema_id="admissible.paired_runner.effect_receipt"))

    def test_reconciliation_refuses_a_receipt_from_another_proposal_or_reservation(self) -> None:
        receipt = self._completed()
        other_specification = _spec("DIRECT", "run-direct", experiment_id="exp-other")
        other_proposal = _proposal_for(other_specification, "read_file")
        other_decision = _decision_for(other_specification, other_proposal)
        other_reservation = EffectReservation.for_decision(
            specification=other_specification, reservation_id="reservation-other", proposal=other_proposal, decision=other_decision
        )
        with self.assertRaises(ValueError):
            receipt.validate_for_causal_chain(
                specification=other_specification, proposal=other_proposal, decision=other_decision, reservation=other_reservation
            )
        with self.assertRaises(ValueError):
            receipt.validate_for_causal_chain(
                specification=self.specification, proposal=self.proposal, decision=self.decision, reservation=other_reservation
            )
        with self.assertRaises(ValueError):
            receipt.validate_for_causal_chain(
                specification=self.specification, proposal=self.proposal, decision=self.decision, reservation=None
            )


class ExactRequestResultTests(unittest.TestCase):
    """M1-R09 and M1-R10: results bind their exact request; argv is explicit."""

    def setUp(self) -> None:
        self.grammar = _grammar()

    def test_successful_write_result_requires_the_exact_byte_count(self) -> None:
        request = WriteFileRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, path="src/new.py", content="abcdef"
        )
        self.assertEqual(len(request.content.encode("utf-8")), 6)
        wrong = WriteFileResult.create(
            request_fingerprint=request.request_fingerprint,
            bytes_written=1,
            written_content_fingerprint=written_content_fingerprint(request.content),
        )
        with self.assertRaises(ValueError):
            wrong.validate_for_request(request)
        exact = WriteFileResult.create(
            request_fingerprint=request.request_fingerprint,
            bytes_written=6,
            written_content_fingerprint=written_content_fingerprint(request.content),
        )
        self.assertIs(exact.validate_for_request(request), exact)

    def test_successful_write_result_requires_the_exact_content_fingerprint(self) -> None:
        request = WriteFileRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, path="src/new.py", content="abcdef"
        )
        wrong = WriteFileResult.create(
            request_fingerprint=request.request_fingerprint,
            bytes_written=6,
            written_content_fingerprint=written_content_fingerprint("abcdeg"),
        )
        with self.assertRaises(ValueError):
            wrong.validate_for_request(request)

    def test_arbitrary_written_content_fingerprint_domain_is_refused(self) -> None:
        request = WriteFileRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, path="src/new.py", content="abcdef"
        )
        self.assertEqual(
            written_content_fingerprint("abcdef").domain, WRITTEN_CONTENT_FINGERPRINT_DOMAIN
        )
        with self.assertRaises(ValueError):
            WriteFileResult.create(
                request_fingerprint=request.request_fingerprint,
                bytes_written=6,
                written_content_fingerprint=fingerprint({"anything": True}, domain="attacker.chosen.domain"),
            )

    def test_refused_or_failed_write_result_cannot_claim_mutation(self) -> None:
        request = WriteFileRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, path="src/new.py", content="abcdef"
        )
        for outcome in ("REFUSED", "FAILED"):
            with self.assertRaises(ValueError, msg=outcome):
                WriteFileResult.create(
                    request_fingerprint=request.request_fingerprint,
                    outcome=outcome,
                    bytes_written=6,
                    written_content_fingerprint=written_content_fingerprint(request.content),
                    error_code="OUT_OF_SCOPE",
                )

    def test_list_files_result_binds_its_request_limit_and_scope(self) -> None:
        request = ListFilesRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, path="src", recursive=False, max_entries=2
        )
        too_many = ListFilesResult.create(
            request_fingerprint=request.request_fingerprint, entries=("src/a.py", "src/b.py", "src/c.py")
        )
        with self.assertRaises(ValueError):
            too_many.validate_for_request(request)
        outside = ListFilesResult.create(request_fingerprint=request.request_fingerprint, entries=("docs/a.md",))
        with self.assertRaises(ValueError):
            outside.validate_for_request(request)
        nested = ListFilesResult.create(request_fingerprint=request.request_fingerprint, entries=("src/pkg/a.py",))
        with self.assertRaises(ValueError):
            nested.validate_for_request(request)
        premature_truncation = ListFilesResult.create(
            request_fingerprint=request.request_fingerprint, entries=("src/a.py",), truncated=True
        )
        with self.assertRaises(ValueError):
            premature_truncation.validate_for_request(request)
        exact = ListFilesResult.create(
            request_fingerprint=request.request_fingerprint, entries=("src/a.py", "src/b.py"), truncated=True
        )
        self.assertIs(exact.validate_for_request(request), exact)

    def test_read_file_result_binds_its_request_line_bound(self) -> None:
        request = ReadFileRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, path="src/main.py", max_lines=2
        )
        too_many_lines = ReadFileResult.create(request_fingerprint=request.request_fingerprint, content="a\nb\nc\n")
        with self.assertRaises(ValueError):
            too_many_lines.validate_for_request(request)
        premature_truncation = ReadFileResult.create(
            request_fingerprint=request.request_fingerprint, content="a\n", truncated=True
        )
        with self.assertRaises(ValueError):
            premature_truncation.validate_for_request(request)
        exact = ReadFileResult.create(request_fingerprint=request.request_fingerprint, content="a\nb\n", truncated=True)
        self.assertIs(exact.validate_for_request(request), exact)
        with self.assertRaises(ValueError):
            ReadFileResult.create(
                request_fingerprint=request.request_fingerprint, outcome="FAILED", content="a\n", error_code="IO_ERROR"
            )

    def test_run_command_output_exceeding_the_request_bound_is_refused(self) -> None:
        request = RunCommandRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, argv=("python", "-V"), max_output_bytes=8
        )
        oversized = RunCommandResult.create(
            request_fingerprint=request.request_fingerprint, stdout="x" * 9, process_started=True, exit_code=0
        )
        with self.assertRaises(ValueError):
            oversized.validate_for_request(request)
        premature_truncation = RunCommandResult.create(
            request_fingerprint=request.request_fingerprint,
            stdout="x",
            stdout_truncated=True,
            process_started=True,
            exit_code=0,
        )
        with self.assertRaises(ValueError):
            premature_truncation.validate_for_request(request)
        exact = RunCommandResult.create(
            request_fingerprint=request.request_fingerprint,
            stdout="x" * 8,
            stdout_truncated=True,
            process_started=True,
            exit_code=0,
        )
        self.assertIs(exact.validate_for_request(request), exact)

    def test_run_command_process_semantics_require_a_started_command(self) -> None:
        request = RunCommandRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, argv=("python", "-V"), max_output_bytes=64
        )
        with self.assertRaises(ValueError):
            RunCommandResult.create(
                request_fingerprint=request.request_fingerprint, outcome="OK", process_started=False, exit_code=0
            )
        with self.assertRaises(ValueError):
            RunCommandResult.create(
                request_fingerprint=request.request_fingerprint,
                outcome="FAILED",
                process_started=False,
                exit_code=3,
                error_code="START_FAILURE",
            )
        with self.assertRaises(ValueError):
            RunCommandResult.create(
                request_fingerprint=request.request_fingerprint,
                outcome="REFUSED",
                process_started=True,
                exit_code=None,
                error_code="OUT_OF_SCOPE",
            )
        non_zero = RunCommandResult.create(
            request_fingerprint=request.request_fingerprint, outcome="OK", process_started=True, exit_code=1
        )
        self.assertEqual(non_zero.outcome, "OK")
        self.assertEqual(non_zero.exit_code, 1)

    def test_results_refuse_a_request_from_another_tool(self) -> None:
        read_request = ReadFileRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, path="src/main.py", max_lines=4
        )
        write_request = WriteFileRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, path="src/new.py", content="abcdef"
        )
        result = ReadFileResult.create(request_fingerprint=read_request.request_fingerprint, content="a\n")
        with self.assertRaises(ValueError):
            result.validate_for_request(write_request)

    def test_run_command_refuses_an_empty_executable_token(self) -> None:
        with self.assertRaises(ValueError):
            RunCommandRequest.create(tool_grammar_fingerprint=self.grammar.grammar_fingerprint, argv=("",))
        with self.assertRaises(ValueError):
            RunCommandRequest.create(tool_grammar_fingerprint=self.grammar.grammar_fingerprint, argv=("", "-V"))
        with self.assertRaises(ValueError):
            RunCommandRequest.create(tool_grammar_fingerprint=self.grammar.grammar_fingerprint, argv=())
        with self.assertRaises(ValueError):
            RunCommandRequest.create(tool_grammar_fingerprint=self.grammar.grammar_fingerprint, argv="python -V")
        with self.assertRaises(ValueError):
            RunCommandRequest.create(tool_grammar_fingerprint=self.grammar.grammar_fingerprint, argv=("python", "\x00"))
        explicit = RunCommandRequest.create(
            tool_grammar_fingerprint=self.grammar.grammar_fingerprint, argv=("python", "-c", "")
        )
        self.assertEqual(explicit.argv, ("python", "-c", ""))


class ToolGrammarSpecificationTests(unittest.TestCase):
    """M1-R11: the experiment binds a machine-verifiable grammar, not a label."""

    def setUp(self) -> None:
        self.specification = _spec("DIRECT", "run-direct")
        self.grammar = self.specification.tool_grammar

    def test_grammar_binds_the_exact_schemas_versions_and_classifications(self) -> None:
        self.assertEqual(self.grammar.tool_names, ("list_files", "read_file", "run_command", "write_file"))
        for entry in self.grammar.entries:
            self.assertEqual(entry.effect_classification, TOOL_EFFECT_CLASSIFICATIONS[entry.tool_name])
            self.assertEqual(entry.request_schema_version, 1)
            self.assertEqual(entry.result_schema_version, 1)
            self.assertTrue(entry.request_schema_id.endswith(".request"))
            self.assertTrue(entry.result_schema_id.endswith(".result"))
        self.assertEqual(
            self.specification.tool_grammar_identity, derive_tool_grammar_identity(self.grammar)
        )

    def test_proposal_using_a_schema_absent_from_the_grammar_is_refused(self) -> None:
        body = self.grammar.to_dict()
        body["entries"] = [entry for entry in body["entries"] if entry["tool_name"] != "run_command"]
        body["tool_names"] = [name for name in body["tool_names"] if name != "run_command"]
        with self.assertRaises(ValueError):
            ToolGrammarSpecification.from_dict(
                _rebuild(body, fingerprint_field="grammar_fingerprint", schema_id=SCHEMA_TOOL_GRAMMAR)
            )
        with self.assertRaises(ValueError):
            self.grammar.entry_for("delete_file")
        forged_request = replace(
            _request_for("read_file", self.grammar),
            schema_id="admissible.paired_runner.tool.list_files.request",
        )
        with self.assertRaises(ValueError):
            self.grammar.validate_request(forged_request)

    def test_proposal_using_another_grammar_version_is_refused(self) -> None:
        other_grammar = _grammar("v2")
        self.assertNotEqual(other_grammar.grammar_fingerprint, self.grammar.grammar_fingerprint)
        foreign_request = _request_for("read_file", other_grammar)
        with self.assertRaises(ValueError):
            self.grammar.validate_request(foreign_request)
        with self.assertRaises(ValueError):
            CanonicalProposal.create(
                specification=self.specification,
                session_identity=_session(self.specification),
                turn_id="turn-0",
                proposal_id="proposal-foreign-grammar",
                prompt_identity=_identity("prompt", "prompt-1"),
                tool_request=foreign_request,
                causal_predecessor=CausalPredecessor.root(),
                wall_clock_observation=ClockObservation.wall_clock(1_725_000_000_000),
                monotonic_observation=ClockObservation.future_runtime_placeholder(),
            )

    def test_forged_descriptor_fingerprint_is_refused(self) -> None:
        entry_body = self.grammar.entries[0].to_dict()
        entry_body["request_descriptor_fingerprint"] = fingerprint(
            {"forged": "descriptor"}, domain=GRAMMAR_DESCRIPTOR_FINGERPRINT_DOMAIN
        ).to_dict()
        with self.assertRaises(ValueError):
            ToolGrammarEntry.from_dict(
                _rebuild(entry_body, fingerprint_field="entry_fingerprint", schema_id=SCHEMA_TOOL_GRAMMAR_ENTRY)
            )
        grammar_body = self.grammar.to_dict()
        grammar_body["entries"][0] = entry_body
        with self.assertRaises(ValueError):
            ToolGrammarSpecification.from_dict(
                _rebuild(grammar_body, fingerprint_field="grammar_fingerprint", schema_id=SCHEMA_TOOL_GRAMMAR)
            )

    def test_forged_effect_classification_is_refused(self) -> None:
        entry_body = self.grammar.entry_for("write_file").to_dict()
        entry_body["effect_classification"] = "READ_ONLY"
        with self.assertRaises(ValueError):
            ToolGrammarEntry.from_dict(
                _rebuild(entry_body, fingerprint_field="entry_fingerprint", schema_id=SCHEMA_TOOL_GRAMMAR_ENTRY)
            )

    def test_a_label_identity_cannot_stand_in_for_the_grammar_contents(self) -> None:
        with self.assertRaises(ValueError):
            replace(
                self.specification,
                tool_grammar_identity=_identity("tool_grammar", "opaque-label"),
            ).validated()
        with self.assertRaises(ValueError):
            replace(self.specification, tool_grammar=_grammar("v2")).validated()

    def test_parity_compares_the_same_grammar_specification_in_both_conditions(self) -> None:
        from admissible.paired_runner import check_parity

        direct = _spec("DIRECT", "run-direct")
        governed_same = _spec("GOVERNED", "run-governed")
        governed_other = _spec("GOVERNED", "run-governed", grammar_version="v2")
        self.assertTrue(check_parity(direct, governed_same).passed)
        report = check_parity(direct, governed_other)
        self.assertFalse(report.passed)
        self.assertEqual(report.refusal_code, "UNAUTHORIZED_DIFFERENCE")
        self.assertTrue(any(item.path.startswith("tool_grammar") for item in report.mismatches))


class TypedChainClosureTests(unittest.TestCase):
    """Positive closure: all four tools, both conditions, no effect executed."""

    def _chain(self, condition_id: str, tool_name: str) -> EffectReceipt:
        specification = _spec(condition_id, f"run-{condition_id.lower()}")
        proposal = _proposal_for(specification, tool_name)
        decision = _decision_for(specification, proposal)
        reservation = EffectReservation.for_decision(
            specification=specification,
            reservation_id=f"reservation-{condition_id.lower()}-{tool_name.replace('_', '-')}",
            proposal=proposal,
            decision=decision,
        )
        reservation.validate_for_decision(specification, proposal, decision)
        result = _successful_result(tool_name, proposal.tool_request)
        result.validate_for_request(proposal.tool_request)
        receipt = EffectReceipt.for_proposal(
            receipt_id=f"receipt-{condition_id.lower()}-{tool_name.replace('_', '-')}",
            proposal=proposal,
            status="COMPLETED",
            reservation=reservation,
            tool_result=result,
            process_exit_code=0 if tool_name == "run_command" else None,
            outcome_reason=f"{tool_name} completed under {condition_id}",
        )
        receipt.validate_for_causal_chain(
            specification=specification, proposal=proposal, decision=decision, reservation=reservation
        )
        restored = EffectReceipt.from_dict(parse_canonical_json(canonical_bytes(receipt.to_dict())))
        self.assertEqual(restored, receipt)
        restored.validate_for_causal_chain(
            specification=specification, proposal=proposal, decision=decision, reservation=reservation
        )
        return receipt

    def test_every_tool_closes_the_typed_chain_in_both_conditions(self) -> None:
        closures = 0
        for condition_id in ("DIRECT", "GOVERNED"):
            for tool_name in ("list_files", "read_file", "write_file", "run_command"):
                receipt = self._chain(condition_id, tool_name)
                self.assertEqual(receipt.status, "COMPLETED")
                self.assertEqual(receipt.effect_application, "APPLIED")
                self.assertEqual(receipt.result_binding, "OK")
                self.assertEqual(receipt.effect_classification, TOOL_EFFECT_CLASSIFICATIONS[tool_name])
                if tool_name == "run_command":
                    self.assertEqual(receipt.process_exit_code, 0)
                else:
                    self.assertIsNone(receipt.process_exit_code)
                closures += 1
        self.assertEqual(closures, 8)

    def test_governed_refusal_closes_without_a_reservation_or_result(self) -> None:
        specification = _spec("GOVERNED", "run-governed")
        proposal = _proposal_for(specification, "write_file")
        refusal = ModeDecision.governed(
            proposal, "REFUSE", governance_decision_reference="admissible-decision-refuse"
        )
        receipt = EffectReceipt.for_proposal(
            receipt_id="receipt-governed-refused",
            proposal=proposal,
            status="REFUSED",
            outcome_reason="the governed decision refused this effect before any mutation",
        )
        self.assertFalse(receipt.executed_effect)
        self.assertEqual(receipt.effect_application, "NOT_APPLIED")
        self.assertIsNone(receipt.tool_result)
        self.assertIs(
            receipt.validate_for_causal_chain(
                specification=specification, proposal=proposal, decision=refusal, reservation=None
            ),
            receipt,
        )

    def test_direct_and_governed_chains_differ_only_at_the_decision(self) -> None:
        direct = _spec("DIRECT", "run-direct")
        governed = _spec("GOVERNED", "run-governed")
        direct_proposal = _proposal_for(direct, "read_file")
        governed_proposal = _proposal_for(governed, "read_file")
        self.assertEqual(direct_proposal.tool_request, governed_proposal.tool_request)
        self.assertEqual(
            ModeDecision.direct(direct_proposal).execution_prerequisite, "NONE"
        )
        self.assertEqual(
            _decision_for(governed, governed_proposal).execution_prerequisite, "ADMISSIBLE_DECISION"
        )


class PreRepairObjectRejectionTests(unittest.TestCase):
    """Version 1 stays only because no pre-repair M1 object still deserializes."""

    def test_pre_repair_shapes_cannot_deserialize(self) -> None:
        specification = _spec("DIRECT", "run-direct")
        proposal = _proposal_for(specification, "run_command")
        decision = _decision_for(specification, proposal)
        reservation = EffectReservation.for_decision(
            specification=specification, reservation_id="reservation-1", proposal=proposal, decision=decision
        )
        pre_repair_specification = specification.to_dict()
        pre_repair_specification.pop("tool_grammar")
        pre_repair_specification.pop("evaluator_specification")
        with self.assertRaises(ValueError):
            ExperimentSpecification.from_dict(pre_repair_specification)

        receipt = EffectReceipt.for_proposal(
            receipt_id="receipt-1",
            proposal=proposal,
            status="COMPLETED",
            reservation=reservation,
            tool_result=_successful_result("run_command", proposal.tool_request),
            process_exit_code=0,
            outcome_reason="completed run_command",
        )
        pre_repair_receipt = receipt.to_dict()
        for field in ("tool_name", "effect_classification", "tool_request_fingerprint", "tool_result",
                      "execution_failure", "effect_application"):
            pre_repair_receipt.pop(field)
        with self.assertRaises(ValueError):
            EffectReceipt.from_dict(pre_repair_receipt)

        pre_repair_result = _successful_result("run_command", proposal.tool_request).to_dict()
        pre_repair_result.pop("process_started")
        with self.assertRaises(ValueError):
            RunCommandResult.from_dict(pre_repair_result)


if __name__ == "__main__":
    unittest.main()
