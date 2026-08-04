from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from itertools import product
import unittest

from admissible.paired_runner import (
    AllowedConditionDifferences,
    BudgetLimits,
    BudgetState,
    CanonicalProposal,
    ComparativeManifest,
    ConditionConfiguration,
    EffectReceipt,
    EffectReservation,
    EvaluatorSpecification,
    ExperimentSpecification,
    Fingerprint,
    HumanInterventionRecord,
    IdentityReference,
    ModeDecision,
    ParityReport,
    RunIdentity,
    SessionIdentity,
    TerminalManifest,
    canonical_bytes,
    check_parity,
    fingerprint,
    fingerprint_bytes,
    parse_canonical_json,
    require_parity,
    ListFilesRequest,
    ListFilesResult,
    ReadFileRequest,
    ReadFileResult,
    RunCommandRequest,
    RunCommandResult,
    WriteFileRequest,
    WriteFileResult,
)
from admissible.paired_runner.canonical import (
    CanonicalizationError,
    DuplicateKeyError,
    NonCanonicalEncodingError,
)
from admissible.paired_runner.specification import (
    CausalPredecessor,
    ClockObservation,
    validate_unique_proposal_ids,
)
from admissible.paired_runner.schemas import RECEIPT_STATE_MATRIX, TERMINAL_STATE_MATRIX
from admissible.paired_runner.tool_schemas import (
    MAX_CONTENT_BYTES,
    RESULT_FINGERPRINT_DOMAINS,
    REQUEST_FINGERPRINT_DOMAINS,
    tool_request_from_dict,
    tool_result_from_dict,
)


def _material_fingerprint(label: str, domain: str) -> Fingerprint:
    return fingerprint({"label": label}, domain=domain)


def _identity(kind: str, label: str) -> IdentityReference:
    return IdentityReference.create(
        kind=kind,
        name=f"{kind}-{label}",
        version="v1",
        material={"label": label, "kind": kind},
    )


def _limits(*, sessions: int = 10) -> BudgetLimits:
    return BudgetLimits(
        sessions=sessions,
        turns=100,
        proposals=1000,
        effects=1000,
        commands=1000,
        wall_time_ms=3_600_000,
        model_active_time_ms=3_000_000,
        output_bytes=10_000_000,
        retries=10,
        continuations=20,
        human_interventions=5,
    )


def _spec(
    condition_id: str,
    run_id: str,
    *,
    experiment_id: str = "exp-m1-fixture",
    prompt_label: str = "prompt-1",
    state_label: str = "state-1",
    model_label: str = "model-1",
    executable_label: str = "executable-1",
    transport_label: str = "transport-1",
    grammar_label: str = "grammar-1",
    environment_label: str = "environment-1",
    dependency_label: str = "dependency-1",
    policy_label: str = "policy-1",
    effect_executor_label: str = "effect-executor-1",
    evaluator_label: str = "evaluator-1",
    working_root_label: str = "root-1",
    scope_label: str = "scope-1",
    sessions_limit: int = 10,
) -> ExperimentSpecification:
    condition = ConditionConfiguration.create(condition_id)
    run = RunIdentity.create(
        experiment_id=experiment_id,
        condition_id=condition_id,
        run_id=run_id,
    )
    prompt_identity = _identity("prompt", prompt_label)
    return ExperimentSpecification.create(
        experiment_id=experiment_id,
        task_prompt_fingerprint=prompt_identity.content_fingerprint,
        initial_state_fingerprint=_material_fingerprint(state_label, "test.initial.state"),
        model_identity=_identity("model", model_label),
        executable_identity=_identity("executable", executable_label),
        executable_digest=_material_fingerprint(executable_label, "test.executable.bytes"),
        transport_identity=_identity("transport", transport_label),
        tool_grammar_identity=_identity("tool_grammar", grammar_label),
        environment_identity=_identity("environment", environment_label),
        dependency_toolchain_identity=_identity("dependency_toolchain", dependency_label),
        common_filesystem_network_process_policy_identity=_identity("filesystem_network_process_policy", policy_label),
        working_root_identity=_identity("working_root", working_root_label),
        scope_identity=_identity("scope", scope_label),
        effect_executor_identity=_identity("effect_executor", effect_executor_label),
        evaluator_identity=_identity("evaluator", evaluator_label),
        common_budgets=BudgetState.create(limits=_limits(sessions=sessions_limit)),
        allowed_condition_differences=AllowedConditionDifferences.create(),
        condition=condition,
        run_identity=run,
    )


def _proposal(condition_id: str = "DIRECT", run_id: str = "run-direct") -> CanonicalProposal:
    specification = _spec(condition_id, run_id, experiment_id="exp-m1-proposal")
    session = SessionIdentity.create(run=specification.run_identity, session_id=f"session-{condition_id.lower()}")
    return CanonicalProposal.create(
        specification=specification,
        session_identity=session,
        turn_id="turn-0",
        proposal_id=f"proposal-{condition_id.lower()}",
        prompt_identity=_identity("prompt", "prompt-1"),
        tool_request=ReadFileRequest.create(
            tool_grammar_fingerprint=specification.tool_grammar_identity.content_fingerprint,
            path="src/main.py",
            start_line=1,
            max_lines=3,
        ),
        causal_predecessor=CausalPredecessor.root(),
        wall_clock_observation=ClockObservation.wall_clock(1_725_000_000_000),
        monotonic_observation=ClockObservation.future_runtime_placeholder(),
    )


def _tool_fixture_records():
    grammar = fingerprint({"grammar": "four-tools-v1"}, domain="test.tool.grammar")
    requests = {
        "list_files": ListFilesRequest.create(tool_grammar_fingerprint=grammar, path="src", recursive=True, max_entries=100),
        "read_file": ReadFileRequest.create(tool_grammar_fingerprint=grammar, path="src/main.py", start_line=1, max_lines=100),
        "write_file": WriteFileRequest.create(tool_grammar_fingerprint=grammar, path="src/new.py", content="pass\n", create_parents=False),
        "run_command": RunCommandRequest.create(tool_grammar_fingerprint=grammar, argv=("python", "-V"), cwd=".", timeout_ms=1000, max_output_bytes=4096),
    }
    content_fp = fingerprint_bytes(b"pass\n", domain="test.written.content")
    results = {
        "list_files": ListFilesResult.create(request_fingerprint=requests["list_files"].request_fingerprint, entries=("src/main.py",)),
        "read_file": ReadFileResult.create(request_fingerprint=requests["read_file"].request_fingerprint, content="print(1)\n"),
        "write_file": WriteFileResult.create(request_fingerprint=requests["write_file"].request_fingerprint, bytes_written=5, written_content_fingerprint=content_fp),
        "run_command": RunCommandResult.create(request_fingerprint=requests["run_command"].request_fingerprint, stdout="Python\n", exit_code=0),
    }
    return requests, results


def _evaluator() -> EvaluatorSpecification:
    return EvaluatorSpecification.create(
        evaluator_id="evaluator-m1",
        evaluator_version="v1",
        requirements_fingerprint=_material_fingerprint("requirements", "test.requirements"),
        scope_fingerprint=_material_fingerprint("scope", "test.scope"),
        test_plan_fingerprint=_material_fingerprint("tests", "test.plan"),
        environment_identity=_identity("environment", "environment-1"),
    )


def _terminal(specification: ExperimentSpecification, label: str, *, task_acceptance: str = "ACCEPTED", reconciliation_complete: bool = True) -> TerminalManifest:
    evaluator = _evaluator()
    return TerminalManifest.create(
        run_identity=specification.run_identity,
        experiment_specification_fingerprint=specification.specification_fingerprint,
        repository_state_fingerprint=_material_fingerprint(f"repo-{label}", "test.repository"),
        proposal_ledger_fingerprint=_material_fingerprint(f"proposals-{label}", "test.proposals"),
        effect_receipt_ledger_fingerprint=_material_fingerprint(f"receipts-{label}", "test.receipts"),
        budget_state_fingerprint=specification.common_budgets.budget_fingerprint,
        evaluator_specification_fingerprint=evaluator.evaluator_fingerprint,
        model_completion_claim="CLAIMED_COMPLETE",
        process_result="SUCCESS",
        task_acceptance=task_acceptance,
        reconciliation_complete=reconciliation_complete,
    )


def _leaf_mutations(value: object, path: str = ""):
    """Yield (leaf path, whole-value mutation) pairs without coercion."""

    if isinstance(value, dict):
        for key in sorted(value):
            child_path = f"{path}.{key}" if path else key
            for leaf_path, child_mutation in _leaf_mutations(value[key], child_path):
                changed = deepcopy(value)
                changed[key] = child_mutation
                yield leaf_path, changed
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            child_path = f"{path}[{index}]"
            for leaf_path, child_mutation in _leaf_mutations(item, child_path):
                changed = deepcopy(value)
                changed[index] = child_mutation
                yield leaf_path, changed
        return
    if isinstance(value, bool):
        yield path, not value
    elif isinstance(value, int):
        yield path, value + 1
    elif isinstance(value, str):
        yield path, value + "-changed"
    elif value is None:
        yield path, 0
    else:
        raise AssertionError(f"unsupported fixture leaf at {path}: {value!r}")


class CanonicalizationTests(unittest.TestCase):
    def test_repeated_serialization_and_insertion_order_are_stable(self) -> None:
        left = {"z": [3, {"b": True, "a": None}], "a": "é"}
        right = {"a": "é", "z": [3, {"a": None, "b": True}]}
        self.assertEqual(canonical_bytes(left), canonical_bytes(right))
        self.assertEqual(canonical_bytes(left), canonical_bytes(left))

    def test_unknown_fields_duplicate_keys_and_noncanonical_values_are_refused(self) -> None:
        identity = RunIdentity.create(
            experiment_id="exp",
            condition_id="DIRECT",
            run_id="run-1",
        )
        raw = identity.to_dict()
        raw["unknown"] = True
        with self.assertRaises(ValueError):
            RunIdentity.from_dict(raw)
        with self.assertRaises(DuplicateKeyError):
            parse_canonical_json(b'{"a":1,"a":2}')
        with self.assertRaises(CanonicalizationError):
            canonical_bytes(float("nan"))
        with self.assertRaises(CanonicalizationError):
            canonical_bytes(float("inf"))
        with self.assertRaises(CanonicalizationError):
            parse_canonical_json(b"NaN")
        with self.assertRaises(CanonicalizationError):
            parse_canonical_json(b"Infinity")
        with self.assertRaises(CanonicalizationError):
            parse_canonical_json(b"-Infinity")
        with self.assertRaises(CanonicalizationError):
            parse_canonical_json(b'{"value":1.0}')
        with self.assertRaises(NonCanonicalEncodingError):
            parse_canonical_json(b'{ "b": 2, "a": 1 }')

    def test_domain_separation_and_normative_mutations_change_fingerprints(self) -> None:
        material = {"a": 1, "b": [True, "x"]}
        self.assertNotEqual(
            fingerprint(material, domain="domain.one"),
            fingerprint(material, domain="domain.two"),
        )
        base = _spec("DIRECT", "run-direct").normative_dict()
        original = fingerprint(base, domain="test.normative")
        mutation_count = 0
        for path, changed in _leaf_mutations(base):
            mutation_count += 1
            self.assertNotEqual(original, fingerprint(changed, domain="test.normative"), path)
        self.assertGreater(mutation_count, 50)


class ToolSchemaTests(unittest.TestCase):
    def test_all_tool_requests_and_results_round_trip_through_exact_schema(self) -> None:
        requests, results = _tool_fixture_records()
        for tool_name, request in requests.items():
            self.assertEqual(request.tool_name, tool_name)
            self.assertEqual(request.__class__.from_dict(request.to_dict()), request)
            self.assertEqual(tool_request_from_dict(request.to_dict()), request)
            self.assertEqual(request.request_fingerprint.domain, REQUEST_FINGERPRINT_DOMAINS[tool_name])
        for tool_name, result in results.items():
            self.assertEqual(result.__class__.from_dict(result.to_dict()), result)
            self.assertEqual(tool_result_from_dict(result.to_dict()), result)
            self.assertEqual(result.result_fingerprint.domain, RESULT_FINGERPRINT_DOMAINS[tool_name])

    def test_missing_extra_wrong_type_over_bound_and_cross_tool_values_are_refused(self) -> None:
        requests, results = _tool_fixture_records()
        read_data = requests["read_file"].to_dict()
        for mutation in (
            lambda value: value.pop("path"),
            lambda value: value.update({"unexpected": True}),
            lambda value: value.update({"path": 4}),
            lambda value: value.update({"max_lines": 10_001}),
        ):
            changed = deepcopy(read_data)
            mutation(changed)
            with self.assertRaises(ValueError):
                ReadFileRequest.from_dict(changed)
        with self.assertRaises(ValueError):
            ListFilesRequest.from_dict(read_data)
        with self.assertRaises(ValueError):
            RunCommandRequest.from_dict({**requests["run_command"].to_dict(), "argv": "python"})
        write_without_optional = requests["write_file"].to_dict()
        write_without_optional.pop("create_parents")
        self.assertEqual(WriteFileRequest.from_dict(write_without_optional), requests["write_file"])
        with self.assertRaises(ValueError):
            WriteFileRequest.from_dict({**requests["write_file"].to_dict(), "create_parents": None})
        with self.assertRaises(ValueError):
            ReadFileResult.from_dict({**results["read_file"].to_dict(), "unexpected": True})
        with self.assertRaises(ValueError):
            WriteFileResult.from_dict({**results["write_file"].to_dict(), "bytes_written": MAX_CONTENT_BYTES + 1})
        with self.assertRaises(ValueError):
            ListFilesResult.create(request_fingerprint=requests["read_file"].request_fingerprint, entries=("src/main.py",))

    def test_formerly_accepted_generic_read_file_payload_is_refused(self) -> None:
        proposal = _proposal()
        raw = proposal.to_dict()
        raw["tool_request"] = {"command": "rm -rf /", "unexpected": True}
        with self.assertRaises(ValueError):
            CanonicalProposal.from_dict(raw)

    def test_cross_tool_request_cannot_hide_behind_a_proposal_tool_name(self) -> None:
        proposal = _proposal()
        forged = replace(proposal, tool_name="write_file")
        with self.assertRaises(ValueError):
            forged.validated()


class SchemaAndIdentityTests(unittest.TestCase):
    def test_identity_and_session_binding(self) -> None:
        run = RunIdentity.create(experiment_id="exp", condition_id="DIRECT", run_id="run-a")
        session = SessionIdentity.create(run=run, session_id="session-a")
        self.assertEqual(SessionIdentity.from_dict(session.to_dict()), session)
        session.validate_for_run(run)
        other_run = RunIdentity.create(experiment_id="exp", condition_id="DIRECT", run_id="run-b")
        with self.assertRaises(ValueError):
            session.validate_for_run(other_run)
        other_condition = RunIdentity.create(experiment_id="exp", condition_id="GOVERNED", run_id="run-c")
        with self.assertRaises(ValueError):
            session.validate_for_run(other_condition)

    def test_all_required_objects_round_trip(self) -> None:
        direct = _spec("DIRECT", "run-direct")
        governed = _spec("GOVERNED", "run-governed")
        proposal = _proposal()
        proposal_spec = _spec("DIRECT", "run-direct", experiment_id="exp-m1-proposal")
        direct_decision = ModeDecision.direct(proposal)
        reservation = EffectReservation.for_decision(
            specification=proposal_spec,
            reservation_id="reservation-direct",
            proposal=proposal,
            decision=direct_decision,
        )
        receipt = EffectReceipt.create(
            receipt_id="receipt-proposed",
            proposal_fingerprint=proposal.proposal_fingerprint,
            status="PROPOSED",
            outcome_reason="proposal is recorded before a future effect",
        )
        intervention = HumanInterventionRecord.create(
            intervention_id="intervention-1",
            actor_class="OPERATOR",
            reason="predeclared observation-only note",
            wall_clock_observation=ClockObservation.wall_clock(1_725_000_000_001),
            monotonic_observation=ClockObservation.future_runtime_placeholder(),
            run_identity=proposal.run_identity,
            session_id=proposal.session_identity.session_id,
            proposal_id=proposal.proposal_id,
            allowed_policy_category="PREDECLARED_ASSISTANCE",
            comparability_disposition="QUALIFY",
        )
        evaluator = EvaluatorSpecification.create(
            evaluator_id="evaluator-m1",
            evaluator_version="v1",
            requirements_fingerprint=_material_fingerprint("requirements", "test.requirements"),
            scope_fingerprint=_material_fingerprint("scope", "test.scope"),
            test_plan_fingerprint=_material_fingerprint("tests", "test.plan"),
            environment_identity=_identity("environment", "environment-1"),
        )
        direct_terminal = TerminalManifest.create(
            run_identity=direct.run_identity,
            experiment_specification_fingerprint=direct.specification_fingerprint,
            repository_state_fingerprint=_material_fingerprint("repo", "test.repository"),
            proposal_ledger_fingerprint=_material_fingerprint("proposals", "test.proposals"),
            effect_receipt_ledger_fingerprint=_material_fingerprint("receipts", "test.receipts"),
            budget_state_fingerprint=direct.common_budgets.budget_fingerprint,
            evaluator_specification_fingerprint=evaluator.evaluator_fingerprint,
            model_completion_claim="CLAIMED_COMPLETE",
            process_result="SUCCESS",
            task_acceptance="REJECTED",
            reconciliation_complete=True,
        )
        governed_terminal = TerminalManifest.create(
            run_identity=governed.run_identity,
            experiment_specification_fingerprint=governed.specification_fingerprint,
            repository_state_fingerprint=_material_fingerprint("repo-governed", "test.repository"),
            proposal_ledger_fingerprint=_material_fingerprint("proposals-governed", "test.proposals"),
            effect_receipt_ledger_fingerprint=_material_fingerprint("receipts-governed", "test.receipts"),
            budget_state_fingerprint=governed.common_budgets.budget_fingerprint,
            evaluator_specification_fingerprint=evaluator.evaluator_fingerprint,
            model_completion_claim="CLAIMED_COMPLETE",
            process_result="SUCCESS",
            task_acceptance="REJECTED",
            reconciliation_complete=True,
        )
        parity = check_parity(direct, governed)
        comparative = ComparativeManifest.create(
            direct_specification=direct,
            governed_specification=governed,
            parity_report=parity,
            direct_terminal_manifest=direct_terminal,
            governed_terminal_manifest=governed_terminal,
        )
        fingerprint_object = fingerprint({"round_trip": True}, domain="test.fingerprint")
        identity = _identity("model", "round-trip-model")
        condition = ConditionConfiguration.create("DIRECT")
        allowlist = AllowedConditionDifferences.create()
        budget = direct.common_budgets
        clock = ClockObservation.wall_clock(1_725_000_000_002)
        causal = CausalPredecessor.root()
        grammar_fp = direct.tool_grammar_identity.content_fingerprint
        list_request = ListFilesRequest.create(tool_grammar_fingerprint=grammar_fp)
        read_request = ReadFileRequest.create(tool_grammar_fingerprint=grammar_fp, path="src/main.py")
        write_request = WriteFileRequest.create(tool_grammar_fingerprint=grammar_fp, path="src/new.py", content="pass\n")
        command_request = RunCommandRequest.create(tool_grammar_fingerprint=grammar_fp, argv=("python", "-V"))
        list_result = ListFilesResult.create(request_fingerprint=list_request.request_fingerprint, entries=("src/main.py",))
        read_result = ReadFileResult.create(request_fingerprint=read_request.request_fingerprint, content="print(1)\n")
        write_result = WriteFileResult.create(
            request_fingerprint=write_request.request_fingerprint,
            written_content_fingerprint=fingerprint_bytes(b"pass\n", domain="test.written.content"),
            bytes_written=5,
        )
        command_result = RunCommandResult.create(request_fingerprint=command_request.request_fingerprint, stdout="Python\n")
        objects = [
            fingerprint_object,
            identity,
            condition,
            allowlist,
            budget,
            clock,
            causal,
            direct,
            proposal.run_identity,
            proposal.session_identity,
            proposal,
            list_request,
            read_request,
            write_request,
            command_request,
            list_result,
            read_result,
            write_result,
            command_result,
            direct_decision,
            reservation,
            receipt,
            intervention,
            evaluator,
            direct_terminal,
            governed_terminal,
            comparative,
            parity,
        ]
        self.assertEqual(len(objects), 28)
        factories = {
            Fingerprint: Fingerprint.from_dict,
            IdentityReference: IdentityReference.from_dict,
            ConditionConfiguration: ConditionConfiguration.from_dict,
            AllowedConditionDifferences: AllowedConditionDifferences.from_dict,
            BudgetState: BudgetState.from_dict,
            ClockObservation: ClockObservation.from_dict,
            CausalPredecessor: CausalPredecessor.from_dict,
            ExperimentSpecification: ExperimentSpecification.from_dict,
            RunIdentity: RunIdentity.from_dict,
            SessionIdentity: SessionIdentity.from_dict,
            CanonicalProposal: CanonicalProposal.from_dict,
            ListFilesRequest: ListFilesRequest.from_dict,
            ReadFileRequest: ReadFileRequest.from_dict,
            WriteFileRequest: WriteFileRequest.from_dict,
            RunCommandRequest: RunCommandRequest.from_dict,
            ListFilesResult: ListFilesResult.from_dict,
            ReadFileResult: ReadFileResult.from_dict,
            WriteFileResult: WriteFileResult.from_dict,
            RunCommandResult: RunCommandResult.from_dict,
            ModeDecision: ModeDecision.from_dict,
            EffectReservation: EffectReservation.from_dict,
            EffectReceipt: EffectReceipt.from_dict,
            HumanInterventionRecord: HumanInterventionRecord.from_dict,
            EvaluatorSpecification: EvaluatorSpecification.from_dict,
            TerminalManifest: TerminalManifest.from_dict,
            ComparativeManifest: ComparativeManifest.from_dict,
            ParityReport: ParityReport.from_dict,
        }
        for obj in objects:
            self.assertEqual(factories[type(obj)](obj.to_dict()), obj, type(obj).__name__)
        self.assertEqual(direct, ExperimentSpecification.from_dict(parse_canonical_json(canonical_bytes(direct.to_dict()))))
        self.assertEqual(comparative, ComparativeManifest.from_dict(parse_canonical_json(canonical_bytes(comparative.to_dict()))))
        comparative.validate_for_specifications(
            direct_specification=direct,
            governed_specification=governed,
            parity_report=parity,
        )
        with self.assertRaises(ValueError):
            ComparativeManifest.create(
                direct_specification=direct,
                governed_specification=_spec("GOVERNED", "run-governed", prompt_label="changed-prompt"),
                parity_report=parity,
                direct_terminal_manifest=direct_terminal,
                governed_terminal_manifest=governed_terminal,
            )
        with self.assertRaises(ValueError):
            ComparativeManifest.create(
                direct_specification=direct,
                governed_specification=governed,
                parity_report=parity,
                direct_terminal_manifest=direct_terminal,
                governed_terminal_manifest=direct_terminal,
            )

    def test_wrong_schema_missing_extra_and_wrong_type_are_refused(self) -> None:
        identity = RunIdentity.create(experiment_id="exp", condition_id="DIRECT", run_id="run")
        raw = identity.to_dict()
        raw["schema_version"] = 2
        with self.assertRaises(ValueError):
            RunIdentity.from_dict(raw)
        raw = identity.to_dict()
        del raw["run_id"]
        with self.assertRaises(ValueError):
            RunIdentity.from_dict(raw)
        raw = identity.to_dict()
        raw["run_id"] = 4
        with self.assertRaises(ValueError):
            RunIdentity.from_dict(raw)

    def test_duplicate_proposal_identity_is_refused(self) -> None:
        proposal = _proposal()
        with self.assertRaises(ValueError):
            validate_unique_proposal_ids((proposal, proposal))


class SpecificationBindingTests(unittest.TestCase):
    def test_proposal_is_fail_closed_against_every_specification_binding_mutation(self) -> None:
        specification = _spec("DIRECT", "run-direct", experiment_id="exp-m1-proposal")
        proposal = _proposal("DIRECT", "run-direct")
        variants = (
            _spec("DIRECT", "run-other", experiment_id="exp-m1-proposal"),
            _spec("GOVERNED", "run-direct", experiment_id="exp-m1-proposal"),
            _spec("DIRECT", "run-direct", experiment_id="exp-m1-proposal", model_label="model-2"),
            _spec("DIRECT", "run-direct", experiment_id="exp-m1-proposal", transport_label="transport-2"),
            _spec("DIRECT", "run-direct", experiment_id="exp-m1-proposal", prompt_label="prompt-2"),
            _spec("DIRECT", "run-direct", experiment_id="exp-m1-proposal", grammar_label="grammar-2"),
            _spec("DIRECT", "run-direct", experiment_id="exp-m1-proposal", working_root_label="root-2"),
            _spec("DIRECT", "run-direct", experiment_id="exp-m1-proposal", scope_label="scope-2"),
        )
        for variant in variants:
            with self.assertRaises(ValueError):
                proposal.validate_for_specification(variant)
        self.assertIs(proposal.validate_for_specification(specification), proposal)

    def test_constructor_rejects_request_from_a_different_grammar(self) -> None:
        specification = _spec("DIRECT", "run-direct", experiment_id="exp-m1-proposal")
        session = SessionIdentity.create(run=specification.run_identity, session_id="session-direct")
        with self.assertRaises(ValueError):
            CanonicalProposal.create(
                specification=specification,
                session_identity=session,
                turn_id="turn-0",
                proposal_id="proposal-direct",
                prompt_identity=_identity("prompt", "prompt-1"),
                tool_request=ReadFileRequest.create(
                    tool_grammar_fingerprint=fingerprint({"different": True}, domain="test.other.grammar"),
                    path="src/main.py",
                ),
                causal_predecessor=CausalPredecessor.root(),
                wall_clock_observation=ClockObservation.wall_clock(1_725_000_000_000),
                monotonic_observation=ClockObservation.future_runtime_placeholder(),
            )

    def test_reservation_binds_exact_specification_and_executor(self) -> None:
        specification = _spec("DIRECT", "run-direct", experiment_id="exp-m1-proposal")
        proposal = _proposal("DIRECT", "run-direct")
        decision = ModeDecision.direct(proposal)
        reservation = EffectReservation.for_decision(
            specification=specification,
            reservation_id="reservation-direct",
            proposal=proposal,
            decision=decision,
        )
        self.assertEqual(reservation.experiment_specification_fingerprint, specification.specification_fingerprint)
        self.assertEqual(reservation.effect_executor_identity, specification.effect_executor_identity)
        forged = replace(reservation, effect_executor_identity=_identity("effect_executor", "different-executor"))
        with self.assertRaises(ValueError):
            forged.validate_for_specification(specification)


class ModeAndReceiptTests(unittest.TestCase):
    def test_decision_boundary_invariants(self) -> None:
        direct = _proposal("DIRECT", "run-direct")
        governed = _proposal("GOVERNED", "run-governed")
        self.assertEqual(ModeDecision.direct(direct).decision, "DIRECT_EXECUTION")
        self.assertFalse(ModeDecision.direct(direct).governance_decision_reference is not None)
        with self.assertRaises(ValueError):
            ModeDecision.direct(governed)
        with self.assertRaises(ValueError):
            ModeDecision.governed(
                direct,
                "ALLOW",
                governance_decision_reference="decision-1",
            )
        governed_decision = ModeDecision.governed(
            governed,
            "ALLOW",
            governance_decision_reference="decision-1",
        )
        self.assertEqual(governed_decision.execution_prerequisite, "ADMISSIBLE_DECISION")
        with self.assertRaises(ValueError):
            EffectReceipt.create(
                receipt_id="refused-executed",
                proposal_fingerprint=direct.proposal_fingerprint,
                status="REFUSED",
                executed_effect=True,
                outcome_reason="impossible combination",
            )
        self.assertTrue(governed_decision.permits_effect)

    def test_exhaustive_receipt_state_matrix_accepts_only_documented_combinations(self) -> None:
        proposal = _proposal()
        reservation_fp = _material_fingerprint("reservation", "test.reservation")
        accepted = 0
        examined = 0
        for status, rule in RECEIPT_STATE_MATRIX.items():
            for flags in product((False, True), repeat=6):
                (
                    effect_started,
                    effect_completed,
                    executed_effect,
                    outcome_known,
                    replay_forbidden,
                    reconciliation_required,
                ) = flags
                examined += 1
                is_valid_flags = flags == (
                    rule.effect_started,
                    rule.effect_completed,
                    rule.executed_effect,
                    rule.outcome_known,
                    rule.replay_forbidden,
                    rule.reconciliation_required,
                )
                try:
                    receipt = EffectReceipt.create(
                        receipt_id=f"receipt-{status.lower()}-{effect_started}{effect_completed}{executed_effect}",
                        proposal_fingerprint=proposal.proposal_fingerprint,
                        reservation_fingerprint=reservation_fp if rule.reservation == "REQUIRED" else None,
                        status=status,
                        effect_started=effect_started,
                        effect_completed=effect_completed,
                        executed_effect=executed_effect,
                        outcome_known=outcome_known,
                        replay_forbidden=replay_forbidden,
                        reconciliation_required=reconciliation_required,
                        process_exit_code=0 if rule.process_exit_code == "REQUIRED" else None,
                        outcome_reason="table-driven receipt fixture",
                    )
                except ValueError:
                    self.assertFalse(is_valid_flags, f"documented valid combination rejected: {status}")
                else:
                    self.assertTrue(is_valid_flags, f"contradictory combination accepted: {status}")
                    self.assertIs(receipt.validated(), receipt)
                    accepted += 1
        self.assertEqual(examined, len(RECEIPT_STATE_MATRIX) * 64)
        self.assertEqual(accepted, len(RECEIPT_STATE_MATRIX))

    def test_every_receipt_status_rejects_contradictory_reservation_and_process_result(self) -> None:
        proposal = _proposal()
        reservation_fp = _material_fingerprint("reservation", "test.reservation")
        for status, rule in RECEIPT_STATE_MATRIX.items():
            if rule.reservation == "REQUIRED":
                with self.assertRaises(ValueError):
                    EffectReceipt.create(
                        receipt_id=f"missing-reservation-{status.lower()}",
                        proposal_fingerprint=proposal.proposal_fingerprint,
                        status=status,
                        reservation_fingerprint=None,
                        effect_started=rule.effect_started,
                        effect_completed=rule.effect_completed,
                        executed_effect=rule.executed_effect,
                        process_exit_code=0 if rule.process_exit_code == "REQUIRED" else None,
                        outcome_reason="missing reservation",
                    )
            else:
                with self.assertRaises(ValueError):
                    EffectReceipt.create(
                        receipt_id=f"unexpected-reservation-{status.lower()}",
                        proposal_fingerprint=proposal.proposal_fingerprint,
                        status=status,
                        reservation_fingerprint=reservation_fp,
                        effect_started=rule.effect_started,
                        effect_completed=rule.effect_completed,
                        executed_effect=rule.executed_effect,
                        process_exit_code=0 if rule.process_exit_code == "REQUIRED" else None,
                        outcome_reason="unexpected reservation",
                    )
            if rule.process_exit_code == "FORBIDDEN":
                with self.assertRaises(ValueError):
                    EffectReceipt.create(
                        receipt_id=f"unexpected-exit-{status.lower()}",
                        proposal_fingerprint=proposal.proposal_fingerprint,
                        status=status,
                        reservation_fingerprint=reservation_fp if rule.reservation == "REQUIRED" else None,
                        effect_started=rule.effect_started,
                        effect_completed=rule.effect_completed,
                        executed_effect=rule.executed_effect,
                        process_exit_code=0,
                        outcome_reason="unexpected process result",
                    )
            elif rule.process_exit_code == "REQUIRED":
                with self.assertRaises(ValueError):
                    EffectReceipt.create(
                        receipt_id=f"missing-exit-{status.lower()}",
                        proposal_fingerprint=proposal.proposal_fingerprint,
                        status=status,
                        reservation_fingerprint=reservation_fp,
                        effect_started=rule.effect_started,
                        effect_completed=rule.effect_completed,
                        executed_effect=rule.executed_effect,
                        process_exit_code=None,
                        outcome_reason="missing process result",
                    )

    def test_ambiguous_receipt_cannot_claim_completion(self) -> None:
        proposal = _proposal()
        with self.assertRaises(ValueError):
            EffectReceipt.create(
                receipt_id="ambiguous-completed",
                proposal_fingerprint=proposal.proposal_fingerprint,
                reservation_fingerprint=_material_fingerprint("reservation", "test.reservation"),
                status="AMBIGUOUS",
                effect_started=True,
                effect_completed=True,
                executed_effect=True,
                process_exit_code=0,
                outcome_reason="contradictory ambiguous result",
            )

    def test_process_completion_is_not_task_acceptance(self) -> None:
        spec = _spec("DIRECT", "run-direct")
        evaluator = EvaluatorSpecification.create(
            evaluator_id="evaluator",
            evaluator_version="v1",
            requirements_fingerprint=_material_fingerprint("r", "test.requirements"),
            scope_fingerprint=_material_fingerprint("s", "test.scope"),
            test_plan_fingerprint=_material_fingerprint("t", "test.plan"),
            environment_identity=_identity("environment", "environment-1"),
        )
        terminal = TerminalManifest.create(
            run_identity=spec.run_identity,
            experiment_specification_fingerprint=spec.specification_fingerprint,
            repository_state_fingerprint=_material_fingerprint("repo", "test.repo"),
            proposal_ledger_fingerprint=_material_fingerprint("proposals", "test.proposals"),
            effect_receipt_ledger_fingerprint=_material_fingerprint("receipts", "test.receipts"),
            budget_state_fingerprint=spec.common_budgets.budget_fingerprint,
            evaluator_specification_fingerprint=evaluator.evaluator_fingerprint,
            model_completion_claim="CLAIMED_COMPLETE",
            process_result="SUCCESS",
            task_acceptance="REJECTED",
            reconciliation_complete=True,
        )
        self.assertEqual(terminal.process_result, "SUCCESS")
        self.assertEqual(terminal.task_acceptance, "REJECTED")
        self.assertEqual(terminal.acceptance_basis, "INDEPENDENT_EVALUATOR")

    def test_terminal_state_matrix_rejects_unreconciled_final_dispositions(self) -> None:
        specification = _spec("DIRECT", "run-direct")
        for disposition in ("ACCEPTED", "REJECTED"):
            with self.assertRaises(ValueError):
                _terminal(specification, f"{disposition.lower()}-pending", task_acceptance=disposition, reconciliation_complete=False)
        with self.assertRaises(ValueError):
            _terminal(specification, "inconclusive-complete", task_acceptance="INCONCLUSIVE", reconciliation_complete=True)
        with self.assertRaises(ValueError):
            _terminal(specification, "not-evaluated-complete", task_acceptance="NOT_EVALUATED", reconciliation_complete=True)
        inconclusive = _terminal(specification, "inconclusive", task_acceptance="INCONCLUSIVE", reconciliation_complete=False)
        not_evaluated = _terminal(specification, "not-evaluated", task_acceptance="NOT_EVALUATED", reconciliation_complete=False)
        self.assertEqual(inconclusive.acceptance_basis, "INDEPENDENT_EVALUATOR")
        self.assertEqual(not_evaluated.acceptance_basis, "NONE")

    def test_exhaustive_terminal_state_matrix_accepts_only_documented_combinations(self) -> None:
        specification = _spec("DIRECT", "run-direct")
        examined = 0
        accepted = 0
        for disposition, rule in TERMINAL_STATE_MATRIX.items():
            for reconciliation_complete in (False, True):
                examined += 1
                try:
                    terminal = _terminal(
                        specification,
                        f"matrix-{disposition.lower()}-{reconciliation_complete}",
                        task_acceptance=disposition,
                        reconciliation_complete=reconciliation_complete,
                    )
                except ValueError:
                    self.assertNotEqual(reconciliation_complete, rule.reconciliation_complete)
                else:
                    self.assertEqual(reconciliation_complete, rule.reconciliation_complete)
                    self.assertIs(terminal.validated(), terminal)
                    accepted += 1
        self.assertEqual(examined, len(TERMINAL_STATE_MATRIX) * 2)
        self.assertEqual(accepted, len(TERMINAL_STATE_MATRIX))

    def test_budget_usage_is_monotone_and_overflow_or_limit_is_refused(self) -> None:
        budget = BudgetState.create(limits=BudgetLimits(sessions=1, turns=2))
        next_budget = budget.advance(sessions=1, turns=1)
        self.assertEqual(next_budget.used.sessions, 1)
        self.assertEqual(next_budget.used.turns, 1)
        with self.assertRaises(ValueError):
            next_budget.advance(sessions=1)
        with self.assertRaises(OverflowError):
            BudgetState.create(limits=BudgetLimits(sessions=None)).advance(sessions=2**63)


class ComparativeClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.direct = _spec("DIRECT", "run-direct")
        self.governed = _spec("GOVERNED", "run-governed")
        self.parity = require_parity(self.direct, self.governed)
        self.direct_terminal = _terminal(self.direct, "direct", task_acceptance="ACCEPTED")
        self.governed_terminal = _terminal(self.governed, "governed", task_acceptance="REJECTED")

    def test_distinct_typed_terminals_create_and_reconcile(self) -> None:
        manifest = ComparativeManifest.create(
            direct_specification=self.direct,
            governed_specification=self.governed,
            parity_report=self.parity,
            direct_terminal_manifest=self.direct_terminal,
            governed_terminal_manifest=self.governed_terminal,
        )
        restored = ComparativeManifest.from_dict(parse_canonical_json(canonical_bytes(manifest.to_dict())))
        self.assertEqual(restored, manifest)
        self.assertIs(restored.validate_for_specifications(
            direct_specification=self.direct,
            governed_specification=self.governed,
            parity_report=self.parity,
        ), restored)

    def test_same_swapped_unrelated_and_other_spec_terminals_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            ComparativeManifest.create(
                direct_specification=self.direct,
                governed_specification=self.governed,
                parity_report=self.parity,
                direct_terminal_manifest=self.direct_terminal,
                governed_terminal_manifest=self.direct_terminal,
            )
        with self.assertRaises(ValueError):
            ComparativeManifest.create(
                direct_specification=self.direct,
                governed_specification=self.governed,
                parity_report=self.parity,
                direct_terminal_manifest=self.governed_terminal,
                governed_terminal_manifest=self.direct_terminal,
            )
        unrelated_spec = _spec("DIRECT", "run-unrelated", experiment_id="other-exp")
        with self.assertRaises(ValueError):
            ComparativeManifest.create(
                direct_specification=self.direct,
                governed_specification=self.governed,
                parity_report=self.parity,
                direct_terminal_manifest=_terminal(unrelated_spec, "unrelated"),
                governed_terminal_manifest=self.governed_terminal,
            )
        other_spec_same_run = _spec("DIRECT", "run-direct", model_label="other-model")
        with self.assertRaises(ValueError):
            ComparativeManifest.create(
                direct_specification=self.direct,
                governed_specification=self.governed,
                parity_report=self.parity,
                direct_terminal_manifest=_terminal(other_spec_same_run, "other-spec"),
                governed_terminal_manifest=self.governed_terminal,
            )

    def test_non_reconciled_final_terminal_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            ComparativeManifest.create(
                direct_specification=self.direct,
                governed_specification=self.governed,
                parity_report=self.parity,
                direct_terminal_manifest=_terminal(self.direct, "pending", task_acceptance="ACCEPTED", reconciliation_complete=False),
                governed_terminal_manifest=self.governed_terminal,
            )


class ParityTests(unittest.TestCase):
    def test_valid_pair_and_allowed_governance_difference_pass(self) -> None:
        report = require_parity(_spec("DIRECT", "run-direct"), _spec("GOVERNED", "run-governed"))
        self.assertTrue(report.passed)
        self.assertEqual(report.refusal_code, "NONE")
        self.assertEqual(report.mismatches, ())
        self.assertEqual(report.to_dict(), check_parity(_spec("GOVERNED", "run-governed"), _spec("DIRECT", "run-direct")).to_dict())

    def test_every_non_governance_input_mutation_fails_with_stable_path(self) -> None:
        direct = _spec("DIRECT", "run-direct")
        baseline = _spec("GOVERNED", "run-governed")
        mutations = {
            "task_prompt_fingerprint": {"prompt_label": "prompt-2"},
            "initial_state_fingerprint": {"state_label": "state-2"},
            "model_identity": {"model_label": "model-2"},
            "executable_identity": {"executable_label": "executable-2"},
            "executable_digest": {"executable_label": "executable-2"},
            "transport_identity": {"transport_label": "transport-2"},
            "tool_grammar_identity": {"grammar_label": "grammar-2"},
            "environment_identity": {"environment_label": "environment-2"},
            "dependency_toolchain_identity": {"dependency_label": "dependency-2"},
            "common_filesystem_network_process_policy_identity": {"policy_label": "policy-2"},
            "effect_executor_label": {"effect_executor_label": "executor-2"},
            "evaluator_identity": {"evaluator_label": "evaluator-2"},
            "common_budgets": {"sessions_limit": 11},
        }
        for field, changes in mutations.items():
            expected_path = "effect_executor_identity" if field == "effect_executor_label" else field
            kwargs = {
                "condition_id": "GOVERNED",
                "run_id": "run-governed",
                **changes,
            }
            changed = _spec(**kwargs)
            report = check_parity(direct, changed)
            self.assertFalse(report.passed, field)
            self.assertEqual(report.refusal_code, "UNAUTHORIZED_DIFFERENCE", field)
            self.assertTrue(any(item.path == expected_path or item.path.startswith(expected_path + ".") for item in report.mismatches), expected_path)

    def test_unknown_difference_category_same_condition_and_unrelated_experiment_fail(self) -> None:
        direct = _spec("DIRECT", "run-direct")
        governed = _spec("GOVERNED", "run-governed")
        manifest = AllowedConditionDifferences.create().to_dict()
        manifest["unknown_category"] = ["condition.model"]
        unknown = check_parity(direct, governed, allowed_differences=manifest)
        self.assertFalse(unknown.passed)
        self.assertEqual(unknown.refusal_code, "UNKNOWN_DIFFERENCE_CATEGORY")
        same = check_parity(direct, _spec("DIRECT", "run-other"))
        self.assertEqual(same.refusal_code, "CONDITION_PAIR_INVALID")
        unrelated = check_parity(direct, _spec("GOVERNED", "run-other", experiment_id="other-exp"))
        self.assertEqual(unrelated.refusal_code, "UNRELATED_EXPERIMENT_IDS")

    def test_parity_does_not_mutate_input(self) -> None:
        left = _spec("DIRECT", "run-direct").to_dict()
        right = _spec("GOVERNED", "run-governed").to_dict()
        left_before = deepcopy(left)
        right_before = deepcopy(right)
        report = check_parity(left, right)
        self.assertTrue(report.passed)
        self.assertEqual(left, left_before)
        self.assertEqual(right, right_before)


if __name__ == "__main__":
    unittest.main()
