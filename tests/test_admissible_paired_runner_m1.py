from __future__ import annotations

from copy import deepcopy
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
    sessions_limit: int = 10,
) -> ExperimentSpecification:
    condition = ConditionConfiguration.create(condition_id)
    run = RunIdentity.create(
        experiment_id=experiment_id,
        condition_id=condition_id,
        run_id=run_id,
    )
    return ExperimentSpecification.create(
        experiment_id=experiment_id,
        task_prompt_fingerprint=fingerprint_bytes(
            prompt_label.encode("utf-8"), domain="test.prompt.bytes"
        ),
        initial_state_fingerprint=_material_fingerprint(state_label, "test.initial.state"),
        model_identity=_identity("model", model_label),
        executable_identity=_identity("executable", executable_label),
        executable_digest=_material_fingerprint(executable_label, "test.executable.bytes"),
        transport_identity=_identity("transport", transport_label),
        tool_grammar_identity=_identity("tool_grammar", grammar_label),
        environment_identity=_identity("environment", environment_label),
        dependency_toolchain_identity=_identity("dependency_toolchain", dependency_label),
        common_filesystem_network_process_policy_identity=_identity("filesystem_network_process_policy", policy_label),
        effect_executor_identity=_identity("effect_executor", effect_executor_label),
        evaluator_identity=_identity("evaluator", evaluator_label),
        common_budgets=BudgetState.create(limits=_limits(sessions=sessions_limit)),
        allowed_condition_differences=AllowedConditionDifferences.create(),
        condition=condition,
        run_identity=run,
    )


def _proposal(condition_id: str = "DIRECT", run_id: str = "run-direct") -> CanonicalProposal:
    run = RunIdentity.create(
        experiment_id="exp-m1-proposal",
        condition_id=condition_id,
        run_id=run_id,
    )
    condition = ConditionConfiguration.create(condition_id)
    session = SessionIdentity.create(run=run, session_id=f"session-{condition_id.lower()}")
    return CanonicalProposal.create(
        run_identity=run,
        condition=condition,
        session_identity=session,
        turn_id="turn-0",
        proposal_id=f"proposal-{condition_id.lower()}",
        tool_name="read_file",
        canonical_arguments={"path": "src/main.py", "lines": [1, 2, 3]},
        working_root_identity=_identity("working_root", "root-1"),
        scope_identity=_identity("scope", "scope-1"),
        causal_predecessor=CausalPredecessor.root(),
        wall_clock_observation=ClockObservation.wall_clock(1_725_000_000_000),
        monotonic_observation=ClockObservation.future_runtime_placeholder(),
        model_identity=_identity("model", "model-1"),
        transport_identity=_identity("transport", "transport-1"),
        prompt_identity=_identity("prompt", "prompt-1"),
        tool_grammar_identity=_identity("tool_grammar", "grammar-1"),
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
        direct_decision = ModeDecision.direct(proposal)
        reservation = EffectReservation.for_decision(
            reservation_id="reservation-direct",
            proposal=proposal,
            decision=direct_decision,
            effect_executor_identity=_identity("effect_executor", "shared-executor"),
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
        terminal = TerminalManifest.create(
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
        parity = check_parity(direct, governed)
        comparative = ComparativeManifest.create(
            direct_specification=direct,
            governed_specification=governed,
            parity_report=parity,
            direct_terminal_manifest_fingerprint=terminal.terminal_manifest_fingerprint,
            governed_terminal_manifest_fingerprint=terminal.terminal_manifest_fingerprint,
        )
        fingerprint_object = fingerprint({"round_trip": True}, domain="test.fingerprint")
        identity = _identity("model", "round-trip-model")
        condition = ConditionConfiguration.create("DIRECT")
        allowlist = AllowedConditionDifferences.create()
        budget = direct.common_budgets
        clock = ClockObservation.wall_clock(1_725_000_000_002)
        causal = CausalPredecessor.root()
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
            direct_decision,
            reservation,
            receipt,
            intervention,
            evaluator,
            terminal,
            comparative,
            parity,
        ]
        self.assertEqual(len(objects), 19)
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
        with self.assertRaises(ValueError):
            ComparativeManifest.create(
                direct_specification=direct,
                governed_specification=_spec("GOVERNED", "run-governed", prompt_label="changed-prompt"),
                parity_report=parity,
                direct_terminal_manifest_fingerprint=terminal.terminal_manifest_fingerprint,
                governed_terminal_manifest_fingerprint=terminal.terminal_manifest_fingerprint,
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

    def test_budget_usage_is_monotone_and_overflow_or_limit_is_refused(self) -> None:
        budget = BudgetState.create(limits=BudgetLimits(sessions=1, turns=2))
        next_budget = budget.advance(sessions=1, turns=1)
        self.assertEqual(next_budget.used.sessions, 1)
        self.assertEqual(next_budget.used.turns, 1)
        with self.assertRaises(ValueError):
            next_budget.advance(sessions=1)
        with self.assertRaises(OverflowError):
            BudgetState.create(limits=BudgetLimits(sessions=None)).advance(sessions=2**63)


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
