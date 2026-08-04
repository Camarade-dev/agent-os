"""Provider-free fixtures for the Milestone 2 shared effect substrate tests.

Everything here is repository-local and standard-library only.  No provider,
model, transport, policy engine, owner authority, broker, mint, witness,
benchmark, production root, or V14-V18 identity is constructed or contacted.
Every physical effect happens inside a disposable temporary workspace owned by
the test process.
"""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import tempfile

from admissible.paired_runner.canonical import fingerprint, fingerprint_bytes
from admissible.paired_runner.identities import IdentityReference, RunIdentity, SessionIdentity
from admissible.paired_runner.specification import (
    AllowedConditionDifferences,
    BudgetLimits,
    BudgetState,
    CanonicalProposal,
    CausalPredecessor,
    ClockObservation,
    ConditionConfiguration,
    EvaluatorSpecification,
    ExperimentSpecification,
    ModeDecision,
)
from admissible.paired_runner.tool_schemas import ToolGrammarSpecification


TASK_PROMPT = b"provider-free milestone 2 substrate fixture prompt"
PROMPT_FINGERPRINT = fingerprint_bytes(TASK_PROMPT, domain="admissible.paired_runner.identity.content.prompt.material")


def _identity(kind: str, name: str, material: str) -> IdentityReference:
    return IdentityReference.create(kind=kind, name=name, version="v1", material={"material": material})


def prompt_identity() -> IdentityReference:
    return IdentityReference.create(
        kind="prompt", name="m2-fixture-prompt", version="v1", material={"bytes_hex": TASK_PROMPT.hex()}
    )


ENVIRONMENT_IDENTITY = _identity("environment", "m2-fixture-environment", "linux-posix-cpython")


def build_specification(condition_id: str, *, run_id: str) -> ExperimentSpecification:
    """One provider-free experiment specification for a single condition."""

    evaluator = EvaluatorSpecification.create(
        evaluator_id="m2-fixture-evaluator",
        evaluator_version="v1",
        requirements_fingerprint=fingerprint({"requirements": []}, domain="m2.fixture.requirements"),
        scope_fingerprint=fingerprint({"scope": []}, domain="m2.fixture.scope"),
        test_plan_fingerprint=fingerprint({"tests": []}, domain="m2.fixture.tests"),
        environment_identity=ENVIRONMENT_IDENTITY,
    )
    return ExperimentSpecification.create(
        experiment_id="m2-shared-substrate",
        task_prompt_fingerprint=prompt_identity().content_fingerprint,
        initial_state_fingerprint=fingerprint({"initial": "empty"}, domain="m2.fixture.initial_state"),
        model_identity=_identity("model", "m2-fixture-model-placeholder", "no-provider-is-contacted"),
        executable_identity=_identity("executable", "m2-fixture-executable-placeholder", "not-launched"),
        executable_digest=fingerprint({"digest": "placeholder"}, domain="m2.fixture.executable"),
        transport_identity=_identity("transport", "m2-fixture-transport-placeholder", "not-implemented-in-m2"),
        tool_grammar=ToolGrammarSpecification.create(),
        environment_identity=ENVIRONMENT_IDENTITY,
        dependency_toolchain_identity=_identity("dependency_toolchain", "m2-fixture-stdlib", "cpython-stdlib-only"),
        common_filesystem_network_process_policy_identity=_identity(
            "filesystem_network_process_policy", "m2-fixture-policy", "workspace-confined-no-network"
        ),
        working_root_identity=_identity("working_root", "m2-fixture-working-root", "disposable-temporary-root"),
        scope_identity=_identity("scope", "m2-fixture-scope", "entire-disposable-workspace"),
        effect_executor_identity=_identity(
            "effect_executor", "m2-shared-effect-substrate", "admissible.paired_runner.effects.SharedEffectSubstrate"
        ),
        evaluator_specification=evaluator,
        common_budgets=BudgetState.create(limits=BudgetLimits()),
        allowed_condition_differences=AllowedConditionDifferences.create(),
        condition=ConditionConfiguration.create(condition_id),
        run_identity=RunIdentity.create(
            experiment_id="m2-shared-substrate", condition_id=condition_id, run_id=run_id
        ),
    )


def build_proposal(
    specification: ExperimentSpecification,
    tool_request,
    *,
    proposal_id: str = "proposal-1",
    turn_id: str = "turn-1",
    session_id: str = "session-1",
    wall_clock_unix_ms: int = 1_700_000_000_000,
    monotonic_ns: int = 1_000_000,
) -> CanonicalProposal:
    session = SessionIdentity.create(run=specification.run_identity, session_id=session_id)
    return CanonicalProposal.create(
        specification=specification,
        session_identity=session,
        turn_id=turn_id,
        proposal_id=proposal_id,
        prompt_identity=prompt_identity(),
        tool_request=tool_request,
        causal_predecessor=CausalPredecessor.root(),
        wall_clock_observation=ClockObservation.wall_clock(wall_clock_unix_ms),
        monotonic_observation=ClockObservation.monotonic_ns(monotonic_ns),
    )


def decision_for(proposal: CanonicalProposal, *, governed_decision: str = "ALLOW") -> ModeDecision:
    """The typed decision a future runner would supply.

    This is not a policy evaluation.  Milestone 2 has no policy engine; the
    decision is an input the substrate reconciles and obeys.
    """

    if proposal.condition.condition_id == "DIRECT":
        return ModeDecision.direct(proposal)
    return ModeDecision.governed(
        proposal, governed_decision, governance_decision_reference="m2-fixture-decision-reference"
    )


class DisposableWorkspace:
    """A temporary directory owned by the test process and always removed."""

    def __init__(self, *, prefix: str = "admissible-m2-") -> None:
        self._directory = tempfile.mkdtemp(prefix=prefix)
        self.root = Path(os.path.realpath(self._directory))
        self.workspace = self.root / "workspace"
        self.store_root = self.root / "durable-store"
        self.workspace.mkdir(mode=0o700)
        self.store_root.mkdir(mode=0o700)

    def close(self) -> None:
        shutil.rmtree(self._directory, ignore_errors=True)

    def __enter__(self) -> "DisposableWorkspace":
        return self

    def __exit__(self, *exception: object) -> None:
        self.close()


def initialise_git_repository(root: Path) -> bool:
    """Create a disposable Git repository; return False when Git is absent."""

    git = shutil.which("git")
    if git is None:
        return False
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(root),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_AUTHOR_NAME": "m2 fixture",
        "GIT_AUTHOR_EMAIL": "m2@example.invalid",
        "GIT_COMMITTER_NAME": "m2 fixture",
        "GIT_COMMITTER_EMAIL": "m2@example.invalid",
    }
    commands = [
        ["init", "--quiet", "--initial-branch=main"],
        ["add", "-A"],
        ["commit", "--quiet", "-m", "fixture"],
    ]
    (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    for arguments in commands:
        completed = subprocess.run(  # noqa: S603 - explicit argv, disposable root
            [git, *arguments], cwd=str(root), env=environment, capture_output=True, check=False
        )
        if completed.returncode != 0:
            return False
    return True


PYTHON = os.path.realpath(os.sys.executable)
