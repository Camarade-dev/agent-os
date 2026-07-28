"""Provider-free end-to-end liveness witness for the mission-scoped authority.

The fake ACP server here is spawned as a *real* child process and driven
through the *real* production stack: ``AcpStdioNativeProcessRunner``,
``AcpServerRequestDispatcher``, ``decide_permission``, ``MissionEffectRuntime``
and the durable ``AcpAuthorityEvidence`` sink.  Nothing is stubbed on the
decision path, and no Cursor agent, model or package manager is ever contacted.

Its request shapes are the installed CLI's own shapes: a write decision is
``kind="edit"`` with a ``diff`` content block carrying the absolute path and an
``oldText`` discriminator; a delete decision is ``kind="edit"`` with no content
at all; a shell decision is ``kind="execute"`` with the command in a code span.

What this witness establishes is exactly one thing: the authority is **live** --
the mission's own required effects can now actually be performed, and the
effects it does not authorize still cannot.  It is not a product-correctness
proof.  The checkpoint and the owner-frozen behavioral verifier remain the only
acceptance oracles, and both run independently of anything here.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from admissible.delegated_gate.acp_authority import (
    ACP_ASK_QUESTION_UNATTENDED_REASON,
    DECISION_ALLOW_ONCE,
    DECISION_REJECT,
    FAILURE_UNANSWERABLE_SERVER_REQUEST,
    FAILURE_WORKSPACE_IDENTITY_CHANGED,
    RECORD_PERMISSION_DECISION,
    RECORD_SERVER_REQUEST,
    RECORD_WORKSPACE_IDENTITY_DIFFERENCE,
    AcpAuthorityEvidence,
)
from admissible.delegated_gate.acp_mission_effects import (
    LIVE_UNAUTHORIZED_PATH,
    RULE_EDIT_AUTHORIZED,
    RULE_EDIT_OPERATION_UNSUPPORTED,
    RULE_EDIT_PATH_NOT_AUTHORIZED,
    RULE_EDIT_PATH_OUTSIDE_WORKSPACE,
    RULE_GIT_COMMIT_AUTHORIZED,
    RULE_GIT_COMMIT_MESSAGE_NOT_EXACT,
    RULE_GIT_STAGE_AUTHORIZED,
    RULE_GIT_STAGE_LIVE_STATE_REFUSED,
    RULE_LOCAL_VERIFICATION_AUTHORIZED,
    RULE_LOCAL_VERIFICATION_NOT_EXACT,
    MissionEffectRuntime,
)
from admissible.delegated_gate.mission_effect_authority import (
    EFFECT_CLASS_GIT_COMMIT,
    NEON_RELAY_MISSION_EFFECT_AUTHORITY,
)
from admissible.delegated_gate.native_executor import (
    PROMPT_TRANSPORT_ACP_STDIO,
    AcpStdioNativeProcessRunner,
    NATIVE_PROMPT_HEADER,
    NativeProcessInvocation,
)
from admissible.delegated_gate.neon_relay_mission import (
    NEON_RELAY_REQUIRED_COMMIT_MESSAGE,
    NEON_RELAY_REQUIRED_MATERIAL_PATHS,
)

FAKE_SERVER = str(
    Path(__file__).parent / "fixtures" / "admissible" / "fake_acp_server_process.py"
)

AUTHORITY = NEON_RELAY_MISSION_EFFECT_AUTHORITY


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def git(repository: Path, *arguments: str) -> subprocess.CompletedProcess:
    environment = dict(os.environ)
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_AUTHOR_NAME": "Admissible", "GIT_AUTHOR_EMAIL": "a@local.invalid",
        "GIT_COMMITTER_NAME": "Admissible", "GIT_COMMITTER_EMAIL": "a@local.invalid",
    })
    return subprocess.run(
        ["git", *arguments], cwd=repository, env=environment, check=True,
        capture_output=True, text=True,
    )


@pytest.fixture()
def fixture_repository(tmp_path: Path) -> Path:
    """A disposable Git fixture shaped like the delivered Neon Relay workspace."""

    work = tmp_path / "work"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    git(work, "config", "commit.gpgsign", "false")
    git(work, "config", "user.name", "Admissible")
    git(work, "config", "user.email", "a@local.invalid")
    (work / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    (work / "LOCAL_DEV.md").write_text("NEON_RELAY_BLANK_FIXTURE_V1\n", encoding="utf-8")
    (work / "package.json").write_text("{}\n", encoding="utf-8")
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "fixture")
    return work


def _child_environment() -> dict[str, str]:
    """The same shape the native lane hands a real provider: an allowlist.

    The witness must be able to reach ``git`` exactly as a real provider does,
    so ``PATH`` is present; the Git control plane is pinned to the repository's
    own config so no owner-level Git configuration can influence the result.
    """

    allowed = ("PATH", "PATHEXT", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP", "TMPDIR")
    environment = {
        name: os.environ[name] for name in allowed if name in os.environ
    }
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return environment


def build_prompt(size_bytes: int = 4096) -> str:
    head = NATIVE_PROMPT_HEADER + "\n\nImmutable mission:\n"
    body = "neon relay mission line\n" * 400
    prompt = (head + body)[:size_bytes]
    while len(prompt.encode("utf-8")) < size_bytes:
        prompt += "."
    return prompt


class StartedRecorder:
    def __init__(self) -> None:
        self.proofs: list[object] = []

    def __call__(self, proof: object) -> None:
        self.proofs.append(proof)


def run_witness(
    repository: Path,
    evidence_path: Path,
    *,
    scenario: str = "mission_liveness",
    probe: str | None = None,
    bind_authority: bool = True,
    fixture_head: str | None = ...,
):
    """Drive the real runner against the fake server; return (outcome, records)."""

    prompt = build_prompt()
    argv = [sys.executable, FAKE_SERVER, "--scenario", scenario]
    if probe is not None:
        argv += ["--probe", probe]
    evidence = AcpAuthorityEvidence(evidence_path, redact=(prompt,))
    effects = None
    if bind_authority:
        head = (
            git(repository, "rev-parse", "HEAD").stdout.strip().lower()
            if fixture_head is ... else fixture_head
        )
        effects = MissionEffectRuntime(
            authority=AUTHORITY, workspace=str(repository), fixture_head=head,
        )
    started = StartedRecorder()
    invocation = NativeProcessInvocation(
        tuple(argv), str(repository), _child_environment(), 180, 4 * 1024 * 1024, started,
        prompt_transport=PROMPT_TRANSPORT_ACP_STDIO, prompt=prompt,
        prompt_fingerprint=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        acp_authority_evidence=evidence, acp_mission_effects=effects,
    )
    outcome = AcpStdioNativeProcessRunner().run(invocation)
    # I.24 / I.25, on every witness in this file: exactly one provider process
    # is ever started, and the prompt bytes never enter argv.
    assert len(started.proofs) == 1
    assert not any(prompt in member for member in argv)
    # The sink is created lazily by its first append, so a turn that recorded
    # nothing legitimately leaves no file at all.
    text = evidence_path.read_text(encoding="utf-8") if evidence_path.exists() else ""
    records = [json.loads(line) for line in text.splitlines()]
    return outcome, records, effects


def decisions(records, *, rule: str | None = None):
    items = [r for r in records if r["record_type"] == RECORD_PERMISSION_DECISION]
    return [r for r in items if rule is None or r["policy_rule_id"] == rule]


def status_of(repository: Path) -> str:
    return git(repository, "status", "--porcelain", "--untracked-files=all").stdout


def commits_since_fixture(repository: Path) -> list[str]:
    log = git(repository, "log", "--format=%H", "main").stdout.split()
    return log[:-1]  # everything above the fixture's initial commit


# ---------------------------------------------------------------------------
# H: the positive end-to-end liveness witness
# ---------------------------------------------------------------------------


def test_the_complete_authorized_mission_is_performable_end_to_end(
    fixture_repository, tmp_path
):
    """H: 14 files, one commit, the exact message, clean tree, no remote."""

    outcome, records, effects = run_witness(
        fixture_repository, tmp_path / "liveness.jsonl"
    )

    assert outcome.returncode == 0, outcome.protocol_failure_detail
    assert outcome.protocol_failure_detail is None

    # -- every required path exists as a regular file ----------------------
    for relative in NEON_RELAY_REQUIRED_MATERIAL_PATHS:
        path = fixture_repository / relative.replace("/", os.sep)
        assert path.is_file(), relative

    # -- exactly one new commit, carrying the exact complete message -------
    new_commits = commits_since_fixture(fixture_repository)
    assert len(new_commits) == 1, new_commits
    message = git(fixture_repository, "log", "-1", "--format=%B").stdout.rstrip("\r\n")
    assert message == NEON_RELAY_REQUIRED_COMMIT_MESSAGE

    # -- clean worktree and index, no remote, no unauthorized path ---------
    assert status_of(fixture_repository) == ""
    assert git(fixture_repository, "remote").stdout.strip() == ""
    tracked = set(git(fixture_repository, "ls-files").stdout.split())
    assert tracked == set(NEON_RELAY_REQUIRED_MATERIAL_PATHS) | {".gitignore"}
    assert not (fixture_repository / "src" / "secret-exfiltrator.js").exists()

    # -- the authority did all of that, and nothing more -------------------
    approved = [r for r in decisions(records) if r["decision"] == DECISION_ALLOW_ONCE]
    assert {r["policy_rule_id"] for r in approved} == {
        RULE_EDIT_AUTHORIZED,
        RULE_LOCAL_VERIFICATION_AUTHORIZED,
        RULE_GIT_STAGE_AUTHORIZED,
        RULE_GIT_COMMIT_AUTHORIZED,
        "bounded_read_only_workspace_inspection",
    }
    assert len(decisions(records, rule=RULE_EDIT_AUTHORIZED)) == 14
    assert len(decisions(records, rule=RULE_GIT_COMMIT_AUTHORIZED)) == 1
    assert effects.ledger.spent(EFFECT_CLASS_GIT_COMMIT) == 1

    # -- allow-always was never selected, on any path ----------------------
    assert {r["selected_option_kind"] for r in approved} == {"allow_once"}
    assert all(r["selected_option_id"] == "allow-once" for r in approved)

    # -- the unauthorized edit was refused without widening anything -------
    refused = decisions(records, rule=RULE_EDIT_PATH_NOT_AUTHORIZED)
    assert len(refused) == 1
    assert refused[0]["decision"] == DECISION_REJECT
    assert refused[0]["normalized_paths"] == []

    # -- the plan and the todo update continued the turn -------------------
    server = [r for r in records if r["record_type"] == RECORD_SERVER_REQUEST]
    assert {r["method"] for r in server} == {"cursor/create_plan", "cursor/update_todos"}
    assert all(r["accepted"] for r in server)

    # -- a decision never claims the effect succeeded ----------------------
    commit_record = decisions(records, rule=RULE_GIT_COMMIT_AUTHORIZED)[0]
    assert commit_record["decision"] == DECISION_ALLOW_ONCE
    assert "committed" not in json.dumps(commit_record)
    assert commit_record["live_repository_observation_fingerprint"] is not None

    # -- I.25: no prompt byte reaches the authority evidence ---------------
    text = (tmp_path / "liveness.jsonl").read_text(encoding="utf-8")
    assert "neon relay mission line" not in text
    assert NATIVE_PROMPT_HEADER not in text


def test_the_witness_cannot_pass_without_the_mission_authority(
    fixture_repository, tmp_path
):
    """The same fake server, with no authority bound, leaves nothing behind."""

    outcome, records, _ = run_witness(
        fixture_repository, tmp_path / "unbound.jsonl", bind_authority=False
    )

    assert not (fixture_repository / "src").exists()
    assert commits_since_fixture(fixture_repository) == []
    assert status_of(fixture_repository) == ""
    assert decisions(records, rule=RULE_EDIT_AUTHORIZED) == []
    assert all(r["decision"] == DECISION_REJECT for r in decisions(records)
               if r["tool_kind"] == "edit")


# ---------------------------------------------------------------------------
# H: the negative end-to-end witnesses
# ---------------------------------------------------------------------------


def test_an_edit_outside_the_workspace_is_refused_end_to_end(fixture_repository, tmp_path):
    outcome, records, _ = run_witness(
        fixture_repository, tmp_path / "outside.jsonl", probe="edit_outside"
    )
    assert outcome.returncode == 0
    assert decisions(records, rule=RULE_EDIT_PATH_OUTSIDE_WORKSPACE)
    assert not (fixture_repository.parent / "escaped.txt").exists()


def test_a_delete_request_is_refused_end_to_end(fixture_repository, tmp_path):
    outcome, records, _ = run_witness(
        fixture_repository, tmp_path / "delete.jsonl", probe="edit_delete"
    )
    assert outcome.returncode == 0
    refused = decisions(records, rule=RULE_EDIT_OPERATION_UNSUPPORTED)
    assert refused and refused[0]["structured_operation"] == "delete"
    # The file the delete named is still there, and still committed.
    assert (fixture_repository / "src" / "game.js").is_file()
    assert status_of(fixture_repository) == ""


def test_npm_install_is_refused_end_to_end(fixture_repository, tmp_path):
    outcome, records, _ = run_witness(
        fixture_repository, tmp_path / "install.jsonl", probe="npm_install"
    )
    assert outcome.returncode == 0
    refused = decisions(records, rule=RULE_LOCAL_VERIFICATION_NOT_EXACT)
    assert refused and refused[0]["decision"] == DECISION_REJECT
    # The authorized spelling in the same turn still succeeded.
    assert decisions(records, rule=RULE_LOCAL_VERIFICATION_AUTHORIZED)
    assert not (fixture_repository / "node_modules").exists()


def test_a_different_commit_message_is_refused_end_to_end(fixture_repository, tmp_path):
    outcome, records, _ = run_witness(
        fixture_repository, tmp_path / "message.jsonl", probe="commit_wrong_message"
    )
    assert outcome.returncode == 0
    assert decisions(records, rule=RULE_GIT_COMMIT_MESSAGE_NOT_EXACT)
    assert decisions(records, rule=RULE_GIT_COMMIT_AUTHORIZED) == []
    # Staging happened; the commit did not.
    assert commits_since_fixture(fixture_repository) == []
    assert status_of(fixture_repository) != ""


def test_an_unauthorized_untracked_path_blocks_staging_end_to_end(
    fixture_repository, tmp_path
):
    outcome, records, _ = run_witness(
        fixture_repository, tmp_path / "untracked.jsonl", probe="unauthorized_untracked"
    )
    assert outcome.returncode == 0
    refused = decisions(records, rule=RULE_GIT_STAGE_LIVE_STATE_REFUSED)
    assert refused
    assert LIVE_UNAUTHORIZED_PATH in refused[0]["live_refusal_reasons"]
    assert decisions(records, rule=RULE_GIT_STAGE_AUTHORIZED) == []
    assert commits_since_fixture(fixture_repository) == []
    assert (fixture_repository / "notes.txt").exists()


def test_a_second_commit_is_refused_end_to_end(fixture_repository, tmp_path):
    """Two independent guards refuse it, and the live one fires first.

    Once the authorized commit exists, HEAD is no longer the initialized
    fixture HEAD, so the live observation refuses before the budget is even
    consulted.  The budget is the second, independent guard; it is proven on
    its own in ``test_a_second_commit_approval_is_refused``, where no commit is
    actually performed.
    """

    outcome, records, effects = run_witness(
        fixture_repository, tmp_path / "second.jsonl", probe="second_commit"
    )
    assert outcome.returncode == 0
    assert len(decisions(records, rule=RULE_GIT_COMMIT_AUTHORIZED)) == 1

    commit_attempts = [
        r for r in decisions(records) if r["authority_class"] == EFFECT_CLASS_GIT_COMMIT
    ]
    assert len(commit_attempts) == 2
    assert commit_attempts[1]["decision"] == DECISION_REJECT
    assert commit_attempts[1]["policy_rule_id"] == "live_repository_state_refuses_the_commit"
    assert "head_is_no_longer_the_initialized_fixture_head" in (
        commit_attempts[1]["live_refusal_reasons"]
    )

    assert len(commits_since_fixture(fixture_repository)) == 1
    assert effects.ledger.spent(EFFECT_CLASS_GIT_COMMIT) == 1


def test_plan_and_question_are_answered_over_the_real_transport(
    fixture_repository, tmp_path
):
    outcome, records, effects = run_witness(
        fixture_repository, tmp_path / "pq.jsonl", scenario="mission_plan_and_question"
    )
    assert outcome.returncode == 0
    assert outcome.protocol_failure_detail is None
    methods = {r["method"] for r in records if r["record_type"] == RECORD_SERVER_REQUEST}
    assert methods == {"cursor/create_plan", "cursor/ask_question"}
    assert ACP_ASK_QUESTION_UNATTENDED_REASON in outcome.stdout
    # Neither answered request spent or changed any authority.
    assert effects.ledger.snapshot() == {name: 0 for name in AUTHORITY.approval_bounds}
    assert decisions(records) == []


@pytest.mark.parametrize(
    "scenario,method",
    [
        ("malformed_create_plan", "cursor/create_plan"),
        ("malformed_ask_question", "cursor/ask_question"),
    ],
)
def test_a_malformed_client_request_fails_closed_end_to_end(
    fixture_repository, tmp_path, scenario, method
):
    outcome, records, _ = run_witness(
        fixture_repository, tmp_path / f"{scenario}.jsonl", scenario=scenario
    )
    assert outcome.returncode == 1
    assert outcome.protocol_failure_detail == f"malformed_server_request:{method}"
    assert commits_since_fixture(fixture_repository) == []


def test_an_unknown_cursor_method_still_fails_closed_with_the_authority_bound(
    fixture_repository, tmp_path
):
    outcome, records, _ = run_witness(
        fixture_repository, tmp_path / "unknown.jsonl", scenario="unknown_request"
    )
    assert outcome.returncode == 1
    assert outcome.protocol_failure_detail == (
        f"{FAILURE_UNANSWERABLE_SERVER_REQUEST}:cursor/task"
    )


def test_a_tracked_content_mutation_before_the_prompt_withholds_the_mission(
    fixture_repository, tmp_path
):
    """The prompt is never submitted, and nothing is cleaned up."""

    before = (fixture_repository / "LOCAL_DEV.md").read_text(encoding="utf-8")
    outcome, records, _ = run_witness(
        fixture_repository, tmp_path / "mutated.jsonl", scenario="tracked_content_mutation"
    )

    assert outcome.returncode == 1
    assert outcome.protocol_failure_detail.startswith(FAILURE_WORKSPACE_IDENTITY_CHANGED)
    persisted = [
        r for r in records if r["record_type"] == RECORD_WORKSPACE_IDENTITY_DIFFERENCE
    ]
    assert persisted
    assert "tracked_content:LOCAL_DEV.md" in persisted[0]["differences"]
    # The prompt never reached the server, so no permission was ever requested.
    assert decisions(records) == []
    # No automatic cleanup: the mutation is preserved exactly as observed.
    assert (fixture_repository / "LOCAL_DEV.md").read_text(encoding="utf-8") != before
    assert commits_since_fixture(fixture_repository) == []


# ---------------------------------------------------------------------------
# Mutation witnesses: each fails if a load-bearing check is removed
# ---------------------------------------------------------------------------


def test_mutation_witness_accepting_every_edit_breaks_the_positive_witness(
    fixture_repository, tmp_path, monkeypatch
):
    """If every ``kind=edit`` were accepted, the unauthorized path would land."""

    import admissible.delegated_gate.acp_mission_effects as effects_module

    original = effects_module.MissionEffectRuntime.rule_on_edit

    def accept_everything(self, *, title, content):
        from admissible.delegated_gate.acp_mission_effects import MissionEffectRuling
        from admissible.delegated_gate.mission_effect_authority import (
            EFFECT_CLASS_MATERIAL_EDIT,
        )

        return MissionEffectRuling(
            True, EFFECT_CLASS_MATERIAL_EDIT, RULE_EDIT_AUTHORIZED, "mutant",
            operation="create", budget_before=0, budget_after=1,
        )

    monkeypatch.setattr(effects_module.MissionEffectRuntime, "rule_on_edit", accept_everything)
    outcome, records, _ = run_witness(fixture_repository, tmp_path / "mutant-a.jsonl")

    # The committed assertion this mutant defeats, restated verbatim:
    with pytest.raises(AssertionError):
        assert not (fixture_repository / "src" / "secret-exfiltrator.js").exists()
    assert (fixture_repository / "src" / "secret-exfiltrator.js").exists()

    monkeypatch.setattr(effects_module.MissionEffectRuntime, "rule_on_edit", original)


def test_mutation_witness_rejecting_every_edit_breaks_the_positive_witness(
    fixture_repository, tmp_path, monkeypatch
):
    """The pre-repair V4 behavior: the mission becomes unexecutable again."""

    import admissible.delegated_gate.acp_mission_effects as effects_module

    def reject_everything(self, *, title, content):
        from admissible.delegated_gate.acp_mission_effects import MissionEffectRuling

        return MissionEffectRuling(
            False, "mission_material_edit", "mutant_refuses_every_edit", "mutant",
            consumes_budget=False,
        )

    monkeypatch.setattr(effects_module.MissionEffectRuntime, "rule_on_edit", reject_everything)
    outcome, records, _ = run_witness(fixture_repository, tmp_path / "mutant-b.jsonl")

    with pytest.raises(AssertionError):
        assert (fixture_repository / "src" / "game.js").is_file()
    with pytest.raises(AssertionError):
        assert len(commits_since_fixture(fixture_repository)) == 1


def test_mutation_witness_removing_the_commit_message_comparison(
    fixture_repository, tmp_path, monkeypatch
):
    """Without the exact-message check, the wrong message is committed."""

    import admissible.delegated_gate.acp_mission_effects as effects_module

    original = effects_module.MissionEffectRuntime._rule_on_git_commit

    def without_message_check(self, tokens):
        ruling = original(self, tokens)
        if ruling.rule_id == RULE_GIT_COMMIT_MESSAGE_NOT_EXACT:
            return self._budgeted(
                EFFECT_CLASS_GIT_COMMIT, RULE_GIT_COMMIT_AUTHORIZED, "mutant",
            )
        return ruling

    monkeypatch.setattr(
        effects_module.MissionEffectRuntime, "_rule_on_git_commit", without_message_check
    )
    run_witness(fixture_repository, tmp_path / "mutant-c.jsonl", probe="commit_wrong_message")

    message = git(fixture_repository, "log", "-1", "--format=%B").stdout.rstrip("\r\n")
    assert message == "chore: wip"
    with pytest.raises(AssertionError):
        assert message == NEON_RELAY_REQUIRED_COMMIT_MESSAGE


def test_mutation_witness_bypassing_live_workspace_validation_before_git_add(
    fixture_repository, tmp_path, monkeypatch
):
    """Trusting the command instead of the repository stages foreign material."""

    import admissible.delegated_gate.acp_mission_effects as effects_module

    monkeypatch.setattr(
        effects_module, "refuse_staging", lambda observation, **kwargs: ()
    )
    _, records, _ = run_witness(
        fixture_repository, tmp_path / "mutant-d.jsonl", probe="unauthorized_untracked"
    )

    # The mutant approves the staging the live observation exists to refuse,
    # and the unauthorized path really does reach the index.
    assert decisions(records, rule=RULE_GIT_STAGE_AUTHORIZED)
    staged = git(fixture_repository, "diff", "--cached", "--name-only").stdout.split()
    assert "notes.txt" in staged

    # The committed assertions this mutant defeats, restated verbatim:
    with pytest.raises(AssertionError):
        assert decisions(records, rule=RULE_GIT_STAGE_AUTHORIZED) == []
    with pytest.raises(AssertionError):
        refused = decisions(records, rule=RULE_GIT_STAGE_LIVE_STATE_REFUSED)
        assert refused

    # The commit authority is an independent second guard and still refuses,
    # so no commit exists -- which is why the staging check must exist on its
    # own rather than being folded into the commit check.
    assert commits_since_fixture(fixture_repository) == []


def test_mutation_witness_restoring_allow_always_on_a_mission_path(
    fixture_repository, tmp_path, monkeypatch
):
    """A mission approval that prefers standing authority cannot reach the wire."""

    import admissible.delegated_gate.acp_authority as authority

    def prefer_allow_always(ruling, *, rejection, approval):
        for option_kind in ("allow_always", "allow_once"):
            if ruling.permitted:
                return authority.PermissionDecision(
                    authority.DECISION_ALLOW_ONCE, "allow-always", option_kind,
                    ruling.rule_id, "mutant", authority.CONTAINMENT_INSIDE_WORKSPACE, (),
                )
        return rejection(ruling.rule_id, ruling.detail)

    monkeypatch.setattr(authority, "_from_mission_ruling", prefer_allow_always)
    outcome, records, _ = run_witness(fixture_repository, tmp_path / "mutant-e.jsonl")

    # The independent response guard refuses to serialize it at all.
    assert outcome.returncode == 1
    assert outcome.protocol_failure_detail == "transport_error:AcpAuthorityRefusal"
    with pytest.raises(AssertionError):
        assert len(commits_since_fixture(fixture_repository)) == 1


def test_mutation_witness_ignoring_a_tracked_content_mutation(
    fixture_repository, tmp_path, monkeypatch
):
    """With the identity comparison neutered, the prompt is submitted anyway."""

    import admissible.delegated_gate.native_executor as executor

    monkeypatch.setattr(executor, "compare_workspace_identity", lambda before, after: ())
    outcome, records, _ = run_witness(
        fixture_repository, tmp_path / "mutant-f.jsonl", scenario="tracked_content_mutation"
    )

    # The mutation is invisible: the turn completes and the mission is
    # submitted against a workspace the server had already rewritten.
    assert outcome.returncode == 0
    assert outcome.protocol_failure_detail is None
    assert [
        r for r in records if r["record_type"] == RECORD_WORKSPACE_IDENTITY_DIFFERENCE
    ] == []

    # The committed assertions this mutant defeats, restated verbatim:
    with pytest.raises(AssertionError):
        assert outcome.returncode == 1
    with pytest.raises(AssertionError):
        assert (outcome.protocol_failure_detail or "").startswith(
            FAILURE_WORKSPACE_IDENTITY_CHANGED
        )
