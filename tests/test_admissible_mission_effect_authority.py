"""Mission-scoped ACP effect authority: model, decision procedure, evidence.

Every proof here is provider-free.  No Cursor agent, no model and no package
manager is ever contacted; the only subprocess any test starts is ``git``
against a disposable temporary repository it created itself.

The request shapes exercised below are not invented.  They are the shapes the
installed ``cursor-agent`` bundle's own ACP approval bridge emits:

* a write decision is ``kind="edit"`` with
  ``content=[{"type":"diff","path":<absolute>,"oldText":null|<str>,"newText":<str>}]``
  and a title of ``Write <path>`` (new) or ``Edit `<path>`` `` (existing);
* a delete decision is ``kind="edit"`` with **no content at all**;
* a shell decision is ``kind="execute"`` with the command in a code span;
* the offered options are always allow-once / allow-always / reject-once.

The CLI's decision enum is exactly ``{write, shell, delete, mcp}``: there is no
directory operation, and an overwrite is a ``write`` carrying the previous
content as ``oldText`` rather than a delete followed by a write.  That is why
this module refuses every delete outright.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from admissible.delegated_gate.acp_authority import (
    ACP_ASK_QUESTION_UNATTENDED_REASON,
    ASK_QUESTION_RESULT,
    CREATE_PLAN_RESULT,
    DECISION_ALLOW_ONCE,
    DECISION_REJECT,
    FORBIDDEN_PERMISSION_OPTION_KINDS,
    PERMISSION_KIND_ALLOW_ONCE,
    RECORD_PERMISSION_DECISION,
    RULE_DUPLICATE_REPLAY,
    RULE_TOOL_KIND_NOT_PERMITTED,
    AcpAuthorityEvidence,
    AcpEvidenceWriteError,
    AcpServerRequestDispatcher,
    capture_workspace_identity,
    compare_workspace_identity,
    decide_permission,
    parse_ask_question,
    parse_create_plan,
    parse_permission_request,
)
from admissible.delegated_gate.acp_mission_effects import (
    LIVE_DELETION_PRESENT,
    LIVE_EXTERNAL_BOUNDARY_MOVED,
    LIVE_HEAD_MOVED,
    LIVE_INDEX_EMPTY,
    LIVE_REMOTE_PRESENT,
    LIVE_UNAUTHORIZED_PATH,
    RULE_BUDGET_EXHAUSTED,
    RULE_DUPLICATE_TOOL_CALL_CONFLICT,
    RULE_EDIT_AUTHORIZED,
    RULE_EDIT_LOCATION_UNPROVEN,
    RULE_EDIT_OPERATION_UNSUPPORTED,
    RULE_EDIT_PATH_NOT_AUTHORIZED,
    RULE_EDIT_PATH_OUTSIDE_WORKSPACE,
    RULE_EDIT_PATH_UNSAFE_FORM,
    RULE_EDIT_REPARSE_POINT,
    RULE_GIT_COMMIT_AUTHORIZED,
    RULE_GIT_COMMIT_FORM_NOT_AUTHORIZED,
    RULE_GIT_COMMIT_LIVE_STATE_REFUSED,
    RULE_GIT_COMMIT_MESSAGE_NOT_EXACT,
    RULE_GIT_STAGE_AUTHORIZED,
    RULE_GIT_STAGE_FORM_NOT_AUTHORIZED,
    RULE_GIT_STAGE_LIVE_STATE_REFUSED,
    RULE_LOCAL_VERIFICATION_AUTHORIZED,
    RULE_LOCAL_VERIFICATION_NOT_EXACT,
    MissionEffectRuntime,
    observe_live_repository,
    parse_edit_tool_call,
    resolve_structured_target,
)
from admissible.delegated_gate.mission_effect_authority import (
    EDIT_OPERATION_CREATE,
    EDIT_OPERATION_UPDATE,
    EFFECT_CLASS_GIT_COMMIT,
    EFFECT_CLASS_GIT_STAGE,
    EFFECT_CLASS_LOCAL_VERIFICATION,
    EFFECT_CLASS_MATERIAL_EDIT,
    MISSION_EFFECT_AUTHORITY_SCHEMA_VERSION,
    NEON_RELAY_MISSION_EFFECT_AUTHORITY,
    MissionEffectAuthority,
    MissionEffectAuthorityError,
    create_mission_effect_authority,
)
from admissible.delegated_gate.neon_relay_mission import (
    NEON_RELAY_REQUIRED_COMMIT_MESSAGE,
    NEON_RELAY_REQUIRED_MATERIAL_PATHS,
)


AUTHORITY = NEON_RELAY_MISSION_EFFECT_AUTHORITY

OPTIONS = [
    {"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"},
    {"optionId": "allow-always", "name": "Allow always", "kind": "allow_always"},
    {"optionId": "reject-once", "name": "Reject", "kind": "reject_once"},
]


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
    """A disposable stand-in for the delivered Neon Relay fixture workspace."""

    work = tmp_path / "work"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    git(work, "config", "commit.gpgsign", "false")
    (work / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    (work / "LOCAL_DEV.md").write_text("NEON_RELAY_BLANK_FIXTURE_V1\n", encoding="utf-8")
    (work / "package.json").write_text("{}\n", encoding="utf-8")
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "fixture")
    return work


def head_of(repository: Path) -> str:
    return git(repository, "rev-parse", "HEAD").stdout.strip().lower()


def runtime_for(repository: Path) -> MissionEffectRuntime:
    return MissionEffectRuntime(
        authority=AUTHORITY, workspace=str(repository), fixture_head=head_of(repository),
    )


def edit_params(
    workspace: Path,
    relative: str,
    *,
    old_text: str | None = None,
    new_text: str = "x\n",
    tool_call_id: str = "call-edit-1",
    absolute: str | None = None,
    content: object = ...,
):
    """Exactly the installed CLI's write-decision permission params."""

    target = absolute if absolute is not None else str(
        (Path(workspace) / relative.replace("/", os.sep))
    )
    tool_call = {
        "toolCallId": tool_call_id,
        "title": f"Edit `{target}`" if old_text is not None else f"Write {target}",
        "kind": "edit",
        "status": "pending",
    }
    if content is ...:
        tool_call["content"] = [
            {"type": "diff", "path": target, "oldText": old_text, "newText": new_text}
        ]
    elif content is not None:
        tool_call["content"] = content
    return {"sessionId": "s", "toolCall": tool_call, "options": list(OPTIONS)}


def shell_params(command: str, *, tool_call_id: str = "call-shell-1"):
    return {
        "sessionId": "s",
        "toolCall": {
            "toolCallId": tool_call_id, "title": f"`{command}`", "kind": "execute",
            "status": "pending",
            "content": [{"type": "content", "content": {"type": "text", "text": "Not in allowlist"}}],
        },
        "options": list(OPTIONS),
    }


def decide(params, *, workspace: Path, effects: MissionEffectRuntime | None):
    request = parse_permission_request(params)
    assert request is not None
    return decide_permission(request, workspace=str(workspace), mission_effects=effects)


def author_full_material(repository: Path) -> None:
    for relative in NEON_RELAY_REQUIRED_MATERIAL_PATHS:
        path = repository / relative.replace("/", os.sep)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"// {relative}\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# A. the canonical authority model
# ---------------------------------------------------------------------------


def test_the_authority_is_canonical_immutable_and_exactly_the_mission_set():
    assert AUTHORITY.schema_version == MISSION_EFFECT_AUTHORITY_SCHEMA_VERSION
    assert AUTHORITY.writable_material_paths == NEON_RELAY_REQUIRED_MATERIAL_PATHS
    assert len(AUTHORITY.writable_material_paths) == 14
    assert AUTHORITY.creatable_directories == ("src", "test")
    assert AUTHORITY.exact_commit_message == NEON_RELAY_REQUIRED_COMMIT_MESSAGE
    assert AUTHORITY.local_verification_commands == (
        ("npm", "run", "test"), ("npm", "test"),
        ("npm.cmd", "run", "test"), ("npm.cmd", "test"),
    )
    assert AUTHORITY.approval_bounds[EFFECT_CLASS_GIT_COMMIT] == 1
    # Round-trips through its canonical document without drift.
    assert MissionEffectAuthority.from_dict(AUTHORITY.to_dict()) == AUTHORITY
    assert AUTHORITY.validated() is AUTHORITY


def test_the_authority_fingerprint_is_not_self_referential_and_detects_tampering():
    tampered = MissionEffectAuthority(
        **{**AUTHORITY.__dict__, "writable_material_paths": AUTHORITY.writable_material_paths + ("evil.js",)}
    )
    with pytest.raises(MissionEffectAuthorityError):
        tampered.validated()
    document = AUTHORITY.to_dict()
    document["exact_commit_message"] = "chore: anything"
    with pytest.raises(MissionEffectAuthorityError):
        MissionEffectAuthority.from_dict(document)


def test_more_than_one_commit_can_never_be_authorized():
    bounds = tuple(
        (name, 5 if name == EFFECT_CLASS_GIT_COMMIT else value)
        for name, value in AUTHORITY.max_approvals_per_effect_class
    )
    with pytest.raises(MissionEffectAuthorityError):
        create_mission_effect_authority(
            **{
                **{k: v for k, v in AUTHORITY.__dict__.items()
                   if k not in ("schema_version", "authority_fingerprint")},
                "max_approvals_per_effect_class": bounds,
            }
        )


def test_a_creatable_directory_no_authorized_path_needs_is_refused():
    with pytest.raises(MissionEffectAuthorityError):
        create_mission_effect_authority(
            **{
                **{k: v for k, v in AUTHORITY.__dict__.items()
                   if k not in ("schema_version", "authority_fingerprint")},
                "creatable_directories": ("src", "test", "tools"),
            }
        )


# ---------------------------------------------------------------------------
# I.1 / I.2: kind=edit is live, and exact authorized writes get allow-once
# ---------------------------------------------------------------------------


def test_kind_edit_no_longer_fails_categorically(fixture_repository):
    """I.1: the exact defect that made the mission unexecutable is closed."""

    effects = runtime_for(fixture_repository)
    params = edit_params(fixture_repository, "src/game.js")

    without = decide(params, workspace=fixture_repository, effects=None)
    assert without.decision == DECISION_REJECT
    assert without.rule_id == RULE_TOOL_KIND_NOT_PERMITTED

    with_authority = decide(params, workspace=fixture_repository, effects=effects)
    assert with_authority.decision == DECISION_ALLOW_ONCE
    assert with_authority.rule_id == RULE_EDIT_AUTHORIZED


def test_every_authorized_material_write_receives_allow_once(fixture_repository):
    """I.2: all fourteen, created and updated, through the real request shape."""

    effects = runtime_for(fixture_repository)
    for index, relative in enumerate(NEON_RELAY_REQUIRED_MATERIAL_PATHS):
        created = decide(
            edit_params(fixture_repository, relative, tool_call_id=f"c{index}"),
            workspace=fixture_repository, effects=effects,
        )
        assert created.decision == DECISION_ALLOW_ONCE, relative
        assert created.selected_option_id == "allow-once"
        assert created.selected_option_kind == PERMISSION_KIND_ALLOW_ONCE
        assert created.structured_operation == EDIT_OPERATION_CREATE
        assert created.authority_class == EFFECT_CLASS_MATERIAL_EDIT

        updated = decide(
            edit_params(fixture_repository, relative, old_text="old\n", tool_call_id=f"u{index}"),
            workspace=fixture_repository, effects=effects,
        )
        assert updated.decision == DECISION_ALLOW_ONCE, relative
        assert updated.structured_operation == EDIT_OPERATION_UPDATE


def test_an_authorized_create_names_its_authorized_parent_directory(fixture_repository):
    decision = decide(
        edit_params(fixture_repository, "src/game.js"),
        workspace=fixture_repository, effects=runtime_for(fixture_repository),
    )
    assert decision.normalized_paths == ("src/", "src/game.js")
    top_level = decide(
        edit_params(fixture_repository, "index.html", tool_call_id="c-top"),
        workspace=fixture_repository, effects=runtime_for(fixture_repository),
    )
    assert top_level.normalized_paths == ("index.html",)


# ---------------------------------------------------------------------------
# I.3 / I.4 / I.5 / I.6: everything an edit may not be
# ---------------------------------------------------------------------------


def test_an_unauthorized_write_path_is_refused(fixture_repository):
    """I.3: containment is not authorization; the set is exact."""

    effects = runtime_for(fixture_repository)
    for relative in ("README.md", "src/extra.js", ".gitignore", "src/nested/deep.js", "notes.txt"):
        decision = decide(
            edit_params(fixture_repository, relative, tool_call_id=f"x-{relative}"),
            workspace=fixture_repository, effects=effects,
        )
        assert decision.decision == DECISION_REJECT, relative
        assert decision.rule_id in {
            RULE_EDIT_PATH_NOT_AUTHORIZED,
        } or decision.rule_id.startswith("edit_target_parent"), (relative, decision.rule_id)


def test_casing_variants_cannot_escape_exact_path_matching(fixture_repository):
    """I.4: contained by Windows semantics, unauthorized by exact comparison."""

    effects = runtime_for(fixture_repository)
    for relative in ("Index.html", "INDEX.HTML", "SRC/game.js", "src/Game.js", "Src/Game.Js"):
        decision = decide(
            edit_params(fixture_repository, relative, tool_call_id=f"case-{relative}"),
            workspace=fixture_repository, effects=effects,
        )
        assert decision.decision == DECISION_REJECT, relative


def test_stream_device_unc_traversal_and_symlink_forms_are_refused(fixture_repository, tmp_path):
    """I.5: every refused path form, named individually."""

    effects = runtime_for(fixture_repository)
    inside = str(fixture_repository / "index.html")
    cases = {
        inside + ":hidden": RULE_EDIT_PATH_UNSAFE_FORM,
        "\\\\?\\" + inside: RULE_EDIT_PATH_UNSAFE_FORM,
        "\\\\.\\" + inside: RULE_EDIT_PATH_UNSAFE_FORM,
        "\\\\server\\share\\index.html": RULE_EDIT_PATH_UNSAFE_FORM,
        "//server/share/index.html": RULE_EDIT_PATH_UNSAFE_FORM,
        str(tmp_path / "escaped.html"): RULE_EDIT_PATH_OUTSIDE_WORKSPACE,
        str(fixture_repository) + os.sep + ".." + os.sep + "escaped.html":
            RULE_EDIT_PATH_OUTSIDE_WORKSPACE,
    }
    for raw, expected in cases.items():
        decision = decide(
            edit_params(fixture_repository, "index.html", absolute=raw, tool_call_id="p"),
            workspace=fixture_repository, effects=effects,
        )
        assert decision.decision == DECISION_REJECT, raw
        assert decision.rule_id == expected, (raw, decision.rule_id)


@pytest.mark.skipif(os.name != "nt", reason="junction creation is a Windows reparse-point form")
def test_a_junction_on_the_resolved_chain_is_refused(fixture_repository, tmp_path):
    """I.5: a reparse point standing in for an authorized directory."""

    outside = tmp_path / "outside"
    outside.mkdir()
    junction = fixture_repository / "src"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:  # pragma: no cover - host policy
        pytest.skip("this host refuses junction creation")
    decision = decide(
        edit_params(fixture_repository, "src/game.js"),
        workspace=fixture_repository, effects=runtime_for(fixture_repository),
    )
    assert decision.decision == DECISION_REJECT
    assert decision.rule_id == RULE_EDIT_REPARSE_POINT


def test_the_delete_decision_shape_is_refused(fixture_repository):
    """I.6: the CLI's delete carries kind=edit and no content at all.

    Its enum is ``{write, shell, delete, mcp}`` and an overwrite is a ``write``
    carrying ``oldText``, so a delete is never part of a replace sequence: it is
    always a free-standing destructive effect this mission does not need.
    """

    effects = runtime_for(fixture_repository)
    target = str(fixture_repository / "src" / "game.js")
    params = {
        "sessionId": "s",
        "toolCall": {
            "toolCallId": "call-del", "title": f"Delete `{target}`",
            "kind": "edit", "status": "pending",
        },
        "options": list(OPTIONS),
    }
    decision = decide(params, workspace=fixture_repository, effects=effects)
    assert decision.decision == DECISION_REJECT
    assert decision.rule_id == RULE_EDIT_OPERATION_UNSUPPORTED
    assert decision.structured_operation == "delete"

    intent = parse_edit_tool_call(title=f"Delete `{target}`", content=None)
    assert intent.operation == "delete" and intent.structured is False


def test_an_edit_without_a_provable_structured_path_is_refused(fixture_repository):
    effects = runtime_for(fixture_repository)
    unprovable = (
        None,
        [],
        [{"type": "content", "content": {"type": "text", "text": "Edit `index.html`"}}],
        [{"type": "diff", "newText": "x"}],
        [{"type": "diff", "path": "index.html", "newText": "x"}],
        [{"type": "diff", "path": "index.html", "oldText": 7, "newText": "x"}],
    )
    for content in unprovable:
        decision = decide(
            edit_params(fixture_repository, "index.html", content=content, tool_call_id="u"),
            workspace=fixture_repository, effects=effects,
        )
        assert decision.decision == DECISION_REJECT, content
        assert decision.rule_id == RULE_EDIT_LOCATION_UNPROVEN, content


def test_the_title_is_never_the_path_authority(fixture_repository):
    """A benign title cannot smuggle in an unauthorized structured target."""

    effects = runtime_for(fixture_repository)
    params = edit_params(fixture_repository, "src/game.js")
    params["toolCall"]["content"][0]["path"] = str(fixture_repository / "README.md")
    decision = decide(params, workspace=fixture_repository, effects=effects)
    assert decision.decision == DECISION_REJECT
    assert decision.rule_id == RULE_EDIT_PATH_NOT_AUTHORIZED
    assert decision.normalized_paths == ()


# ---------------------------------------------------------------------------
# I.7 / I.8: local verification
# ---------------------------------------------------------------------------


def test_the_four_exact_local_verification_spellings_are_permitted(fixture_repository):
    """I.7: the exact verification path is guaranteed, not accidental."""

    effects = runtime_for(fixture_repository)
    for index, command in enumerate(
        ("npm test", "npm.cmd test", "npm run test", "npm.cmd run test")
    ):
        decision = decide(
            shell_params(command, tool_call_id=f"v{index}"),
            workspace=fixture_repository, effects=effects,
        )
        assert decision.decision == DECISION_ALLOW_ONCE, command
        assert decision.rule_id == RULE_LOCAL_VERIFICATION_AUTHORIZED
        assert decision.authority_class == EFFECT_CLASS_LOCAL_VERIFICATION


def test_every_other_npm_invocation_is_refused_decisively(fixture_repository):
    """I.8: refused *as an unauthorized verification*, not as a stray token."""

    effects = runtime_for(fixture_repository)
    refused = (
        "npm install", "npm install left-pad", "npm i", "npm ci", "npm audit",
        "npm update", "npm exec node", "npm publish", "npm test --watch",
        "npm test extra", "npm.cmd install", "npm run build", "npm run test:watch",
        "npm --prefix .. test", "npm test -- --reporter=tap",
    )
    for index, command in enumerate(refused):
        decision = decide(
            shell_params(command, tool_call_id=f"n{index}"),
            workspace=fixture_repository, effects=effects,
        )
        assert decision.decision == DECISION_REJECT, command
        assert decision.rule_id == RULE_LOCAL_VERIFICATION_NOT_EXACT, command


def test_npx_and_shell_composition_around_npm_stay_refused(fixture_repository):
    effects = runtime_for(fixture_repository)
    for index, command in enumerate(
        ("npx serve", "npm test | tee out.txt", "npm test > out.txt",
         "npm test; npm install", "cmd /c npm test", "NODE_ENV=x npm test")
    ):
        decision = decide(
            shell_params(command, tool_call_id=f"c{index}"),
            workspace=fixture_repository, effects=effects,
        )
        assert decision.decision == DECISION_REJECT, command


# ---------------------------------------------------------------------------
# I.9 / I.10: staging is granted by live observation, never by the command
# ---------------------------------------------------------------------------


def test_git_add_is_granted_only_after_live_path_set_validation(fixture_repository):
    """I.9: the same command, refused and then permitted by observation alone."""

    effects = runtime_for(fixture_repository)

    empty = decide(shell_params("git add .", tool_call_id="s0"),
                   workspace=fixture_repository, effects=effects)
    assert empty.decision == DECISION_REJECT
    assert empty.rule_id == RULE_GIT_STAGE_LIVE_STATE_REFUSED

    author_full_material(fixture_repository)
    granted = decide(shell_params("git add .", tool_call_id="s1"),
                     workspace=fixture_repository, effects=effects)
    assert granted.decision == DECISION_ALLOW_ONCE
    assert granted.rule_id == RULE_GIT_STAGE_AUTHORIZED
    assert granted.authority_class == EFFECT_CLASS_GIT_STAGE
    assert granted.live_observation_fingerprint is not None
    assert set(granted.normalized_paths) == set(NEON_RELAY_REQUIRED_MATERIAL_PATHS)


def test_every_authorized_staging_form_and_no_other(fixture_repository):
    author_full_material(fixture_repository)
    for index, command in enumerate(("git add -A", "git add --all", "git add .")):
        decision = decide(shell_params(command, tool_call_id=f"f{index}"),
                          workspace=fixture_repository, effects=runtime_for(fixture_repository))
        assert decision.decision == DECISION_ALLOW_ONCE, command
    explicit = decide(
        shell_params("git add -- index.html src/game.js", tool_call_id="fe"),
        workspace=fixture_repository, effects=runtime_for(fixture_repository),
    )
    assert explicit.decision == DECISION_ALLOW_ONCE

    for index, command in enumerate((
        "git add -A -f", "git add --force .", "git add -u", "git add",
        "git add ..", "git add -- ../outside.txt", "git add -- .gitignore",
        "git add -A --chmod=+x", "git add -p",
    )):
        decision = decide(shell_params(command, tool_call_id=f"r{index}"),
                          workspace=fixture_repository, effects=runtime_for(fixture_repository))
        assert decision.decision == DECISION_REJECT, command
        assert decision.rule_id != RULE_GIT_STAGE_AUTHORIZED, command


def test_unexpected_workspace_material_blocks_git_add(fixture_repository):
    """I.10: one unauthorized untracked path refuses the whole staging."""

    author_full_material(fixture_repository)
    (fixture_repository / "notes.txt").write_text("scratch\n", encoding="utf-8")
    decision = decide(shell_params("git add -A", tool_call_id="s2"),
                      workspace=fixture_repository, effects=runtime_for(fixture_repository))
    assert decision.decision == DECISION_REJECT
    assert decision.rule_id == RULE_GIT_STAGE_LIVE_STATE_REFUSED
    assert LIVE_UNAUTHORIZED_PATH in decision.live_refusal_reasons


def test_a_remote_a_moved_head_or_a_deletion_refuses_staging(fixture_repository, tmp_path):
    author_full_material(fixture_repository)

    git(fixture_repository, "remote", "add", "origin", str(tmp_path / "elsewhere"))
    with_remote = decide(shell_params("git add -A", tool_call_id="s3"),
                         workspace=fixture_repository, effects=runtime_for(fixture_repository))
    assert LIVE_REMOTE_PRESENT in with_remote.live_refusal_reasons
    git(fixture_repository, "remote", "remove", "origin")

    stale = MissionEffectRuntime(
        authority=AUTHORITY, workspace=str(fixture_repository), fixture_head="0" * 40,
    )
    moved = decide(shell_params("git add -A", tool_call_id="s4"),
                   workspace=fixture_repository, effects=stale)
    assert LIVE_HEAD_MOVED in moved.live_refusal_reasons

    (fixture_repository / "package.json").unlink()
    deleted = decide(shell_params("git add -A", tool_call_id="s5"),
                     workspace=fixture_repository, effects=runtime_for(fixture_repository))
    assert LIVE_DELETION_PRESENT in deleted.live_refusal_reasons


# ---------------------------------------------------------------------------
# I.11 / I.12 / I.13: the one exact commit
# ---------------------------------------------------------------------------


def test_the_exact_commit_permits_only_after_valid_staging(fixture_repository):
    """I.11: an empty index refuses; a validly staged index permits."""

    effects = runtime_for(fixture_repository)
    command = f'git commit -m "{NEON_RELAY_REQUIRED_COMMIT_MESSAGE}"'

    unstaged = decide(shell_params(command, tool_call_id="k0"),
                      workspace=fixture_repository, effects=effects)
    assert unstaged.decision == DECISION_REJECT
    assert unstaged.rule_id == RULE_GIT_COMMIT_LIVE_STATE_REFUSED
    assert LIVE_INDEX_EMPTY in unstaged.live_refusal_reasons

    author_full_material(fixture_repository)
    git(fixture_repository, "add", "-A")
    granted = decide(shell_params(command, tool_call_id="k1"),
                     workspace=fixture_repository, effects=effects)
    assert granted.decision == DECISION_ALLOW_ONCE
    assert granted.rule_id == RULE_GIT_COMMIT_AUTHORIZED
    assert granted.authority_class == EFFECT_CLASS_GIT_COMMIT
    assert set(granted.normalized_paths) == set(NEON_RELAY_REQUIRED_MATERIAL_PATHS)


def test_all_three_authorized_commit_spellings_carry_the_exact_message(fixture_repository):
    author_full_material(fixture_repository)
    git(fixture_repository, "add", "-A")
    message = NEON_RELAY_REQUIRED_COMMIT_MESSAGE
    for index, command in enumerate((
        f'git commit -m "{message}"',
        f"git commit -m '{message}'",
        f'git commit --message "{message}"',
        f'git commit --message="{message}"',
    )):
        decision = decide(shell_params(command, tool_call_id=f"m{index}"),
                          workspace=fixture_repository, effects=runtime_for(fixture_repository))
        assert decision.decision == DECISION_ALLOW_ONCE, command


def test_a_different_commit_message_is_refused(fixture_repository):
    """I.12: including near-misses that differ by one character."""

    author_full_material(fixture_repository)
    git(fixture_repository, "add", "-A")
    effects = runtime_for(fixture_repository)
    exact = NEON_RELAY_REQUIRED_COMMIT_MESSAGE
    for index, message in enumerate((
        "chore: wip",
        exact + ".",
        exact + " ",
        " " + exact,
        exact.replace("playable", "Playable"),
        exact.upper(),
        exact[:-1],
    )):
        decision = decide(
            shell_params(f'git commit -m "{message}"', tool_call_id=f"w{index}"),
            workspace=fixture_repository, effects=effects,
        )
        assert decision.decision == DECISION_REJECT, message
        assert decision.rule_id == RULE_GIT_COMMIT_MESSAGE_NOT_EXACT, message


def test_every_commit_shape_other_than_a_plain_local_commit_is_refused(fixture_repository):
    author_full_material(fixture_repository)
    git(fixture_repository, "add", "-A")
    effects = runtime_for(fixture_repository)
    exact = NEON_RELAY_REQUIRED_COMMIT_MESSAGE
    refused = (
        f'git commit --amend -m "{exact}"',
        f'git commit -m "{exact}" --amend',
        f'git commit --fixup HEAD -m "{exact}"',
        f'git commit --squash HEAD -m "{exact}"',
        f'git commit -S -m "{exact}"',
        f'git commit --gpg-sign -m "{exact}"',
        f'git commit --no-verify -m "{exact}"',
        f'git commit --author "Someone Else" -m "{exact}"',
        f'git commit -m "{exact}" -- index.html',
        f'git commit -am "{exact}"',
        f'git commit -a -m "{exact}"',
        f'git -c user.name=x commit -m "{exact}"',
        f'git commit -m "{exact}" -m "second paragraph"',
        "git commit-tree HEAD",
        "git commit",
    )
    for index, command in enumerate(refused):
        decision = decide(shell_params(command, tool_call_id=f"s{index}"),
                          workspace=fixture_repository, effects=effects)
        assert decision.decision == DECISION_REJECT, command
        assert decision.rule_id != RULE_GIT_COMMIT_AUTHORIZED, command


def test_a_second_commit_approval_is_refused(fixture_repository):
    """I.13: the commit budget is one, and it is spent by the first approval."""

    author_full_material(fixture_repository)
    git(fixture_repository, "add", "-A")
    evidence = AcpAuthorityEvidence(fixture_repository.parent / "authority.jsonl")
    effects = runtime_for(fixture_repository)
    dispatcher = AcpServerRequestDispatcher(
        evidence=evidence, workspace=str(fixture_repository), mission_effects=effects,
    )
    command = f'git commit -m "{NEON_RELAY_REQUIRED_COMMIT_MESSAGE}"'

    first = dispatcher.dispatch(
        method="session/request_permission", message_id=1,
        params=shell_params(command, tool_call_id="commit-1"),
    )
    assert first.response["result"]["outcome"]["optionId"] == "allow-once"
    assert effects.ledger.spent(EFFECT_CLASS_GIT_COMMIT) == 1

    second = dispatcher.dispatch(
        method="session/request_permission", message_id=2,
        params=shell_params(command, tool_call_id="commit-2"),
    )
    assert second.response["result"]["outcome"]["optionId"] == "reject-once"
    assert dispatcher.decisions[-1].rule_id == RULE_BUDGET_EXHAUSTED
    assert effects.ledger.spent(EFFECT_CLASS_GIT_COMMIT) == 1


def test_an_identical_retransmission_replays_without_spending_authority(fixture_repository):
    author_full_material(fixture_repository)
    git(fixture_repository, "add", "-A")
    evidence = AcpAuthorityEvidence(fixture_repository.parent / "dup.jsonl")
    effects = runtime_for(fixture_repository)
    dispatcher = AcpServerRequestDispatcher(
        evidence=evidence, workspace=str(fixture_repository), mission_effects=effects,
    )
    params = shell_params(
        f'git commit -m "{NEON_RELAY_REQUIRED_COMMIT_MESSAGE}"', tool_call_id="commit-x"
    )
    dispatcher.dispatch(method="session/request_permission", message_id=1, params=params)
    dispatcher.dispatch(method="session/request_permission", message_id=2, params=params)
    assert effects.ledger.spent(EFFECT_CLASS_GIT_COMMIT) == 1
    assert dispatcher.decisions[-1].rule_id == RULE_DUPLICATE_REPLAY
    assert dispatcher.decisions[-1].replayed is True

    conflicting = shell_params("git add -A", tool_call_id="commit-x")
    dispatcher.dispatch(method="session/request_permission", message_id=3, params=conflicting)
    assert dispatcher.decisions[-1].rule_id == RULE_DUPLICATE_TOOL_CALL_CONFLICT
    assert dispatcher.decisions[-1].decision == DECISION_REJECT


# ---------------------------------------------------------------------------
# I.14: evidence precedes the response
# ---------------------------------------------------------------------------


def test_git_mutation_evidence_is_durable_before_the_response(fixture_repository):
    """I.14: an approval whose record cannot be persisted is never sent."""

    author_full_material(fixture_repository)
    git(fixture_repository, "add", "-A")
    path = fixture_repository.parent / "ordered.jsonl"
    evidence = AcpAuthorityEvidence(path)
    dispatcher = AcpServerRequestDispatcher(
        evidence=evidence, workspace=str(fixture_repository),
        mission_effects=runtime_for(fixture_repository),
    )
    outcome = dispatcher.dispatch(
        method="session/request_permission", message_id=7,
        params=shell_params(f'git commit -m "{NEON_RELAY_REQUIRED_COMMIT_MESSAGE}"'),
    )
    assert outcome.response is not None
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert records[-1]["record_type"] == RECORD_PERMISSION_DECISION
    assert records[-1]["authority_class"] == EFFECT_CLASS_GIT_COMMIT
    assert records[-1]["policy_rule_id"] == RULE_GIT_COMMIT_AUTHORIZED
    assert records[-1]["live_repository_observation_fingerprint"] is not None
    assert records[-1]["mission_effect_authority_fingerprint"] == AUTHORITY.authority_fingerprint
    assert records[-1]["authority_budget_before"][EFFECT_CLASS_GIT_COMMIT] == 0
    assert records[-1]["authority_budget_after"][EFFECT_CLASS_GIT_COMMIT] == 1
    assert records[-1]["tool_call_digest"]
    # The decision itself never claims the effect happened.
    assert "succeeded" not in json.dumps(records[-1])


def test_an_unwritable_evidence_sink_blocks_every_approval(fixture_repository):
    author_full_material(fixture_repository)
    git(fixture_repository, "add", "-A")
    effects = runtime_for(fixture_repository)

    class Refusing(AcpAuthorityEvidence):
        def _append(self, body):
            raise AcpEvidenceWriteError("sink is unavailable")

    dispatcher = AcpServerRequestDispatcher(
        evidence=Refusing(fixture_repository.parent / "never.jsonl"),
        workspace=str(fixture_repository), mission_effects=effects,
    )
    outcome = dispatcher.dispatch(
        method="session/request_permission", message_id=1,
        params=shell_params(f'git commit -m "{NEON_RELAY_REQUIRED_COMMIT_MESSAGE}"'),
    )
    assert outcome.response is None
    assert outcome.failure == "permission_evidence_write_failed"


# ---------------------------------------------------------------------------
# I.15 - I.18: the two new client requests
# ---------------------------------------------------------------------------


def test_create_plan_is_acknowledged_and_causes_no_effect(fixture_repository):
    """I.15: the plan bears no authority and the turn continues."""

    evidence = AcpAuthorityEvidence(fixture_repository.parent / "plan.jsonl")
    dispatcher = AcpServerRequestDispatcher(
        evidence=evidence, workspace=str(fixture_repository),
        mission_effects=runtime_for(fixture_repository),
    )
    before = sorted(p.name for p in fixture_repository.iterdir())
    outcome = dispatcher.dispatch(method="cursor/create_plan", message_id=3, params={
        "toolCallId": "call-plan", "name": "n", "overview": "o", "plan": "p",
        "todos": [{"id": "1", "content": "c", "status": "pending"}],
        "isProject": False,
        "phases": [{"name": "phase", "todos": [{"id": "2", "content": "d", "status": "completed"}]}],
    })
    assert outcome.failure is None
    assert outcome.response["result"] == {"outcome": {"outcome": "accepted"}}
    assert outcome.response["result"] == CREATE_PLAN_RESULT
    assert sorted(p.name for p in fixture_repository.iterdir()) == before
    summary = evidence.records[-1]["summary"]
    assert summary["todo_count"] == 2 and summary["phase_count"] == 1
    assert summary["filesystem_effect"] is False and summary["process_effect"] is False


def test_ask_question_receives_the_deterministic_bounded_response(fixture_repository):
    """I.16: no fabricated answer, no option selected, no authority changed."""

    evidence = AcpAuthorityEvidence(fixture_repository.parent / "ask.jsonl")
    effects = runtime_for(fixture_repository)
    dispatcher = AcpServerRequestDispatcher(
        evidence=evidence, workspace=str(fixture_repository), mission_effects=effects,
    )
    outcome = dispatcher.dispatch(method="cursor/ask_question", message_id=4, params={
        "sessionId": "s", "toolCallId": "call-ask", "title": "Which palette?",
        "questions": [{
            "id": "q1", "prompt": "Pick one",
            "options": [{"id": "cyan", "label": "Cyan"}, {"id": "magenta", "label": "Magenta"}],
            "allowMultiple": False,
        }],
    })
    assert outcome.failure is None
    result = outcome.response["result"]
    assert result == ASK_QUESTION_RESULT
    assert result["outcome"]["outcome"] == "skipped"
    assert result["outcome"]["reason"] == ACP_ASK_QUESTION_UNATTENDED_REASON
    # No answer was invented and no option id was selected.
    assert "answers" not in result["outcome"]
    assert "cyan" not in json.dumps(result) and "magenta" not in json.dumps(result)
    # The response is deterministic across repetitions.
    again = dispatcher.dispatch(method="cursor/ask_question", message_id=5, params={
        "toolCallId": "call-ask-2",
        "questions": [{"id": "q", "prompt": "p", "options": [], "allowMultiple": True}],
    })
    assert again.response["result"] == result
    # The authority is untouched by anything a question said.
    assert effects.ledger.snapshot() == {name: 0 for name in AUTHORITY.approval_bounds}


def test_malformed_plan_and_question_requests_fail_closed(fixture_repository):
    """I.17: an invalid-params error *and* a terminated turn."""

    evidence = AcpAuthorityEvidence(fixture_repository.parent / "bad.jsonl")
    dispatcher = AcpServerRequestDispatcher(
        evidence=evidence, workspace=str(fixture_repository),
        mission_effects=runtime_for(fixture_repository),
    )
    malformed_plans = (
        None, [], "plan", {}, {"todos": []},
        {"toolCallId": "", "todos": [{"id": "1", "content": "c", "status": "pending"}]},
        {"toolCallId": "t", "todos": [{"id": "1", "content": "c", "status": "half-done"}]},
        {"toolCallId": "t", "todos": [{"id": "1", "content": "c", "status": "pending"}], "extra": 1},
        {"toolCallId": "t", "todos": [{"id": "1", "content": "c", "status": "pending"}],
         "phases": [{"name": "n", "todos": [{"id": "2", "content": "d", "status": "nope"}]}]},
    )
    for params in malformed_plans:
        assert parse_create_plan(params) is None, params
        outcome = dispatcher.dispatch(method="cursor/create_plan", message_id=1, params=params)
        assert outcome.response["error"]["code"] == -32602
        assert outcome.failure == "malformed_server_request:cursor/create_plan"

    malformed_questions = (
        None, [], {}, {"questions": []}, {"questions": "q"},
        {"questions": [{"id": "q1"}]},
        {"questions": [{"id": "q1", "prompt": "p", "options": [{"id": "a"}]}]},
        {"questions": [{"id": "q1", "prompt": "p", "options": [], "allowMultiple": "yes"}]},
        {"questions": [{"id": "q1", "prompt": "p", "extra": 1}]},
        {"questions": [{"id": "q1", "prompt": "p"}] * 17},
    )
    for params in malformed_questions:
        assert parse_ask_question(params) is None, params
        outcome = dispatcher.dispatch(method="cursor/ask_question", message_id=2, params=params)
        assert outcome.response["error"]["code"] == -32602
        assert outcome.failure == "malformed_server_request:cursor/ask_question"


def test_unknown_cursor_methods_stay_fail_closed(fixture_repository):
    """I.18: no generic ``cursor/*`` acknowledgement was introduced."""

    evidence = AcpAuthorityEvidence(fixture_repository.parent / "unknown.jsonl")
    dispatcher = AcpServerRequestDispatcher(
        evidence=evidence, workspace=str(fixture_repository),
        mission_effects=runtime_for(fixture_repository),
    )
    for method in ("cursor/task", "cursor/generate_image", "cursor/list_available_models",
                   "cursor/Create_Plan", "cursor/ask_questions", "cursor/", "cursor/*"):
        outcome = dispatcher.dispatch(method=method, message_id=1, params={})
        assert outcome.response is None, method
        assert outcome.failure == f"unanswerable_server_request:{method}", method

    # A near-miss that differs only by surrounding whitespace is matched
    # exactly, so it is unanswerable too; the persisted detail is normalized.
    padded = dispatcher.dispatch(method=" cursor/ask_question ", message_id=2, params={})
    assert padded.response is None
    assert padded.failure == "unanswerable_server_request:cursor/ask_question"


# ---------------------------------------------------------------------------
# I.19: the complete pre-prompt workspace identity
# ---------------------------------------------------------------------------


def test_a_tracked_content_mutation_with_an_identical_path_set_is_detected(fixture_repository):
    """I.19: the exact case a path-name inventory is structurally blind to."""

    from admissible.delegated_gate.acp_authority import workspace_inventory

    before_paths = workspace_inventory(fixture_repository)
    before = capture_workspace_identity(fixture_repository)

    (fixture_repository / "LOCAL_DEV.md").write_text("silently rewritten\n", encoding="utf-8")

    after_paths = workspace_inventory(fixture_repository)
    after = capture_workspace_identity(fixture_repository)

    # The pollution boundary sees nothing at all.
    assert set(after_paths) - set(before_paths) == set()
    # The identity sees exactly the mutation.
    differences = compare_workspace_identity(before, after)
    assert "tracked_content:LOCAL_DEV.md" in differences
    assert before.identity_fingerprint != after.identity_fingerprint


def test_the_identity_covers_head_index_untracked_and_reparse_state(fixture_repository):
    before = capture_workspace_identity(fixture_repository)
    assert before.git_head == head_of(fixture_repository)
    assert before.index_fingerprint is not None
    assert dict((p, m) for p, m, _ in before.tracked_entries).keys() >= {
        ".gitignore", "LOCAL_DEV.md", "package.json"
    }
    assert before.ignored_path_policy == "ignored_paths_are_observed_and_recorded_never_cleaned"

    (fixture_repository / "index.html").write_text("<html>\n", encoding="utf-8")
    added = compare_workspace_identity(before, capture_workspace_identity(fixture_repository))
    assert "untracked_added:index.html" in added
    assert "git_status" in added

    git(fixture_repository, "add", "-A")
    staged = compare_workspace_identity(before, capture_workspace_identity(fixture_repository))
    assert "git_index" in staged

    git(fixture_repository, "commit", "-q", "-m", "second")
    committed = compare_workspace_identity(before, capture_workspace_identity(fixture_repository))
    assert "git_head" in committed

    assert compare_workspace_identity(before, before) == ()


def test_a_workspace_without_git_still_yields_a_content_sensitive_identity(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "a.txt").write_text("one\n", encoding="utf-8")
    before = capture_workspace_identity(plain)
    assert before.git_head is None and before.index_fingerprint is None
    (plain / "a.txt").write_text("two\n", encoding="utf-8")
    assert "untracked_content:a.txt" in compare_workspace_identity(
        before, capture_workspace_identity(plain)
    )


# ---------------------------------------------------------------------------
# I.20 - I.22: the V4 boundary is intact
# ---------------------------------------------------------------------------


def test_the_generic_deny_by_default_grammar_is_unchanged(fixture_repository):
    """I.20 + I.21: nothing the mission authority added widened the fallback."""

    effects = runtime_for(fixture_repository)
    destructive = (
        '`cmd /c "rmdir /s /q %SystemDrive%"`',
        "`Remove-Item -Recurse -Force .`",
        "`git push origin main`",
        "`Invoke-WebRequest http://example.invalid`",
        "`node server.js`",
        "`Start-Process powershell`",
        "`git status --short; Remove-Item -Recurse -Force '%SystemDrive%'`",
    )
    for index, title in enumerate(destructive):
        with_authority = decide(
            {"sessionId": "s",
             "toolCall": {"toolCallId": f"d{index}", "title": title, "kind": "execute",
                          "status": "pending"},
             "options": list(OPTIONS)},
            workspace=fixture_repository, effects=effects,
        )
        assert with_authority.decision == DECISION_REJECT, title
        assert with_authority.authority_class is None, title

    # And the read-only inspection language still works, unchanged.
    permitted = decide(shell_params("git status --short", tool_call_id="ro"),
                       workspace=fixture_repository, effects=effects)
    assert permitted.decision == DECISION_ALLOW_ONCE
    assert permitted.authority_class is None


def test_allow_always_remains_unreachable_on_every_mission_path(fixture_repository):
    """I.22: including the three new approval paths."""

    author_full_material(fixture_repository)
    effects = runtime_for(fixture_repository)
    approvals = [
        edit_params(fixture_repository, "src/game.js", tool_call_id="a1"),
        shell_params("npm test", tool_call_id="a2"),
        shell_params("git add -A", tool_call_id="a3"),
    ]
    for params in approvals:
        decision = decide(params, workspace=fixture_repository, effects=effects)
        assert decision.decision == DECISION_ALLOW_ONCE
        assert decision.selected_option_kind == PERMISSION_KIND_ALLOW_ONCE
        assert decision.selected_option_kind not in FORBIDDEN_PERMISSION_OPTION_KINDS
        assert decision.selected_option_id == "allow-once"

    # With only standing authority on offer, every mission path refuses.
    only_always = [
        {"optionId": "allow-always", "name": "Allow always", "kind": "allow_always"},
        {"optionId": "reject-once", "name": "Reject", "kind": "reject_once"},
    ]
    for index, params in enumerate([
        edit_params(fixture_repository, "src/render.js", tool_call_id="b1"),
        shell_params("npm test", tool_call_id="b2"),
    ]):
        params["options"] = list(only_always)
        decision = decide(params, workspace=fixture_repository, effects=effects)
        assert decision.decision == DECISION_REJECT
        assert decision.selected_option_kind == "reject_once"


def test_the_material_edit_budget_is_bounded(fixture_repository):
    evidence = AcpAuthorityEvidence(fixture_repository.parent / "budget.jsonl")
    effects = runtime_for(fixture_repository)
    dispatcher = AcpServerRequestDispatcher(
        evidence=evidence, workspace=str(fixture_repository), mission_effects=effects,
    )
    bound = AUTHORITY.approval_bounds[EFFECT_CLASS_MATERIAL_EDIT]
    for index in range(bound + 3):
        outcome = dispatcher.dispatch(
            method="session/request_permission", message_id=index,
            params=edit_params(fixture_repository, "src/game.js", tool_call_id=f"e{index}"),
        )
        selected = outcome.response["result"]["outcome"]["optionId"]
        assert selected == ("allow-once" if index < bound else "reject-once"), index
    assert effects.ledger.spent(EFFECT_CLASS_MATERIAL_EDIT) == bound
    assert dispatcher.decisions[-1].rule_id == RULE_BUDGET_EXHAUSTED


# ---------------------------------------------------------------------------
# I.25: no prompt bytes anywhere in authority evidence
# ---------------------------------------------------------------------------


def test_prompt_bytes_never_reach_authority_evidence(fixture_repository):
    secret = "OWNER-SECRET-MISSION-PROMPT-0xdeadbeef"
    path = fixture_repository.parent / "redacted.jsonl"
    evidence = AcpAuthorityEvidence(path, redact=(secret,))
    dispatcher = AcpServerRequestDispatcher(
        evidence=evidence, workspace=str(fixture_repository),
        mission_effects=runtime_for(fixture_repository),
    )
    dispatcher.dispatch(
        method="session/request_permission", message_id=1,
        params=edit_params(fixture_repository, "index.html", new_text=secret),
    )
    dispatcher.dispatch(method="cursor/create_plan", message_id=2, params={
        "toolCallId": "p", "plan": secret,
        "todos": [{"id": "1", "content": secret, "status": "pending"}],
    })
    dispatcher.dispatch(method="cursor/ask_question", message_id=3, params={
        "toolCallId": "q",
        "questions": [{"id": "1", "prompt": secret, "options": [], "allowMultiple": False}],
    })
    text = path.read_text(encoding="utf-8")
    assert secret not in text
    # The diff body is never copied at all, redacted or otherwise.
    assert "newText" not in text


# ---------------------------------------------------------------------------
# structural helpers
# ---------------------------------------------------------------------------


def test_resolve_structured_target_reports_the_exact_relative_path(fixture_repository):
    workspace = str(fixture_repository)
    target, rule = resolve_structured_target(
        str(fixture_repository / "src" / "game.js"), workspace=workspace
    )
    assert rule == "" and target is not None
    assert target.relative_posix == "src/game.js"
    assert target.parent_relative_posix == "src"

    relative_form, rule = resolve_structured_target("src/game.js", workspace=workspace)
    assert rule == "" and relative_form.relative_posix == "src/game.js"

    forward, rule = resolve_structured_target(
        str(fixture_repository).replace("\\", "/") + "/src/game.js", workspace=workspace
    )
    assert rule == "" and forward.relative_posix == "src/game.js"

    escaped, rule = resolve_structured_target("../outside.js", workspace=workspace)
    assert escaped is None and rule == RULE_EDIT_PATH_OUTSIDE_WORKSPACE

    itself, rule = resolve_structured_target(workspace, workspace=workspace)
    assert itself is None and rule == RULE_EDIT_PATH_OUTSIDE_WORKSPACE


def test_the_source_and_parent_boundary_is_checked_before_a_git_mutation(
    fixture_repository, tmp_path
):
    """D: staging is refused while anything outside the workspace has moved."""

    source = tmp_path / "source"
    source.mkdir()
    git(source, "init", "-q", "-b", "main")
    git(source, "config", "commit.gpgsign", "false")
    (source / "a.txt").write_text("one\n", encoding="utf-8")
    git(source, "add", "-A")
    git(source, "commit", "-q", "-m", "source")

    parent = fixture_repository.parent
    effects = MissionEffectRuntime(
        authority=AUTHORITY, workspace=str(fixture_repository),
        fixture_head=head_of(fixture_repository),
        source_repository=str(source), parent_directory=str(parent),
        excluded_parent_children=frozenset({fixture_repository.name}),
    )
    assert effects.baseline_boundary is not None

    author_full_material(fixture_repository)
    granted = decide(shell_params("git add -A", tool_call_id="b0"),
                     workspace=fixture_repository, effects=effects)
    assert granted.decision == DECISION_ALLOW_ONCE

    # A commit inside the source repository is exactly the boundary movement
    # the executor's own before/after comparison exists to catch, observed here
    # *before* the approval instead of after the run.
    (source / "a.txt").write_text("two\n", encoding="utf-8")
    git(source, "add", "-A")
    git(source, "commit", "-q", "-m", "mutated")
    moved = decide(shell_params("git add -A", tool_call_id="b1"),
                   workspace=fixture_repository, effects=effects)
    assert moved.decision == DECISION_REJECT
    assert LIVE_EXTERNAL_BOUNDARY_MOVED in moved.live_refusal_reasons

    # A new sibling under the canary parent moves it too.
    restored = MissionEffectRuntime(
        authority=AUTHORITY, workspace=str(fixture_repository),
        fixture_head=head_of(fixture_repository),
        source_repository=str(source), parent_directory=str(parent),
        excluded_parent_children=frozenset({fixture_repository.name}),
    )
    assert decide(shell_params("git add -A", tool_call_id="b2"),
                  workspace=fixture_repository, effects=restored).decision == DECISION_ALLOW_ONCE
    (parent / "unexpected-sibling").mkdir()
    sibling = decide(shell_params("git add -A", tool_call_id="b3"),
                     workspace=fixture_repository, effects=restored)
    assert sibling.decision == DECISION_REJECT
    assert LIVE_EXTERNAL_BOUNDARY_MOVED in sibling.live_refusal_reasons


def test_the_deterministic_windows_environment_authority_is_unchanged():
    """I.23: the V4 shell-folder derivation is bound and drift-checked still."""

    from admissible.delegated_gate.acp_authority import (
        WINDOWS_SHELL_FOLDER_DERIVATION_POLICY,
        WINDOWS_SHELL_FOLDER_NAMES,
        validate_derived_windows_environment,
    )

    assert WINDOWS_SHELL_FOLDER_NAMES == ("ALLUSERSPROFILE", "ProgramData", "SystemDrive")
    assert WINDOWS_SHELL_FOLDER_DERIVATION_POLICY == (
        "systemdrive=splitdrive(attested-SYSTEMROOT);"
        "programdata=known-folder-FOLDERID_ProgramData-else-<systemdrive>\\ProgramData;"
        "allusersprofile=canonically-equal-to-programdata;"
        "all-absolute-existing-directories-outside-the-authorized-work-workspace;"
        "never-inherited-from-the-parent-environment"
    )
    with pytest.raises(Exception):
        validate_derived_windows_environment({"SystemDrive": "C:", "ProgramData": "C:\\X"})


def test_the_live_observation_is_bounded_and_fingerprinted(fixture_repository):
    author_full_material(fixture_repository)
    observation = observe_live_repository(fixture_repository)
    assert observation.head == head_of(fixture_repository)
    assert observation.remotes == ()
    assert observation.submodule_present is False
    assert set(observation.affected_paths) == set(NEON_RELAY_REQUIRED_MATERIAL_PATHS)
    assert observation.deleted_paths == () and observation.renamed_paths == ()
    assert observation.observation_fingerprint == observe_live_repository(
        fixture_repository
    ).observation_fingerprint
