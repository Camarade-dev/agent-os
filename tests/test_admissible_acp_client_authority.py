"""ACP client authority: request dispatch, permission policy, durable evidence.

Every proof here is provider-free.  The protocol tests drive the deterministic
fake ACP server as a *real* child process through the real ``ManagedProcess``
lifecycle, so PIDs, process-tree cleanup and hard timeouts are real facts.  No
Cursor agent and no model is ever contacted, and nothing in this file deletes a
path or runs a command the policy would reject.

The numbered comments map to the run-003 repair's required regression proofs.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import admissible.delegated_gate.native_executor as native_executor
from admissible.delegated_gate.acp_authority import (
    ACP_METHOD_ASK_QUESTION,
    ACP_METHOD_CREATE_PLAN,
    ACP_METHOD_REQUEST_PERMISSION,
    ACP_METHOD_UPDATE_TODOS,
    ACP_SUPPORTED_SERVER_REQUEST_METHODS,
    AcpAuthorityEvidence,
    AcpAuthorityRefusal,
    AcpEvidenceWriteError,
    AcpServerRequestDispatcher,
    CONTAINMENT_INSIDE_WORKSPACE,
    DECISION_ALLOW_ONCE,
    DECISION_REJECT,
    FAILURE_MALFORMED_SERVER_REQUEST,
    FAILURE_PERMISSION_EVIDENCE_WRITE,
    FAILURE_PERMISSION_REJECTION_UNAVAILABLE,
    FAILURE_UNANSWERABLE_SERVER_REQUEST,
    FAILURE_WORKSPACE_POLLUTED,
    FORBIDDEN_PERMISSION_OPTION_KINDS,
    PERMISSION_KIND_ALLOW_ALWAYS,
    PERMISSION_KIND_ALLOW_ONCE,
    PERMISSION_KIND_REJECT_ONCE,
    RECORD_PERMISSION_DECISION,
    RECORD_PROTOCOL_FAILURE,
    RECORD_SERVER_REQUEST,
    RECORD_WORKSPACE_POLLUTION,
    RULE_ALLOW_ONCE_UNAVAILABLE,
    RULE_BOUNDED_READ_ONLY_INSPECTION,
    RULE_DESTRUCTIVE_COMMAND,
    RULE_NESTED_SHELL,
    RULE_PARENT_TRAVERSAL,
    RULE_PATH_OUTSIDE_WORKSPACE,
    RULE_TOOL_KIND_NOT_PERMITTED,
    RULE_UNRESOLVED_ENVIRONMENT_TOKEN,
    TODO_STATUSES,
    UPDATE_TODOS_RESULT,
    WINDOWS_SHELL_FOLDER_DERIVATION_POLICY,
    WINDOWS_SHELL_FOLDER_NAMES,
    decide_permission,
    derive_windows_shell_folders,
    derived_windows_environment,
    parse_permission_request,
    parse_update_todos,
    permission_response,
    workspace_inventory,
)
from admissible.delegated_gate.native_executor import (
    DEFAULT_ENVIRONMENT_ALLOWLIST,
    OBSERVATION_PROVEN_EMPTY,
    PROMPT_TRANSPORT_ACP_STDIO,
    PROMPT_TRANSPORT_ARGV,
    AcpStdioNativeProcessRunner,
    CursorNativeBackendConfig,
    ManagedNativeProcessRunner,
    NATIVE_PROMPT_HEADER,
    NativeEvidenceInvalid,
    NativeProcessInvocation,
)

FAKE_SERVER = str(
    Path(__file__).parent / "fixtures" / "admissible" / "fake_acp_server_process.py"
)

# Verbatim from the run-003 stdout artifact: the two requests that were granted.
RUN_003_INSPECTION_TITLE = (
    "`Get-ChildItem -Force | Format-Table Name, Mode; if (Test-Path '%SystemDrive%') "
    "{ Remove-Item -Recurse -Force '%SystemDrive%' }; git status --short`"
)
RUN_003_DESTRUCTIVE_TITLE = (
    "`cmd /c \"rmdir /s /q %SystemDrive%\" 2>$null; if (Test-Path -LiteralPath "
    "'%SystemDrive%') { Remove-Item -LiteralPath '%SystemDrive%' -Recurse -Force }; "
    "git status --short; Get-ChildItem -Force | Select-Object Name`"
)
RUN_003_OPTIONS = [
    {"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"},
    {"optionId": "allow-always", "name": "Allow always", "kind": "allow_always"},
    {"optionId": "reject-once", "name": "Reject", "kind": "reject_once"},
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def build_prompt(size_bytes: int = 4096) -> str:
    head = NATIVE_PROMPT_HEADER + "\n\nImmutable mission:\n"
    body = "neon relay mission line\n" * 400
    prompt = (head + body)[:size_bytes]
    while len(prompt.encode("utf-8")) < size_bytes:
        prompt += "."
    return prompt


def server_argv(scenario: str, record: str | None = None) -> tuple[str, ...]:
    argv = [sys.executable, FAKE_SERVER, "--scenario", scenario]
    if record is not None:
        argv += ["--record", record]
    return tuple(argv)


class StartedRecorder:
    def __init__(self) -> None:
        self.proofs: list[object] = []

    def __call__(self, proof: object) -> None:
        self.proofs.append(proof)


def make_invocation(
    argv: tuple[str, ...],
    prompt: str,
    *,
    cwd: str,
    started: StartedRecorder,
    evidence: AcpAuthorityEvidence,
    timeout_seconds: int = 60,
    env: dict[str, str] | None = None,
) -> NativeProcessInvocation:
    return NativeProcessInvocation(
        argv, cwd, env or {}, timeout_seconds, 1024 * 1024, started,
        prompt_transport=PROMPT_TRANSPORT_ACP_STDIO, prompt=prompt,
        prompt_fingerprint=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        acp_authority_evidence=evidence,
    )


def permission_params(title: str, *, kind: str = "execute", options=None, tool_call_id="call-1"):
    return {
        "sessionId": "sess-0001",
        "toolCall": {
            "toolCallId": tool_call_id,
            "title": title,
            "kind": kind,
            "status": "pending",
            "content": [{"type": "content", "content": {"type": "text", "text": "Not in allowlist"}}],
        },
        "options": list(RUN_003_OPTIONS if options is None else options),
    }


def rule_for(title: str, *, workspace: str, kind: str = "execute"):
    request = parse_permission_request(permission_params(title, kind=kind))
    assert request is not None
    return decide_permission(request, workspace=workspace)


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    work.mkdir()
    (work / "package.json").write_text("{}\n", encoding="utf-8")
    return work


@pytest.fixture()
def evidence(tmp_path: Path) -> AcpAuthorityEvidence:
    return AcpAuthorityEvidence(tmp_path / "acp-client-authority.jsonl")


# ---------------------------------------------------------------------------
# G.1 / G.16: valid cursor/update_todos is answered and the turn continues
# ---------------------------------------------------------------------------


def test_valid_update_todos_is_answered_and_the_turn_continues(tmp_path, workspace):
    """G.1 + G.16: the exact run-003 killer now completes the turn."""

    prompt = build_prompt()
    started = StartedRecorder()
    record = tmp_path / "received.txt"
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("update_todos", str(record)), prompt,
                        cwd=str(workspace), started=started, evidence=log)
    )

    assert outcome.returncode == 0 and outcome.protocol_failure_detail is None
    assert record.read_text(encoding="utf-8") == prompt  # clean startup permitted the prompt
    # The server received the exact protocol-compatible success response.
    echoed = [line for line in outcome.stdout.splitlines() if "todos=" in line]
    assert echoed, outcome.stdout
    payload = json.loads(json.loads(echoed[-1])["params"]["update"]["content"]["text"][len("todos="):])
    assert payload == {"jsonrpc": "2.0", "id": 2, "result": dict(UPDATE_TODOS_RESULT)}

    recorded = [r for r in log.records if r["record_type"] == RECORD_SERVER_REQUEST]
    assert len(recorded) == 1
    assert recorded[0]["method"] == ACP_METHOD_UPDATE_TODOS and recorded[0]["accepted"] is True
    assert recorded[0]["summary"]["todo_count"] == 2
    assert recorded[0]["summary"]["statuses"] == ["in_progress", "pending"]


def test_update_todos_is_metadata_only_and_produces_no_effect(tmp_path, workspace, evidence):
    """It is acknowledged, never executed: nothing is written or spawned."""

    before = workspace_inventory(workspace)
    dispatcher = AcpServerRequestDispatcher(evidence=evidence, workspace=str(workspace))
    outcome = dispatcher.dispatch(
        method=ACP_METHOD_UPDATE_TODOS, message_id=2,
        params={"toolCallId": "c1", "todos": [{"id": "1", "content": "x", "status": "pending"}],
                "merge": False},
    )
    assert outcome.failure is None
    assert outcome.response == {"jsonrpc": "2.0", "id": 2, "result": {}}
    assert workspace_inventory(workspace) == before
    assert dispatcher.decisions == []


# ---------------------------------------------------------------------------
# G.2: malformed cursor/update_todos fails closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        None,
        {},
        {"toolCallId": "c1"},
        {"toolCallId": "", "todos": [{"id": "1", "content": "x", "status": "pending"}], "merge": False},
        {"toolCallId": "c1", "todos": [], "merge": False},
        {"toolCallId": "c1", "todos": [{"id": "1", "content": "x", "status": "half-done"}], "merge": False},
        {"toolCallId": "c1", "todos": [{"id": "1", "content": "x"}], "merge": False},
        {"toolCallId": "c1", "todos": [{"id": "1", "content": "x", "status": "pending", "extra": 1}], "merge": False},
        {"toolCallId": "c1", "todos": [{"id": "1", "content": "x", "status": "pending"}], "merge": "no"},
        {"toolCallId": "c1", "todos": [{"id": "1", "content": "x", "status": "pending"}], "merge": False, "other": 1},
    ],
)
def test_malformed_update_todos_is_refused_by_the_strict_parser(params):
    assert parse_update_todos(params) is None


def test_malformed_update_todos_fails_closed_over_the_real_transport(tmp_path, workspace):
    """G.2: an unvalidatable todo update terminates the turn, fail-closed."""

    prompt = build_prompt()
    started = StartedRecorder()
    record = tmp_path / "received.txt"
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("malformed_update_todos", str(record)), prompt,
                        cwd=str(workspace), started=started, evidence=log, timeout_seconds=60)
    )

    assert outcome.returncode == 1
    assert outcome.protocol_failure_detail == f"{FAILURE_MALFORMED_SERVER_REQUEST}:{ACP_METHOD_UPDATE_TODOS}"
    failures = [r for r in log.records if r["record_type"] == RECORD_PROTOCOL_FAILURE]
    assert any(r["detail"].startswith(FAILURE_MALFORMED_SERVER_REQUEST) for r in failures)
    assert any(r["method"] == ACP_METHOD_UPDATE_TODOS for r in failures)
    # G.20: cleanup stays observation-proven empty even on a fail-closed turn.
    assert outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY and outcome.cleanup_confirmed
    # G.19: exactly one process, never a retry.
    assert len(started.proofs) == 1


def test_the_todo_status_vocabulary_is_exactly_the_cli_s_own_four():
    assert TODO_STATUSES == {"pending", "in_progress", "completed", "cancelled"}


# ---------------------------------------------------------------------------
# G.3: unknown server request methods fail closed with the exact detail
# ---------------------------------------------------------------------------


def test_the_dispatch_table_is_an_exact_closed_set_with_no_wildcard(evidence, workspace):
    """The table grew by exactly two audited methods; it is still closed.

    ``cursor/ask_question`` and ``cursor/create_plan`` were added only after
    their request and response shapes were read out of the installed CLI's own
    bundle.  Every other ``cursor/*`` method -- including ones that exist, like
    ``cursor/task`` and ``cursor/generate_image`` -- is still unanswerable, so
    no wildcard was introduced along with them.
    """

    assert ACP_SUPPORTED_SERVER_REQUEST_METHODS == (
        ACP_METHOD_ASK_QUESTION, ACP_METHOD_CREATE_PLAN,
        ACP_METHOD_UPDATE_TODOS, ACP_METHOD_REQUEST_PERMISSION,
    )
    dispatcher = AcpServerRequestDispatcher(evidence=evidence, workspace=str(workspace))
    unanswerable = (
        "cursor/task", "cursor/generate_image", "cursor/list_available_models",
        "cursor/", "cursor/ask_question_", "fs/read_text_file", "terminal/create",
        "session/anything", "",
    )
    for method in unanswerable:
        outcome = dispatcher.dispatch(method=method, message_id=9, params={})
        assert outcome.response is None
        assert outcome.failure == f"{FAILURE_UNANSWERABLE_SERVER_REQUEST}:{method}"
    persisted = [r for r in evidence.records if r["record_type"] == RECORD_PROTOCOL_FAILURE]
    assert [r["method"] for r in persisted] == list(unanswerable)


def test_unknown_server_request_fails_closed_over_the_real_transport(tmp_path, workspace):
    """G.3: the exact method reaches durable evidence, not just a log line."""

    prompt = build_prompt()
    started = StartedRecorder()
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("unknown_request"), prompt,
                        cwd=str(workspace), started=started, evidence=log)
    )

    assert outcome.returncode == 1
    assert outcome.protocol_failure_detail == (
        f"{FAILURE_UNANSWERABLE_SERVER_REQUEST}:cursor/task"
    )
    on_disk = [
        json.loads(line)
        for line in (tmp_path / "authority.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        r["record_type"] == RECORD_PROTOCOL_FAILURE and r["method"] == "cursor/task"
        for r in on_disk
    )
    assert len(started.proofs) == 1


# ---------------------------------------------------------------------------
# G.4: allow-always is never selected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    [
        "`Get-ChildItem -Force -Name`",
        "`git status --short`",
        RUN_003_INSPECTION_TITLE,
        RUN_003_DESTRUCTIVE_TITLE,
        "`Get-Content package.json`",
        "`Remove-Item -Recurse -Force .`",
    ],
)
@pytest.mark.parametrize(
    "options",
    [
        RUN_003_OPTIONS,
        # allow-always offered first, and as the only grant.
        [{"optionId": "allow-always", "kind": "allow_always"},
         {"optionId": "reject-once", "kind": "reject_once"}],
        [{"optionId": "aa", "kind": "allow_always"}, {"optionId": "ao", "kind": "allow_once"},
         {"optionId": "ro", "kind": "reject_once"}],
    ],
)
def test_no_permission_decision_can_ever_select_allow_always(title, options, workspace):
    """G.4: across every command class and every option layout."""

    request = parse_permission_request(permission_params(title, options=options))
    assert request is not None
    decision = decide_permission(request, workspace=str(workspace))
    assert decision.selected_option_kind not in FORBIDDEN_PERMISSION_OPTION_KINDS
    assert decision.selected_option_kind in {PERMISSION_KIND_ALLOW_ONCE, PERMISSION_KIND_REJECT_ONCE}
    assert decision.selected_option_id != "allow-always"
    if decision.approved:
        assert decision.selected_option_kind == PERMISSION_KIND_ALLOW_ONCE
        assert permission_response(decision)["outcome"]["optionId"] == decision.selected_option_id


def test_a_safe_command_whose_only_grant_is_standing_authority_is_refused(workspace):
    """Narrowing is never achieved by escalating to allow-always."""

    request = parse_permission_request(permission_params(
        "`git status --short`",
        options=[{"optionId": "aa", "kind": PERMISSION_KIND_ALLOW_ALWAYS},
                 {"optionId": "ro", "kind": PERMISSION_KIND_REJECT_ONCE}],
    ))
    decision = decide_permission(request, workspace=str(workspace))
    assert decision.decision == DECISION_REJECT
    assert decision.rule_id == RULE_ALLOW_ONCE_UNAVAILABLE
    assert decision.selected_option_id == "ro"


def test_permission_response_refuses_a_forbidden_kind_defensively(workspace):
    from dataclasses import replace as _replace

    decision = rule_for("`git status --short`", workspace=str(workspace))
    assert decision.approved
    escalated = _replace(decision, selected_option_kind=PERMISSION_KIND_ALLOW_ALWAYS)
    with pytest.raises(AcpAuthorityRefusal):
        permission_response(escalated)


def test_a_request_offering_no_rejection_terminates_rather_than_granting(workspace, evidence):
    request = parse_permission_request(permission_params(
        RUN_003_DESTRUCTIVE_TITLE,
        options=[{"optionId": "aa", "kind": PERMISSION_KIND_ALLOW_ALWAYS},
                 {"optionId": "ao", "kind": PERMISSION_KIND_ALLOW_ONCE}],
    ))
    decision = decide_permission(request, workspace=str(workspace))
    assert decision.decision == DECISION_REJECT
    assert decision.selected_option_id is None
    assert decision.protocol_failure == FAILURE_PERMISSION_REJECTION_UNAVAILABLE

    dispatcher = AcpServerRequestDispatcher(evidence=evidence, workspace=str(workspace))
    outcome = dispatcher.dispatch(
        method=ACP_METHOD_REQUEST_PERMISSION, message_id=1,
        params=permission_params(
            RUN_003_DESTRUCTIVE_TITLE,
            options=[{"optionId": "aa", "kind": PERMISSION_KIND_ALLOW_ALWAYS},
                     {"optionId": "ao", "kind": PERMISSION_KIND_ALLOW_ONCE}],
        ),
    )
    assert outcome.response is None
    assert outcome.failure == FAILURE_PERMISSION_REJECTION_UNAVAILABLE


# ---------------------------------------------------------------------------
# G.5: the two run-003 requests are now classified correctly
# ---------------------------------------------------------------------------


def test_run_003_inspection_request_is_not_positively_safe_and_is_rejected(workspace):
    """G.5a: the compound command carries Remove-Item, so it is not safe.

    The narrow allow-once grant is available only when the *complete* compound
    command is positively safe; this one is not.
    """

    decision = rule_for(RUN_003_INSPECTION_TITLE, workspace=str(workspace))
    assert decision.decision == DECISION_REJECT
    assert decision.rule_id == RULE_DESTRUCTIVE_COMMAND
    assert "Remove-Item" in decision.detail
    assert decision.selected_option_id == "reject-once"


def test_run_003_destructive_request_is_rejected(workspace):
    """G.5b: ``cmd /c "rmdir /s /q %SystemDrive%"`` -- the command that ran."""

    decision = rule_for(RUN_003_DESTRUCTIVE_TITLE, workspace=str(workspace))
    assert decision.decision == DECISION_REJECT
    assert decision.rule_id == RULE_NESTED_SHELL
    assert decision.selected_option_kind == PERMISSION_KIND_REJECT_ONCE


def test_the_inspection_half_alone_is_permitted_once_the_destruction_is_removed(workspace):
    """The policy is narrow, not blanket: Format-Table/Test-Path alone pass."""

    decision = rule_for(
        "`Get-ChildItem -Force | Format-Table Name, Mode; git status --short`",
        workspace=str(workspace),
    )
    assert decision.decision == DECISION_ALLOW_ONCE
    assert decision.selected_option_id == "allow-once"
    assert rule_for("`Test-Path package.json`", workspace=str(workspace)).approved


# ---------------------------------------------------------------------------
# G.6 - G.8: environment tokens, absolute paths, parent traversal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    [
        "`Get-ChildItem -LiteralPath '%SystemDrive%'`",
        "`Get-Content %ProgramData%/x.txt`",
        "`Test-Path $env:TEMP`",
        "`Test-Path ${env:TEMP}`",
        "`Get-ChildItem $PSScriptRoot`",
    ],
)
def test_unresolved_environment_variables_are_rejected(title, workspace):
    """G.6."""

    decision = rule_for(title, workspace=str(workspace))
    assert decision.decision == DECISION_REJECT
    assert decision.rule_id == RULE_UNRESOLVED_ENVIRONMENT_TOKEN


@pytest.mark.parametrize(
    "title",
    [
        r"`Get-Content C:\Windows\System32\drivers\etc\hosts`",
        r"`Test-Path D:\elsewhere`",
        "`Get-ChildItem /etc`",
    ],
)
def test_absolute_paths_outside_the_workspace_are_rejected(title, workspace):
    """G.7."""

    decision = rule_for(title, workspace=str(workspace))
    assert decision.decision == DECISION_REJECT
    assert decision.rule_id == RULE_PATH_OUTSIDE_WORKSPACE


@pytest.mark.parametrize(
    "title",
    [
        r"`Get-Content ..\secrets.txt`",
        "`Get-ChildItem ../../`",
        r"`Test-Path sub\..\..\outside`",
    ],
)
def test_parent_traversal_is_rejected(title, workspace):
    """G.8."""

    decision = rule_for(title, workspace=str(workspace))
    assert decision.decision == DECISION_REJECT
    assert decision.rule_id == RULE_PARENT_TRAVERSAL


def test_traversal_that_normalizes_back_inside_is_contained_not_rejected(workspace):
    """Containment is proven by normalization, not by banning the characters."""

    decision = rule_for(r"`Get-Content src\..\package.json`", workspace=str(workspace))
    assert decision.approved and decision.containment == CONTAINMENT_INSIDE_WORKSPACE


def test_an_absolute_path_inside_the_workspace_is_contained(workspace):
    decision = rule_for(f"`Test-Path {workspace / 'package.json'}`", workspace=str(workspace))
    assert decision.approved


def test_a_git_material_path_bound_by_the_attestation_may_be_referenced(tmp_path, workspace):
    """The single documented carve-out, and it is exact-match only."""

    launcher = tmp_path / "versions" / "index.js"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("//\n", encoding="utf-8")
    request = parse_permission_request(permission_params(f"`Test-Path {launcher}`"))
    assert decide_permission(request, workspace=str(workspace)).decision == DECISION_REJECT
    permitted = decide_permission(
        request, workspace=str(workspace),
        additional_authorized_paths=frozenset({str(launcher)}),
    )
    assert permitted.approved


# ---------------------------------------------------------------------------
# G.9: bounded read-only inspection may receive allow-once
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    [
        "`Get-ChildItem -Force -Name`",
        "`Get-Content package.json`",
        "`Test-Path package.json`",
        "`Select-String -Pattern relay src/main.js`",
        "`Get-ChildItem -Force | Select-Object Name`",
        "`Get-ChildItem -Force | Format-Table Name, Mode`",
        "`Write-Output done`",
        "`Write-Host done`",
        "`git status --short`",
        "`git log --oneline -1`",
        "`git diff --stat`",
        "`git show --stat`",
        "`git rev-parse --abbrev-ref HEAD`",
        "`git remote -v`",
        "`Get-ChildItem -Force -Name; git status --short; git diff --cached --stat`",
    ],
)
def test_bounded_read_only_workspace_inspection_receives_allow_once(title, workspace):
    """G.9."""

    decision = rule_for(title, workspace=str(workspace))
    assert decision.decision == DECISION_ALLOW_ONCE, decision
    assert decision.rule_id == RULE_BOUNDED_READ_ONLY_INSPECTION
    assert decision.selected_option_kind == PERMISSION_KIND_ALLOW_ONCE
    assert decision.containment == CONTAINMENT_INSIDE_WORKSPACE


@pytest.mark.parametrize(
    "title",
    [
        "`ls`", "`dir`", "`cat package.json`", "`gci`", "`echo hi`",
        "`git push`", "`git remote add origin https://x`", "`git commit -m x`",
        "`npm test`", "`node build.js`", "`Get-ChildItem -Weird`",
        "`Get-Content package.json > out.txt`",
        "`Invoke-Expression 'x'`", "`Start-Process notepad`",
        "`schtasks /create /tn x`", "`reg add HKCU\\x`", "`Stop-Process -Name x`",
        "`Set-Content package.json x`", "`New-Item -ItemType Directory tmp`",
        "`powershell -Command Get-ChildItem`", "`bash -lc ls`", "`wsl ls`",
        "`curl https://example.invalid`", "`format C:`", "`diskpart`",
    ],
)
def test_everything_outside_the_finite_grammar_is_rejected(title, workspace):
    """Deny by default: an unknown or ambiguous class is never widened."""

    assert rule_for(title, workspace=str(workspace)).decision == DECISION_REJECT


def test_a_non_execute_tool_kind_is_never_reauthorized_through_this_fallback(workspace):
    for kind in ("edit", "delete", "read", "search", "other", "fetch", None):
        decision = rule_for("`git status --short`", workspace=str(workspace), kind=kind)
        assert decision.decision == DECISION_REJECT
        assert decision.rule_id == RULE_TOOL_KIND_NOT_PERMITTED


# ---------------------------------------------------------------------------
# G.10 - G.11: durable evidence before the reply
# ---------------------------------------------------------------------------


def test_the_decision_is_on_disk_before_dispatch_returns_a_response(tmp_path, workspace):
    """G.10 at the dispatcher boundary."""

    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl")
    dispatcher = AcpServerRequestDispatcher(evidence=log, workspace=str(workspace))
    outcome = dispatcher.dispatch(
        method=ACP_METHOD_REQUEST_PERMISSION, message_id=11,
        params=permission_params("`git status --short`"),
    )
    assert outcome.response is not None
    on_disk = [
        json.loads(line)
        for line in (tmp_path / "authority.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(on_disk) == 1
    record = on_disk[0]
    assert record["record_type"] == RECORD_PERMISSION_DECISION
    assert record["decision"] == DECISION_ALLOW_ONCE
    assert record["jsonrpc_request_id"] == "11"
    assert record["acp_session_id"] == "sess-0001"
    assert record["tool_call_id"] == "call-1"
    assert record["tool_kind"] == "execute"
    assert record["server_reason"] == "Not in allowlist"
    assert record["offered_options"] == [
        {"optionId": "allow-once", "kind": "allow_once"},
        {"optionId": "allow-always", "kind": "allow_always"},
        {"optionId": "reject-once", "kind": "reject_once"},
    ]
    assert record["selected_option_id"] == "allow-once"
    assert record["policy_rule_id"] == RULE_BOUNDED_READ_ONLY_INSPECTION
    assert record["containment_result"] == CONTAINMENT_INSIDE_WORKSPACE
    assert record["authorized_workspace"] == str(workspace)
    assert record["recorded_at"].endswith("Z")
    assert len(record["record_fingerprint"]) == 64


def test_persistence_strictly_precedes_the_wire_write_in_the_real_runner(
    tmp_path, workspace, monkeypatch,
):
    """G.10 end to end: the ordering is observed, not merely asserted."""

    trace: list[str] = []

    class TracingEvidence(AcpAuthorityEvidence):
        def record_permission_decision(self, **kwargs):
            record = super().record_permission_decision(**kwargs)
            trace.append("persist")
            return record

    original_send = native_executor._acp_send_message

    def tracing_send(connection, payload):
        if "result" in payload and "outcome" in (payload.get("result") or {}):
            trace.append("send")
        return original_send(connection, payload)

    monkeypatch.setattr(native_executor, "_acp_send_message", tracing_send)

    prompt = build_prompt()
    log = TracingEvidence(tmp_path / "authority.jsonl", redact=(prompt,))
    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("permission_safe"), prompt,
                        cwd=str(workspace), started=StartedRecorder(), evidence=log)
    )

    assert outcome.returncode == 0
    assert trace == ["persist", "send"]
    assert "permission=allow-once" in outcome.stdout


def test_evidence_write_failure_prevents_approval(tmp_path, workspace):
    """G.11: an approval that cannot be recorded is never sent."""

    class BrokenEvidence(AcpAuthorityEvidence):
        def record_permission_decision(self, **kwargs):
            raise AcpEvidenceWriteError("disk is gone")

    log = BrokenEvidence(tmp_path / "authority.jsonl")
    dispatcher = AcpServerRequestDispatcher(evidence=log, workspace=str(workspace))
    outcome = dispatcher.dispatch(
        method=ACP_METHOD_REQUEST_PERMISSION, message_id=3,
        params=permission_params("`git status --short`"),  # positively safe, yet unrecordable
    )
    assert outcome.response is None
    assert outcome.failure == FAILURE_PERMISSION_EVIDENCE_WRITE
    assert dispatcher.decisions == []


def test_evidence_write_failure_fails_the_turn_closed_over_the_real_transport(tmp_path, workspace):
    class BrokenEvidence(AcpAuthorityEvidence):
        def record_permission_decision(self, **kwargs):
            raise AcpEvidenceWriteError("disk is gone")

    prompt = build_prompt()
    started = StartedRecorder()
    log = BrokenEvidence(tmp_path / "authority.jsonl", redact=(prompt,))
    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("permission_safe"), prompt,
                        cwd=str(workspace), started=started, evidence=log, timeout_seconds=60)
    )
    assert outcome.returncode == 1
    assert outcome.protocol_failure_detail == FAILURE_PERMISSION_EVIDENCE_WRITE
    assert "permission=" not in outcome.stdout
    assert len(started.proofs) == 1


def test_an_acp_invocation_without_an_evidence_sink_is_refused(tmp_path, workspace):
    invocation = NativeProcessInvocation(
        server_argv("success"), str(workspace), {}, 30, 4096, StartedRecorder(),
        prompt_transport=PROMPT_TRANSPORT_ACP_STDIO, prompt=build_prompt(),
        prompt_fingerprint=hashlib.sha256(build_prompt().encode("utf-8")).hexdigest(),
    )
    with pytest.raises(NativeEvidenceInvalid, match="client-authority evidence sink"):
        AcpStdioNativeProcessRunner().run(invocation)


# ---------------------------------------------------------------------------
# G.12 - G.14: deterministic Windows environment
# ---------------------------------------------------------------------------


def test_the_derived_environment_is_exactly_the_three_missing_names():
    """G.12."""

    assert set(WINDOWS_SHELL_FOLDER_NAMES) == {"SystemDrive", "ProgramData", "ALLUSERSPROFILE"}
    root = os.environ.get("SYSTEMROOT") or os.environ.get("SystemRoot")
    if root is None:
        pytest.skip("no SYSTEMROOT on this host")
    values = derive_windows_shell_folders(systemroot=root)
    assert set(values) == set(WINDOWS_SHELL_FOLDER_NAMES)
    assert values["SystemDrive"] == os.path.splitdrive(root)[0].upper()
    assert values["ALLUSERSPROFILE"] == values["ProgramData"]
    for name, value in values.items():
        probe = value + os.sep if name == "SystemDrive" else value
        assert os.path.isabs(probe) and os.path.isdir(probe)


def test_the_child_environment_carries_the_derived_values_and_never_inherits_them(tmp_path):
    """G.12 + D.7: derived, not inherited, and not allowlistable."""

    config = CursorNativeBackendConfig(executable="cursor-agent")
    assert not {name.upper() for name in WINDOWS_SHELL_FOLDER_NAMES} & {
        name.upper() for name in DEFAULT_ENVIRONMENT_ALLOWLIST
    }
    with pytest.raises(ValueError, match="derived, never allowlisted"):
        CursorNativeBackendConfig(
            executable="cursor-agent",
            environment_allowlist=DEFAULT_ENVIRONMENT_ALLOWLIST + ("ProgramData",),
        )

    root = os.environ.get("SYSTEMROOT") or os.environ.get("SystemRoot")
    if root is None:
        pytest.skip("no SYSTEMROOT on this host")
    base = {"SYSTEMROOT": root, "PATH": os.environ.get("PATH", ""),
            "SystemDrive": "Z:", "ProgramData": r"Z:\Nope", "SECRET": "leak"}
    built = config.build_environment(base=base, work_workspace=tmp_path)
    assert "SECRET" not in built
    # The parent's bogus values were replaced by derived ones, not carried.
    assert built["SystemDrive"] == os.path.splitdrive(root)[0].upper()
    assert built["ProgramData"] != r"Z:\Nope"
    assert built["ALLUSERSPROFILE"] == built["ProgramData"]
    assert config.build_environment(base=base, derive_shell_folders=False).get("SystemDrive") is None


def test_the_derivation_refuses_rather_than_guessing(tmp_path):
    with pytest.raises(AcpAuthorityRefusal):
        derive_windows_shell_folders(systemroot=str(tmp_path / "absent"))
    with pytest.raises(AcpAuthorityRefusal):
        derive_windows_shell_folders(systemroot="relative")
    root = os.environ.get("SYSTEMROOT") or os.environ.get("SystemRoot")
    if root is not None:
        with pytest.raises(AcpAuthorityRefusal):
            derive_windows_shell_folders(
                systemroot=root, known_folder=lambda: str(tmp_path / "missing-program-data"),
            )
        # A ProgramData that resolves inside the workspace is refused outright.
        inside = tmp_path / "work" / "ProgramData"
        inside.mkdir(parents=True)
        with pytest.raises(AcpAuthorityRefusal):
            derive_windows_shell_folders(
                systemroot=root, work_workspace=tmp_path / "work",
                known_folder=lambda: str(inside),
            )


def test_the_derivation_policy_string_is_the_audited_one():
    assert "never-inherited-from-the-parent-environment" in WINDOWS_SHELL_FOLDER_DERIVATION_POLICY
    assert "splitdrive(attested-SYSTEMROOT)" in WINDOWS_SHELL_FOLDER_DERIVATION_POLICY


@pytest.mark.skipif(os.name != "nt", reason="Windows shell-folder resolution")
def test_no_literal_systemdrive_tree_is_created_by_a_fake_shell_subprocess(tmp_path):
    """G.13: the exact run-003 mechanism, reproduced and then repaired.

    The child resolves ``%SystemDrive%\\ProgramData\\...`` the way Windows shell
    folders do and creates it only when the expansion stays relative.  Under the
    broken environment that is a literal ``%SystemDrive%`` directory in the cwd;
    under the constructed environment it is an absolute path that is never
    created here.  No Cursor process is involved.
    """

    script = tmp_path / "fake_shell.py"
    script.write_text(
        "import os, sys\n"
        "target = os.path.expandvars(r'%SystemDrive%\\ProgramData\\Admissible\\Probe')\n"
        "if not os.path.isabs(target):\n"
        "    os.makedirs(target, exist_ok=True)\n"
        "sys.stdout.write(target)\n",
        encoding="utf-8",
    )
    config = CursorNativeBackendConfig(executable="cursor-agent")

    broken_cwd = tmp_path / "broken"
    broken_cwd.mkdir()
    broken_env = config.build_environment(derive_shell_folders=False)
    broken = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=broken_cwd, env=broken_env,
        capture_output=True, text=True, timeout=60,
    )
    assert broken.returncode == 0
    assert broken.stdout.startswith("%SystemDrive%")
    assert (broken_cwd / "%SystemDrive%" / "ProgramData" / "Admissible" / "Probe").is_dir()

    repaired_cwd = tmp_path / "repaired"
    repaired_cwd.mkdir()
    repaired_env = config.build_environment(work_workspace=repaired_cwd)
    repaired = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=repaired_cwd, env=repaired_env,
        capture_output=True, text=True, timeout=60,
    )
    assert repaired.returncode == 0
    assert repaired.stdout == os.path.join(
        repaired_env["SystemDrive"] + os.sep, "ProgramData", "Admissible", "Probe",
    )
    assert not (repaired_cwd / "%SystemDrive%").exists()
    assert workspace_inventory(repaired_cwd) == ()


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell shell-folder resolution")
def test_a_real_powershell_child_creates_no_literal_systemdrive_directory(tmp_path):
    """G.13 again, with a real ``powershell.exe`` rather than a Python stand-in."""

    powershell = os.path.join(
        os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
        "powershell.exe",
    )
    if not os.path.isfile(powershell):
        pytest.skip("powershell.exe is unavailable")
    command = (
        "$p = [System.Environment]::ExpandEnvironmentVariables("
        "'%SystemDrive%\\ProgramData\\Admissible\\Probe'); "
        "if (-not [System.IO.Path]::IsPathRooted($p)) "
        "{ New-Item -ItemType Directory -Force -Path $p | Out-Null }; "
        "Write-Output $p"
    )
    config = CursorNativeBackendConfig(executable="cursor-agent")
    cwd = tmp_path / "ps"
    cwd.mkdir()
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=cwd, env=config.build_environment(work_workspace=cwd),
        capture_output=True, text=True, timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().lower().startswith(
        config.build_environment(work_workspace=cwd)["SystemDrive"].lower()
    )
    assert not (cwd / "%SystemDrive%").exists()
    assert workspace_inventory(cwd) == ()


def test_a_windows_child_environment_without_systemroot_is_refused():
    """G.14 boundary: derivation authority absent is a refusal, not a default."""

    if os.name != "nt":
        assert derived_windows_environment({"PATH": "/usr/bin"}) == {}
        return
    with pytest.raises(AcpAuthorityRefusal, match="attested SYSTEMROOT"):
        derived_windows_environment({"PATH": "x"})


# ---------------------------------------------------------------------------
# G.15 - G.16: the post-startup workspace pollution boundary
# ---------------------------------------------------------------------------


def test_post_startup_pollution_prevents_prompt_submission(tmp_path, workspace):
    """G.15: the mission is not submitted, nothing is deleted, nothing succeeds."""

    prompt = build_prompt()
    started = StartedRecorder()
    record = tmp_path / "received.txt"
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("startup_pollution", str(record)), prompt,
                        cwd=str(workspace), started=started, evidence=log, timeout_seconds=60)
    )

    assert outcome.returncode == 1
    assert outcome.protocol_failure_detail.startswith(FAILURE_WORKSPACE_POLLUTED)
    assert not record.exists()  # the prompt was never submitted
    # The pollution is recorded exactly, and deliberately not removed.
    pollution = [r for r in log.records if r["record_type"] == RECORD_WORKSPACE_POLLUTION]
    assert len(pollution) == 1
    assert "%SystemDrive%/" in pollution[0]["added_paths"]
    assert pollution[0]["classifications"]["%SystemDrive%/"] == (
        "unresolved_environment_variable_literal"
    )
    assert (workspace / "%SystemDrive%" / "ProgramData").is_dir()
    # No permission request was answered, so no cleanup command was approved.
    assert not [r for r in log.records if r["record_type"] == RECORD_PERMISSION_DECISION]
    assert len(started.proofs) == 1
    assert outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY


def test_clean_startup_permits_prompt_submission(tmp_path, workspace):
    """G.16."""

    prompt = build_prompt()
    record = tmp_path / "received.txt"
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))
    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("success", str(record)), prompt,
                        cwd=str(workspace), started=StartedRecorder(), evidence=log)
    )
    assert outcome.returncode == 0
    assert record.read_text(encoding="utf-8") == prompt
    assert not [r for r in log.records if r["record_type"] == RECORD_WORKSPACE_POLLUTION]


def test_the_inventory_ignores_git_metadata_churn(tmp_path):
    root = tmp_path / "repo"
    (root / ".git" / "objects").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src" / "a.js").write_text("//\n", encoding="utf-8")
    before = workspace_inventory(root)
    (root / ".git" / "index").write_text("x", encoding="utf-8")
    assert workspace_inventory(root) == before == ("src/", "src/a.js")


# ---------------------------------------------------------------------------
# G.17: prompt bytes never reach argv or the authority evidence
# ---------------------------------------------------------------------------


def test_prompt_bytes_are_absent_from_argv_and_permission_evidence(tmp_path, workspace):
    """G.17."""

    prompt = build_prompt()
    marker = prompt[:120]
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))
    argv = server_argv("permission_safe")
    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(argv, prompt, cwd=str(workspace), started=StartedRecorder(), evidence=log)
    )
    assert outcome.returncode == 0
    assert all(prompt not in member for member in argv)
    raw = (tmp_path / "authority.jsonl").read_text(encoding="utf-8")
    assert prompt not in raw and marker not in raw
    assert NATIVE_PROMPT_HEADER not in raw


def test_a_prompt_echoed_inside_a_permission_title_is_redacted(tmp_path, workspace):
    prompt = build_prompt()
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))
    dispatcher = AcpServerRequestDispatcher(evidence=log, workspace=str(workspace))
    dispatcher.dispatch(
        method=ACP_METHOD_REQUEST_PERMISSION, message_id=1,
        params=permission_params(f"`Get-Content {prompt}`"),
    )
    raw = (tmp_path / "authority.jsonl").read_text(encoding="utf-8")
    assert prompt not in raw
    assert "<redacted: prompt bytes>" in raw


# ---------------------------------------------------------------------------
# G.18 - G.20: compatibility, no retry, proven cleanup
# ---------------------------------------------------------------------------


def test_the_argv_wrapper_chain_runner_is_unchanged_and_needs_no_evidence_sink(tmp_path):
    """G.18: the ARGV transport takes neither a dispatcher nor a sink."""

    script = tmp_path / "echo.py"
    script.write_text("import sys; sys.stdout.write('argv-ok')\n", encoding="utf-8")
    started = StartedRecorder()
    invocation = NativeProcessInvocation(
        (sys.executable, "-I", str(script)), str(tmp_path), {}, 60, 4096, started,
        prompt_transport=PROMPT_TRANSPORT_ARGV,
    )
    outcome = ManagedNativeProcessRunner().run(invocation)
    assert outcome.returncode == 0 and outcome.stdout == "argv-ok"
    assert outcome.protocol_failure_detail is None
    assert invocation.acp_authority_evidence is None
    assert len(started.proofs) == 1


@pytest.mark.parametrize(
    "scenario",
    ["unknown_request", "malformed_update_todos", "startup_pollution", "permission_destructive"],
)
def test_no_second_provider_process_is_ever_started(scenario, tmp_path, workspace):
    """G.19 + G.20 across every new fail-closed boundary."""

    prompt = build_prompt()
    started = StartedRecorder()
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))
    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv(scenario), prompt, cwd=str(workspace),
                        started=started, evidence=log, timeout_seconds=60)
    )
    assert len(started.proofs) == 1
    assert outcome.cleanup_confirmed and outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY
    assert outcome.orphan_process_ids == ()


def test_a_rejected_destructive_request_still_completes_the_turn(tmp_path, workspace):
    """Rejection is an answer, not a protocol failure: the turn continues."""

    prompt = build_prompt()
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))
    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("permission_destructive"), prompt,
                        cwd=str(workspace), started=StartedRecorder(), evidence=log)
    )
    assert outcome.returncode == 0 and outcome.protocol_failure_detail is None
    assert "permission=reject-once" in outcome.stdout
    decision = [r for r in log.records if r["record_type"] == RECORD_PERMISSION_DECISION][0]
    assert decision["decision"] == DECISION_REJECT
    assert decision["policy_rule_id"] == RULE_NESTED_SHELL
    # And the workspace is untouched: nothing was deleted on our behalf.
    assert (workspace / "package.json").exists()


def test_the_exact_protocol_boundary_is_kept_beside_the_compatible_classification(
    tmp_path, workspace,
):
    """F: the high-level token stays the prefix; the boundary is appended."""

    prompt = build_prompt()
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))
    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("unknown_request"), prompt,
                        cwd=str(workspace), started=StartedRecorder(), evidence=log)
    )
    assert outcome.termination_reason.startswith(native_executor.ACP_TERMINATION_PROTOCOL_FAILED)
    assert "cursor/task" in outcome.termination_reason
    assert len(outcome.termination_reason.encode("utf-8")) <= 256


# ---------------------------------------------------------------------------
# Direct mutation witness
# ---------------------------------------------------------------------------


def test_mutation_witness_restoring_unconditional_allow_always_fails_the_suite(
    tmp_path, workspace, monkeypatch,
):
    """The defect, reintroduced: the run-003 policy is put back and observed.

    ``_acp_client_reply``'s exact former body preferred ``allow_always`` over
    ``allow_once`` and inspected nothing.  Reinstating it makes the destructive
    run-003 request approved again -- which is precisely what the assertions in
    ``test_run_003_destructive_request_is_rejected``,
    ``test_no_permission_decision_can_ever_select_allow_always`` and
    ``test_a_rejected_destructive_request_still_completes_the_turn`` forbid.
    """

    import admissible.delegated_gate.acp_authority as authority

    def unconditional_allow_always(
        request, *, workspace, additional_authorized_paths=frozenset(), mission_effects=None,
    ):
        # The exact pre-repair preference order.
        for preferred in ("allow_always", "allow_once"):
            for option in request.options:
                if option.kind == preferred:
                    return authority.PermissionDecision(
                        authority.DECISION_ALLOW_ONCE, option.option_id, option.kind,
                        "pre_repair_unconditional_grant", "granted without inspection",
                        authority.CONTAINMENT_NOT_EVALUATED, (),
                    )
        raise AssertionError("no grant offered")

    monkeypatch.setattr(authority, "decide_permission", unconditional_allow_always)

    # 1. The policy-level proof fails.
    request = parse_permission_request(permission_params(RUN_003_DESTRUCTIVE_TITLE))
    mutated = authority.decide_permission(request, workspace=str(workspace))
    assert mutated.selected_option_kind == PERMISSION_KIND_ALLOW_ALWAYS
    assert mutated.selected_option_id == "allow-always"
    assert mutated.approved
    # The committed assertions that would now fail, restated verbatim:
    with pytest.raises(AssertionError):
        assert mutated.decision == DECISION_REJECT
    with pytest.raises(AssertionError):
        assert mutated.selected_option_kind not in FORBIDDEN_PERMISSION_OPTION_KINDS

    # 2. The independent response guard catches this mutation on its own: even
    #    with the policy subverted, allow-always cannot reach the wire, and the
    #    turn fails closed instead.
    prompt = build_prompt()
    guarded = AcpAuthorityEvidence(tmp_path / "guarded.jsonl", redact=(prompt,))
    blocked = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("permission_destructive"), prompt,
                        cwd=str(workspace), started=StartedRecorder(), evidence=guarded)
    )
    assert blocked.returncode == 1
    assert blocked.protocol_failure_detail == "transport_error:AcpAuthorityRefusal"
    assert "permission=allow-always" not in blocked.stdout

    # 3. Remove that second guard too -- the complete pre-repair behavior -- and
    #    allow-always reaches the wire, failing the committed assertions.
    monkeypatch.setattr(
        authority, "permission_response",
        lambda decision: {"outcome": {"outcome": "selected", "optionId": decision.selected_option_id}},
    )
    log = AcpAuthorityEvidence(tmp_path / "authority.jsonl", redact=(prompt,))
    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("permission_destructive"), prompt,
                        cwd=str(workspace), started=StartedRecorder(), evidence=log)
    )
    assert "permission=allow-always" in outcome.stdout
    with pytest.raises(AssertionError):
        assert "permission=reject-once" in outcome.stdout
    granted = [r for r in log.records if r["record_type"] == RECORD_PERMISSION_DECISION][0]
    assert granted["selected_option_kind"] == PERMISSION_KIND_ALLOW_ALWAYS
