"""Client-side ACP authority for the native lane.

Neon Relay run 003 exposed four defects that all live on the *client* side of the
``cursor-agent acp`` connection, not in the transport:

1. the client answered exactly one server-to-client method, so the ordinary
   ``cursor/update_todos`` request terminated the turn;
2. every ``session/request_permission`` was granted, preferring ``allow_always``
   over ``allow_once`` and inspecting nothing;
3. ``cmd /c "rmdir /s /q %SystemDrive%"`` was therefore approved and executed;
4. the hardened child environment omitted ``SystemDrive``/``ProgramData``/
   ``ALLUSERSPROFILE``, so Windows shell-folder resolution created a literal
   ``%SystemDrive%\\ProgramData\\...`` tree inside the work workspace, which every
   PowerShell subprocess recreated.

This module owns the repair, and only the repair:

* :class:`AcpServerRequestDispatcher` -- an explicit, fail-closed table of the
  exact server-to-client requests this client answers.  There is no ``cursor/*``
  wildcard and no guessed response; each member was added only after its request
  and response shapes were read out of the installed CLI's own bundle.
* :func:`decide_permission` -- a deterministic deny-by-default permission policy
  built from a finite command grammar.  ``allow-always`` is never selectable,
  and the grammar accepts a tiny read-only inspection language rather than
  pretending to parse PowerShell.
* :class:`AcpAuthorityEvidence` -- an append-only, fsync-durable decision log.
  A decision that cannot be persisted cannot be approved.
* :func:`derive_windows_shell_folders` -- deterministic derivation of the three
  missing shell-folder variables from the attested ``SYSTEMROOT``, never
  inherited from the parent environment.
* :func:`workspace_inventory` / :func:`capture_workspace_identity` -- the
  post-startup workspace boundary, by path name *and* by content.

A later independent liveness audit established that this boundary, while safe,
also refuses every effect the Neon Relay mission itself requires.  The repair for
that is deliberately not a category: :mod:`acp_mission_effects` rules on
``kind=edit``, ``npm``, ``git add`` and ``git commit`` against one owner-
authorized :class:`~admissible.delegated_gate.mission_effect_authority.MissionEffectAuthority`
whose members are exact paths, exact command spellings and one exact commit
message.  When no such authority is bound -- every profile that predates it --
this module's behavior is unchanged in every respect.

Nothing here executes a command, deletes a path, or contacts a provider.  The
only subprocess it starts is a read-only ``git`` observation of the authorized
workspace.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ntpath
import os
from pathlib import Path
import posixpath
import re
import stat
import subprocess
from typing import Any, Callable, Iterable, Mapping, Sequence

from admissible.delegated_gate.acp_mission_effects import (
    MissionEffectRuling,
    MissionEffectRuntime,
    RULE_DUPLICATE_TOOL_CALL_CONFLICT,
    request_digest,
)
from admissible.delegated_gate.canonical import canonical_bytes


# ---------------------------------------------------------------------------
# Method table
# ---------------------------------------------------------------------------

ACP_METHOD_REQUEST_PERMISSION = "session/request_permission"
ACP_METHOD_UPDATE_TODOS = "cursor/update_todos"
ACP_METHOD_CREATE_PLAN = "cursor/create_plan"
ACP_METHOD_ASK_QUESTION = "cursor/ask_question"

#: The exact, closed set of server-to-client *requests* this client answers.
#: Anything else terminates the turn fail-closed with its exact method recorded.
#: There is deliberately no ``cursor/*`` wildcard: each member below was added
#: only after its request and response shapes were read out of the installed
#: CLI's own bundle.
ACP_SUPPORTED_SERVER_REQUEST_METHODS: tuple[str, ...] = (
    ACP_METHOD_ASK_QUESTION,
    ACP_METHOD_CREATE_PLAN,
    ACP_METHOD_UPDATE_TODOS,
    ACP_METHOD_REQUEST_PERMISSION,
)


# ---------------------------------------------------------------------------
# Exact protocol-failure vocabulary (persisted verbatim)
# ---------------------------------------------------------------------------

FAILURE_UNANSWERABLE_SERVER_REQUEST = "unanswerable_server_request"
FAILURE_MALFORMED_SERVER_REQUEST = "malformed_server_request"
FAILURE_PERMISSION_EVIDENCE_WRITE = "permission_evidence_write_failed"
FAILURE_PERMISSION_REJECTION_UNAVAILABLE = "permission_rejection_unavailable"
FAILURE_RESPONSE_WRITE = "response_write_failed"
FAILURE_WORKSPACE_POLLUTED = "workspace_polluted_before_prompt"
FAILURE_WORKSPACE_IDENTITY_CHANGED = "workspace_identity_changed_before_prompt"

_DETAIL_LIMIT = 160


def bounded_token(value: Any, *, limit: int = 64) -> str:
    """One-line, length-bounded rendering of an untrusted server value."""

    text = " ".join(str(value).split())
    return text[:limit]


def unanswerable_detail(method: Any) -> str:
    return f"{FAILURE_UNANSWERABLE_SERVER_REQUEST}:{bounded_token(method)}"


def malformed_detail(method: Any) -> str:
    return f"{FAILURE_MALFORMED_SERVER_REQUEST}:{bounded_token(method)}"


# ---------------------------------------------------------------------------
# Permission option kinds
# ---------------------------------------------------------------------------

PERMISSION_KIND_ALLOW_ONCE = "allow_once"
PERMISSION_KIND_ALLOW_ALWAYS = "allow_always"
PERMISSION_KIND_REJECT_ONCE = "reject_once"
PERMISSION_KIND_REJECT_ALWAYS = "reject_always"

#: Kinds this client must never select.  ``allow_always`` grants standing
#: authority the mission never conferred; ``reject_always`` is equally
#: session-scoped authority and is refused for the same reason.
FORBIDDEN_PERMISSION_OPTION_KINDS = frozenset(
    {PERMISSION_KIND_ALLOW_ALWAYS, PERMISSION_KIND_REJECT_ALWAYS}
)

DECISION_ALLOW_ONCE = "ALLOW_ONCE"
DECISION_REJECT = "REJECT"

#: The generic, mission-independent grammar rules on ``execute`` only.  It is
#: unchanged and remains deny-by-default: everything it accepted before still
#: is accepted, and everything it refused before still is refused.
PERMITTED_TOOL_KIND = "execute"

#: ``kind=edit`` is *not* generically permitted.  Without a mission-scoped
#: effect authority it stays categorically refused exactly as in V4; with one,
#: it is ruled on against that authority's exact enumerated paths and never as
#: a category.
MISSION_SCOPED_TOOL_KIND = "edit"


# ---------------------------------------------------------------------------
# Policy rule identifiers
# ---------------------------------------------------------------------------

RULE_MALFORMED_REQUEST = "malformed_permission_request"
RULE_TOOL_KIND_NOT_PERMITTED = "tool_kind_not_permitted"
RULE_COMMAND_TEXT_MISSING = "command_text_missing"
RULE_COMMAND_TEXT_TOO_LONG = "command_text_too_long"
RULE_NESTED_SHELL = "nested_shell_invocation"
RULE_DESTRUCTIVE_COMMAND = "destructive_filesystem_command"
RULE_DYNAMIC_EVALUATION = "dynamic_code_evaluation"
RULE_PROCESS_MUTATION = "process_management_mutation"
RULE_SERVICE_OR_TASK_MUTATION = "service_or_task_scheduler_mutation"
RULE_REGISTRY_MUTATION = "registry_mutation"
RULE_NETWORK_OR_DEPLOYMENT = "network_remote_or_deployment_behavior"
RULE_OUTPUT_REDIRECTION = "redirection_to_a_path"
RULE_UNRESOLVED_ENVIRONMENT_TOKEN = "unresolved_environment_variable_token"
RULE_UNSUPPORTED_CHARACTER = "character_outside_the_accepted_grammar"
RULE_UNTERMINATED_QUOTE = "unterminated_quoted_argument"
RULE_EMPTY_SEGMENT = "empty_command_segment"
RULE_UNKNOWN_VERB = "unknown_or_ambiguous_command_class"
RULE_UNKNOWN_SWITCH = "unknown_or_ambiguous_switch"
RULE_PATH_OUTSIDE_WORKSPACE = "absolute_path_outside_authorized_workspace"
RULE_PARENT_TRAVERSAL = "parent_traversal_not_provably_contained"
RULE_ALLOW_ONCE_UNAVAILABLE = "narrow_allow_once_option_absent"
RULE_BOUNDED_READ_ONLY_INSPECTION = "bounded_read_only_workspace_inspection"
RULE_DUPLICATE_REPLAY = "identical_request_replayed_without_consuming_authority"

CONTAINMENT_NOT_EVALUATED = "not_evaluated"
CONTAINMENT_INSIDE_WORKSPACE = "all_referenced_paths_inside_authorized_workspace"
CONTAINMENT_VIOLATION = "referenced_path_outside_authorized_workspace"


# ---------------------------------------------------------------------------
# Deny classification (whole-token, case-insensitive)
# ---------------------------------------------------------------------------

# Tokens are compared whole and lowercased, with leading dashes stripped, so
# ``Format-Table`` never matches ``format`` and ``rd`` never matches inside
# ``Get-ChildItem``.  Each set carries its own rule id so a rejection reports
# *why* rather than merely that it happened.
_DENY_NESTED_SHELL = frozenset({
    "cmd", "cmd.exe", "command.com", "powershell", "powershell.exe", "pwsh",
    "pwsh.exe", "bash", "sh", "zsh", "dash", "wsl", "wsl.exe", "conhost",
    "conhost.exe", "start", "call", "source",
})
_DENY_DESTRUCTIVE = frozenset({
    "remove-item", "ri", "rm", "rmdir", "rd", "del", "erase", "format",
    "diskpart", "clear-content", "clear-item", "set-content", "add-content",
    "out-file", "tee-object", "new-item", "move-item", "copy-item",
    "rename-item", "mkdir", "md", "fsutil", "cipher", "takeown", "icacls",
    "attrib", "robocopy", "xcopy", "compact", "chkdsk", "vssadmin",
})
_DENY_DYNAMIC = frozenset({
    "invoke-expression", "iex", "invoke-command", "icm", "add-type",
    "invoke-item", "ii", "start-job", "receive-job", "scriptblock",
})
_DENY_PROCESS = frozenset({
    "start-process", "saps", "stop-process", "spps", "kill", "taskkill",
    "wmic", "wait-process", "debug-process",
})
_DENY_SERVICE_OR_TASK = frozenset({
    "sc", "sc.exe", "net", "net.exe", "net1", "schtasks", "at", "shutdown",
    "bcdedit", "set-service", "start-service", "stop-service",
    "restart-service", "new-service", "remove-service",
    "register-scheduledtask", "unregister-scheduledtask",
    "start-scheduledtask", "stop-scheduledtask", "set-scheduledtask",
})
_DENY_REGISTRY = frozenset({
    "reg", "reg.exe", "regedit", "regedit.exe", "regsvr32", "regini",
    "set-itemproperty", "new-itemproperty", "remove-itemproperty",
    "set-item", "new-psdrive", "remove-psdrive",
})
# ``remote`` is deliberately absent: ``git remote -v`` is explicitly permitted
# and is bounded by the git grammar below instead.
_DENY_NETWORK = frozenset({
    "push", "pull", "fetch", "clone", "deploy", "publish", "serve", "server",
    "watch", "curl", "curl.exe", "wget", "invoke-webrequest", "iwr",
    "invoke-restmethod", "irm", "ssh", "scp", "sftp", "ftp", "telnet", "nc",
    "ncat", "netsh", "ping", "tracert", "nslookup", "npm", "npm.cmd", "npx",
    "node", "yarn", "pnpm", "pip", "python", "dotnet", "docker", "kubectl",
    "http-server", "live-server", "start-webrequest",
})

_DENY_SETS: tuple[tuple[frozenset[str], str], ...] = (
    (_DENY_NESTED_SHELL, RULE_NESTED_SHELL),
    (_DENY_DESTRUCTIVE, RULE_DESTRUCTIVE_COMMAND),
    (_DENY_DYNAMIC, RULE_DYNAMIC_EVALUATION),
    (_DENY_PROCESS, RULE_PROCESS_MUTATION),
    (_DENY_SERVICE_OR_TASK, RULE_SERVICE_OR_TASK_MUTATION),
    (_DENY_REGISTRY, RULE_REGISTRY_MUTATION),
    (_DENY_NETWORK, RULE_NETWORK_OR_DEPLOYMENT),
)

_DENY_SCAN_TOKEN = re.compile(r"[A-Za-z0-9_.\-]+")
_REDIRECTION = re.compile(r"[<>]")
# ``%`` and ``$`` are the only variable sigils cmd and PowerShell have; either
# one means the command carries a token this client cannot resolve or contain.
_ENVIRONMENT_SIGIL = re.compile(r"%[^%\s]*%?|\$\{?[A-Za-z_:]?[^\s]*")

_COMMAND_TEXT_LIMIT = 2048


# ---------------------------------------------------------------------------
# Positive grammar
# ---------------------------------------------------------------------------

_ACCEPTED_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " _-.,:;|/\\'\"="
)

#: Bounded, read-only PowerShell inspection verbs.  Aliases (``ls``, ``gci``,
#: ``cat``, ``sls``, ``ft``, ``echo``) are deliberately absent: an alias is an
#: unknown class, and unknown classes are rejected.
_ALLOWED_POWERSHELL_VERBS = frozenset({
    "get-childitem", "get-content", "test-path", "select-string",
    "select-object", "format-table", "write-output", "write-host",
})

_ALLOWED_POWERSHELL_SWITCHES = frozenset({
    "-force", "-recurse", "-name", "-path", "-literalpath", "-filter",
    "-include", "-exclude", "-file", "-directory", "-depth", "-totalcount",
    "-tail", "-raw", "-encoding", "-pattern", "-simplematch", "-casesensitive",
    "-first", "-last", "-skip", "-property", "-expandproperty", "-unique",
    "-autosize", "-wrap", "-hidden", "-list", "-erroraction", "-nonewline",
})

_GIT_COMMAND = "git"
_ALLOWED_GIT_SUBCOMMANDS: Mapping[str, frozenset[str]] = {
    "status": frozenset({
        "--short", "-s", "--porcelain", "--porcelain=v1", "--branch", "-b",
        "--untracked-files=all", "-uall", "--no-color",
    }),
    "log": frozenset({
        "--oneline", "-1", "-n", "--stat", "--name-only", "--no-color",
        "--max-count=1", "--graph", "--decorate",
    }),
    "diff": frozenset({
        "--stat", "--cached", "--staged", "--name-only", "--no-color",
        "--numstat", "--shortstat",
    }),
    "show": frozenset({"--stat", "--name-only", "--no-color", "-s"}),
    "rev-parse": frozenset({"--abbrev-ref", "--show-toplevel", "--git-dir", "--verify"}),
    "remote": frozenset({"-v"}),
}
#: ``git remote`` is read-only only in its ``-v`` form; every other shape is an
#: unknown class.
_GIT_SUBCOMMANDS_REQUIRING_SWITCH: Mapping[str, str] = {"remote": "-v"}

_SEGMENT_SEPARATORS = frozenset({";", "|"})


class AcpEvidenceWriteError(RuntimeError):
    """The permission/authority decision could not be made durable."""


class AcpAuthorityRefusal(ValueError):
    """A deterministic authority derivation refused; never a soft warning."""


# ---------------------------------------------------------------------------
# Command tokenizer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Token:
    text: str
    quoted: bool
    separator: bool = False


def _strip_code_span(text: str) -> str:
    """Remove the single markdown code span Cursor wraps tool titles in."""

    candidate = text.strip()
    if len(candidate) >= 2 and candidate.startswith("`") and candidate.endswith("`"):
        candidate = candidate[1:-1].strip()
    return candidate


def _tokenize(text: str) -> tuple[tuple[_Token, ...] | None, str]:
    """Split the accepted alphabet into words, quoted strings and separators.

    Returns ``(tokens, "")`` or ``(None, rule_id)``.  This is not a shell
    parser: it accepts one tiny language and refuses everything else.
    """

    tokens: list[_Token] = []
    buffer: list[str] = []

    def flush() -> None:
        if buffer:
            tokens.append(_Token("".join(buffer), quoted=False))
            buffer.clear()

    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        if character in ("'", '"'):
            flush()
            closing = text.find(character, index + 1)
            if closing == -1:
                return None, RULE_UNTERMINATED_QUOTE
            tokens.append(_Token(text[index + 1 : closing], quoted=True))
            index = closing + 1
            continue
        if character == " ":
            flush()
            index += 1
            continue
        if character in _SEGMENT_SEPARATORS:
            flush()
            tokens.append(_Token(character, quoted=False, separator=True))
            index += 1
            continue
        buffer.append(character)
        index += 1
    flush()
    return tuple(tokens), ""


def _segments(tokens: Sequence[_Token]) -> list[list[_Token]]:
    segments: list[list[_Token]] = [[]]
    for token in tokens:
        if token.separator:
            segments.append([])
            continue
        segments[-1].append(token)
    return segments


# ---------------------------------------------------------------------------
# Path containment
# ---------------------------------------------------------------------------


def _normcase(value: str) -> str:
    return ntpath.normcase(value) if os.name == "nt" else value


def _contained(candidate: str, root: str) -> bool:
    """True when ``candidate`` is ``root`` or lexically inside it."""

    normalized = _normcase(os.path.normpath(candidate))
    base = _normcase(os.path.normpath(root))
    if normalized == base:
        return True
    return normalized.startswith(base.rstrip("\\/") + os.sep)


def normalize_referenced_path(
    token: str, *, workspace: str, additional_authorized_paths: frozenset[str] = frozenset()
) -> tuple[str | None, str]:
    """Normalize one referenced path token; return ``(normalized, rule_id)``.

    Every non-switch argument is treated as a candidate path.  A harmless bare
    word (``Name``, ``Mode``) trivially normalizes inside the workspace, so the
    rule stays conservative without needing to know which arguments are paths.
    """

    if not token:
        return None, RULE_EMPTY_SEGMENT
    for authorized in additional_authorized_paths:
        if _normcase(os.path.normpath(token)) == _normcase(os.path.normpath(authorized)):
            return os.path.normpath(token), ""
    drive, _ = ntpath.splitdrive(token)
    absolute = bool(drive) or token.startswith(("\\", "/"))
    if absolute:
        normalized = os.path.normpath(token)
        if not _contained(normalized, workspace):
            return None, RULE_PATH_OUTSIDE_WORKSPACE
        return normalized, ""
    joined = os.path.normpath(os.path.join(workspace, token))
    if not _contained(joined, workspace):
        return None, RULE_PARENT_TRAVERSAL
    return joined, ""


# ---------------------------------------------------------------------------
# Command classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandRuling:
    permitted: bool
    rule_id: str
    detail: str
    normalized_paths: tuple[str, ...]
    containment: str


def _deny_scan(text: str) -> tuple[str, str] | None:
    for raw in _DENY_SCAN_TOKEN.findall(text):
        token = raw.lower().lstrip("-")
        if not token:
            continue
        for members, rule_id in _DENY_SETS:
            if token in members:
                return rule_id, bounded_token(raw)
    return None


def classify_command(
    command: str,
    *,
    workspace: str,
    additional_authorized_paths: frozenset[str] = frozenset(),
) -> CommandRuling:
    """Deny by default; permit only positively classified read-only inspection."""

    text = _strip_code_span(command)
    if not text:
        return CommandRuling(False, RULE_COMMAND_TEXT_MISSING, "empty command text", (), CONTAINMENT_NOT_EVALUATED)
    if len(text) > _COMMAND_TEXT_LIMIT:
        return CommandRuling(
            False, RULE_COMMAND_TEXT_TOO_LONG, f"{len(text)} characters", (), CONTAINMENT_NOT_EVALUATED,
        )

    denied = _deny_scan(text)
    if denied is not None:
        rule_id, token = denied
        return CommandRuling(False, rule_id, f"token {token!r}", (), CONTAINMENT_NOT_EVALUATED)

    sigil = _ENVIRONMENT_SIGIL.search(text)
    if sigil is not None:
        return CommandRuling(
            False, RULE_UNRESOLVED_ENVIRONMENT_TOKEN, bounded_token(sigil.group(0)), (), CONTAINMENT_NOT_EVALUATED,
        )
    redirection = _REDIRECTION.search(text)
    if redirection is not None:
        return CommandRuling(
            False, RULE_OUTPUT_REDIRECTION, f"operator {redirection.group(0)!r}", (), CONTAINMENT_NOT_EVALUATED,
        )
    unsupported = [character for character in text if character not in _ACCEPTED_CHARACTERS]
    if unsupported:
        return CommandRuling(
            False, RULE_UNSUPPORTED_CHARACTER, bounded_token("".join(sorted(set(unsupported)))),
            (), CONTAINMENT_NOT_EVALUATED,
        )

    tokens, failure = _tokenize(text)
    if tokens is None:
        return CommandRuling(False, failure, "quoting is not closed", (), CONTAINMENT_NOT_EVALUATED)

    normalized_paths: list[str] = []
    for segment in _segments(tokens):
        if not segment:
            return CommandRuling(False, RULE_EMPTY_SEGMENT, "empty segment", (), CONTAINMENT_NOT_EVALUATED)
        ruling = _classify_segment(
            segment, workspace=workspace,
            additional_authorized_paths=additional_authorized_paths,
            normalized_paths=normalized_paths,
        )
        if ruling is not None:
            return ruling
    return CommandRuling(
        True, RULE_BOUNDED_READ_ONLY_INSPECTION, bounded_token(text, limit=_DETAIL_LIMIT),
        tuple(normalized_paths), CONTAINMENT_INSIDE_WORKSPACE,
    )


def _classify_segment(
    segment: Sequence[_Token],
    *,
    workspace: str,
    additional_authorized_paths: frozenset[str],
    normalized_paths: list[str],
) -> CommandRuling | None:
    """Return a rejection ruling, or ``None`` when the segment is acceptable."""

    verb_token = segment[0]
    if verb_token.quoted:
        return CommandRuling(False, RULE_UNKNOWN_VERB, "quoted verb", (), CONTAINMENT_NOT_EVALUATED)
    verb = verb_token.text.lower()
    arguments = list(segment[1:])

    if verb == _GIT_COMMAND:
        if not arguments or arguments[0].quoted:
            return CommandRuling(False, RULE_UNKNOWN_VERB, "git without a subcommand", (), CONTAINMENT_NOT_EVALUATED)
        subcommand = arguments[0].text.lower()
        allowed_switches = _ALLOWED_GIT_SUBCOMMANDS.get(subcommand)
        if allowed_switches is None:
            return CommandRuling(
                False, RULE_UNKNOWN_VERB, f"git {bounded_token(subcommand)}", (), CONTAINMENT_NOT_EVALUATED,
            )
        arguments = arguments[1:]
        required = _GIT_SUBCOMMANDS_REQUIRING_SWITCH.get(subcommand)
        if required is not None and [item.text.lower() for item in arguments] != [required]:
            return CommandRuling(
                False, RULE_UNKNOWN_VERB, f"git {subcommand} accepts only {required}",
                (), CONTAINMENT_NOT_EVALUATED,
            )
        switch_set = allowed_switches
    elif verb in _ALLOWED_POWERSHELL_VERBS:
        switch_set = _ALLOWED_POWERSHELL_SWITCHES
    else:
        return CommandRuling(False, RULE_UNKNOWN_VERB, bounded_token(verb), (), CONTAINMENT_NOT_EVALUATED)

    for argument in arguments:
        if not argument.quoted and argument.text.startswith("-"):
            if argument.text.lower() not in switch_set:
                return CommandRuling(
                    False, RULE_UNKNOWN_SWITCH, bounded_token(argument.text), (), CONTAINMENT_NOT_EVALUATED,
                )
            continue
        normalized, rule_id = normalize_referenced_path(
            argument.text, workspace=workspace,
            additional_authorized_paths=additional_authorized_paths,
        )
        if normalized is None:
            return CommandRuling(
                False, rule_id, bounded_token(argument.text), (), CONTAINMENT_VIOLATION,
            )
        normalized_paths.append(normalized)
    return None


# ---------------------------------------------------------------------------
# Permission request validation and ruling
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PermissionOption:
    option_id: str
    kind: str


@dataclass(frozen=True)
class PermissionRequest:
    acp_session_id: str | None
    tool_call_id: str | None
    tool_kind: str | None
    title: str
    server_reason: str | None
    options: tuple[PermissionOption, ...]
    #: The structured ``toolCall.content`` array exactly as delivered.  This is
    #: where the installed CLI puts the authoritative diff location, so it is
    #: retained rather than collapsed into ``server_reason``.
    raw_content: Any = None


@dataclass(frozen=True)
class PermissionDecision:
    """A complete, self-describing decision: never just an option id."""

    decision: str
    selected_option_id: str | None
    selected_option_kind: str | None
    rule_id: str
    detail: str
    containment: str
    normalized_paths: tuple[str, ...]
    #: Set when the protocol itself cannot express the decision.
    protocol_failure: str | None = None
    #: Mission-scoped fields; ``None``/empty for a generic grammar decision.
    authority_class: str | None = None
    structured_operation: str | None = None
    live_observation_fingerprint: str | None = None
    live_refusal_reasons: tuple[str, ...] = ()
    budget_before: int | None = None
    budget_after: int | None = None
    #: Set when this decision replayed an already-decided identical request.
    replayed: bool = False

    @property
    def approved(self) -> bool:
        return self.decision == DECISION_ALLOW_ONCE


def parse_permission_request(params: Any) -> PermissionRequest | None:
    """Strictly parse ``session/request_permission`` params; ``None`` if malformed."""

    if not isinstance(params, Mapping):
        return None
    raw_options = params.get("options")
    if not isinstance(raw_options, list) or not raw_options:
        return None
    options: list[PermissionOption] = []
    for entry in raw_options:
        if not isinstance(entry, Mapping):
            return None
        option_id = entry.get("optionId")
        kind = entry.get("kind")
        if not isinstance(option_id, str) or not option_id:
            return None
        if not isinstance(kind, str) or not kind:
            return None
        options.append(PermissionOption(option_id, kind))

    session_id = params.get("sessionId")
    tool_call = params.get("toolCall")
    tool_call_id: str | None = None
    tool_kind: str | None = None
    title = ""
    reason: str | None = None
    raw_content: Any = None
    if isinstance(tool_call, Mapping):
        raw_id = tool_call.get("toolCallId")
        tool_call_id = raw_id if isinstance(raw_id, str) else None
        raw_kind = tool_call.get("kind")
        tool_kind = raw_kind if isinstance(raw_kind, str) else None
        raw_title = tool_call.get("title")
        title = raw_title if isinstance(raw_title, str) else ""
        raw_content = tool_call.get("content")
        reason = _first_text_content(raw_content)
    return PermissionRequest(
        acp_session_id=session_id if isinstance(session_id, str) else None,
        tool_call_id=tool_call_id, tool_kind=tool_kind, title=title,
        server_reason=reason, options=tuple(options), raw_content=raw_content,
    )


def _first_text_content(content: Any) -> str | None:
    if not isinstance(content, list):
        return None
    for entry in content:
        if not isinstance(entry, Mapping):
            continue
        inner = entry.get("content")
        if isinstance(inner, Mapping) and isinstance(inner.get("text"), str):
            return inner["text"]
        if isinstance(entry.get("text"), str):
            return entry["text"]
    return None


def _select(options: Sequence[PermissionOption], kind: str) -> PermissionOption | None:
    for option in options:
        if option.kind == kind:
            return option
    return None


def decide_permission(
    request: PermissionRequest,
    *,
    workspace: str,
    additional_authorized_paths: frozenset[str] = frozenset(),
    mission_effects: "MissionEffectRuntime | None" = None,
) -> PermissionDecision:
    """Deny-by-default ruling plus the exact option this client will select.

    Three disjoint paths reach an approval, and every one of them terminates in
    an exact enumerated member:

    * ``kind=edit`` -- only against a mission-scoped effect authority, and only
      for one of its exact writable material paths.  With no authority bound,
      the V4 categorical refusal is unchanged.
    * ``kind=execute`` naming a mission effect (``npm``/``npm.cmd``, ``git
      add``, ``git commit``) -- ruled on *decisively* by the mission authority,
      so ``npm install`` is refused as an unauthorized verification rather than
      falling through to a generic network-token match.
    * ``kind=execute`` naming anything else -- the unchanged V4 read-only
      inspection grammar.

    ``allow_always`` is unreachable by construction on all three: the approval
    branch looks up ``allow_once`` and nothing else, and the final assertion
    refuses any forbidden kind a future edit might reintroduce.
    """

    reject = _select(request.options, PERMISSION_KIND_REJECT_ONCE)

    def rejection(
        rule_id: str,
        detail: str,
        containment: str = CONTAINMENT_NOT_EVALUATED,
        **mission: Any,
    ) -> PermissionDecision:
        if reject is None:
            return PermissionDecision(
                DECISION_REJECT, None, None, rule_id, detail, containment, (),
                protocol_failure=FAILURE_PERMISSION_REJECTION_UNAVAILABLE, **mission,
            )
        return PermissionDecision(
            DECISION_REJECT, reject.option_id, reject.kind, rule_id, detail, containment, (),
            **mission,
        )

    def approval(
        rule_id: str,
        detail: str,
        containment: str,
        paths: tuple[str, ...],
        **mission: Any,
    ) -> PermissionDecision:
        allow_once = _select(request.options, PERMISSION_KIND_ALLOW_ONCE)
        if allow_once is None:
            # A positively safe effect whose only grant is standing authority
            # is still refused: narrowing is never available by escalating.
            return rejection(RULE_ALLOW_ONCE_UNAVAILABLE, "no allow_once option was offered")
        if allow_once.kind in FORBIDDEN_PERMISSION_OPTION_KINDS:  # pragma: no cover - defensive
            raise AcpAuthorityRefusal("allow-always is never selectable")
        return PermissionDecision(
            DECISION_ALLOW_ONCE, allow_once.option_id, allow_once.kind,
            rule_id, detail, containment, paths, **mission,
        )

    if not request.tool_call_id:
        return rejection(RULE_MALFORMED_REQUEST, "tool call carries no identifier")

    if request.tool_kind == MISSION_SCOPED_TOOL_KIND:
        if mission_effects is None:
            return rejection(RULE_TOOL_KIND_NOT_PERMITTED, bounded_token(request.tool_kind))
        ruling = mission_effects.rule_on_edit(
            title=request.title, content=request.raw_content
        )
        return _from_mission_ruling(ruling, rejection=rejection, approval=approval)

    if request.tool_kind != PERMITTED_TOOL_KIND:
        return rejection(RULE_TOOL_KIND_NOT_PERMITTED, bounded_token(request.tool_kind))

    if mission_effects is not None:
        mission_ruling = mission_effects.rule_on_command(request.title)
        if mission_ruling is not None:
            return _from_mission_ruling(
                mission_ruling, rejection=rejection, approval=approval
            )

    ruling = classify_command(
        request.title, workspace=workspace,
        additional_authorized_paths=additional_authorized_paths,
    )
    if not ruling.permitted:
        return rejection(ruling.rule_id, ruling.detail, ruling.containment)
    return approval(
        ruling.rule_id, ruling.detail, ruling.containment, ruling.normalized_paths,
    )


def _rejection_for(
    request: PermissionRequest, rule_id: str, detail: str
) -> PermissionDecision:
    """A refusal expressed with the exact reject option the server offered."""

    reject = _select(request.options, PERMISSION_KIND_REJECT_ONCE)
    if reject is None:
        return PermissionDecision(
            DECISION_REJECT, None, None, rule_id, detail, CONTAINMENT_NOT_EVALUATED, (),
            protocol_failure=FAILURE_PERMISSION_REJECTION_UNAVAILABLE,
        )
    return PermissionDecision(
        DECISION_REJECT, reject.option_id, reject.kind, rule_id, detail,
        CONTAINMENT_NOT_EVALUATED, (),
    )


def _replayed_decision(request: PermissionRequest, approved: bool) -> PermissionDecision:
    """Re-answer one byte-identical retransmission without spending authority."""

    if not approved:
        decision = _rejection_for(request, RULE_DUPLICATE_REPLAY, "identical request already refused")
        return PermissionDecision(**{**decision.__dict__, "replayed": True})
    allow_once = _select(request.options, PERMISSION_KIND_ALLOW_ONCE)
    if allow_once is None:
        return _rejection_for(request, RULE_ALLOW_ONCE_UNAVAILABLE, "no allow_once option was offered")
    if allow_once.kind in FORBIDDEN_PERMISSION_OPTION_KINDS:  # pragma: no cover - defensive
        raise AcpAuthorityRefusal("allow-always is never selectable")
    return PermissionDecision(
        DECISION_ALLOW_ONCE, allow_once.option_id, allow_once.kind,
        RULE_DUPLICATE_REPLAY, "identical request already approved",
        CONTAINMENT_INSIDE_WORKSPACE, (), replayed=True,
    )


def _deep_copy(value: Any) -> Any:
    """A fresh, plain-JSON copy so a canonical result literal stays immutable."""

    if isinstance(value, Mapping):
        return {key: _deep_copy(value[key]) for key in value}
    if isinstance(value, list):
        return [_deep_copy(item) for item in value]
    return value


def _from_mission_ruling(
    ruling: "MissionEffectRuling",
    *,
    rejection: Callable[..., PermissionDecision],
    approval: Callable[..., PermissionDecision],
) -> PermissionDecision:
    """Project one mission-scoped ruling onto the protocol decision."""

    mission = {
        "authority_class": ruling.effect_class,
        "structured_operation": ruling.operation,
        "live_observation_fingerprint": ruling.live_observation_fingerprint,
        "live_refusal_reasons": ruling.live_reasons,
        "budget_before": ruling.budget_before,
        "budget_after": ruling.budget_after,
        "replayed": ruling.replayed,
    }
    if not ruling.permitted:
        return rejection(
            ruling.rule_id, ruling.detail, CONTAINMENT_NOT_EVALUATED, **mission
        )
    return approval(
        ruling.rule_id, ruling.detail, CONTAINMENT_INSIDE_WORKSPACE,
        ruling.normalized_targets, **mission,
    )


def permission_response(decision: PermissionDecision) -> dict[str, Any]:
    """The exact ACP ``RequestPermissionResponse`` for a decided request."""

    if decision.selected_option_id is None:
        raise AcpAuthorityRefusal("a permission decision without an option cannot be answered")
    if decision.selected_option_kind in FORBIDDEN_PERMISSION_OPTION_KINDS:
        raise AcpAuthorityRefusal("allow-always is never selectable")
    return {"outcome": {"outcome": "selected", "optionId": decision.selected_option_id}}


# ---------------------------------------------------------------------------
# cursor/update_todos
# ---------------------------------------------------------------------------

#: Exactly the four statuses the installed Cursor CLI emits (its own
#: ``convertTodoStatus`` maps every internal value onto this closed set).
TODO_STATUSES = frozenset({"pending", "in_progress", "completed", "cancelled"})
_MAX_TODOS = 256
_TODO_TEXT_LIMIT = 512


@dataclass(frozen=True)
class TodoUpdate:
    tool_call_id: str
    merge: bool
    statuses: tuple[str, ...]

    @property
    def todo_count(self) -> int:
        return len(self.statuses)


def parse_update_todos(params: Any) -> TodoUpdate | None:
    """Strictly validate ``cursor/update_todos``; ``None`` if malformed.

    The request is session metadata: it bears no authority, causes no
    filesystem or process effect, and only its shape and bounded status
    vector are retained.
    """

    if not isinstance(params, Mapping):
        return None
    if set(params) - {"toolCallId", "todos", "merge"}:
        return None
    tool_call_id = params.get("toolCallId")
    todos = params.get("todos")
    merge = params.get("merge", False)
    if not isinstance(tool_call_id, str) or not tool_call_id:
        return None
    if not isinstance(merge, bool):
        return None
    if not isinstance(todos, list) or not todos or len(todos) > _MAX_TODOS:
        return None
    statuses: list[str] = []
    for entry in todos:
        if not isinstance(entry, Mapping):
            return None
        if set(entry) - {"id", "content", "status"}:
            return None
        identifier = entry.get("id")
        content = entry.get("content")
        status = entry.get("status")
        if not isinstance(identifier, str) or not identifier or len(identifier) > _TODO_TEXT_LIMIT:
            return None
        if not isinstance(content, str) or not content or len(content) > _TODO_TEXT_LIMIT:
            return None
        if status not in TODO_STATUSES:
            return None
        statuses.append(status)
    return TodoUpdate(tool_call_id, merge, tuple(statuses))


#: ``cursor/update_todos`` is dispatched by the CLI through the ACP SDK's
#: untyped ``extMethod``, whose result is not schema-validated; an empty object
#: is the protocol-compatible success acknowledgement.
UPDATE_TODOS_RESULT: Mapping[str, Any] = {}

JSONRPC_INVALID_PARAMS = -32602


# ---------------------------------------------------------------------------
# cursor/create_plan
# ---------------------------------------------------------------------------
#
# Request shape, read out of the installed CLI's own create-plan handler:
#
#   {toolCallId, name?, overview?, plan, todos: [{id, content, status}],
#    isProject?, phases?: [{name, todos: [{id, content, status}]}]}
#
# and its response reader accepts
#
#   {outcome: {outcome: "accepted", planUri?}}
#   {outcome: {outcome: "rejected", reason?}}
#   {outcome: {outcome: "cancelled"}}
#
# The plan bears no authority: it authorizes no path, no command and no commit,
# and every effect it describes must still pass the permission boundary
# individually.  It is therefore acknowledged as accepted so the turn continues,
# and only a bounded normalized record of its shape is retained.

_MAX_PLAN_TODOS = 256
_MAX_PLAN_PHASES = 64
_PLAN_TEXT_LIMIT = 4096


@dataclass(frozen=True)
class PlanRequest:
    tool_call_id: str
    todo_count: int
    phase_count: int
    statuses: tuple[str, ...]
    is_project: bool


def parse_create_plan(params: Any) -> PlanRequest | None:
    """Strictly validate ``cursor/create_plan``; ``None`` if malformed."""

    if not isinstance(params, Mapping):
        return None
    if set(params) - {"toolCallId", "name", "overview", "plan", "todos", "isProject", "phases"}:
        return None
    tool_call_id = params.get("toolCallId")
    if not isinstance(tool_call_id, str) or not tool_call_id or len(tool_call_id) > _PLAN_TEXT_LIMIT:
        return None
    for key in ("name", "overview", "plan"):
        value = params.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or len(value) > _PLAN_TEXT_LIMIT:
            return None
    is_project = params.get("isProject", False)
    if is_project is None:
        is_project = False
    if not isinstance(is_project, bool):
        return None

    statuses = _plan_todo_statuses(params.get("todos", []))
    if statuses is None:
        return None
    phases = params.get("phases")
    phase_count = 0
    if phases is not None:
        if not isinstance(phases, list) or len(phases) > _MAX_PLAN_PHASES:
            return None
        for phase in phases:
            if not isinstance(phase, Mapping) or set(phase) - {"name", "todos"}:
                return None
            name = phase.get("name")
            if name is not None and (not isinstance(name, str) or len(name) > _PLAN_TEXT_LIMIT):
                return None
            phase_statuses = _plan_todo_statuses(phase.get("todos", []))
            if phase_statuses is None:
                return None
            statuses = statuses + phase_statuses
        phase_count = len(phases)
    if len(statuses) > _MAX_PLAN_TODOS:
        return None
    return PlanRequest(tool_call_id, len(statuses), phase_count, statuses, bool(is_project))


def _plan_todo_statuses(todos: Any) -> tuple[str, ...] | None:
    if not isinstance(todos, list) or len(todos) > _MAX_PLAN_TODOS:
        return None
    statuses: list[str] = []
    for entry in todos:
        if not isinstance(entry, Mapping) or set(entry) - {"id", "content", "status"}:
            return None
        identifier = entry.get("id")
        content = entry.get("content")
        status = entry.get("status")
        if not isinstance(identifier, str) or not identifier or len(identifier) > _TODO_TEXT_LIMIT:
            return None
        if not isinstance(content, str) or len(content) > _TODO_TEXT_LIMIT:
            return None
        if status not in TODO_STATUSES:
            return None
        statuses.append(status)
    return tuple(statuses)


#: The exact protocol-compatible acknowledgement.  ``planUri`` is deliberately
#: omitted rather than invented: this client creates no plan artifact, and
#: fabricating a URI would be a claim about a file that does not exist.
CREATE_PLAN_RESULT: Mapping[str, Any] = {"outcome": {"outcome": "accepted"}}


# ---------------------------------------------------------------------------
# cursor/ask_question
# ---------------------------------------------------------------------------
#
# Request shape, read out of the installed CLI's own ask-question handler:
#
#   {sessionId?, toolCallId?, title?,
#    questions: [{id, prompt, options: [{id, label}], allowMultiple}]}
#
# and its response reader accepts
#
#   {outcome: {outcome: "answered", answers: [{questionId, selectedOptionIds}]}}
#   {outcome: {outcome: "skipped", reason?}}
#   {outcome: {outcome: "cancelled"}}
#
# The run is non-interactive: no owner is present, and no owner authorization
# covers whatever the question happens to ask.  "answered" is therefore
# unreachable -- selecting an option is exactly how a question turns into new
# authority -- and "cancelled" would tell the model a human refused, which is
# false.  "skipped" carrying an exact, deterministic reason is the one shape
# that states the truth, invents no fact, and reaches the model verbatim: the
# CLI surfaces the reason string as the tool result.

_MAX_QUESTIONS = 16
_MAX_QUESTION_OPTIONS = 32
_QUESTION_TEXT_LIMIT = 4096

ACP_ASK_QUESTION_UNATTENDED_REASON = (
    "No additional owner input is available. Continue autonomously within the "
    "authorized mission, use conservative defaults, and do not broaden scope."
)


@dataclass(frozen=True)
class QuestionRequest:
    tool_call_id: str | None
    question_count: int
    option_counts: tuple[int, ...]
    allows_multiple: tuple[bool, ...]


def parse_ask_question(params: Any) -> QuestionRequest | None:
    """Strictly validate ``cursor/ask_question``; ``None`` if malformed."""

    if not isinstance(params, Mapping):
        return None
    if set(params) - {"sessionId", "toolCallId", "title", "questions"}:
        return None
    tool_call_id = params.get("toolCallId")
    if tool_call_id is not None and (
        not isinstance(tool_call_id, str) or not tool_call_id or len(tool_call_id) > _QUESTION_TEXT_LIMIT
    ):
        return None
    title = params.get("title")
    if title is not None and (not isinstance(title, str) or len(title) > _QUESTION_TEXT_LIMIT):
        return None
    questions = params.get("questions")
    if not isinstance(questions, list) or not questions or len(questions) > _MAX_QUESTIONS:
        return None
    option_counts: list[int] = []
    multiple: list[bool] = []
    for question in questions:
        if not isinstance(question, Mapping) or set(question) - {
            "id", "prompt", "options", "allowMultiple"
        }:
            return None
        identifier = question.get("id")
        prompt = question.get("prompt")
        if not isinstance(identifier, str) or not identifier or len(identifier) > _QUESTION_TEXT_LIMIT:
            return None
        if not isinstance(prompt, str) or not prompt or len(prompt) > _QUESTION_TEXT_LIMIT:
            return None
        options = question.get("options", [])
        if not isinstance(options, list) or len(options) > _MAX_QUESTION_OPTIONS:
            return None
        for option in options:
            if not isinstance(option, Mapping) or set(option) - {"id", "label"}:
                return None
            option_id = option.get("id")
            label = option.get("label")
            if not isinstance(option_id, str) or not option_id or len(option_id) > _QUESTION_TEXT_LIMIT:
                return None
            if not isinstance(label, str) or len(label) > _QUESTION_TEXT_LIMIT:
                return None
        allow_multiple = question.get("allowMultiple", False)
        if allow_multiple is None:
            allow_multiple = False
        if not isinstance(allow_multiple, bool):
            return None
        option_counts.append(len(options))
        multiple.append(allow_multiple)
    return QuestionRequest(
        tool_call_id if isinstance(tool_call_id, str) else None,
        len(questions), tuple(option_counts), tuple(multiple),
    )


ASK_QUESTION_RESULT: Mapping[str, Any] = {
    "outcome": {"outcome": "skipped", "reason": ACP_ASK_QUESTION_UNATTENDED_REASON}
}


def jsonrpc_error(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0", "id": message_id,
        "error": {"code": code, "message": bounded_token(message, limit=_DETAIL_LIMIT)},
    }


# ---------------------------------------------------------------------------
# Durable authority evidence
# ---------------------------------------------------------------------------

#: v2 extends v1 additively.  Every v1 field keeps its exact name, type and
#: meaning, and the append-only fsync-before-reply ordering is unchanged; v2
#: only adds the mission-scoped authority fields a v1 record had nowhere to put.
ACP_AUTHORITY_EVIDENCE_SCHEMA_VERSION = "admissible_acp_client_authority_evidence_v2"
ACP_AUTHORITY_EVIDENCE_SCHEMA_VERSION_V1 = "admissible_acp_client_authority_evidence_v1"

RECORD_PERMISSION_DECISION = "permission_decision"
RECORD_SERVER_REQUEST = "server_request"
RECORD_PROTOCOL_FAILURE = "protocol_failure"
RECORD_WORKSPACE_POLLUTION = "workspace_pollution"
RECORD_WORKSPACE_IDENTITY_DIFFERENCE = "workspace_identity_difference"

_EVIDENCE_REDACTION = "<redacted: prompt bytes>"
_MAX_RECORDED_PATHS = 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AcpAuthorityEvidence:
    """Append-only, fsync-durable decision log written before every reply.

    Records are canonical JSON, one per line.  A write that cannot be made
    durable raises :class:`AcpEvidenceWriteError`, and the caller must treat
    that as a refusal: an unrecorded approval is never sent.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        redact: Iterable[str] = (),
        clock: Callable[[], str] = _utc_now,
    ) -> None:
        self.path = Path(path)
        self._redactions = tuple(value for value in redact if value)
        self._clock = clock
        self._sequence = 0
        self._directory_synced = False
        self.records: list[dict[str, Any]] = []

    # -- redaction ---------------------------------------------------------
    def _scrub(self, value: str | None, *, limit: int = 512) -> str | None:
        if value is None:
            return None
        text = value
        for secret in self._redactions:
            if secret and secret in text:
                text = text.replace(secret, _EVIDENCE_REDACTION)
        text = " ".join(text.split())
        return text[:limit]

    # -- durable append ----------------------------------------------------
    def _append(self, body: Mapping[str, Any]) -> dict[str, Any]:
        self._sequence += 1
        record = {
            "schema_version": ACP_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
            "sequence": self._sequence,
            "recorded_at": self._clock(),
            **dict(body),
        }
        record["record_fingerprint"] = hashlib.sha256(canonical_bytes(record)).hexdigest()
        line = canonical_bytes(record) + b"\n"
        try:
            with open(self.path, "ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            if not self._directory_synced:
                self._fsync_directory()
                self._directory_synced = True
        except OSError as exc:
            self._sequence -= 1
            raise AcpEvidenceWriteError(f"ACP authority evidence append failed: {exc}") from exc
        self.records.append(record)
        return record

    def _fsync_directory(self) -> None:
        if os.name == "nt":
            # Windows has no directory handle to fsync; the file's own fsync is
            # the durability boundary the platform offers here.
            return
        descriptor = os.open(str(self.path.parent), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    # -- record kinds ------------------------------------------------------
    def record_permission_decision(
        self,
        *,
        request: PermissionRequest,
        decision: PermissionDecision,
        jsonrpc_request_id: Any,
        workspace: str,
        tool_call_digest: str | None = None,
        authority_fingerprint: str | None = None,
        budget_state_before: Mapping[str, int] | None = None,
        budget_state_after: Mapping[str, int] | None = None,
    ) -> dict[str, Any]:
        return self._append({
            "record_type": RECORD_PERMISSION_DECISION,
            "acp_session_id": self._scrub(request.acp_session_id, limit=128),
            "jsonrpc_request_id": bounded_token(jsonrpc_request_id, limit=128),
            "tool_call_id": self._scrub(request.tool_call_id, limit=256),
            "tool_call_digest": tool_call_digest,
            "tool_kind": self._scrub(request.tool_kind, limit=64),
            "title": self._scrub(request.title),
            "server_reason": self._scrub(request.server_reason, limit=256),
            "offered_options": [
                {"optionId": option.option_id, "kind": option.kind}
                for option in request.options
            ],
            "decision": decision.decision,
            "selected_option_id": decision.selected_option_id,
            "selected_option_kind": decision.selected_option_kind,
            "policy_rule_id": decision.rule_id,
            "policy_detail": self._scrub(decision.detail, limit=256),
            "containment_result": decision.containment,
            "normalized_paths": [
                self._scrub(item, limit=512) for item in decision.normalized_paths[:_MAX_RECORDED_PATHS]
            ],
            "authorized_workspace": workspace,
            "protocol_failure": decision.protocol_failure,
            # -- v2 mission-scoped authority fields ------------------------
            "authority_class": decision.authority_class,
            "structured_operation": decision.structured_operation,
            "mission_effect_authority_fingerprint": authority_fingerprint,
            "live_repository_observation_fingerprint": decision.live_observation_fingerprint,
            "live_refusal_reasons": list(decision.live_refusal_reasons[:_MAX_RECORDED_PATHS]),
            "authority_budget_before": (
                None if budget_state_before is None
                else {key: budget_state_before[key] for key in sorted(budget_state_before)}
            ),
            "authority_budget_after": (
                None if budget_state_after is None
                else {key: budget_state_after[key] for key in sorted(budget_state_after)}
            ),
            "duplicate_replay": bool(decision.replayed),
        })

    def record_workspace_identity_difference(
        self, *, workspace: str, differences: Sequence[str], stage: str,
    ) -> dict[str, Any]:
        return self._append({
            "record_type": RECORD_WORKSPACE_IDENTITY_DIFFERENCE,
            "stage": stage,
            "authorized_workspace": workspace,
            "difference_count": len(differences),
            "differences": [
                self._scrub(item, limit=512) for item in differences[:_MAX_RECORDED_PATHS]
            ],
        })

    def record_server_request(
        self, *, method: str, jsonrpc_request_id: Any, accepted: bool, summary: Mapping[str, Any],
    ) -> dict[str, Any]:
        return self._append({
            "record_type": RECORD_SERVER_REQUEST,
            "method": bounded_token(method, limit=128),
            "jsonrpc_request_id": bounded_token(jsonrpc_request_id, limit=128),
            "accepted": bool(accepted),
            "summary": {key: summary[key] for key in sorted(summary)},
        })

    def record_protocol_failure(self, *, detail: str, method: Any = None) -> dict[str, Any]:
        return self._append({
            "record_type": RECORD_PROTOCOL_FAILURE,
            "method": None if method is None else bounded_token(method, limit=128),
            "detail": bounded_token(detail, limit=256),
        })

    def record_workspace_pollution(
        self, *, workspace: str, added: Sequence[str], classifications: Mapping[str, str], stage: str,
    ) -> dict[str, Any]:
        return self._append({
            "record_type": RECORD_WORKSPACE_POLLUTION,
            "stage": stage,
            "authorized_workspace": workspace,
            "added_paths": [self._scrub(item, limit=512) for item in added[:_MAX_RECORDED_PATHS]],
            "added_path_count": len(added),
            "classifications": {key: classifications[key] for key in sorted(classifications)},
        })


# ---------------------------------------------------------------------------
# Explicit server-request dispatcher
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DispatchOutcome:
    """What the client does with one server-to-client request."""

    #: JSON-RPC message to write back, or ``None`` when nothing can be answered.
    response: dict[str, Any] | None
    #: Exact protocol failure detail; ``None`` means the turn continues.
    failure: str | None


class AcpServerRequestDispatcher:
    """Explicit, fail-closed table of answerable server-to-client requests.

    There is deliberately no ``cursor/*`` fallback: an unknown method is neither
    ignored (which stalls the turn until the hard timeout) nor guessed at.  It
    terminates the turn with its exact method persisted.
    """

    def __init__(
        self,
        *,
        evidence: AcpAuthorityEvidence,
        workspace: str,
        additional_authorized_paths: frozenset[str] = frozenset(),
        mission_effects: MissionEffectRuntime | None = None,
    ) -> None:
        self.evidence = evidence
        self.workspace = str(workspace)
        self.additional_authorized_paths = frozenset(additional_authorized_paths)
        self.mission_effects = mission_effects
        self.decisions: list[PermissionDecision] = []

    @property
    def supported_methods(self) -> tuple[str, ...]:
        return ACP_SUPPORTED_SERVER_REQUEST_METHODS

    def dispatch(self, *, method: Any, message_id: Any, params: Any) -> DispatchOutcome:
        if method == ACP_METHOD_REQUEST_PERMISSION:
            return self._permission(message_id, params)
        if method == ACP_METHOD_UPDATE_TODOS:
            return self._update_todos(message_id, params)
        if method == ACP_METHOD_CREATE_PLAN:
            return self._create_plan(message_id, params)
        if method == ACP_METHOD_ASK_QUESTION:
            return self._ask_question(message_id, params)
        detail = unanswerable_detail(method)
        self._record_failure(detail, method)
        return DispatchOutcome(None, detail)

    # -- session/request_permission ---------------------------------------
    def _permission(self, message_id: Any, params: Any) -> DispatchOutcome:
        request = parse_permission_request(params)
        if request is None:
            detail = malformed_detail(ACP_METHOD_REQUEST_PERMISSION)
            self._record_failure(detail, ACP_METHOD_REQUEST_PERMISSION)
            return DispatchOutcome(
                jsonrpc_error(message_id, JSONRPC_INVALID_PARAMS, "malformed permission request"),
                detail,
            )
        effects = self.mission_effects
        digest = request_digest(
            method=ACP_METHOD_REQUEST_PERMISSION, tool_kind=request.tool_kind,
            title=request.title, content=request.raw_content,
        )
        before = effects.ledger.snapshot() if effects is not None else None

        decision = self._decide(request, digest, effects)
        after = effects.ledger.snapshot() if effects is not None else None

        # Persist *before* the reply: an approval whose record cannot be made
        # durable is not sent at all.  The budget is committed only once that
        # record is durable, so a lost write can never spend authority.
        try:
            self.evidence.record_permission_decision(
                request=request, decision=decision,
                jsonrpc_request_id=message_id, workspace=self.workspace,
                tool_call_digest=digest,
                authority_fingerprint=(
                    None if effects is None else effects.authority.authority_fingerprint
                ),
                budget_state_before=before, budget_state_after=after,
            )
        except AcpEvidenceWriteError:
            return DispatchOutcome(None, FAILURE_PERMISSION_EVIDENCE_WRITE)
        if effects is not None and request.tool_call_id:
            effects.ledger.remember(request.tool_call_id, digest, decision.approved)
        self.decisions.append(decision)
        if decision.protocol_failure is not None:
            return DispatchOutcome(None, decision.protocol_failure)
        return DispatchOutcome(
            {"jsonrpc": "2.0", "id": message_id, "result": permission_response(decision)},
            None,
        )

    def _decide(
        self,
        request: PermissionRequest,
        digest: str,
        effects: MissionEffectRuntime | None,
    ) -> PermissionDecision:
        """Decide once, then consume authority once.

        A retransmitted identical request replays its recorded decision without
        spending budget a second time; the same tool-call id carrying a
        *different* request is a conflict and is refused outright rather than
        silently redecided.
        """

        if effects is not None and request.tool_call_id:
            replay = effects.ledger.replay(request.tool_call_id, digest)
            if replay is not None:
                approved, conflict = replay
                if conflict:
                    return _rejection_for(
                        request, RULE_DUPLICATE_TOOL_CALL_CONFLICT,
                        bounded_token(request.tool_call_id, limit=256),
                    )
                return _replayed_decision(request, approved)

        decision = decide_permission(
            request, workspace=self.workspace,
            additional_authorized_paths=self.additional_authorized_paths,
            mission_effects=effects,
        )
        if effects is not None and decision.approved and decision.authority_class is not None:
            effects.ledger.consume(decision.authority_class)
        return decision

    # -- cursor/create_plan ------------------------------------------------
    def _create_plan(self, message_id: Any, params: Any) -> DispatchOutcome:
        plan = parse_create_plan(params)
        if plan is None:
            detail = malformed_detail(ACP_METHOD_CREATE_PLAN)
            self._record_failure(detail, ACP_METHOD_CREATE_PLAN)
            return DispatchOutcome(
                jsonrpc_error(message_id, JSONRPC_INVALID_PARAMS, "malformed plan request"),
                detail,
            )
        try:
            self.evidence.record_server_request(
                method=ACP_METHOD_CREATE_PLAN, jsonrpc_request_id=message_id, accepted=True,
                summary={
                    "tool_call_id": bounded_token(plan.tool_call_id, limit=256),
                    "todo_count": plan.todo_count,
                    "phase_count": plan.phase_count,
                    "statuses": list(plan.statuses),
                    "is_project": plan.is_project,
                    "filesystem_effect": False,
                    "process_effect": False,
                },
            )
        except AcpEvidenceWriteError:
            return DispatchOutcome(None, FAILURE_PERMISSION_EVIDENCE_WRITE)
        return DispatchOutcome(
            {"jsonrpc": "2.0", "id": message_id, "result": _deep_copy(CREATE_PLAN_RESULT)}, None,
        )

    # -- cursor/ask_question -----------------------------------------------
    def _ask_question(self, message_id: Any, params: Any) -> DispatchOutcome:
        question = parse_ask_question(params)
        if question is None:
            detail = malformed_detail(ACP_METHOD_ASK_QUESTION)
            self._record_failure(detail, ACP_METHOD_ASK_QUESTION)
            return DispatchOutcome(
                jsonrpc_error(message_id, JSONRPC_INVALID_PARAMS, "malformed question request"),
                detail,
            )
        try:
            self.evidence.record_server_request(
                method=ACP_METHOD_ASK_QUESTION, jsonrpc_request_id=message_id, accepted=True,
                summary={
                    "tool_call_id": bounded_token(question.tool_call_id, limit=256),
                    "question_count": question.question_count,
                    "option_counts": list(question.option_counts),
                    "allows_multiple": list(question.allows_multiple),
                    "outcome": "skipped",
                    "answer_fabricated": False,
                    "authority_changed": False,
                },
            )
        except AcpEvidenceWriteError:
            return DispatchOutcome(None, FAILURE_PERMISSION_EVIDENCE_WRITE)
        return DispatchOutcome(
            {"jsonrpc": "2.0", "id": message_id, "result": _deep_copy(ASK_QUESTION_RESULT)}, None,
        )

    # -- cursor/update_todos ----------------------------------------------
    def _update_todos(self, message_id: Any, params: Any) -> DispatchOutcome:
        update = parse_update_todos(params)
        if update is None:
            detail = malformed_detail(ACP_METHOD_UPDATE_TODOS)
            self._record_failure(detail, ACP_METHOD_UPDATE_TODOS)
            return DispatchOutcome(
                jsonrpc_error(message_id, JSONRPC_INVALID_PARAMS, "malformed todo update"),
                detail,
            )
        try:
            self.evidence.record_server_request(
                method=ACP_METHOD_UPDATE_TODOS, jsonrpc_request_id=message_id, accepted=True,
                summary={
                    "tool_call_id": bounded_token(update.tool_call_id, limit=256),
                    "todo_count": update.todo_count,
                    "statuses": list(update.statuses),
                    "merge": update.merge,
                },
            )
        except AcpEvidenceWriteError:
            return DispatchOutcome(None, FAILURE_PERMISSION_EVIDENCE_WRITE)
        return DispatchOutcome(
            {"jsonrpc": "2.0", "id": message_id, "result": dict(UPDATE_TODOS_RESULT)}, None,
        )

    def _record_failure(self, detail: str, method: Any) -> None:
        try:
            self.evidence.record_protocol_failure(detail=detail, method=method)
        except AcpEvidenceWriteError:
            # The turn is already terminating fail-closed; a lost failure
            # record cannot widen authority.
            pass


# ---------------------------------------------------------------------------
# Deterministic Windows shell-folder environment
# ---------------------------------------------------------------------------

WINDOWS_SHELL_FOLDER_NAMES: tuple[str, ...] = ("ALLUSERSPROFILE", "ProgramData", "SystemDrive")

WINDOWS_SHELL_FOLDER_DERIVATION_POLICY = (
    "systemdrive=splitdrive(attested-SYSTEMROOT);"
    "programdata=known-folder-FOLDERID_ProgramData-else-<systemdrive>\\ProgramData;"
    "allusersprofile=canonically-equal-to-programdata;"
    "all-absolute-existing-directories-outside-the-authorized-work-workspace;"
    "never-inherited-from-the-parent-environment"
)

_DRIVE = re.compile(r"\A[A-Za-z]:\Z")
_FOLDERID_PROGRAM_DATA = "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}"


def _known_folder_program_data() -> str | None:
    """``SHGetKnownFolderPath(FOLDERID_ProgramData)``; ``None`` when unavailable."""

    if os.name != "nt":  # pragma: no cover - platform branch
        return None
    try:  # pragma: no cover - exercised only on a real Windows host
        import ctypes
        from ctypes import wintypes

        class _GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        guid = _GUID()
        if ctypes.windll.ole32.CLSIDFromString(  # type: ignore[attr-defined]
            ctypes.c_wchar_p(_FOLDERID_PROGRAM_DATA), ctypes.byref(guid)
        ) != 0:
            return None
        buffer = ctypes.c_wchar_p()
        if ctypes.windll.shell32.SHGetKnownFolderPath(  # type: ignore[attr-defined]
            ctypes.byref(guid), 0, None, ctypes.byref(buffer)
        ) != 0:
            return None
        try:
            value = buffer.value
        finally:
            ctypes.windll.ole32.CoTaskMemFree(buffer)  # type: ignore[attr-defined]
        return value or None
    except Exception:
        return None


def _existing_directory(value: str, label: str) -> str:
    if not value or not os.path.isabs(value):
        raise AcpAuthorityRefusal(f"{label} is not an absolute path")
    normalized = os.path.normpath(value)
    try:
        metadata = os.stat(normalized)
    except OSError as exc:
        raise AcpAuthorityRefusal(f"{label} does not exist: {normalized}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise AcpAuthorityRefusal(f"{label} is not a directory: {normalized}")
    return normalized


def derive_windows_shell_folders(
    *,
    systemroot: str,
    work_workspace: str | Path | None = None,
    known_folder: Callable[[], str | None] = _known_folder_program_data,
) -> dict[str, str]:
    """Derive ``SystemDrive``/``ProgramData``/``ALLUSERSPROFILE`` deterministically.

    Nothing is inherited: the drive comes from the attested ``SYSTEMROOT``, and
    ``ProgramData`` comes from the Windows known-folder API when it answers, or
    from ``<SystemDrive>\\ProgramData`` otherwise.  Every value is validated as
    an existing directory outside the authorized work workspace, and
    ``ALLUSERSPROFILE`` must resolve to the same canonical directory as
    ``ProgramData``.
    """

    root = _existing_directory(systemroot, "SYSTEMROOT")
    drive, _ = ntpath.splitdrive(root)
    if not _DRIVE.match(drive):
        raise AcpAuthorityRefusal(f"SYSTEMROOT carries no drive letter: {root}")
    system_drive = drive.upper()

    candidate = known_folder()
    if not candidate:
        candidate = ntpath.join(system_drive + ntpath.sep, "ProgramData")
    program_data = _existing_directory(candidate, "ProgramData")
    all_users_profile = program_data
    if _normcase(program_data) != _normcase(all_users_profile):  # pragma: no cover - defensive
        raise AcpAuthorityRefusal("ALLUSERSPROFILE must resolve to the ProgramData directory")
    if not _contained(program_data, system_drive + ntpath.sep):
        raise AcpAuthorityRefusal("ProgramData is not on the attested system drive")

    values = {
        "SystemDrive": system_drive,
        "ProgramData": program_data,
        "ALLUSERSPROFILE": all_users_profile,
    }
    if work_workspace is not None:
        workspace = os.path.normpath(str(work_workspace))
        for name, value in values.items():
            probe = value if name != "SystemDrive" else value + ntpath.sep
            if _contained(probe, workspace):
                raise AcpAuthorityRefusal(
                    f"{name} resolves inside the authorized work workspace"
                )
    return values


def derived_windows_environment(
    environment: Mapping[str, str],
    *,
    work_workspace: str | Path | None = None,
    known_folder: Callable[[], str | None] = _known_folder_program_data,
) -> dict[str, str]:
    """Derive the shell-folder authority for a filtered child environment.

    A child environment carrying an attested ``SYSTEMROOT`` (that is, a Windows
    child) must carry all three derived values; one that does not is not a
    Windows shell-folder consumer and gets none.
    """

    systemroot = None
    for key, value in environment.items():
        if key.upper() == "SYSTEMROOT":
            systemroot = value
            break
    if systemroot is None:
        if os.name == "nt":
            raise AcpAuthorityRefusal(
                "a Windows child environment must carry the attested SYSTEMROOT"
            )
        return {}
    return derive_windows_shell_folders(
        systemroot=systemroot, work_workspace=work_workspace, known_folder=known_folder,
    )


def validate_derived_windows_environment(values: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Structural validation of a persisted derived-environment mapping."""

    if not isinstance(values, Mapping):
        raise AcpAuthorityRefusal("derived environment must be a mapping")
    if not values:
        return ()
    if set(values) != set(WINDOWS_SHELL_FOLDER_NAMES):
        raise AcpAuthorityRefusal("derived environment names differ from the audited set")
    for name in WINDOWS_SHELL_FOLDER_NAMES:
        value = values[name]
        if not isinstance(value, str) or not value or "\x00" in value:
            raise AcpAuthorityRefusal(f"derived environment value for {name} is invalid")
    if not _DRIVE.match(values["SystemDrive"]):
        raise AcpAuthorityRefusal("derived SystemDrive is not a bare drive letter")
    if _normcase(values["ProgramData"]) != _normcase(values["ALLUSERSPROFILE"]):
        raise AcpAuthorityRefusal("ALLUSERSPROFILE differs from ProgramData")
    if not ntpath.isabs(values["ProgramData"]):
        raise AcpAuthorityRefusal("derived ProgramData is not absolute")
    if _normcase(ntpath.splitdrive(values["ProgramData"])[0]) != _normcase(values["SystemDrive"]):
        raise AcpAuthorityRefusal("derived ProgramData is not on the derived system drive")
    return tuple(sorted((name, values[name]) for name in WINDOWS_SHELL_FOLDER_NAMES))


# ---------------------------------------------------------------------------
# Workspace pollution boundary
# ---------------------------------------------------------------------------

POLLUTION_UNRESOLVED_VARIABLE = "unresolved_environment_variable_literal"
POLLUTION_UNEXPECTED_PATH = "unexpected_path"
POLLUTION_STAGE_POST_STARTUP = "after_acp_session_creation_before_session_prompt"

_INVENTORY_LIMIT = 4096


def workspace_inventory(root: str | Path, *, limit: int = _INVENTORY_LIMIT) -> tuple[str, ...]:
    """Bounded relative inventory of a workspace, excluding Git's own metadata.

    Git metadata is excluded for the same reason the material snapshot excludes
    it: ``.git`` churn is not provider pollution, and the pollution boundary is
    about paths the ACP server created in the working tree.
    """

    base = Path(root)
    entries: list[str] = []
    for directory, dirnames, filenames in os.walk(base, topdown=True, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name != ".git")
        current = Path(directory)
        for name in dirnames:
            entries.append((current / name).relative_to(base).as_posix() + "/")
        for name in sorted(filenames):
            if name == ".git":
                continue
            entries.append((current / name).relative_to(base).as_posix())
        if len(entries) > limit:
            break
    return tuple(sorted(entries[:limit]))


def classify_workspace_additions(added: Iterable[str]) -> dict[str, str]:
    """Name why each added path is pollution, without deleting anything."""

    classifications: dict[str, str] = {}
    for path in added:
        head = posixpath.normpath(path).split("/", 1)[0]
        if "%" in head or "$" in head:
            classifications[path] = POLLUTION_UNRESOLVED_VARIABLE
        else:
            classifications[path] = POLLUTION_UNEXPECTED_PATH
    return classifications


@dataclass(frozen=True)
class WorkspacePollution:
    added: tuple[str, ...]
    classifications: Mapping[str, str]

    @property
    def polluted(self) -> bool:
        return bool(self.added)


def observe_workspace_pollution(
    before: Sequence[str], after: Sequence[str]
) -> WorkspacePollution:
    added = tuple(sorted(set(after) - set(before)))
    return WorkspacePollution(added, classify_workspace_additions(added))


# ---------------------------------------------------------------------------
# Complete pre-prompt workspace identity
# ---------------------------------------------------------------------------
#
# The path-name inventory above answers "did a path appear?".  It cannot answer
# "did an existing tracked file's *content* change?", and a server that rewrote
# one delivered file in place before the prompt would pass it unchanged.  The
# identity below closes that: it is content-, mode-, index- and HEAD-sensitive,
# and every difference it finds withholds the prompt.
#
# Nothing here cleans anything up.  A workspace whose identity moved is
# preserved exactly as observed and the mission is simply not submitted.

WORKSPACE_IDENTITY_SCHEMA_VERSION = "admissible_acp_pre_prompt_workspace_identity_v1"

IDENTITY_STAGE_PRE_PROMPT = "after_acp_session_creation_before_session_prompt"

IGNORED_PATH_POLICY = "ignored_paths_are_observed_and_recorded_never_cleaned"

_IDENTITY_FILE_LIMIT = 4096
_IDENTITY_BYTE_LIMIT = 8 * 1024 * 1024


@dataclass(frozen=True)
class WorkspaceIdentity:
    """One bounded, complete identity of the authorized workspace."""

    schema_version: str
    git_head: str | None
    index_fingerprint: str | None
    status_fingerprint: str | None
    tracked_entries: tuple[tuple[str, str, str], ...]
    untracked_entries: tuple[tuple[str, str], ...]
    ignored_paths: tuple[str, ...]
    ignored_path_policy: str
    reparse_paths: tuple[str, ...]
    material_tree_fingerprint: str

    @property
    def identity_fingerprint(self) -> str:
        return hashlib.sha256(canonical_bytes(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "git_head": self.git_head,
            "index_fingerprint": self.index_fingerprint,
            "status_fingerprint": self.status_fingerprint,
            "tracked_entries": [list(entry) for entry in self.tracked_entries],
            "untracked_entries": [list(entry) for entry in self.untracked_entries],
            "ignored_paths": list(self.ignored_paths),
            "ignored_path_policy": self.ignored_path_policy,
            "reparse_paths": list(self.reparse_paths),
            "material_tree_fingerprint": self.material_tree_fingerprint,
        }


def _identity_git(workspace: str, *arguments: str) -> str | None:
    """One hardened read-only Git observation; ``None`` when Git cannot answer.

    A workspace that is not a repository is a legitimate shape for this
    boundary (several native fixtures are plain directories), so Git's absence
    degrades to the content-based half of the identity rather than failing the
    whole comparison open.
    """

    environment = dict(os.environ)
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "",
    })
    try:
        result = subprocess.run(
            ["git", *arguments], cwd=workspace, env=environment, shell=False, check=False,
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or len(result.stdout) > _IDENTITY_BYTE_LIMIT:
        return None
    return result.stdout.decode("utf-8", errors="replace")


def capture_workspace_identity(workspace: str | Path) -> WorkspaceIdentity:
    """Capture the complete bounded identity of one workspace."""

    root = str(workspace)
    head = _identity_git(root, "rev-parse", "--verify", "HEAD")
    head_value = head.strip().lower() if head and head.strip() else None
    index = _identity_git(root, "ls-files", "-s", "-z")
    status = _identity_git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    ignored_text = _identity_git(root, "status", "--porcelain=v1", "-z", "--ignored=matching")

    tracked_modes: dict[str, str] = {}
    if index is not None:
        for entry in index.split("\0"):
            if not entry or "\t" not in entry:
                continue
            mode = entry.split(" ", 1)[0]
            tracked_modes[entry.split("\t", 1)[1]] = mode

    ignored: list[str] = []
    if ignored_text is not None:
        for record in ignored_text.split("\0"):
            if len(record) > 3 and record[:2] == "!!":
                ignored.append(record[3:])

    tracked: list[tuple[str, str, str]] = []
    untracked: list[tuple[str, str]] = []
    reparse: list[str] = []
    digest = hashlib.sha256()
    base = Path(root)
    count = 0
    for directory, dirnames, filenames in os.walk(base, topdown=True, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name != ".git")
        current = Path(directory)
        for name in list(dirnames):
            try:
                metadata = os.lstat(current / name)
            except OSError:  # pragma: no cover - transient
                continue
            if _is_reparse_metadata(metadata):
                reparse.append((current / name).relative_to(base).as_posix() + "/")
        for name in sorted(filenames):
            path = current / name
            relative = path.relative_to(base).as_posix()
            count += 1
            if count > _IDENTITY_FILE_LIMIT:
                break
            try:
                metadata = os.lstat(path)
            except OSError:  # pragma: no cover - transient
                continue
            if _is_reparse_metadata(metadata):
                reparse.append(relative)
                content = "reparse-point"
            else:
                content = _file_digest(path)
            digest.update(f"{relative}\0{content}\0{metadata.st_size}\n".encode("utf-8"))
            if relative in tracked_modes:
                tracked.append((relative, tracked_modes[relative], content))
            else:
                untracked.append((relative, content))
        if count > _IDENTITY_FILE_LIMIT:
            break

    return WorkspaceIdentity(
        schema_version=WORKSPACE_IDENTITY_SCHEMA_VERSION,
        git_head=head_value,
        index_fingerprint=(
            None if index is None else hashlib.sha256(index.encode("utf-8")).hexdigest()
        ),
        status_fingerprint=(
            None if status is None else hashlib.sha256(status.encode("utf-8")).hexdigest()
        ),
        tracked_entries=tuple(sorted(tracked)),
        untracked_entries=tuple(sorted(untracked)),
        ignored_paths=tuple(sorted(set(ignored))),
        ignored_path_policy=IGNORED_PATH_POLICY,
        reparse_paths=tuple(sorted(set(reparse))),
        material_tree_fingerprint=digest.hexdigest(),
    )


def _is_reparse_metadata(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        return True
    return bool(getattr(metadata, "st_reparse_tag", 0))


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return "unreadable"
    return digest.hexdigest()


def compare_workspace_identity(
    before: WorkspaceIdentity, after: WorkspaceIdentity
) -> tuple[str, ...]:
    """Every exact difference between two identities, in canonical order.

    A content change under an unchanged path name -- the case the path-name
    inventory is blind to -- surfaces here as ``tracked_content:<path>``.
    """

    differences: list[str] = []
    if before.git_head != after.git_head:
        differences.append("git_head")
    if before.index_fingerprint != after.index_fingerprint:
        differences.append("git_index")
    if before.status_fingerprint != after.status_fingerprint:
        differences.append("git_status")
    if before.ignored_paths != after.ignored_paths:
        differences.append("ignored_paths")
    if before.reparse_paths != after.reparse_paths:
        differences.append("reparse_paths")

    def index_by_path(entries: Iterable[Sequence[str]]) -> dict[str, tuple[str, ...]]:
        return {entry[0]: tuple(entry[1:]) for entry in entries}

    for label, previous, current in (
        ("tracked", index_by_path(before.tracked_entries), index_by_path(after.tracked_entries)),
        ("untracked", index_by_path(before.untracked_entries), index_by_path(after.untracked_entries)),
    ):
        for path in sorted(set(previous) - set(current)):
            differences.append(f"{label}_removed:{path}")
        for path in sorted(set(current) - set(previous)):
            differences.append(f"{label}_added:{path}")
        for path in sorted(set(previous) & set(current)):
            if previous[path] == current[path]:
                continue
            changed = "mode" if len(previous[path]) > 1 and previous[path][0] != current[path][0] else "content"
            differences.append(f"{label}_{changed}:{path}")

    if before.material_tree_fingerprint != after.material_tree_fingerprint and not differences:
        # Defensive: the tree fingerprint moved for a reason the per-path walk
        # did not express, which must still withhold the prompt.
        differences.append("material_tree_fingerprint")
    return tuple(differences[:_MAX_RECORDED_PATHS])


__all__ = [
    "ACP_ASK_QUESTION_UNATTENDED_REASON",
    "ACP_AUTHORITY_EVIDENCE_SCHEMA_VERSION",
    "ACP_AUTHORITY_EVIDENCE_SCHEMA_VERSION_V1",
    "ACP_METHOD_ASK_QUESTION",
    "ACP_METHOD_CREATE_PLAN",
    "ACP_METHOD_REQUEST_PERMISSION",
    "ACP_METHOD_UPDATE_TODOS",
    "ACP_SUPPORTED_SERVER_REQUEST_METHODS",
    "ASK_QUESTION_RESULT",
    "CREATE_PLAN_RESULT",
    "FAILURE_WORKSPACE_IDENTITY_CHANGED",
    "IDENTITY_STAGE_PRE_PROMPT",
    "IGNORED_PATH_POLICY",
    "MISSION_SCOPED_TOOL_KIND",
    "PlanRequest",
    "QuestionRequest",
    "RECORD_WORKSPACE_IDENTITY_DIFFERENCE",
    "RULE_DUPLICATE_REPLAY",
    "WORKSPACE_IDENTITY_SCHEMA_VERSION",
    "WorkspaceIdentity",
    "capture_workspace_identity",
    "compare_workspace_identity",
    "parse_ask_question",
    "parse_create_plan",
    "AcpAuthorityEvidence",
    "AcpAuthorityRefusal",
    "AcpEvidenceWriteError",
    "AcpServerRequestDispatcher",
    "CONTAINMENT_INSIDE_WORKSPACE",
    "CONTAINMENT_NOT_EVALUATED",
    "CONTAINMENT_VIOLATION",
    "CommandRuling",
    "DECISION_ALLOW_ONCE",
    "DECISION_REJECT",
    "DispatchOutcome",
    "FAILURE_MALFORMED_SERVER_REQUEST",
    "FAILURE_PERMISSION_EVIDENCE_WRITE",
    "FAILURE_PERMISSION_REJECTION_UNAVAILABLE",
    "FAILURE_RESPONSE_WRITE",
    "FAILURE_UNANSWERABLE_SERVER_REQUEST",
    "FAILURE_WORKSPACE_POLLUTED",
    "FORBIDDEN_PERMISSION_OPTION_KINDS",
    "PERMISSION_KIND_ALLOW_ALWAYS",
    "PERMISSION_KIND_ALLOW_ONCE",
    "PERMISSION_KIND_REJECT_ONCE",
    "PERMITTED_TOOL_KIND",
    "POLLUTION_STAGE_POST_STARTUP",
    "POLLUTION_UNEXPECTED_PATH",
    "POLLUTION_UNRESOLVED_VARIABLE",
    "PermissionDecision",
    "PermissionOption",
    "PermissionRequest",
    "RECORD_PERMISSION_DECISION",
    "RECORD_PROTOCOL_FAILURE",
    "RECORD_SERVER_REQUEST",
    "RECORD_WORKSPACE_POLLUTION",
    "RULE_ALLOW_ONCE_UNAVAILABLE",
    "RULE_BOUNDED_READ_ONLY_INSPECTION",
    "RULE_DESTRUCTIVE_COMMAND",
    "RULE_DYNAMIC_EVALUATION",
    "RULE_MALFORMED_REQUEST",
    "RULE_NESTED_SHELL",
    "RULE_NETWORK_OR_DEPLOYMENT",
    "RULE_OUTPUT_REDIRECTION",
    "RULE_PARENT_TRAVERSAL",
    "RULE_PATH_OUTSIDE_WORKSPACE",
    "RULE_PROCESS_MUTATION",
    "RULE_REGISTRY_MUTATION",
    "RULE_SERVICE_OR_TASK_MUTATION",
    "RULE_TOOL_KIND_NOT_PERMITTED",
    "RULE_UNKNOWN_SWITCH",
    "RULE_UNKNOWN_VERB",
    "RULE_UNRESOLVED_ENVIRONMENT_TOKEN",
    "RULE_UNSUPPORTED_CHARACTER",
    "TODO_STATUSES",
    "TodoUpdate",
    "UPDATE_TODOS_RESULT",
    "WINDOWS_SHELL_FOLDER_DERIVATION_POLICY",
    "WINDOWS_SHELL_FOLDER_NAMES",
    "WorkspacePollution",
    "bounded_token",
    "classify_command",
    "classify_workspace_additions",
    "decide_permission",
    "derive_windows_shell_folders",
    "derived_windows_environment",
    "malformed_detail",
    "observe_workspace_pollution",
    "parse_permission_request",
    "parse_update_todos",
    "permission_response",
    "unanswerable_detail",
    "validate_derived_windows_environment",
    "workspace_inventory",
]
