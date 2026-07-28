"""Decision procedure for one :class:`MissionEffectAuthority`.

This module answers exactly one question, four times:

* may this ``kind=edit`` tool call write this exact path?
* may this ``kind=execute`` tool call run this exact local verification command?
* may this ``kind=execute`` tool call stage, given what is *actually* in the
  live repository right now?
* may this ``kind=execute`` tool call create the one authorized commit, given
  what is *actually* staged right now?

Three properties are structural rather than incidental.

**Structured over prose.**  The installed Cursor CLI formats a write decision
as ``kind="edit"`` with ``content = [{"type": "diff", "path": ..., "oldText":
..., "newText": ...}]``.  The path therefore exists as a structured field and is
the only thing consulted; the human-readable ``title`` is recorded as evidence
and never trusted for a path.  A request whose structured location is absent or
unprovable is refused, which is also exactly what happens to the CLI's delete
decision (``kind="edit"``, ``content: undefined``).

**Observation over trust.**  ``git add -A`` is not approved because it says
``-A``; it is approved because an independent, hardened observation of the live
repository proves that the complete set of paths that would be staged lies
inside the authorized material set.  The same holds for the commit: what is
already staged is observed, not assumed.

**Nothing is a category.**  There is no "edit" permission, no "npm" permission
and no "Git mutation" permission.  Every accept path terminates in an exact
member of an owner-authorized enumeration.

Nothing here executes the effect it rules on.  The only subprocess this module
starts is a read-only ``git`` observation of the authorized workspace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ntpath
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Iterable, Mapping, Sequence

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_effect_authority import (
    EDIT_OPERATION_CREATE,
    EDIT_OPERATION_CREATE_DIRECTORY,
    EDIT_OPERATION_UPDATE,
    EFFECT_CLASS_GIT_COMMIT,
    EFFECT_CLASS_GIT_STAGE,
    EFFECT_CLASS_LOCAL_VERIFICATION,
    EFFECT_CLASS_MATERIAL_EDIT,
    GIT_COMMIT_FORM_LONG,
    GIT_COMMIT_FORM_LONG_EQUALS,
    GIT_COMMIT_FORM_SHORT,
    GIT_STAGE_FORM_ALL_LONG,
    GIT_STAGE_FORM_ALL_SHORT,
    GIT_STAGE_FORM_DOT,
    GIT_STAGE_FORM_EXPLICIT_PATHS,
    MissionEffectAuthority,
    UNSUPPORTED_EDIT_OPERATION_DELETE,
)


# ---------------------------------------------------------------------------
# Installed-CLI request shapes (empirically pinned)
# ---------------------------------------------------------------------------
#
# Taken from the installed cursor-agent bundle's own ACP approval bridge.  Its
# decision enum is exactly {write, shell, delete, mcp}; there is no directory
# operation, and an overwrite is a `write` carrying the previous content as
# `oldText` rather than a delete followed by a write.

#: ``session/request_permission`` tool kind for a write or a delete decision.
CURSOR_TOOL_KIND_EDIT = "edit"
#: ``session/request_permission`` tool kind for a shell decision.
CURSOR_TOOL_KIND_EXECUTE = "execute"
#: The structured content block a write decision carries.
CURSOR_CONTENT_TYPE_DIFF = "diff"
#: The exact title prefix the CLI emits for its delete decision, which carries
#: no structured content at all.
CURSOR_DELETE_TITLE_PREFIX = "Delete "

SUPPORTED_EDIT_REQUEST_SHAPES: tuple[str, ...] = (
    'create: kind="edit" content=[{"type":"diff","path":<abs>,"oldText":null,"newText":<str>}]',
    'update: kind="edit" content=[{"type":"diff","path":<abs>,"oldText":<str>,"newText":<str>}]',
    'delete: kind="edit" content absent (title "Delete `<path>`") -- always refused',
    "create_directory: the installed CLI exposes no directory operation; "
    "authorized directories are reachable only as implicit parents of an authorized create",
)


# ---------------------------------------------------------------------------
# Policy rule identifiers
# ---------------------------------------------------------------------------

RULE_MISSION_AUTHORITY_ABSENT = "mission_effect_authority_absent"

RULE_EDIT_REQUEST_MALFORMED = "edit_request_shape_is_not_strictly_valid"
RULE_EDIT_LOCATION_UNPROVEN = "edit_structured_location_absent_or_unprovable"
RULE_EDIT_OPERATION_UNSUPPORTED = "edit_operation_is_not_an_authorized_operation"
RULE_EDIT_TOO_MANY_TARGETS = "edit_request_names_more_than_one_target"
RULE_EDIT_PATH_UNSAFE_FORM = "edit_target_uses_a_refused_path_form"
RULE_EDIT_PATH_OUTSIDE_WORKSPACE = "edit_target_resolves_outside_the_authorized_workspace"
RULE_EDIT_PARENT_TRAVERSAL = "edit_target_retains_parent_traversal_after_normalization"
RULE_EDIT_REPARSE_POINT = "edit_target_or_an_ancestor_is_a_symlink_or_reparse_point"
RULE_EDIT_PATH_NOT_AUTHORIZED = "edit_target_is_not_an_exact_authorized_material_path"
RULE_EDIT_PARENT_NOT_AUTHORIZED = "edit_target_parent_is_not_an_authorized_creatable_directory"
RULE_EDIT_AUTHORIZED = "mission_authorized_material_edit"

RULE_LOCAL_VERIFICATION_NOT_EXACT = "local_verification_command_is_not_an_exact_authorized_spelling"
RULE_LOCAL_VERIFICATION_MANIFEST_MISSING = "local_verification_requires_the_authorized_package_manifest"
RULE_LOCAL_VERIFICATION_AUTHORIZED = "mission_authorized_local_verification"

RULE_GIT_STAGE_FORM_NOT_AUTHORIZED = "git_staging_form_is_not_an_authorized_form"
RULE_GIT_STAGE_PATH_NOT_AUTHORIZED = "git_staging_names_a_path_outside_the_authorized_material_set"
RULE_GIT_STAGE_LIVE_STATE_REFUSED = "live_repository_state_refuses_staging"
RULE_GIT_STAGE_AUTHORIZED = "mission_authorized_git_stage"

RULE_GIT_COMMIT_FORM_NOT_AUTHORIZED = "git_commit_form_is_not_an_authorized_form"
RULE_GIT_COMMIT_MESSAGE_NOT_EXACT = "git_commit_message_is_not_the_exact_authorized_message"
RULE_GIT_COMMIT_LIVE_STATE_REFUSED = "live_repository_state_refuses_the_commit"
RULE_GIT_COMMIT_AUTHORIZED = "mission_authorized_git_commit"

RULE_COMMAND_TEXT_MISSING = "mission_command_text_missing"
RULE_COMMAND_TEXT_TOO_LONG = "mission_command_text_too_long"
RULE_COMMAND_UNSUPPORTED_CHARACTER = "mission_command_character_outside_the_accepted_grammar"
RULE_COMMAND_UNTERMINATED_QUOTE = "mission_command_quoting_is_not_closed"
RULE_COMMAND_EXTRA_ARGUMENTS = "mission_command_carries_arguments_it_may_not_carry"

RULE_BUDGET_EXHAUSTED = "mission_effect_authority_budget_exhausted"
RULE_DUPLICATE_TOOL_CALL_CONFLICT = "tool_call_identifier_reused_for_a_different_request"

RULE_REPOSITORY_UNOBSERVABLE = "live_repository_could_not_be_observed"

#: Exact live-observation refusal reasons, persisted verbatim.
LIVE_HEAD_MOVED = "head_is_no_longer_the_initialized_fixture_head"
LIVE_REMOTE_PRESENT = "a_git_remote_exists"
LIVE_SUBMODULE_PRESENT = "a_git_submodule_exists"
LIVE_UNAUTHORIZED_PATH = "an_affected_path_is_outside_the_authorized_material_set"
LIVE_AUTHORIZED_PATH_IGNORED = "an_authorized_material_path_is_git_ignored"
LIVE_DELETION_PRESENT = "a_deletion_is_present_and_no_deletion_is_authorized"
LIVE_RENAME_PRESENT = "a_rename_is_present_and_no_rename_is_authorized"
LIVE_SYMLINK_PRESENT = "a_symlink_or_reparse_point_is_tracked_or_present"
LIVE_NOTHING_TO_STAGE = "no_authorized_material_change_is_present_to_stage"
LIVE_INDEX_EMPTY = "the_index_carries_no_staged_change"
LIVE_STAGED_OUTSIDE_AUTHORITY = "a_staged_path_is_outside_the_authorized_material_set"
LIVE_UNSTAGED_UNAUTHORIZED = "an_unstaged_or_untracked_path_is_outside_the_authorized_material_set"
LIVE_EXTERNAL_BOUNDARY_MOVED = "the_source_repository_or_the_canary_parent_changed"


# ---------------------------------------------------------------------------
# Bounded command grammar
# ---------------------------------------------------------------------------

#: The complete accepted alphabet for a mission-scoped command.  Every shell
#: metacharacter -- pipeline, redirection, separator, substitution, glob,
#: variable sigil, newline -- is outside it, so "no redirection, pipeline,
#: compound statement or nested shell" is a property of the alphabet rather than
#: a list of patterns to keep up to date.
_MISSION_ACCEPTED_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " _-./\\:'\"=,"
)

_MISSION_COMMAND_TEXT_LIMIT = 2048
_MAX_MISSION_TOKENS = 64

_NPM_VERBS = frozenset({"npm", "npm.cmd"})
_GIT_VERBS = frozenset({"git", "git.exe"})
_GIT_MUTATION_SUBCOMMANDS = frozenset({"add", "commit"})

_DETAIL_LIMIT = 256
_MAX_RECORDED = 64


@dataclass(frozen=True)
class _MissionToken:
    #: The assembled token with quote characters removed, exactly as a shell
    #: would pass it: ``--message="a b"`` is the single token ``--message=a b``.
    text: str
    #: True when any part of the token was quoted.
    quoted: bool
    #: The literal characters that appeared *outside* any quote, in order.  A
    #: switch must be literal to count as a switch, so ``"-A"`` can never be
    #: mistaken for ``-A`` while ``--message="x"`` still parses as one switch
    #: carrying one quoted value.
    literal_prefix: str = ""

    @property
    def fully_literal(self) -> bool:
        return not self.quoted and self.literal_prefix == self.text


def _bounded(value: Any, *, limit: int = _DETAIL_LIMIT) -> str:
    return " ".join(str(value).split())[:limit]


def strip_code_span(text: str) -> str:
    """Remove the single markdown code span Cursor wraps a shell title in."""

    candidate = text.strip()
    if len(candidate) >= 2 and candidate.startswith("`") and candidate.endswith("`"):
        candidate = candidate[1:-1].strip()
    # The CLI escapes an embedded backtick when it builds the title; undo
    # exactly that one transformation and nothing else.
    return candidate.replace("\\`", "`")


def tokenize_mission_command(text: str) -> tuple[tuple[_MissionToken, ...] | None, str]:
    """Split one mission command into words and quoted strings.

    Returns ``(tokens, "")`` or ``(None, rule_id)``.  This is not a shell parser
    and cannot become one: the accepted alphabet excludes every operator.
    """

    if not text:
        return None, RULE_COMMAND_TEXT_MISSING
    if len(text) > _MISSION_COMMAND_TEXT_LIMIT:
        return None, RULE_COMMAND_TEXT_TOO_LONG
    unsupported = sorted({character for character in text if character not in _MISSION_ACCEPTED_CHARACTERS})
    if unsupported:
        return None, RULE_COMMAND_UNSUPPORTED_CHARACTER

    tokens: list[_MissionToken] = []
    buffer: list[str] = []
    literal: list[str] = []
    quoted = False
    open_token = False

    def flush() -> None:
        nonlocal quoted, open_token
        if open_token:
            tokens.append(_MissionToken("".join(buffer), quoted, "".join(literal)))
        buffer.clear()
        literal.clear()
        quoted = False
        open_token = False

    index = 0
    while index < len(text):
        character = text[index]
        if character in ("'", '"'):
            closing = text.find(character, index + 1)
            if closing == -1:
                return None, RULE_COMMAND_UNTERMINATED_QUOTE
            # A quote never splits a token: ``--message="a b"`` is one argument
            # exactly as every shell would deliver it.
            buffer.append(text[index + 1 : closing])
            quoted = True
            open_token = True
            index = closing + 1
            continue
        if character == " ":
            flush()
            index += 1
            continue
        buffer.append(character)
        literal.append(character)
        open_token = True
        index += 1
    flush()
    if len(tokens) > _MAX_MISSION_TOKENS:
        return None, RULE_COMMAND_EXTRA_ARGUMENTS
    return tuple(tokens), ""


def mission_command_class(tokens: Sequence[_MissionToken]) -> str | None:
    """Which mission effect class this command *claims* to be, if any.

    A command that claims one of these classes is ruled on decisively here and
    never falls through to the generic read-only grammar: ``npm install`` must
    be refused as an unauthorized local verification, not merely as a network
    token.
    """

    if not tokens or not tokens[0].fully_literal:
        return None
    verb = tokens[0].text.lower()
    if verb in _NPM_VERBS:
        return EFFECT_CLASS_LOCAL_VERIFICATION
    if verb in _GIT_VERBS and len(tokens) >= 2 and tokens[1].fully_literal:
        subcommand = tokens[1].text.lower()
        if subcommand == "add":
            return EFFECT_CLASS_GIT_STAGE
        if subcommand == "commit":
            return EFFECT_CLASS_GIT_COMMIT
    return None


# ---------------------------------------------------------------------------
# Path containment
# ---------------------------------------------------------------------------

_DEVICE_PREFIXES = ("\\\\?\\", "\\\\.\\", "//?/", "//./")


def _normcase(value: str) -> str:
    return ntpath.normcase(value) if os.name == "nt" else value


def _is_reparse(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        return True
    return bool(getattr(metadata, "st_reparse_tag", 0))


@dataclass(frozen=True)
class ResolvedTarget:
    """One structured edit target, proven contained and exactly authorized."""

    raw: str
    absolute: str
    relative_posix: str
    parent_relative_posix: str


def resolve_workspace(workspace: str | Path) -> str:
    """The canonical absolute authorized workspace, with symlinks resolved."""

    return os.path.normpath(os.path.realpath(str(workspace)))


def resolve_structured_target(
    raw: Any, *, workspace: str
) -> tuple[ResolvedTarget | None, str]:
    """Prove one structured path is inside the workspace; ``(target, rule_id)``.

    Every refused form is named: a device or UNC path, an alternate data
    stream, a NUL byte, retained parent traversal, or a symlink/junction on the
    resolved chain.  Containment is compared with Windows case semantics, but
    the authorization match performed by the caller stays exact and
    case-sensitive, so ``Index.html`` is contained yet unauthorized.
    """

    if not isinstance(raw, str) or not raw:
        return None, RULE_EDIT_LOCATION_UNPROVEN
    if "\x00" in raw or len(raw) > 4096:
        return None, RULE_EDIT_PATH_UNSAFE_FORM
    unified = raw.replace("/", "\\") if os.name == "nt" else raw
    if any(raw.startswith(prefix) or unified.startswith(prefix) for prefix in _DEVICE_PREFIXES):
        return None, RULE_EDIT_PATH_UNSAFE_FORM
    # A UNC path names a different volume authority entirely.
    if unified.startswith("\\\\") or raw.startswith("//"):
        return None, RULE_EDIT_PATH_UNSAFE_FORM

    drive, remainder = ntpath.splitdrive(raw)
    if ":" in remainder:
        # An alternate data stream (``file.txt:hidden``) writes bytes no
        # containment check on the visible path would ever observe.
        return None, RULE_EDIT_PATH_UNSAFE_FORM

    absolute = bool(drive) or raw.startswith(("\\", "/"))
    candidate = os.path.normpath(raw) if absolute else os.path.normpath(os.path.join(workspace, raw))
    if not os.path.isabs(candidate):
        return None, RULE_EDIT_PATH_OUTSIDE_WORKSPACE
    if ".." in Path(candidate).parts:
        return None, RULE_EDIT_PARENT_TRAVERSAL

    base = _normcase(workspace).rstrip("\\/")
    normalized = _normcase(candidate)
    if normalized == base or not normalized.startswith(base + os.sep):
        return None, RULE_EDIT_PATH_OUTSIDE_WORKSPACE

    relative = os.path.relpath(candidate, workspace).replace("\\", "/")
    if relative.startswith("../") or relative == "..":
        return None, RULE_EDIT_PARENT_TRAVERSAL

    # Nothing on the chain from the workspace to the target may redirect.
    probe = Path(workspace)
    for part in relative.split("/"):
        probe = probe / part
        try:
            metadata = os.lstat(probe)
        except OSError:
            # A component that does not exist yet cannot redirect; the parts
            # after it are equally non-existent, so the walk is complete.
            break
        if _is_reparse(metadata):
            return None, RULE_EDIT_REPARSE_POINT

    parent = relative.rsplit("/", 1)[0] if "/" in relative else ""
    return ResolvedTarget(raw, os.path.normpath(candidate), relative, parent), ""


# ---------------------------------------------------------------------------
# Edit request parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EditIntent:
    """The structured operation and target the CLI actually asked for."""

    operation: str | None
    raw_paths: tuple[str, ...]
    structured: bool
    detail: str


_MAX_DIFF_BLOCKS = 8


def parse_edit_tool_call(*, title: Any, content: Any) -> EditIntent:
    """Read the structured location out of a ``kind=edit`` permission request.

    The installed CLI's write decision always carries exactly one ``diff``
    content block whose ``path`` is the resolved absolute target, whose
    ``oldText`` is ``null`` for a new file and the previous content otherwise.
    Its delete decision carries no content at all, so the absence of a diff
    block is itself the discriminator -- the title is never the authority.
    """

    text_title = title if isinstance(title, str) else ""
    if content is None:
        # Exactly the CLI's delete shape.  Named explicitly so evidence records
        # *what* was refused rather than only that a shape was missing.
        if strip_code_span(text_title).startswith(CURSOR_DELETE_TITLE_PREFIX):
            return EditIntent(
                UNSUPPORTED_EDIT_OPERATION_DELETE, (), False,
                "delete decision carries no structured content",
            )
        return EditIntent(None, (), False, "edit request carries no content")
    if not isinstance(content, list) or not content or len(content) > _MAX_DIFF_BLOCKS:
        return EditIntent(None, (), False, "edit content is not a bounded content array")

    paths: list[str] = []
    operations: set[str] = set()
    for entry in content:
        if not isinstance(entry, Mapping):
            return EditIntent(None, (), False, "edit content entry is not an object")
        if entry.get("type") != CURSOR_CONTENT_TYPE_DIFF:
            continue
        raw_path = entry.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            return EditIntent(None, (), False, "diff block carries no structured path")
        old_text = entry.get("oldText", ...)
        new_text = entry.get("newText", ...)
        if old_text is ...:
            return EditIntent(None, (), False, "diff block carries no oldText discriminator")
        if not isinstance(new_text, str):
            return EditIntent(None, (), False, "diff block carries no newText content")
        if old_text is None:
            operations.add(EDIT_OPERATION_CREATE)
        elif isinstance(old_text, str):
            operations.add(EDIT_OPERATION_UPDATE)
        else:
            return EditIntent(None, (), False, "diff block oldText is neither null nor text")
        paths.append(raw_path)

    if not paths:
        if strip_code_span(text_title).startswith(CURSOR_DELETE_TITLE_PREFIX):
            return EditIntent(
                UNSUPPORTED_EDIT_OPERATION_DELETE, (), False,
                "delete decision carries no diff block",
            )
        return EditIntent(None, (), False, "edit request carries no structured diff block")
    if len(operations) != 1:
        return EditIntent(None, tuple(paths), True, "edit request mixes operations")
    return EditIntent(operations.pop(), tuple(paths), True, "structured diff block")


# ---------------------------------------------------------------------------
# Live repository observation
# ---------------------------------------------------------------------------

_HARDENED_GIT_ENVIRONMENT: dict[str, str] = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else os.devnull,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_PAGER": "",
}

_GIT_OUTPUT_LIMIT = 4 * 1024 * 1024
_GIT_TIMEOUT_SECONDS = 30


class LiveObservationError(RuntimeError):
    """The live repository could not be observed; never a soft warning."""


def _git(workspace: str, *arguments: str, tolerated_exit_codes: tuple[int, ...] = ()) -> str:
    environment = dict(os.environ)
    environment.update(_HARDENED_GIT_ENVIRONMENT)
    try:
        result = subprocess.run(
            ["git", *arguments], cwd=workspace, env=environment, shell=False, check=False,
            capture_output=True, timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LiveObservationError(f"git observation failed: {type(exc).__name__}") from exc
    if len(result.stdout) > _GIT_OUTPUT_LIMIT:
        raise LiveObservationError("git observation exceeded its output bound")
    if result.returncode != 0 and result.returncode not in tolerated_exit_codes:
        raise LiveObservationError(f"git {arguments[0]} exited {result.returncode}")
    return result.stdout.decode("utf-8", errors="replace")


def _nul_records(text: str) -> list[str]:
    return [item for item in text.split("\0") if item]


@dataclass(frozen=True)
class LiveRepositoryObservation:
    """One bounded, hardened observation of the live authorized repository."""

    head: str | None
    remotes: tuple[str, ...]
    submodule_present: bool
    affected_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...]
    renamed_paths: tuple[str, ...]
    staged_paths: tuple[str, ...]
    unstaged_paths: tuple[str, ...]
    untracked_paths: tuple[str, ...]
    ignored_paths: tuple[str, ...]
    symlink_paths: tuple[str, ...]
    index_entry_count: int

    @property
    def observation_fingerprint(self) -> str:
        return hashlib.sha256(canonical_bytes(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "head": self.head,
            "remotes": list(self.remotes[:_MAX_RECORDED]),
            "submodule_present": self.submodule_present,
            "affected_paths": list(self.affected_paths[:_MAX_RECORDED]),
            "deleted_paths": list(self.deleted_paths[:_MAX_RECORDED]),
            "renamed_paths": list(self.renamed_paths[:_MAX_RECORDED]),
            "staged_paths": list(self.staged_paths[:_MAX_RECORDED]),
            "unstaged_paths": list(self.unstaged_paths[:_MAX_RECORDED]),
            "untracked_paths": list(self.untracked_paths[:_MAX_RECORDED]),
            "ignored_paths": list(self.ignored_paths[:_MAX_RECORDED]),
            "symlink_paths": list(self.symlink_paths[:_MAX_RECORDED]),
            "index_entry_count": self.index_entry_count,
        }


def observe_live_repository(workspace: str | Path) -> LiveRepositoryObservation:
    """Observe the live repository with a hardened, read-only Git environment.

    ``-z`` framing is used throughout so a path carrying a quote, a space or a
    non-ASCII byte is delivered verbatim rather than through Git's C-style
    quoting, which a parser can misread.
    """

    root = str(workspace)
    # An unborn HEAD is a legitimate observation, not an observation failure.
    head_text = _git(
        root, "rev-parse", "--verify", "--quiet", "HEAD", tolerated_exit_codes=(1,)
    ).strip() or None
    head = head_text.lower() if head_text else None
    remotes = tuple(line.strip() for line in _git(root, "remote").splitlines() if line.strip())

    modules = _git(root, "ls-files", "-z", "--", ".gitmodules")
    submodule_present = bool(_nul_records(modules)) or os.path.exists(
        os.path.join(root, ".gitmodules")
    )

    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching")
    affected: list[str] = []
    deleted: list[str] = []
    renamed: list[str] = []
    unstaged: list[str] = []
    untracked: list[str] = []
    ignored: list[str] = []
    records = status.split("\0")
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record or len(record) < 4:
            continue
        code, path = record[:2], record[3:]
        if code[0] in ("R", "C") or code[1] in ("R", "C"):
            # ``-z`` follows a rename/copy record with its original path.
            renamed.append(path)
            if index < len(records):
                renamed.append(records[index])
                index += 1
            affected.append(path)
            continue
        if code == "!!":
            ignored.append(path)
            continue
        if code == "??":
            untracked.append(path)
            affected.append(path)
            continue
        affected.append(path)
        if "D" in code:
            deleted.append(path)
        if code[1] != " ":
            unstaged.append(path)

    staged: tuple[str, ...] = ()
    if head is not None:
        staged = tuple(sorted(set(_nul_records(_git(root, "diff", "--cached", "--name-only", "-z")))))
    index_entries = _nul_records(_git(root, "ls-files", "-s", "-z"))

    symlinks: list[str] = []
    for entry in index_entries:
        # ``<mode> <object> <stage>\t<path>``
        mode, _, remainder = entry.partition(" ")
        if mode == "120000" and "\t" in remainder:
            symlinks.append(remainder.split("\t", 1)[1])
    base = resolve_workspace(root)
    for relative in sorted(set(affected) | set(staged)):
        probe = Path(base)
        for part in relative.split("/"):
            probe = probe / part
            try:
                metadata = os.lstat(probe)
            except OSError:
                break
            if _is_reparse(metadata):
                symlinks.append(relative)
                break

    return LiveRepositoryObservation(
        head=head,
        remotes=remotes,
        submodule_present=submodule_present,
        affected_paths=tuple(sorted(set(affected))),
        deleted_paths=tuple(sorted(set(deleted))),
        renamed_paths=tuple(sorted(set(renamed))),
        staged_paths=staged,
        unstaged_paths=tuple(sorted(set(unstaged))),
        untracked_paths=tuple(sorted(set(untracked))),
        ignored_paths=tuple(sorted(set(ignored))),
        symlink_paths=tuple(sorted(set(symlinks))),
        index_entry_count=len(index_entries),
    )


@dataclass(frozen=True)
class ExternalBoundary:
    """A bounded identity of the two directories the mission may never touch.

    The executor already compares the source repository and the canary parent
    before and after the whole run.  This is the same boundary observed *before
    an approval*, so a Git mutation is never granted while the world outside the
    authorized workspace has already moved.  It is deliberately cheap -- Git
    control plane plus a child-name inventory -- rather than a full content
    snapshot, because it runs on every staging and commit decision.
    """

    source_head: str | None
    source_status_fingerprint: str | None
    source_control_fingerprint: str | None
    parent_children: tuple[str, ...]

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(canonical_bytes({
            "source_head": self.source_head,
            "source_status_fingerprint": self.source_status_fingerprint,
            "source_control_fingerprint": self.source_control_fingerprint,
            "parent_children": list(self.parent_children),
        })).hexdigest()


_MAX_PARENT_CHILDREN = 512


def observe_external_boundary(
    *,
    source_repository: str | Path | None,
    parent_directory: str | Path | None,
    excluded_children: frozenset[str] = frozenset(),
) -> ExternalBoundary:
    """Observe everything outside the authorized workspace, boundedly."""

    head: str | None = None
    status_digest: str | None = None
    control_digest: str | None = None
    if source_repository is not None:
        root = str(source_repository)
        try:
            head = (
                _git(root, "rev-parse", "--verify", "--quiet", "HEAD", tolerated_exit_codes=(1,))
                .strip()
                .lower()
                or None
            )
            status_digest = hashlib.sha256(
                _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all").encode("utf-8")
            ).hexdigest()
            control = _git(root, "show-ref") + "\0" + _git(root, "remote", "-v")
            config = Path(root) / ".git" / "config"
            control_bytes = control.encode("utf-8")
            if config.is_file() and config.stat().st_size <= 1024 * 1024:
                control_bytes += b"\0" + config.read_bytes()
            control_digest = hashlib.sha256(control_bytes).hexdigest()
        except (LiveObservationError, OSError):
            # An unobservable boundary is a *difference* from an observable
            # one, so it refuses rather than passing silently.
            head = status_digest = control_digest = None

    children: tuple[str, ...] = ()
    if parent_directory is not None:
        try:
            children = tuple(sorted(
                name for name in os.listdir(str(parent_directory))
                if name not in excluded_children
            )[:_MAX_PARENT_CHILDREN])
        except OSError:
            children = ("<unobservable>",)
    return ExternalBoundary(head, status_digest, control_digest, children)


def refuse_staging(
    observation: LiveRepositoryObservation,
    *,
    authorized: frozenset[str],
    fixture_head: str | None,
) -> tuple[str, ...]:
    """Every reason the live repository refuses staging, in canonical order."""

    reasons: list[str] = []
    if fixture_head is not None and observation.head != fixture_head:
        reasons.append(LIVE_HEAD_MOVED)
    if observation.remotes:
        reasons.append(LIVE_REMOTE_PRESENT)
    if observation.submodule_present:
        reasons.append(LIVE_SUBMODULE_PRESENT)
    if observation.renamed_paths:
        reasons.append(LIVE_RENAME_PRESENT)
    if observation.deleted_paths:
        reasons.append(LIVE_DELETION_PRESENT)
    if observation.symlink_paths:
        reasons.append(LIVE_SYMLINK_PRESENT)
    if any(path not in authorized for path in observation.affected_paths):
        reasons.append(LIVE_UNAUTHORIZED_PATH)
    if any(path not in authorized for path in observation.staged_paths):
        reasons.append(LIVE_STAGED_OUTSIDE_AUTHORITY)
    if any(path in authorized for path in observation.ignored_paths):
        reasons.append(LIVE_AUTHORIZED_PATH_IGNORED)
    if not observation.affected_paths and not observation.staged_paths:
        reasons.append(LIVE_NOTHING_TO_STAGE)
    return tuple(sorted(set(reasons)))


def refuse_commit(
    observation: LiveRepositoryObservation,
    *,
    authorized: frozenset[str],
    fixture_head: str | None,
) -> tuple[str, ...]:
    """Every reason the live repository refuses the one authorized commit."""

    reasons: list[str] = []
    if fixture_head is not None and observation.head != fixture_head:
        reasons.append(LIVE_HEAD_MOVED)
    if observation.remotes:
        reasons.append(LIVE_REMOTE_PRESENT)
    if observation.submodule_present:
        reasons.append(LIVE_SUBMODULE_PRESENT)
    if not observation.staged_paths:
        reasons.append(LIVE_INDEX_EMPTY)
    if any(path not in authorized for path in observation.staged_paths):
        reasons.append(LIVE_STAGED_OUTSIDE_AUTHORITY)
    if any(path not in authorized for path in observation.untracked_paths):
        reasons.append(LIVE_UNSTAGED_UNAUTHORIZED)
    if any(path not in authorized for path in observation.unstaged_paths):
        reasons.append(LIVE_UNSTAGED_UNAUTHORIZED)
    if observation.deleted_paths:
        reasons.append(LIVE_DELETION_PRESENT)
    if observation.renamed_paths:
        reasons.append(LIVE_RENAME_PRESENT)
    if observation.symlink_paths:
        reasons.append(LIVE_SYMLINK_PRESENT)
    return tuple(sorted(set(reasons)))


# ---------------------------------------------------------------------------
# Budget ledger
# ---------------------------------------------------------------------------


@dataclass
class MissionEffectLedger:
    """Per-run approval budget with deterministic duplicate handling."""

    authority: MissionEffectAuthority
    consumed: dict[str, int] = field(default_factory=dict)
    #: ``tool_call_id -> (request_digest, approved)`` for exact replay.
    decided: dict[str, tuple[str, bool]] = field(default_factory=dict)

    def spent(self, effect_class: str) -> int:
        return self.consumed.get(effect_class, 0)

    def remaining(self, effect_class: str) -> int:
        return max(0, self.authority.approval_bounds.get(effect_class, 0) - self.spent(effect_class))

    def would_exhaust(self, effect_class: str) -> bool:
        return self.remaining(effect_class) <= 0

    def consume(self, effect_class: str) -> None:
        self.consumed[effect_class] = self.spent(effect_class) + 1

    def replay(self, tool_call_id: str, request_digest: str) -> tuple[bool, bool] | None:
        """``(approved, conflict)`` when this exact call was already decided."""

        previous = self.decided.get(tool_call_id)
        if previous is None:
            return None
        digest, approved = previous
        return (approved, digest != request_digest)

    def remember(self, tool_call_id: str, request_digest: str, approved: bool) -> None:
        self.decided[tool_call_id] = (request_digest, approved)

    def snapshot(self) -> dict[str, int]:
        return {name: self.spent(name) for name in sorted(self.authority.approval_bounds)}


# ---------------------------------------------------------------------------
# Rulings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MissionEffectRuling:
    """A complete mission-scoped ruling: never merely permitted/refused."""

    permitted: bool
    effect_class: str | None
    rule_id: str
    detail: str
    operation: str | None = None
    normalized_targets: tuple[str, ...] = ()
    live_reasons: tuple[str, ...] = ()
    live_observation_fingerprint: str | None = None
    budget_before: int | None = None
    budget_after: int | None = None
    #: True when the effect class was consumed and must not be consumed again.
    consumes_budget: bool = True
    #: True when this ruling replayed an already-decided identical request.
    replayed: bool = False


def _refusal(
    effect_class: str | None,
    rule_id: str,
    detail: str,
    **extra: Any,
) -> MissionEffectRuling:
    return MissionEffectRuling(
        False, effect_class, rule_id, _bounded(detail), consumes_budget=False, **extra
    )


# ---------------------------------------------------------------------------
# The runtime
# ---------------------------------------------------------------------------


class MissionEffectRuntime:
    """One authority bound to one live workspace for the length of one run."""

    def __init__(
        self,
        *,
        authority: MissionEffectAuthority,
        workspace: str | Path,
        fixture_head: str | None = None,
        observer: Any = None,
        source_repository: str | Path | None = None,
        parent_directory: str | Path | None = None,
        excluded_parent_children: frozenset[str] = frozenset(),
    ) -> None:
        self.authority = authority.validated()
        self.workspace = resolve_workspace(workspace)
        self.fixture_head = fixture_head.lower() if isinstance(fixture_head, str) else None
        self.ledger = MissionEffectLedger(self.authority)
        self._observer = observer or observe_live_repository
        self.authorized_paths = frozenset(self.authority.writable_material_paths)
        self.creatable_directories = frozenset(self.authority.creatable_directories)
        self._source_repository = source_repository
        self._parent_directory = parent_directory
        self._excluded_parent_children = frozenset(excluded_parent_children)
        self.baseline_boundary: ExternalBoundary | None = (
            self._observe_boundary()
            if source_repository is not None or parent_directory is not None
            else None
        )

    # -- entry points ------------------------------------------------------
    def rule_on_edit(self, *, title: Any, content: Any) -> MissionEffectRuling:
        intent = parse_edit_tool_call(title=title, content=content)
        if intent.operation == UNSUPPORTED_EDIT_OPERATION_DELETE:
            return _refusal(
                EFFECT_CLASS_MATERIAL_EDIT, RULE_EDIT_OPERATION_UNSUPPORTED,
                "delete is never an authorized mission effect",
                operation=UNSUPPORTED_EDIT_OPERATION_DELETE,
            )
        if not intent.structured or intent.operation is None:
            return _refusal(
                EFFECT_CLASS_MATERIAL_EDIT, RULE_EDIT_LOCATION_UNPROVEN, intent.detail
            )
        if not self.authority.permits_edit_operation(intent.operation):
            return _refusal(
                EFFECT_CLASS_MATERIAL_EDIT, RULE_EDIT_OPERATION_UNSUPPORTED, intent.operation,
                operation=intent.operation,
            )
        if len(intent.raw_paths) != 1:
            return _refusal(
                EFFECT_CLASS_MATERIAL_EDIT, RULE_EDIT_TOO_MANY_TARGETS,
                f"{len(intent.raw_paths)} targets", operation=intent.operation,
            )

        target, rule_id = resolve_structured_target(intent.raw_paths[0], workspace=self.workspace)
        if target is None:
            return _refusal(
                EFFECT_CLASS_MATERIAL_EDIT, rule_id, _bounded(intent.raw_paths[0]),
                operation=intent.operation,
            )
        if target.relative_posix not in self.authorized_paths:
            return _refusal(
                EFFECT_CLASS_MATERIAL_EDIT, RULE_EDIT_PATH_NOT_AUTHORIZED, target.relative_posix,
                operation=intent.operation, normalized_targets=(target.relative_posix,),
            )
        if target.parent_relative_posix and target.parent_relative_posix not in self.creatable_directories:
            return _refusal(
                EFFECT_CLASS_MATERIAL_EDIT, RULE_EDIT_PARENT_NOT_AUTHORIZED,
                target.parent_relative_posix, operation=intent.operation,
                normalized_targets=(target.relative_posix,),
            )
        # The authorized parent directory is brought into existence implicitly
        # by this create; the installed CLI has no directory operation to ask
        # about it with, so the authorization is stated here rather than
        # silently assumed.
        targets = (
            (target.parent_relative_posix + "/", target.relative_posix)
            if target.parent_relative_posix and intent.operation == EDIT_OPERATION_CREATE
            else (target.relative_posix,)
        )
        return self._budgeted(
            EFFECT_CLASS_MATERIAL_EDIT, RULE_EDIT_AUTHORIZED,
            f"{intent.operation} {target.relative_posix}",
            operation=intent.operation, normalized_targets=targets,
        )

    def rule_on_command(self, command_text: str) -> MissionEffectRuling | None:
        """Rule on a ``kind=execute`` title, or ``None`` when out of scope.

        ``None`` means "this is not a mission effect": the caller falls back to
        the unchanged, deny-by-default read-only grammar.  It never means
        "allow".
        """

        text = strip_code_span(command_text if isinstance(command_text, str) else "")
        tokens, failure = tokenize_mission_command(text)
        if tokens is None:
            # A command whose alphabet or quoting is already refused is not
            # claimed here: the generic grammar refuses it with its own rule.
            return None
        effect_class = mission_command_class(tokens)
        if effect_class is None:
            return None
        if effect_class == EFFECT_CLASS_LOCAL_VERIFICATION:
            return self._rule_on_local_verification(tokens)
        if effect_class == EFFECT_CLASS_GIT_STAGE:
            return self._rule_on_git_stage(tokens)
        return self._rule_on_git_commit(tokens)

    # -- local verification ------------------------------------------------
    def _rule_on_local_verification(
        self, tokens: Sequence[_MissionToken]
    ) -> MissionEffectRuling:
        spelling = tuple(token.text for token in tokens)
        if any(not token.fully_literal for token in tokens):
            return _refusal(
                EFFECT_CLASS_LOCAL_VERIFICATION, RULE_LOCAL_VERIFICATION_NOT_EXACT,
                "a local verification command carries no quoted token",
            )
        if spelling not in self.authority.local_verification_commands:
            return _refusal(
                EFFECT_CLASS_LOCAL_VERIFICATION, RULE_LOCAL_VERIFICATION_NOT_EXACT,
                " ".join(spelling),
            )
        # The command runs in the authorized workspace against the authorized
        # manifest; a verification with no manifest to verify is refused rather
        # than allowed to invent one.
        if "package.json" not in self.authorized_paths:
            return _refusal(
                EFFECT_CLASS_LOCAL_VERIFICATION, RULE_LOCAL_VERIFICATION_MANIFEST_MISSING,
                "package.json is not an authorized material path",
            )
        if not os.path.isfile(os.path.join(self.workspace, "package.json")):
            return _refusal(
                EFFECT_CLASS_LOCAL_VERIFICATION, RULE_LOCAL_VERIFICATION_MANIFEST_MISSING,
                "the authorized workspace carries no package.json",
            )
        return self._budgeted(
            EFFECT_CLASS_LOCAL_VERIFICATION, RULE_LOCAL_VERIFICATION_AUTHORIZED,
            " ".join(spelling), normalized_targets=("package.json",),
        )

    # -- git staging -------------------------------------------------------
    def _rule_on_git_stage(self, tokens: Sequence[_MissionToken]) -> MissionEffectRuling:
        arguments = list(tokens[2:])
        form: str | None = None
        named: tuple[str, ...] = ()
        plain = [token.text for token in arguments]
        literal = [token.text for token in arguments if token.fully_literal]
        if literal == plain == ["-A"]:
            form = GIT_STAGE_FORM_ALL_SHORT
        elif literal == plain == ["--all"]:
            form = GIT_STAGE_FORM_ALL_LONG
        elif literal == plain == ["."]:
            form = GIT_STAGE_FORM_DOT
        elif len(plain) > 1 and plain[0] == "--" and arguments[0].fully_literal:
            # Paths themselves may legitimately be quoted; the separator may not.
            form = GIT_STAGE_FORM_EXPLICIT_PATHS
            named = tuple(item.replace("\\", "/") for item in plain[1:])
        if form is None or form not in self.authority.git_staging_forms:
            return _refusal(
                EFFECT_CLASS_GIT_STAGE, RULE_GIT_STAGE_FORM_NOT_AUTHORIZED, " ".join(plain) or "git add",
            )
        unauthorized = [path for path in named if path not in self.authorized_paths]
        if unauthorized:
            return _refusal(
                EFFECT_CLASS_GIT_STAGE, RULE_GIT_STAGE_PATH_NOT_AUTHORIZED,
                ", ".join(unauthorized[:8]),
            )

        observation, failure = self._observe()
        if observation is None:
            return _refusal(EFFECT_CLASS_GIT_STAGE, RULE_REPOSITORY_UNOBSERVABLE, failure)
        reasons = self._with_boundary(refuse_staging(
            observation, authorized=self.authorized_paths, fixture_head=self.fixture_head
        ))
        if reasons:
            return _refusal(
                EFFECT_CLASS_GIT_STAGE, RULE_GIT_STAGE_LIVE_STATE_REFUSED, form,
                live_reasons=reasons,
                live_observation_fingerprint=observation.observation_fingerprint,
            )
        return self._budgeted(
            EFFECT_CLASS_GIT_STAGE, RULE_GIT_STAGE_AUTHORIZED, form,
            normalized_targets=tuple(observation.affected_paths[:_MAX_RECORDED]),
            live_observation_fingerprint=observation.observation_fingerprint,
        )

    # -- git commit --------------------------------------------------------
    def _rule_on_git_commit(self, tokens: Sequence[_MissionToken]) -> MissionEffectRuling:
        arguments = list(tokens[2:])
        form: str | None = None
        message: str | None = None
        if len(arguments) == 2 and arguments[0].fully_literal:
            switch = arguments[0].text
            if switch == "-m":
                form, message = GIT_COMMIT_FORM_SHORT, arguments[1].text
            elif switch == "--message":
                form, message = GIT_COMMIT_FORM_LONG, arguments[1].text
        elif len(arguments) == 1 and arguments[0].literal_prefix.startswith("--message="):
            # ``--message="..."`` is one token whose switch half is literal and
            # whose value half may be quoted.
            form, message = GIT_COMMIT_FORM_LONG_EQUALS, arguments[0].text[len("--message=") :]
        if form is None or form not in self.authority.git_commit_forms:
            return _refusal(
                EFFECT_CLASS_GIT_COMMIT, RULE_GIT_COMMIT_FORM_NOT_AUTHORIZED,
                " ".join(token.text for token in arguments) or "git commit",
            )
        if message != self.authority.exact_commit_message:
            return _refusal(
                EFFECT_CLASS_GIT_COMMIT, RULE_GIT_COMMIT_MESSAGE_NOT_EXACT, _bounded(message),
            )

        observation, failure = self._observe()
        if observation is None:
            return _refusal(EFFECT_CLASS_GIT_COMMIT, RULE_REPOSITORY_UNOBSERVABLE, failure)
        reasons = self._with_boundary(refuse_commit(
            observation, authorized=self.authorized_paths, fixture_head=self.fixture_head
        ))
        if reasons:
            return _refusal(
                EFFECT_CLASS_GIT_COMMIT, RULE_GIT_COMMIT_LIVE_STATE_REFUSED, form,
                live_reasons=reasons,
                live_observation_fingerprint=observation.observation_fingerprint,
            )
        return self._budgeted(
            EFFECT_CLASS_GIT_COMMIT, RULE_GIT_COMMIT_AUTHORIZED, form,
            normalized_targets=tuple(observation.staged_paths[:_MAX_RECORDED]),
            live_observation_fingerprint=observation.observation_fingerprint,
        )

    # -- helpers -----------------------------------------------------------
    def _observe_boundary(self) -> ExternalBoundary:
        return observe_external_boundary(
            source_repository=self._source_repository,
            parent_directory=self._parent_directory,
            excluded_children=self._excluded_parent_children,
        )

    def _with_boundary(self, reasons: tuple[str, ...]) -> tuple[str, ...]:
        if self._external_boundary_moved():
            return tuple(sorted(set(reasons) | {LIVE_EXTERNAL_BOUNDARY_MOVED}))
        return reasons

    def _external_boundary_moved(self) -> bool:
        """True when anything outside the authorized workspace has changed."""

        if self.baseline_boundary is None:
            return False
        return self._observe_boundary() != self.baseline_boundary

    def _observe(self) -> tuple[LiveRepositoryObservation | None, str]:
        try:
            return self._observer(self.workspace), ""
        except LiveObservationError as exc:
            return None, _bounded(exc)
        except OSError as exc:  # pragma: no cover - defensive
            return None, _bounded(f"{type(exc).__name__}")

    def _budgeted(
        self, effect_class: str, rule_id: str, detail: str, **extra: Any
    ) -> MissionEffectRuling:
        before = self.ledger.spent(effect_class)
        if self.ledger.would_exhaust(effect_class):
            return _refusal(
                effect_class, RULE_BUDGET_EXHAUSTED,
                f"{effect_class} budget {before}/{self.authority.approval_bounds[effect_class]}",
                budget_before=before, budget_after=before, **extra,
            )
        return MissionEffectRuling(
            True, effect_class, rule_id, _bounded(detail),
            budget_before=before, budget_after=before + 1, **extra,
        )


def request_digest(*, method: str, tool_kind: Any, title: Any, content: Any) -> str:
    """A stable digest of one server request, for deterministic replay."""

    body = {
        "method": method,
        "tool_kind": tool_kind if isinstance(tool_kind, str) else None,
        "title": title if isinstance(title, str) else None,
        "content": _canonical_content(content),
    }
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _canonical_content(content: Any) -> Any:
    if isinstance(content, list):
        return [_canonical_content(item) for item in content[:_MAX_DIFF_BLOCKS]]
    if isinstance(content, Mapping):
        return {str(key): _canonical_content(content[key]) for key in sorted(map(str, content))}
    if isinstance(content, (str, int, float, bool)) or content is None:
        return content
    return str(content)[:_DETAIL_LIMIT]


__all__ = [
    "CURSOR_CONTENT_TYPE_DIFF",
    "CURSOR_DELETE_TITLE_PREFIX",
    "CURSOR_TOOL_KIND_EDIT",
    "CURSOR_TOOL_KIND_EXECUTE",
    "EditIntent",
    "LIVE_AUTHORIZED_PATH_IGNORED",
    "LIVE_DELETION_PRESENT",
    "LIVE_EXTERNAL_BOUNDARY_MOVED",
    "LIVE_HEAD_MOVED",
    "LIVE_INDEX_EMPTY",
    "LIVE_NOTHING_TO_STAGE",
    "LIVE_REMOTE_PRESENT",
    "LIVE_RENAME_PRESENT",
    "LIVE_STAGED_OUTSIDE_AUTHORITY",
    "LIVE_SUBMODULE_PRESENT",
    "LIVE_SYMLINK_PRESENT",
    "LIVE_UNAUTHORIZED_PATH",
    "LIVE_UNSTAGED_UNAUTHORIZED",
    "ExternalBoundary",
    "LiveObservationError",
    "LiveRepositoryObservation",
    "MissionEffectLedger",
    "MissionEffectRuling",
    "MissionEffectRuntime",
    "RULE_BUDGET_EXHAUSTED",
    "RULE_DUPLICATE_TOOL_CALL_CONFLICT",
    "RULE_EDIT_AUTHORIZED",
    "RULE_EDIT_LOCATION_UNPROVEN",
    "RULE_EDIT_OPERATION_UNSUPPORTED",
    "RULE_EDIT_PARENT_NOT_AUTHORIZED",
    "RULE_EDIT_PARENT_TRAVERSAL",
    "RULE_EDIT_PATH_NOT_AUTHORIZED",
    "RULE_EDIT_PATH_OUTSIDE_WORKSPACE",
    "RULE_EDIT_PATH_UNSAFE_FORM",
    "RULE_EDIT_REPARSE_POINT",
    "RULE_EDIT_REQUEST_MALFORMED",
    "RULE_EDIT_TOO_MANY_TARGETS",
    "RULE_GIT_COMMIT_AUTHORIZED",
    "RULE_GIT_COMMIT_FORM_NOT_AUTHORIZED",
    "RULE_GIT_COMMIT_LIVE_STATE_REFUSED",
    "RULE_GIT_COMMIT_MESSAGE_NOT_EXACT",
    "RULE_GIT_STAGE_AUTHORIZED",
    "RULE_GIT_STAGE_FORM_NOT_AUTHORIZED",
    "RULE_GIT_STAGE_LIVE_STATE_REFUSED",
    "RULE_GIT_STAGE_PATH_NOT_AUTHORIZED",
    "RULE_LOCAL_VERIFICATION_AUTHORIZED",
    "RULE_LOCAL_VERIFICATION_MANIFEST_MISSING",
    "RULE_LOCAL_VERIFICATION_NOT_EXACT",
    "RULE_MISSION_AUTHORITY_ABSENT",
    "RULE_REPOSITORY_UNOBSERVABLE",
    "ResolvedTarget",
    "SUPPORTED_EDIT_REQUEST_SHAPES",
    "observe_external_boundary",
    "observe_live_repository",
    "parse_edit_tool_call",
    "refuse_commit",
    "refuse_staging",
    "request_digest",
    "resolve_structured_target",
    "resolve_workspace",
    "strip_code_span",
    "tokenize_mission_command",
]
