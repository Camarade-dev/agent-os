"""Canonical, immutable mission-scoped effect authority.

The V4 ACP client is safe and categorically inert: it answers exactly two
server requests, refuses every tool kind other than lowercase ``execute``, and
accepts a tiny read-only inspection grammar.  An independent liveness audit
established that this boundary *also* refuses every effect the Neon Relay
mission itself requires -- the 14 material writes, the local ``npm test``, the
Git staging and the one exact commit -- so the mission is unexecutable.

The repair is deliberately *not* a category.  Nothing here authorizes
"editing", "writing", "npm", "Git mutation" or "shell execution".  A
:class:`MissionEffectAuthority` is a closed, canonical enumeration of the exact
effects one named mission needs:

* the exact writable material paths, and nothing else;
* the exact directories those paths may require, and nothing else;
* the exact local verification command spellings, and nothing else;
* the exact Git staging forms, each still subject to independent live
  observation of what would actually be staged;
* exactly one commit, carrying one exact complete message;
* a maximum approval count per effect class.

It is canonical data only -- no callable, no path handle, no environment
lookup -- and it is bound by one non-self-referential fingerprint.  That
fingerprint is folded into the mission profile, and therefore into the profile
fingerprint and the owner-authorized payload, so the effect authority is
something the owner authorized rather than something inferred from prompt text
at execution time.

Nothing in this module touches the filesystem, spawns a process, or contacts a
provider.  The decision procedure that *consults* this authority lives in
:mod:`admissible.delegated_gate.acp_mission_effects`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from admissible.delegated_gate.canonical import (
    fingerprint,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_safe_relative_path,
    require_sha256,
    require_strict_int,
    require_string_list,
)


MISSION_EFFECT_AUTHORITY_SCHEMA_VERSION = "admissible_mission_effect_authority_v1"

#: The only workspace identity this schema can express: the exact work
#: workspace the native lane delivered for this run.  It is a named constant
#: rather than a path so the canonical authority stays host-independent, and the
#: runtime binds it to the delivered directory.
WORKSPACE_IDENTITY_DELIVERED_WORK_WORKSPACE = "the_exact_delivered_native_work_workspace"

WORKSPACE_IDENTITIES = frozenset({WORKSPACE_IDENTITY_DELIVERED_WORK_WORKSPACE})


# ---------------------------------------------------------------------------
# Effect classes and edit operations
# ---------------------------------------------------------------------------

EFFECT_CLASS_MATERIAL_EDIT = "mission_material_edit"
EFFECT_CLASS_LOCAL_VERIFICATION = "mission_local_verification"
EFFECT_CLASS_GIT_STAGE = "mission_git_stage"
EFFECT_CLASS_GIT_COMMIT = "mission_git_commit"

EFFECT_CLASSES: tuple[str, ...] = (
    EFFECT_CLASS_GIT_COMMIT,
    EFFECT_CLASS_GIT_STAGE,
    EFFECT_CLASS_LOCAL_VERIFICATION,
    EFFECT_CLASS_MATERIAL_EDIT,
)

#: Creating a file that does not exist yet.
EDIT_OPERATION_CREATE = "create"
#: Replacing the complete content of a file that already exists.
EDIT_OPERATION_UPDATE = "update"
#: Creating one of the exact authorized directories.  The installed Cursor CLI
#: exposes no explicit directory operation (its decision enum is exactly
#: ``{write, shell, delete, mcp}``), so this operation is reachable only as the
#: implicit parent of an authorized create.  It is enumerated anyway so the
#: authority states the boundary rather than leaving it to inference.
EDIT_OPERATION_CREATE_DIRECTORY = "create_directory"

EDIT_OPERATIONS: tuple[str, ...] = (
    EDIT_OPERATION_CREATE,
    EDIT_OPERATION_CREATE_DIRECTORY,
    EDIT_OPERATION_UPDATE,
)

#: Deletion is deliberately absent from :data:`EDIT_OPERATIONS`.  The installed
#: CLI represents an overwrite as a ``write`` decision carrying the previous
#: content as ``oldText``; it never decomposes an overwrite into delete + write.
#: A delete is therefore always a free-standing destructive effect, and this
#: mission needs none.
UNSUPPORTED_EDIT_OPERATION_DELETE = "delete"


# ---------------------------------------------------------------------------
# Git staging and commit forms
# ---------------------------------------------------------------------------

GIT_STAGE_FORM_ALL_SHORT = "git add -A"
GIT_STAGE_FORM_ALL_LONG = "git add --all"
GIT_STAGE_FORM_DOT = "git add ."
GIT_STAGE_FORM_EXPLICIT_PATHS = "git add -- <authorized material paths>"

GIT_STAGE_FORMS: tuple[str, ...] = (
    GIT_STAGE_FORM_ALL_LONG,
    GIT_STAGE_FORM_ALL_SHORT,
    GIT_STAGE_FORM_DOT,
    GIT_STAGE_FORM_EXPLICIT_PATHS,
)

GIT_COMMIT_FORM_SHORT = "git commit -m <exact message>"
GIT_COMMIT_FORM_LONG = "git commit --message <exact message>"
GIT_COMMIT_FORM_LONG_EQUALS = "git commit --message=<exact message>"

GIT_COMMIT_FORMS: tuple[str, ...] = (
    GIT_COMMIT_FORM_LONG,
    GIT_COMMIT_FORM_LONG_EQUALS,
    GIT_COMMIT_FORM_SHORT,
)


# ---------------------------------------------------------------------------
# Standing constraints
# ---------------------------------------------------------------------------

CONSTRAINT_NO_REMOTES = "no_git_remote_may_exist_or_be_created"
CONSTRAINT_NO_PUSH = "no_push_or_fetch_is_authorized"
CONSTRAINT_NO_DEPLOY = "no_deployment_publication_or_server_is_authorized"
CONSTRAINT_NO_NETWORK = "no_network_capable_command_is_authorized"
CONSTRAINT_NO_SUBMODULES = "no_submodule_may_exist_or_be_created"
CONSTRAINT_WORKSPACE_ONLY = "no_path_outside_the_authorized_work_workspace_may_be_affected"
CONSTRAINT_ALLOW_ONCE_ONLY = "only_allow_once_may_ever_be_selected"

STANDING_CONSTRAINTS: tuple[str, ...] = (
    CONSTRAINT_ALLOW_ONCE_ONLY,
    CONSTRAINT_NO_DEPLOY,
    CONSTRAINT_NO_NETWORK,
    CONSTRAINT_NO_PUSH,
    CONSTRAINT_NO_REMOTES,
    CONSTRAINT_NO_SUBMODULES,
    CONSTRAINT_WORKSPACE_ONLY,
)


_MAX_PATHS = 256
_MAX_COMMAND_TOKENS = 8
_MAX_COMMANDS = 16


class MissionEffectAuthorityError(ValueError):
    """A mission-scoped effect authority is not canonical or not coherent."""


def _require_ordered_unique(values: Any, label: str, *, limit: int) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise MissionEffectAuthorityError(f"{label} must be an ordered tuple")
    if len(values) > limit:
        raise MissionEffectAuthorityError(f"{label} exceeds its bound")
    for value in values:
        require_nonempty_text(value, label, max_bytes=4096)
    if len(set(values)) != len(values):
        raise MissionEffectAuthorityError(f"{label} must be unique")
    return values


@dataclass(frozen=True)
class MissionEffectAuthority:
    """One immutable, canonically fingerprinted mission-scoped effect authority."""

    schema_version: str
    authority_id: str
    workspace_identity: str
    #: Exactly the relative paths this mission may create or update.
    writable_material_paths: tuple[str, ...]
    #: Exactly the relative directories this mission may bring into existence.
    creatable_directories: tuple[str, ...]
    #: Exactly the edit operations this mission may perform.
    allowed_edit_operations: tuple[str, ...]
    #: Exactly the local verification commands, as canonical argv token tuples.
    local_verification_commands: tuple[tuple[str, ...], ...]
    #: Exactly the Git staging forms this mission may use.
    git_staging_forms: tuple[str, ...]
    #: Exactly the Git commit spellings this mission may use.
    git_commit_forms: tuple[str, ...]
    #: The one exact, complete commit message.
    exact_commit_message: str
    #: Maximum allow-once approvals per effect class, as ordered pairs.
    max_approvals_per_effect_class: tuple[tuple[str, int], ...]
    #: Standing constraints that no request can ever satisfy its way past.
    constraints: tuple[str, ...]
    authority_fingerprint: str

    # -- canonical body ----------------------------------------------------
    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority_id": self.authority_id,
            "workspace_identity": self.workspace_identity,
            "writable_material_paths": list(self.writable_material_paths),
            "creatable_directories": list(self.creatable_directories),
            "allowed_edit_operations": list(self.allowed_edit_operations),
            "local_verification_commands": [
                list(command) for command in self.local_verification_commands
            ],
            "git_staging_forms": list(self.git_staging_forms),
            "git_commit_forms": list(self.git_commit_forms),
            "exact_commit_message": self.exact_commit_message,
            "max_approvals_per_effect_class": [
                [name, value] for name, value in self.max_approvals_per_effect_class
            ],
            "constraints": list(self.constraints),
        }

    # -- validation --------------------------------------------------------
    def validated(self) -> "MissionEffectAuthority":
        if self.schema_version != MISSION_EFFECT_AUTHORITY_SCHEMA_VERSION:
            raise MissionEffectAuthorityError("unsupported mission effect authority schema")
        require_identifier(self.authority_id, "mission effect authority id")
        if self.workspace_identity not in WORKSPACE_IDENTITIES:
            raise MissionEffectAuthorityError("unsupported authorized workspace identity")

        paths = _require_ordered_unique(
            self.writable_material_paths, "writable material path", limit=_MAX_PATHS
        )
        if not paths:
            raise MissionEffectAuthorityError("a mission effect authority must name at least one writable path")
        for path in paths:
            require_safe_relative_path(path, "writable material path")

        directories = _require_ordered_unique(
            self.creatable_directories, "creatable directory", limit=_MAX_PATHS
        )
        for directory in directories:
            require_safe_relative_path(directory, "creatable directory")

        # Every authorized parent must itself be authorized: a write whose
        # parent directory is not creatable could never be performed, and a
        # creatable directory that no authorized path needs is standing
        # authority the mission never asked for.
        needed = {
            path.rsplit("/", 1)[0] for path in paths if "/" in path
        }
        if set(directories) != needed:
            raise MissionEffectAuthorityError(
                "creatable directories must be exactly the parents the writable paths require"
            )
        for directory in directories:
            if "/" in directory:
                raise MissionEffectAuthorityError(
                    "a creatable directory must be a direct child of the authorized workspace"
                )

        operations = _require_ordered_unique(
            self.allowed_edit_operations, "allowed edit operation", limit=16
        )
        if not operations:
            raise MissionEffectAuthorityError("a mission effect authority must allow at least one edit operation")
        for operation in operations:
            if operation not in EDIT_OPERATIONS:
                raise MissionEffectAuthorityError(f"unsupported edit operation: {operation}")
        if operations != tuple(sorted(operations)):
            raise MissionEffectAuthorityError("allowed edit operations must be canonically ordered")

        if not isinstance(self.local_verification_commands, tuple) or not self.local_verification_commands:
            raise MissionEffectAuthorityError("local verification commands must be a non-empty ordered tuple")
        if len(self.local_verification_commands) > _MAX_COMMANDS:
            raise MissionEffectAuthorityError("local verification commands exceed their bound")
        for command in self.local_verification_commands:
            if not isinstance(command, tuple) or not command:
                raise MissionEffectAuthorityError("a local verification command must be a non-empty token tuple")
            if len(command) > _MAX_COMMAND_TOKENS:
                raise MissionEffectAuthorityError("a local verification command exceeds its token bound")
            for token in command:
                require_nonempty_text(token, "local verification token", max_bytes=256)
                if any(character.isspace() for character in token):
                    raise MissionEffectAuthorityError("a local verification token must carry no whitespace")
        if len(set(self.local_verification_commands)) != len(self.local_verification_commands):
            raise MissionEffectAuthorityError("local verification commands must be unique")

        staging = _require_ordered_unique(self.git_staging_forms, "git staging form", limit=16)
        if not staging:
            raise MissionEffectAuthorityError("a mission effect authority must name at least one staging form")
        for form in staging:
            if form not in GIT_STAGE_FORMS:
                raise MissionEffectAuthorityError(f"unsupported git staging form: {form}")

        commits = _require_ordered_unique(self.git_commit_forms, "git commit form", limit=16)
        if not commits:
            raise MissionEffectAuthorityError("a mission effect authority must name at least one commit form")
        for form in commits:
            if form not in GIT_COMMIT_FORMS:
                raise MissionEffectAuthorityError(f"unsupported git commit form: {form}")

        require_nonempty_text(self.exact_commit_message, "exact commit message", max_bytes=1024)
        if "\n" in self.exact_commit_message or "\r" in self.exact_commit_message:
            raise MissionEffectAuthorityError("the exact commit message must be one single line")
        if self.exact_commit_message != self.exact_commit_message.strip():
            raise MissionEffectAuthorityError("the exact commit message must carry no surrounding whitespace")

        if not isinstance(self.max_approvals_per_effect_class, tuple):
            raise MissionEffectAuthorityError("approval bounds must be an ordered tuple")
        names: list[str] = []
        for entry in self.max_approvals_per_effect_class:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise MissionEffectAuthorityError("an approval bound must be an ordered (class, count) pair")
            name, value = entry
            if name not in EFFECT_CLASSES:
                raise MissionEffectAuthorityError(f"unknown effect class: {name}")
            require_strict_int(value, "approval bound", minimum=1, maximum=1024)
            names.append(name)
        if tuple(names) != EFFECT_CLASSES:
            raise MissionEffectAuthorityError(
                "approval bounds must cover exactly the known effect classes in canonical order"
            )
        commit_bound = dict(self.max_approvals_per_effect_class)[EFFECT_CLASS_GIT_COMMIT]
        if commit_bound != 1:
            raise MissionEffectAuthorityError("exactly one commit may ever be authorized")

        constraints = _require_ordered_unique(self.constraints, "constraint", limit=32)
        if constraints != STANDING_CONSTRAINTS:
            raise MissionEffectAuthorityError(
                "a mission effect authority must carry exactly the standing constraint set"
            )

        require_sha256(self.authority_fingerprint, "mission effect authority fingerprint")
        if fingerprint(self._body()) != self.authority_fingerprint:
            raise MissionEffectAuthorityError("mission effect authority fingerprint mismatch")
        return self

    # -- serialization -----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["authority_fingerprint"] = self.authority_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MissionEffectAuthority":
        if not isinstance(data, Mapping):
            raise MissionEffectAuthorityError("mission effect authority must be a JSON object")
        require_exact_keys(
            data,
            {
                "schema_version",
                "authority_id",
                "workspace_identity",
                "writable_material_paths",
                "creatable_directories",
                "allowed_edit_operations",
                "local_verification_commands",
                "git_staging_forms",
                "git_commit_forms",
                "exact_commit_message",
                "max_approvals_per_effect_class",
                "constraints",
                "authority_fingerprint",
            },
            "mission effect authority",
        )
        raw_commands = data["local_verification_commands"]
        if not isinstance(raw_commands, list):
            raise MissionEffectAuthorityError("local verification commands must be an ordered array")
        commands = tuple(
            require_string_list(item, "local verification command") for item in raw_commands
        )
        raw_bounds = data["max_approvals_per_effect_class"]
        if not isinstance(raw_bounds, list) or any(
            not isinstance(entry, list) or len(entry) != 2 for entry in raw_bounds
        ):
            raise MissionEffectAuthorityError("approval bounds must be an ordered array of [class, count] pairs")
        bounds = tuple((entry[0], entry[1]) for entry in raw_bounds)
        return cls(
            schema_version=data["schema_version"],
            authority_id=data["authority_id"],
            workspace_identity=data["workspace_identity"],
            writable_material_paths=require_string_list(
                data["writable_material_paths"], "writable material paths"
            ),
            creatable_directories=require_string_list(
                data["creatable_directories"], "creatable directories"
            ),
            allowed_edit_operations=require_string_list(
                data["allowed_edit_operations"], "allowed edit operations"
            ),
            local_verification_commands=commands,
            git_staging_forms=require_string_list(data["git_staging_forms"], "git staging forms"),
            git_commit_forms=require_string_list(data["git_commit_forms"], "git commit forms"),
            exact_commit_message=data["exact_commit_message"],
            max_approvals_per_effect_class=bounds,
            constraints=require_string_list(data["constraints"], "constraints"),
            authority_fingerprint=data["authority_fingerprint"],
        ).validated()

    # -- derived helpers ---------------------------------------------------
    @property
    def approval_bounds(self) -> Mapping[str, int]:
        return dict(self.max_approvals_per_effect_class)

    def permits_edit_operation(self, operation: str) -> bool:
        return operation in self.allowed_edit_operations


def create_mission_effect_authority(**values: Any) -> MissionEffectAuthority:
    """Build one canonically fingerprinted, validated mission effect authority."""

    provisional = MissionEffectAuthority(
        schema_version=MISSION_EFFECT_AUTHORITY_SCHEMA_VERSION,
        authority_fingerprint="0" * 64,
        **values,
    )
    return MissionEffectAuthority(
        **{**provisional.__dict__, "authority_fingerprint": fingerprint(provisional._body())}
    ).validated()


# ---------------------------------------------------------------------------
# The Neon Relay mission effect authority
# ---------------------------------------------------------------------------
#
# Constructed from the mission's own canonical constants rather than restated,
# so the writable set and the commit message cannot drift from the profile's
# ``required_material_paths`` and ``required_complete_commit_message``.

from admissible.delegated_gate.neon_relay_mission import (  # noqa: E402  (cycle-free leaf import)
    NEON_RELAY_REQUIRED_COMMIT_MESSAGE,
    NEON_RELAY_REQUIRED_MATERIAL_PATHS,
)


#: The exact local verification spellings.  ``npm`` and ``npm.cmd`` are both
#: present because the host allowlist happens to contain only ``npm.cmd`` and
#: the mission text says ``npm test``: relying on that accident is exactly how
#: the exact verification path stops being guaranteed.  ``run test`` is the
#: explicit spelling of the same script.  Nothing else -- no install, update,
#: audit, exec, npx, ci, publish or argument -- is expressible here.
NEON_RELAY_LOCAL_VERIFICATION_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("npm", "run", "test"),
    ("npm", "test"),
    ("npm.cmd", "run", "test"),
    ("npm.cmd", "test"),
)

NEON_RELAY_MISSION_EFFECT_AUTHORITY = create_mission_effect_authority(
    authority_id="neon-relay-mission-effects",
    workspace_identity=WORKSPACE_IDENTITY_DELIVERED_WORK_WORKSPACE,
    writable_material_paths=NEON_RELAY_REQUIRED_MATERIAL_PATHS,
    creatable_directories=("src", "test"),
    allowed_edit_operations=(
        EDIT_OPERATION_CREATE,
        EDIT_OPERATION_CREATE_DIRECTORY,
        EDIT_OPERATION_UPDATE,
    ),
    local_verification_commands=NEON_RELAY_LOCAL_VERIFICATION_COMMANDS,
    git_staging_forms=GIT_STAGE_FORMS,
    git_commit_forms=GIT_COMMIT_FORMS,
    exact_commit_message=NEON_RELAY_REQUIRED_COMMIT_MESSAGE,
    max_approvals_per_effect_class=(
        (EFFECT_CLASS_GIT_COMMIT, 1),
        (EFFECT_CLASS_GIT_STAGE, 8),
        (EFFECT_CLASS_LOCAL_VERIFICATION, 8),
        # Fourteen files, each of which a real agent may legitimately write more
        # than once while it iterates; four passes over the complete set is a
        # bound the mission cannot exceed by accident and cannot exploit.
        (EFFECT_CLASS_MATERIAL_EDIT, 56),
    ),
    constraints=STANDING_CONSTRAINTS,
)


__all__ = [
    "CONSTRAINT_ALLOW_ONCE_ONLY",
    "CONSTRAINT_NO_DEPLOY",
    "CONSTRAINT_NO_NETWORK",
    "CONSTRAINT_NO_PUSH",
    "CONSTRAINT_NO_REMOTES",
    "CONSTRAINT_NO_SUBMODULES",
    "CONSTRAINT_WORKSPACE_ONLY",
    "EDIT_OPERATIONS",
    "EDIT_OPERATION_CREATE",
    "EDIT_OPERATION_CREATE_DIRECTORY",
    "EDIT_OPERATION_UPDATE",
    "EFFECT_CLASSES",
    "EFFECT_CLASS_GIT_COMMIT",
    "EFFECT_CLASS_GIT_STAGE",
    "EFFECT_CLASS_LOCAL_VERIFICATION",
    "EFFECT_CLASS_MATERIAL_EDIT",
    "GIT_COMMIT_FORMS",
    "GIT_COMMIT_FORM_LONG",
    "GIT_COMMIT_FORM_LONG_EQUALS",
    "GIT_COMMIT_FORM_SHORT",
    "GIT_STAGE_FORMS",
    "GIT_STAGE_FORM_ALL_LONG",
    "GIT_STAGE_FORM_ALL_SHORT",
    "GIT_STAGE_FORM_DOT",
    "GIT_STAGE_FORM_EXPLICIT_PATHS",
    "MISSION_EFFECT_AUTHORITY_SCHEMA_VERSION",
    "MissionEffectAuthority",
    "MissionEffectAuthorityError",
    "NEON_RELAY_LOCAL_VERIFICATION_COMMANDS",
    "NEON_RELAY_MISSION_EFFECT_AUTHORITY",
    "STANDING_CONSTRAINTS",
    "UNSUPPORTED_EDIT_OPERATION_DELETE",
    "WORKSPACE_IDENTITIES",
    "WORKSPACE_IDENTITY_DELIVERED_WORK_WORKSPACE",
    "create_mission_effect_authority",
]
