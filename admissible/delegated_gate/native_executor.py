"""One-shot native delegated-executor boundary for the Act-2A canary.

This module authorizes one locally-attested coding-agent process.  It does not
interpret the agent's commands, provide a sandbox, or claim global containment.
All provider output is bounded evidence only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Any, Callable, Mapping, Protocol
import weakref

from admissible.delegated_gate.canonical import (
    canonical_bytes,
    fingerprint,
    require_bool,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_optional_git_oid,
    require_safe_relative_path,
    require_sha256,
    require_strict_int,
    require_string_list,
)
from admissible.delegated_gate.durability import (
    DurabilityAdapterError,
    PlatformDurabilityAdapter,
    PostPublicationReloadFailure,
    PublicationConflict,
    PublicationMode,
    PublicationVisibleButMetadataUncertain,
)
from admissible.delegated_gate.store import _FileLock
from admissible.managed_process import (
    ManagedProcess,
    ManagedProcessError,
    OBSERVATION_PROVEN_EMPTY,
    TERMINATION_COMPLETED,
    TERMINATION_HARD_TIMEOUT,
)


REQUEST_SCHEMA_VERSION = "admissible_native_execution_request_v2"
RESULT_SCHEMA_VERSION = "admissible_native_execution_result_v2"
ARTIFACT_SCHEMA_VERSION = "admissible_native_execution_artifact_v2"
ATTESTATION_SCHEMA_VERSION = "admissible_native_backend_attestation_v1"
WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION_LEGACY_V1 = "admissible_cursor_wrapper_chain_attestation_v1"
WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION = "admissible_cursor_wrapper_chain_attestation_v2"
WINDOWS_COMMAND_RESOLUTION_SCHEMA_VERSION = "admissible_windows_command_resolution_authority_v1"
WINDOWS_WHERE_DIAGNOSTIC_SCHEMA_VERSION = "admissible_windows_where_diagnostic_v1"
ATTESTATION_CLASS_PACKAGE_BIN = "PACKAGE_BIN_PROVENANCE"
ATTESTATION_CLASS_WRAPPER_CHAIN = "LOCAL_WRAPPER_CHAIN"
CAPTURE_ATTEMPT_SCHEMA_VERSION = "admissible_native_capture_attempt_v1"
CAPTURE_ATTEMPT_SCHEMA_VERSION_V2 = "admissible_native_capture_attempt_v2"
CAPTURE_EXPECTED_SUCCESS_STATUS = "CHECKPOINT_CAPTURED"
TERMINAL_SCHEMA_VERSION = "admissible_native_canary_terminal_v1"
TERMINAL_SCHEMA_VERSION_V2 = "admissible_native_canary_terminal_v2"
ATTEMPT_RESERVED_SCHEMA_VERSION = "admissible_native_attempt_reserved_v1"
PROCESS_STARTED_SCHEMA_VERSION = "admissible_native_process_started_v1"
PROCESS_OBSERVATION_SCHEMA_VERSION = "admissible_native_process_observation_v1"
EXECUTION_ELIGIBILITY_SCHEMA_VERSION = "admissible_native_execution_eligibility_v1"
SELECTED_VERSION_MTIME_DIAGNOSTIC = "selected_version:METADATA_ONLY_DRIFT"
FUTURE_ATTESTATION_REFRESH_DIAGNOSTIC = "selected_version:METADATA_ONLY_DRIFT:FUTURE_ATTESTATION_REFRESH_REQUIRED"
BACKEND_IDENTITY = "cursor-agent-native-oneshot"
BACKEND_PROTOCOL_VERSION = "cursor-agent-print-force-v2"
CURSOR_DISCOVERY_MECHANISM = "shutil.which:cursor-agent"
WRAPPER_CHAIN_DISCOVERY_MECHANISM = "deterministic-windows-path-pathext+shutil.which+powershell-get-command:cursor-agent"
CURSOR_DISCOVERY_COMMAND = "cursor-agent"
WRAPPER_CHAIN_READY_REASON = "LOCAL_CURSOR_WRAPPER_CHAIN_ATTESTED_FOR_EXPERIMENT"
WRAPPER_CHAIN_BLOCKED_REASON = "LOCAL_WRAPPER_CHAIN_ATTESTATION_BLOCKED"
PACKAGE_BIN_NON_CLAIMS: tuple[str, ...] = (
    "publisher identity is not cryptographically established",
    "javascript payload integrity is locally hashed, not signed",
)
WRAPPER_CHAIN_NON_CLAIMS: tuple[str, ...] = (
    "anysphere publisher identity is not established",
    "ownership by the signed cursor desktop installation is not established",
    "package-manager or installer ownership is not established",
    "the javascript payload carries no verified signature",
    "native cli argument and capability behavior is experimentally unproven",
    "production trustworthiness is not established",
    "suitable only for an explicitly owner-authorized local experiment",
    "windows-wide command behavior outside the exact bound environment is not established",
    "protection against a hostile process modifying the environment is not established",
)
WRAPPER_CHAIN_CLAIMS: dict[str, bool] = {
    "deterministic_windows_path_pathext_resolution_established": True,
    "shutil_which_agreement_established": True,
    "powershell_inventory_agreement_established": True,
    "command_routing_chain_established": True,
    "local_file_identity_established": True,
    "deterministic_version_selection_established": True,
    "wrapper_stability_between_attestation_and_spawn_required": True,
    "publisher_provenance_established": False,
    "cursor_desktop_ownership_established": False,
    "package_manager_ownership_established": False,
    "javascript_payload_signature_present": False,
    "cli_capability_behavior_proven": False,
    "production_trustworthiness_established": False,
    "windows_wide_command_behavior_established": False,
    "hostile_environment_protection_established": False,
}
EXPECTED_CURSOR_PACKAGE_NAME = "@anysphere/agent-cli-runtime"
PROCESS_TREE_CLEANUP_POLICY = "managed-process-tree-hard-timeout-and-proven-empty"
NATIVE_PROMPT_HEADER = "You are the Admissible native coding agent."
DEFAULT_ENVIRONMENT_ALLOWLIST: tuple[str, ...] = (
    "APPDATA", "COMSPEC", "HOME", "HOMEDRIVE", "HOMEPATH", "LANG", "LC_ALL",
    "LOCALAPPDATA", "PATH", "PATHEXT", "SHELL", "SYSTEMROOT", "TEMP", "TMP",
    "TMPDIR", "USERPROFILE",
)
_HARDENED_GIT_ENVIRONMENT: dict[str, str] = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else os.devnull,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_PAGER": "",
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "core.fsmonitor",
    "GIT_CONFIG_VALUE_0": "false",
}
WINDOWS_SHELL_WRAPPER_SUFFIXES = (".bat", ".cmd", ".ps1")
_FLAG_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])(--[A-Za-z0-9][A-Za-z0-9-]*)")
_PROBE_LIMIT = 128 * 1024
_WINDOWS_PATH_SEPARATOR = ";"
_PATHEXT_COMPONENT = re.compile(r"\.[A-Za-z0-9]+\Z")


class NativePreflightStatus(str, Enum):
    PREFLIGHT_READY = "PREFLIGHT_READY"
    PREFLIGHT_BLOCKED = "PREFLIGHT_BLOCKED"


class NativeExecutionStatus(str, Enum):
    PROCESS_SUCCEEDED = "PROCESS_SUCCEEDED"
    PROCESS_FAILED = "PROCESS_FAILED"
    TIMED_OUT = "TIMED_OUT"
    CLEANUP_UNCERTAIN = "CLEANUP_UNCERTAIN"


class NativeCaptureTerminalStatus(str, Enum):
    PRECAPTURE_FAILED = "PRECAPTURE_FAILED"
    CAPTURE_FAILED = "CAPTURE_FAILED"
    DURABILITY_UNCERTAIN = "DURABILITY_UNCERTAIN"


class NativeExecutionStoreError(RuntimeError):
    pass


class NativeProcessStartError(RuntimeError):
    pass


class NativeResultIneligible(RuntimeError):
    """The process was observed, but the durable eligibility record rejected it."""

    def __init__(self, eligibility: "NativeExecutionEligibility") -> None:
        self.eligibility = eligibility
        super().__init__("; ".join(eligibility.ineligibility_reasons))


class NativeProcessObservationPublicationError(NativeExecutionStoreError):
    """A started process completed, but its observation could not be published."""


class NativeRequestAlreadyExists(NativeExecutionStoreError):
    pass


class NativeResultAlreadyExists(NativeExecutionStoreError):
    pass


class NativeEvidenceNotFound(NativeExecutionStoreError):
    pass


class NativeEvidenceInvalid(NativeExecutionStoreError):
    pass


class NativeCommittedButDurabilityUncertain(NativeExecutionStoreError):
    """Publication is visible, but its containing directory was not durable."""

    def __init__(self, *, operation: str, path: Path, original_error: BaseException) -> None:
        super().__init__(f"{operation} is visible but directory durability is uncertain: {path.name}")
        self.operation = operation
        self.path = path
        self.original_error = original_error


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_timestamp(value: Any, label: str) -> str:
    require_nonempty_text(value, label, max_bytes=64)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must carry a timezone")
    return value


def _is_redirecting_path(path: Path, metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    if getattr(metadata, "st_file_attributes", 0) & reparse_flag:
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction is not None and isjunction(os.fspath(path)))


def _lexical_absolute(value: str | Path, label: str) -> Path:
    if not isinstance(value, (str, Path)) or "\x00" in os.fspath(value):
        raise ValueError(f"{label} must be an absolute path")
    text = os.fspath(value)
    if not os.path.isabs(text):
        raise ValueError(f"{label} must be an absolute path")
    path = Path(os.path.abspath(text))
    if not path.anchor:
        raise ValueError(f"{label} has an ambiguous drive or root")
    return path


def _existing_components(path: Path, label: str) -> os.stat_result:
    """Reject every symlink, junction, reparse point, and bad parent component."""

    anchor = Path(path.anchor)
    current = anchor
    parts = path.parts[1:]
    if not parts:
        raise ValueError(f"{label} cannot be a filesystem root")
    final: os.stat_result | None = None
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError as exc:
            raise ValueError(f"{label} does not exist: {current}") from exc
        except OSError as exc:
            raise ValueError(f"{label} cannot be inspected: {exc}") from exc
        if _is_redirecting_path(current, metadata):
            raise ValueError(f"{label} contains a redirecting link or reparse point")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"{label} has a non-directory component")
        final = metadata
    assert final is not None
    return final


@dataclass(frozen=True)
class NativeFilesystemIdentity:
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    file_attributes: int

    @property
    def entry_kind(self) -> str:
        """Return the authority-bearing entry kind encoded by ``mode``."""

        if stat.S_ISREG(self.mode):
            return "REGULAR_FILE"
        if stat.S_ISDIR(self.mode):
            return "DIRECTORY"
        raise ValueError("filesystem identity entry kind is unsupported")

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> "NativeFilesystemIdentity":
        mode = int(metadata.st_mode)
        if stat.S_ISREG(mode):
            size = int(metadata.st_size)
        elif stat.S_ISDIR(mode):
            # Windows directory st_size is not a stable observation.  Directory
            # authority always carries the explicit canonical value zero.
            size = 0
        else:
            raise ValueError("filesystem identity entry kind is unsupported")
        return cls(
            device=int(metadata.st_dev),
            inode=int(metadata.st_ino),
            mode=mode,
            size=size,
            mtime_ns=int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))),
            file_attributes=int(getattr(metadata, "st_file_attributes", 0)),
        ).validated()

    def validated(self) -> "NativeFilesystemIdentity":
        for label, value in self.__dict__.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"filesystem identity {label} must be a non-negative integer")
        kind = self.entry_kind
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
        if self.file_attributes & reparse_flag:
            raise ValueError("filesystem identity cannot authorize a reparse point")
        if kind == "DIRECTORY" and self.size != 0:
            raise ValueError("filesystem identity directory size must be canonical zero")
        return self

    def to_dict(self) -> dict[str, int]:
        self.validated()
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeFilesystemIdentity":
        require_exact_keys(data, {"device", "inode", "mode", "size", "mtime_ns", "file_attributes"}, "filesystem identity")
        return cls(**dict(data)).validated()


def _same_directory_identity(left: NativeFilesystemIdentity, right: NativeFilesystemIdentity) -> bool:
    """Compare complete immutable directory authority, including mtime."""

    left.validated(); right.validated()
    if left.entry_kind != "DIRECTORY" or right.entry_kind != "DIRECTORY":
        raise ValueError("directory identity comparison requires directories")
    return left == right


def _same_mutable_directory_entry(left: NativeFilesystemIdentity, right: NativeFilesystemIdentity) -> bool:
    """Compare the physical entry for roots whose children intentionally change."""

    left.validated(); right.validated()
    if left.entry_kind != "DIRECTORY" or right.entry_kind != "DIRECTORY":
        raise ValueError("mutable directory comparison requires directories")
    return (
        left.device,
        left.inode,
        left.mode,
        left.file_attributes,
    ) == (
        right.device,
        right.inode,
        right.mode,
        right.file_attributes,
    )


def _safe_directory(value: str | Path, label: str) -> tuple[Path, NativeFilesystemIdentity]:
    path = _lexical_absolute(value, label)
    metadata = _existing_components(path, label)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be an existing non-redirecting directory")
    return path, NativeFilesystemIdentity.from_stat(metadata).validated()


def _safe_file(value: str | Path, label: str) -> tuple[Path, NativeFilesystemIdentity]:
    path = _lexical_absolute(value, label)
    metadata = _existing_components(path, label)
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be an existing non-redirecting regular file")
    return path, NativeFilesystemIdentity.from_stat(metadata).validated()


def _safe_create_directory(value: str | Path, label: str) -> tuple[Path, NativeFilesystemIdentity]:
    path = _lexical_absolute(value, label)
    parent = path.parent
    _safe_directory(parent, f"{label} parent")
    if path.exists():
        return _safe_directory(path, label)
    try:
        path.mkdir()
    except OSError as exc:
        raise NativeExecutionStoreError(f"cannot create {label}: {exc}") from exc
    return _safe_directory(path, label)


def _inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _require_disjoint_roots(*roots: tuple[str, Path]) -> None:
    for index, (left_label, left) in enumerate(roots):
        for right_label, right in roots[index + 1:]:
            if _inside(left, right) or _inside(right, left):
                raise NativeEvidenceInvalid(f"{left_label} and {right_label} must be distinct non-overlapping roots")


def _safe_artifact_directory(store_root: str | Path, value: str | Path) -> tuple[Path, NativeFilesystemIdentity]:
    """Require an already-created, bounded artifact child before spawn."""

    root, _ = _safe_directory(store_root, "execution evidence root")
    candidate = _lexical_absolute(value, "native artifact directory")
    if candidate == root or not _inside(candidate, root):
        raise NativeEvidenceInvalid("native artifact directory must be a bounded child of the execution evidence root")
    artifacts, identity = _safe_directory(candidate, "native artifact directory")
    if not _inside(artifacts, root):
        raise NativeEvidenceInvalid("native artifact directory escapes the execution evidence root")
    return artifacts, identity


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_argv(value: tuple[str, ...], label: str) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        raise ValueError(f"{label} must be a non-empty immutable argv")
    for item in value:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise ValueError(f"{label} contains an invalid argument")
        if len(item.encode("utf-8")) > 256 * 1024:
            raise ValueError(f"{label} contains an oversized argument")
    if sum(len(item.encode("utf-8")) for item in value) > 512 * 1024:
        raise ValueError(f"{label} exceeds its total byte bound")
    return value


@dataclass(frozen=True)
class CursorNativeBackendConfig:
    """Requested Cursor mode. It becomes authority only after local attestation."""

    executable: str
    launcher_prefix: tuple[str, ...] = ()
    model: str = "auto"
    environment_allowlist: tuple[str, ...] = DEFAULT_ENVIRONMENT_ALLOWLIST
    attestation_class: str = ATTESTATION_CLASS_PACKAGE_BIN

    def __post_init__(self) -> None:
        if not isinstance(self.executable, str) or not self.executable or "\x00" in self.executable:
            raise ValueError("a native Cursor executable is required")
        if self.attestation_class not in {ATTESTATION_CLASS_PACKAGE_BIN, ATTESTATION_CLASS_WRAPPER_CHAIN}:
            raise ValueError("unsupported native attestation class")
        if self.attestation_class == ATTESTATION_CLASS_WRAPPER_CHAIN and (
            self.executable != CURSOR_DISCOVERY_COMMAND or self.launcher_prefix
        ):
            # Wrapper-chain mode derives every launcher file from canonical
            # host command discovery; a caller-supplied root or prefix is not
            # an acceptable substitute for the winning OS resolution.
            raise ValueError("wrapper-chain attestation accepts only the bare canonical cursor-agent command")
        _validate_argv((self.executable, *self.launcher_prefix), "Cursor launcher")
        require_nonempty_text(self.model, "Cursor model", max_bytes=256)
        if not isinstance(self.environment_allowlist, tuple) or not self.environment_allowlist:
            raise ValueError("environment allowlist must be a non-empty tuple")
        for name in self.environment_allowlist:
            if not isinstance(name, str) or not name or not name.replace("_", "").isalnum():
                raise ValueError("environment allowlist contains an invalid name")

    def build_environment(self, *, base: Mapping[str, str] | None = None) -> dict[str, str]:
        source = os.environ if base is None else base
        allowed = {name.upper() for name in self.environment_allowlist}
        return {key: value for key, value in source.items() if key.upper() in allowed}


def _hardened_git_environment(
    *, base: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Return a child-only environment that cannot consult owner Git config."""

    environment = dict(os.environ if base is None else base)
    environment.update(_HARDENED_GIT_ENVIRONMENT)
    return environment


@dataclass(frozen=True)
class NativeBackendFileAttestation:
    canonical_path: str
    sha256: str
    byte_count: int
    filesystem_identity: NativeFilesystemIdentity

    @classmethod
    def observe(cls, value: str | Path, label: str) -> "NativeBackendFileAttestation":
        path, identity = _safe_file(value, label)
        return cls(str(path), _sha256_file(path), identity.size, identity).validated()

    def validated(self) -> "NativeBackendFileAttestation":
        path, identity = _safe_file(self.canonical_path, "attested backend file")
        if str(path) != self.canonical_path or identity != self.filesystem_identity:
            raise ValueError("attested backend file identity changed")
        require_sha256(self.sha256, "backend file sha256")
        require_strict_int(self.byte_count, "backend file byte_count", minimum=0, maximum=2**63 - 1)
        if self.byte_count != identity.size or _sha256_file(path) != self.sha256:
            raise ValueError("attested backend file hash changed")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {"canonical_path": self.canonical_path, "sha256": self.sha256, "byte_count": self.byte_count, "filesystem_identity": self.filesystem_identity.to_dict()}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeBackendFileAttestation":
        require_exact_keys(data, {"canonical_path", "sha256", "byte_count", "filesystem_identity"}, "backend file attestation")
        return cls(
            canonical_path=data["canonical_path"], sha256=data["sha256"], byte_count=data["byte_count"],
            filesystem_identity=NativeFilesystemIdentity.from_dict(data["filesystem_identity"]),
        ).validated()


@dataclass(frozen=True)
class CursorInstallationProvenance:
    """Locally measured Cursor Agent installation chain, not publisher proof.

    The native canary deliberately accepts only the installed ``cursor-agent``
    command discovered by the host, then requires its selected runtime package
    to declare the launcher used by the bounded argv.  This is a local
    installation-chain attestation; it is not a cryptographic publisher claim.
    """

    discovery_mechanism: str
    discovered_shim: NativeBackendFileAttestation
    installation_root: str
    installation_root_identity: NativeFilesystemIdentity
    package_root: str
    package_root_identity: NativeFilesystemIdentity
    package_manifest: NativeBackendFileAttestation
    package_name: str
    bin_command: str
    bin_relative_path: str
    launcher: NativeBackendFileAttestation

    def _body(self) -> dict[str, Any]:
        return {
            "discovery_mechanism": self.discovery_mechanism,
            "discovered_shim": self.discovered_shim.to_dict(),
            "installation_root": self.installation_root,
            "installation_root_identity": self.installation_root_identity.to_dict(),
            "package_root": self.package_root,
            "package_root_identity": self.package_root_identity.to_dict(),
            "package_manifest": self.package_manifest.to_dict(),
            "package_name": self.package_name,
            "bin_command": self.bin_command,
            "bin_relative_path": self.bin_relative_path,
            "launcher": self.launcher.to_dict(),
        }

    def validated(self) -> "CursorInstallationProvenance":
        if self.discovery_mechanism != CURSOR_DISCOVERY_MECHANISM:
            raise ValueError("unsupported Cursor discovery mechanism")
        self.discovered_shim.validated()
        installation_root, installation_identity = _safe_directory(self.installation_root, "Cursor installation root")
        package_root, package_identity = _safe_directory(self.package_root, "Cursor package root")
        if (
            str(installation_root) != self.installation_root
            or not _same_directory_identity(installation_identity, self.installation_root_identity)
            or str(package_root) != self.package_root
            or not _same_directory_identity(package_identity, self.package_root_identity)
        ):
            raise ValueError("Cursor installation provenance directory identity changed")
        if not _inside(package_root, installation_root):
            raise ValueError("Cursor package root is outside discovered installation root")
        self.package_manifest.validated()
        self.launcher.validated()
        if Path(self.package_manifest.canonical_path) != package_root / "package.json":
            raise ValueError("Cursor package manifest is not the package-root manifest")
        if not _inside(Path(self.launcher.canonical_path), package_root):
            raise ValueError("Cursor launcher is outside the attested package root")
        if self.package_name != EXPECTED_CURSOR_PACKAGE_NAME:
            raise ValueError("unexpected local Cursor Agent package identity")
        if self.bin_command != CURSOR_DISCOVERY_COMMAND:
            raise ValueError("Cursor package bin command differs from canonical discovery command")
        require_safe_relative_path(self.bin_relative_path, "Cursor package bin path")
        try:
            manifest = json.loads(Path(self.package_manifest.canonical_path).read_text(encoding="utf-8"))
        except (OSError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cursor package manifest is unreadable: {exc}") from exc
        if not isinstance(manifest, Mapping) or manifest.get("name") != self.package_name:
            raise ValueError("Cursor package manifest identity differs from provenance")
        declared_bin = manifest.get("bin")
        if isinstance(declared_bin, str):
            mapping = {CURSOR_DISCOVERY_COMMAND: declared_bin}
        elif isinstance(declared_bin, Mapping):
            mapping = dict(declared_bin)
        else:
            raise ValueError("Cursor package manifest lacks a bin mapping")
        if mapping.get(self.bin_command) != self.bin_relative_path:
            raise ValueError("Cursor package bin mapping differs from provenance")
        launcher, _ = _safe_file(package_root / self.bin_relative_path, "Cursor package launcher")
        if str(launcher) != self.launcher.canonical_path:
            raise ValueError("Cursor package bin mapping does not resolve to the attested launcher")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self._body()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CursorInstallationProvenance":
        require_exact_keys(
            data,
            {
                "discovery_mechanism", "discovered_shim", "installation_root", "installation_root_identity",
                "package_root", "package_root_identity", "package_manifest", "package_name", "bin_command",
                "bin_relative_path", "launcher",
            },
            "Cursor installation provenance",
        )
        values = dict(data)
        for key in ("discovered_shim", "package_manifest", "launcher"):
            values[key] = NativeBackendFileAttestation.from_dict(data[key])
        for key in ("installation_root_identity", "package_root_identity"):
            values[key] = NativeFilesystemIdentity.from_dict(data[key])
        return cls(**values).validated()


_VERSION_DIR_PATTERN = re.compile(r"^\d{4}\.\d{1,2}\.\d{1,2}(-\d{2}-\d{2}-\d{2})?-[a-f0-9]+$")
_CMD_BANNED_CHARACTERS = re.compile(r"[&|<>^!]")
_CMD_INVOCATION_PATTERN = re.compile(
    r'%SystemRoot%\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe'
    r' -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\\(?P<target>[A-Za-z0-9][A-Za-z0-9._-]*\.ps1)" %\*'
)
# The exact locally observed Anysphere launcher grammar, normalized by
# removing comment-only and blank lines.  The recognizer accepts nothing else:
# any added executable behavior changes at least one non-comment line.
_POWERSHELL_WRAPPER_TEMPLATE_LINES: tuple[str, ...] = (
    "if (-not $env:CURSOR_INVOKED_AS) {",
    "    $env:CURSOR_INVOKED_AS = Split-Path -leaf $MyInvocation.MyCommand.Name",
    "}",
    "$scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition",
    "function Parse-VersionString {",
    "    param (",
    "        [string]$versionString",
    "    )",
    "    $datePart = $versionString.Split('-')[0]",
    "    $parts = $datePart.Split('.')",
    "    if ($parts.Length -ne 3) {",
    '        throw "Invalid version format. Expected format: YYYY.MM.DD-commit"',
    "    }",
    "    $year = $parts[0]",
    "    $month = $parts[1].PadLeft(2, '0')",
    "    $day = $parts[2].PadLeft(2, '0')",
    "    return [int]($year + $month + $day)",
    "}",
    "if (-not $env:NODE_COMPILE_CACHE) {",
    '    $env:NODE_COMPILE_CACHE = "$env:LOCALAPPDATA\\cursor-compile-cache"',
    "}",
    'if (Test-Path "$scriptPath\\node.exe") {',
    '    & "$scriptPath\\node.exe" "$scriptPath\\index.js" $args',
    "    exit $LASTEXITCODE",
    "}",
    '$versionDir = Get-ChildItem -Path "$scriptPath\\versions" -Directory |',
    "    Where-Object {",
    "        $name = $_.Name",
    "        $name -match '^\\d{4}\\.\\d{1,2}\\.\\d{1,2}(-\\d{2}-\\d{2}-\\d{2})?-[a-f0-9]+$'",
    "    } |",
    "    Sort-Object { Parse-VersionString $_.Name } -Descending |",
    "    Select-Object -First 1",
    "if (-not $versionDir) {",
    '    Write-Error "No version directories found in $scriptPath"',
    "    exit 1",
    "}",
    "$versionName = $versionDir.Name",
    '$nodePath = "$scriptPath\\versions\\$versionName\\node.exe"',
    '& "$nodePath" "$scriptPath\\versions\\$versionName\\index.js" $args',
    "exit $LASTEXITCODE",
)


def _parse_cmd_wrapper(data: bytes, *, wrapper_name: str) -> dict[str, Any]:
    """Strict recognizer for the exact observed cursor-agent.cmd semantics.

    This is deliberately not a batch interpreter.  Anything beyond the audited
    ``powershell.exe -NoProfile ... adjacent .ps1 %*`` forwarding shape fails.
    """

    if not isinstance(data, bytes) or len(data) > 8192:
        raise ValueError("cmd wrapper bytes are missing or oversized")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("cmd wrapper must be plain ASCII") from exc
    if _CMD_BANNED_CHARACTERS.search(text):
        raise ValueError("cmd wrapper contains shell operators, chaining, or redirection")
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    body = [line for line in lines if line.strip() and not line.strip().upper().startswith("REM ")]
    if len(body) != 6:
        raise ValueError("cmd wrapper command structure differs from the audited grammar")
    if body[0].lower() != "@echo off" or body[1].lower() != "setlocal enabledelayedexpansion":
        raise ValueError("cmd wrapper prologue differs from the audited grammar")
    if body[2] != 'set "CURSOR_INVOKED_AS=%~nx0"' or body[3] != 'set "SCRIPT_DIR=%~dp0"':
        raise ValueError("cmd wrapper variable derivation differs from the audited grammar")
    if body[4] != 'if "%SCRIPT_DIR:~-1%"=="\\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"':
        raise ValueError("cmd wrapper directory normalization differs from the audited grammar")
    invocation = _CMD_INVOCATION_PATTERN.fullmatch(body[5])
    if invocation is None:
        raise ValueError("cmd wrapper does not perform the single audited adjacent PowerShell invocation")
    target = invocation.group("target")
    expected = f"{Path(wrapper_name).stem}.ps1"
    if target != expected:
        raise ValueError("cmd wrapper targets a PowerShell script other than its adjacent same-name wrapper")
    return {
        "wrapper_kind": "cmd",
        "interpreter": "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "no_profile": True,
        "execution_policy": "Bypass",
        "adjacent_powershell_target": target,
        "argument_forwarding": "%*",
        "changes_cwd": False,
        "extra_commands": 0,
        "shell_operators": 0,
    }


def _parse_powershell_wrapper(data: bytes) -> dict[str, Any]:
    """Bounded recognizer for the observed version-selecting launcher script.

    It accepts exactly the audited statement sequence and fails closed on any
    unrecognized executable behavior; it does not interpret PowerShell.
    """

    if not isinstance(data, bytes) or len(data) > 64 * 1024:
        raise ValueError("PowerShell wrapper bytes are missing or oversized")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("PowerShell wrapper must be UTF-8 text") from exc
    if "<#" in text or '@"' in text or "@'" in text:
        raise ValueError("PowerShell wrapper contains block comments or here-strings outside the audited grammar")
    normalized: list[str] = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.endswith("`"):
            raise ValueError("PowerShell wrapper uses line continuation outside the audited grammar")
        normalized.append(line)
    if tuple(normalized) != _POWERSHELL_WRAPPER_TEMPLATE_LINES:
        raise ValueError("PowerShell wrapper contains executable behavior outside the audited launcher grammar")
    grammar_line = next(line for line in normalized if "-match" in line)
    grammar = grammar_line.strip()[len("$name -match '"):-1]
    if grammar != _VERSION_DIR_PATTERN.pattern:
        raise ValueError("PowerShell wrapper version grammar differs from the audited pattern")
    return {
        "wrapper_kind": "powershell",
        "derives_own_directory": True,
        "adjacent_node_shortcut": True,
        "version_enumeration_root": "versions",
        "version_name_grammar": grammar,
        "ordering": "date-integer-descending",
        "selection": "latest-single",
        "executes": "selected-version node.exe index.js",
        "argument_forwarding": "$args",
        "network_actions": 0,
        "installer_actions": 0,
        "leaves_wrapper_root": False,
    }


def _wrapper_version_key(name: str) -> int:
    year, month, day = name.split("-")[0].split(".")
    return int(year + month.zfill(2) + day.zfill(2))


def _select_wrapper_version(wrapper_root: Path) -> tuple[tuple[str, ...], str]:
    """Recompute the wrapper's deterministic latest-version selection."""

    versions_dir, _ = _safe_directory(wrapper_root / "versions", "Cursor versions directory")
    names: list[str] = []
    for child in sorted(versions_dir.iterdir(), key=lambda item: item.name):
        if not _VERSION_DIR_PATTERN.match(child.name):
            continue
        metadata = os.lstat(child)
        if _is_redirecting_path(child, metadata):
            raise ValueError("Cursor version directory contains a redirecting link or reparse point")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Cursor version candidate is not a plain directory")
        names.append(child.name)
    if not names:
        raise ValueError("no Cursor version directory matches the audited wrapper grammar")
    best = max(_wrapper_version_key(name) for name in names)
    winners = [name for name in names if _wrapper_version_key(name) == best]
    if len(winners) != 1:
        raise ValueError("Cursor version selection is ambiguous for the audited wrapper ordering")
    return tuple(names), winners[0]


@dataclass(frozen=True)
class PowerShellCommandObservation:
    candidates: tuple[tuple[str, str, str], ...]
    preferred: tuple[str, str, str] | None


@dataclass(frozen=True)
class WhereCommandObservation:
    executable: str | None
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    execution_error: bool = False


class WrapperChainDiscovery(Protocol):
    """Host command-resolution surface for wrapper-chain attestation.

    Tests may substitute a deterministic fake adapter only through the private
    attestor.  The production CLI exposes no discovery or environment seam.
    """

    def which_cursor_agent(self, *, path_value: str, pathext_value: str) -> str | None: ...
    def powershell_cursor_agent(self) -> PowerShellCommandObservation | None: ...
    def where_cursor_agent(self) -> WhereCommandObservation: ...
    def path_value(self) -> str: ...
    def pathext_value(self) -> str: ...
    def node_signature_context(self, node_path: Path) -> str: ...


class HostWrapperChainDiscovery:
    """Real host discovery for cursor-agent; never executes the wrapper bundle."""

    @staticmethod
    def _bounded_bytes(argv: list[str]) -> tuple[int, bytes, bytes] | None:
        try:
            completed = subprocess.run(
                argv, shell=False, check=False, capture_output=True, timeout=20,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if len(completed.stdout) > _PROBE_LIMIT or len(completed.stderr) > _PROBE_LIMIT:
            return None
        return completed.returncode, completed.stdout, completed.stderr

    @classmethod
    def _bounded_lines(cls, argv: list[str]) -> tuple[str, ...] | None:
        observed = cls._bounded_bytes(argv)
        if observed is None or observed[0] != 0:
            return None
        return tuple(
            line.strip()
            for line in observed[1].decode("utf-8", errors="replace").splitlines()
            if line.strip()
        )

    def which_cursor_agent(self, *, path_value: str, pathext_value: str) -> str | None:
        if os.environ.get("PATH", "") != path_value or os.environ.get("PATHEXT", "") != pathext_value:
            raise ValueError("PATH or PATHEXT changed before shutil.which observation")
        located = shutil.which(CURSOR_DISCOVERY_COMMAND, path=path_value)
        if os.environ.get("PATH", "") != path_value or os.environ.get("PATHEXT", "") != pathext_value:
            raise ValueError("PATH or PATHEXT changed during shutil.which observation")
        return located

    def powershell_cursor_agent(self) -> PowerShellCommandObservation | None:
        command = (
            "$items = @(Get-Command cursor-agent -All -ErrorAction SilentlyContinue); "
            "foreach ($item in $items) { "
            "$path = if ($null -ne $item.Path) { [string]$item.Path } else { '' }; "
            "[Console]::Out.WriteLine(([string]$item.CommandType) + \"`t\" + "
            "([string]$item.Name) + \"`t\" + $path) }"
        )
        observed = self._bounded_bytes([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command,
        ])
        if observed is None or observed[0] != 0:
            return None
        rows: list[tuple[str, str, str]] = []
        for line in observed[1].decode("utf-8", errors="replace").splitlines():
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) != 3:
                raise ValueError("PowerShell command inventory emitted an unsupported record")
            rows.append((parts[0], parts[1], parts[2]))
        candidates = tuple(rows)
        return PowerShellCommandObservation(candidates, candidates[0] if candidates else None)

    def where_cursor_agent(self) -> WhereCommandObservation:
        located = shutil.which("where.exe")
        if located is None:
            return WhereCommandObservation(None, ("where.exe", CURSOR_DISCOVERY_COMMAND), None, b"", b"")
        try:
            where_file = _canonical_backend_file(located, "where.exe diagnostic executable")
        except (OSError, ValueError) as exc:
            return WhereCommandObservation(
                None, (located, CURSOR_DISCOVERY_COMMAND), None, b"", str(exc).encode("utf-8"), True,
            )
        argv = (where_file.canonical_path, CURSOR_DISCOVERY_COMMAND)
        try:
            completed = subprocess.run(
                list(argv), shell=False, check=False, capture_output=True, timeout=20,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return WhereCommandObservation(
                where_file.canonical_path, argv, None,
                bytes(getattr(exc, "stdout", None) or b""),
                bytes(getattr(exc, "stderr", None) or str(exc).encode("utf-8")), True,
            )
        return WhereCommandObservation(
            where_file.canonical_path, argv, completed.returncode, completed.stdout, completed.stderr,
        )

    def path_value(self) -> str:
        return os.environ.get("PATH", "")

    def pathext_value(self) -> str:
        return os.environ.get("PATHEXT", "")

    def node_signature_context(self, node_path: Path) -> str:
        text = os.fspath(node_path)
        if "'" in text or "\x00" in text:
            return "signature-context-unavailable"
        lines = self._bounded_lines([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            f"$s = Get-AuthenticodeSignature -LiteralPath '{text}'; Write-Output ($s.Status.ToString() + '|' + [string]$s.SignerCertificate.Subject)",
        ])
        if not lines:
            return "signature-context-unavailable"
        return "|".join(lines)[:512]


def _normalized_path(value: str) -> str:
    return ntpath.normcase(ntpath.abspath(value)).casefold()


def _canonical_backend_file(value: str | Path, label: str) -> NativeBackendFileAttestation:
    path, _identity = _safe_file(value, label)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} cannot be canonically resolved: {exc}") from exc
    canonical, _canonical_identity = _safe_file(resolved, label)
    return NativeBackendFileAttestation.observe(canonical, label)


def _same_file_authority(left: NativeBackendFileAttestation, right: NativeBackendFileAttestation) -> bool:
    left.validated(); right.validated()
    return (
        _normalized_path(left.canonical_path) == _normalized_path(right.canonical_path)
        and left.filesystem_identity == right.filesystem_identity
        and left.byte_count == right.byte_count
        and left.sha256 == right.sha256
    )


@dataclass(frozen=True)
class WindowsPathCandidate:
    path_entry_index: int
    pathext_index: int
    path_entry: str
    extension: str
    file: NativeBackendFileAttestation

    def validated(self) -> "WindowsPathCandidate":
        require_strict_int(self.path_entry_index, "PATH candidate entry index", minimum=0, maximum=65535)
        require_strict_int(self.pathext_index, "PATH candidate PATHEXT index", minimum=0, maximum=1023)
        require_nonempty_text(self.path_entry, "PATH candidate entry", max_bytes=32768)
        require_nonempty_text(self.extension, "PATH candidate extension", max_bytes=256)
        self.file.validated()
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {
            "path_entry_index": self.path_entry_index, "pathext_index": self.pathext_index,
            "path_entry": self.path_entry, "extension": self.extension, "file": self.file.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WindowsPathCandidate":
        require_exact_keys(data, set(cls.__dataclass_fields__), "Windows PATH candidate")
        return cls(
            data["path_entry_index"], data["pathext_index"], data["path_entry"], data["extension"],
            NativeBackendFileAttestation.from_dict(data["file"]),
        ).validated()


@dataclass(frozen=True)
class DeterministicWindowsCommandResolution:
    schema_version: str
    command: str
    path_entries: tuple[str, ...]
    path_sha256: str
    pathext: tuple[str, ...]
    pathext_sha256: str
    authoritative_path_entry: str
    authoritative_path_index: int
    winning_extension: str
    winning_pathext_index: int
    material_candidates: tuple[WindowsPathCandidate, ...]
    winner: NativeBackendFileAttestation

    def validated(self) -> "DeterministicWindowsCommandResolution":
        if self.schema_version != WINDOWS_COMMAND_RESOLUTION_SCHEMA_VERSION or self.command != CURSOR_DISCOVERY_COMMAND:
            raise ValueError("unsupported deterministic Windows command resolution")
        if not isinstance(self.path_entries, tuple) or not self.path_entries:
            raise ValueError("deterministic PATH must be a non-empty immutable sequence")
        if len(self.path_entries) > 4096 or sum(len(item.encode("utf-8")) for item in self.path_entries) > 1024 * 1024:
            raise ValueError("deterministic PATH exceeds its authority bound")
        if any(not isinstance(item, str) or "\x00" in item for item in self.path_entries):
            raise ValueError("deterministic PATH contains an invalid component")
        if any(item and (not ntpath.isabs(item) or '"' in item) for item in self.path_entries):
            raise ValueError("deterministic PATH contains a relative or malformed component")
        require_sha256(self.path_sha256, "deterministic PATH fingerprint")
        if hashlib.sha256(_WINDOWS_PATH_SEPARATOR.join(self.path_entries).encode("utf-8", "surrogatepass")).hexdigest() != self.path_sha256:
            raise ValueError("deterministic PATH fingerprint mismatch")
        if not isinstance(self.pathext, tuple) or not self.pathext:
            raise ValueError("deterministic PATHEXT must be a non-empty immutable sequence")
        if len(self.pathext) > 128 or sum(len(item.encode("utf-8")) for item in self.pathext) > 32768:
            raise ValueError("deterministic PATHEXT exceeds its authority bound")
        if any(not isinstance(item, str) or not _PATHEXT_COMPONENT.fullmatch(item) for item in self.pathext):
            raise ValueError("deterministic PATHEXT contains a malformed component")
        if len({item.casefold() for item in self.pathext}) != len(self.pathext):
            raise ValueError("deterministic PATHEXT contains a duplicate component")
        require_sha256(self.pathext_sha256, "deterministic PATHEXT fingerprint")
        if hashlib.sha256(_WINDOWS_PATH_SEPARATOR.join(self.pathext).encode("utf-8", "surrogatepass")).hexdigest() != self.pathext_sha256:
            raise ValueError("deterministic PATHEXT fingerprint mismatch")
        require_strict_int(self.authoritative_path_index, "authoritative PATH index", minimum=0, maximum=len(self.path_entries) - 1)
        require_strict_int(self.winning_pathext_index, "winning PATHEXT index", minimum=0, maximum=len(self.pathext) - 1)
        if self.authoritative_path_entry != self.path_entries[self.authoritative_path_index]:
            raise ValueError("authoritative PATH entry/index binding differs")
        if self.winning_extension != self.pathext[self.winning_pathext_index]:
            raise ValueError("winning PATHEXT entry/index binding differs")
        if not isinstance(self.material_candidates, tuple) or not self.material_candidates:
            raise ValueError("deterministic resolution lacks its material winner candidate")
        self.winner.validated()
        for item in self.material_candidates:
            item.validated()
            if (
                item.path_entry_index != self.authoritative_path_index
                or item.pathext_index != self.winning_pathext_index
                or item.path_entry != self.authoritative_path_entry
                or item.extension != self.winning_extension
                or not _same_file_authority(item.file, self.winner)
            ):
                raise ValueError("material PATH candidate differs from the deterministic winner")
        winner_path = Path(self.winner.canonical_path)
        if winner_path.stem.casefold() != self.command.casefold() or winner_path.suffix.casefold() != self.winning_extension.casefold():
            raise ValueError("deterministic winner name or extension differs")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {
            "schema_version": self.schema_version, "command": self.command,
            "path_entries": list(self.path_entries), "path_sha256": self.path_sha256,
            "pathext": list(self.pathext), "pathext_sha256": self.pathext_sha256,
            "authoritative_path_entry": self.authoritative_path_entry,
            "authoritative_path_index": self.authoritative_path_index,
            "winning_extension": self.winning_extension,
            "winning_pathext_index": self.winning_pathext_index,
            "material_candidates": [item.to_dict() for item in self.material_candidates],
            "winner": self.winner.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DeterministicWindowsCommandResolution":
        require_exact_keys(data, set(cls.__dataclass_fields__), "deterministic Windows command resolution")
        return cls(
            schema_version=data["schema_version"], command=data["command"],
            path_entries=require_string_list(data["path_entries"], "path_entries"),
            path_sha256=data["path_sha256"], pathext=require_string_list(data["pathext"], "pathext"),
            pathext_sha256=data["pathext_sha256"], authoritative_path_entry=data["authoritative_path_entry"],
            authoritative_path_index=data["authoritative_path_index"], winning_extension=data["winning_extension"],
            winning_pathext_index=data["winning_pathext_index"],
            material_candidates=tuple(WindowsPathCandidate.from_dict(item) for item in data["material_candidates"]),
            winner=NativeBackendFileAttestation.from_dict(data["winner"]),
        ).validated()


def _deterministic_windows_resolve(
    *, command: str, path_value: str, pathext_value: str,
) -> DeterministicWindowsCommandResolution:
    if command != CURSOR_DISCOVERY_COMMAND or ntpath.isabs(command) or ntpath.dirname(command) or "/" in command or "\\" in command:
        raise ValueError("deterministic resolver accepts only the fixed bare cursor-agent command")
    if not isinstance(path_value, str) or "\x00" in path_value:
        raise ValueError("PATH is malformed")
    if len(path_value.encode("utf-8", "surrogatepass")) > 1024 * 1024:
        raise ValueError("PATH exceeds the deterministic resolver bound")
    path_entries = tuple(path_value.split(_WINDOWS_PATH_SEPARATOR))
    if not path_entries:
        raise ValueError("PATH is empty")
    for entry in path_entries:
        if entry and (not ntpath.isabs(entry) or '"' in entry):
            raise ValueError("PATH contains a relative or malformed component")
    if not isinstance(pathext_value, str) or "\x00" in pathext_value:
        raise ValueError("PATHEXT is malformed")
    if len(pathext_value.encode("utf-8", "surrogatepass")) > 32768:
        raise ValueError("PATHEXT exceeds the deterministic resolver bound")
    pathext = tuple(pathext_value.split(_WINDOWS_PATH_SEPARATOR))
    if not pathext or any(not item or not _PATHEXT_COMPONENT.fullmatch(item) for item in pathext):
        raise ValueError("PATHEXT contains an empty or malformed component")
    if len({item.casefold() for item in pathext}) != len(pathext):
        raise ValueError("PATHEXT contains duplicate case-insensitive components")
    path_hash = hashlib.sha256(path_value.encode("utf-8", "surrogatepass")).hexdigest()
    pathext_hash = hashlib.sha256(pathext_value.encode("utf-8", "surrogatepass")).hexdigest()
    for path_index, entry in enumerate(path_entries):
        entry_path = Path.cwd() if not entry else Path(os.path.abspath(entry))
        if not entry_path.exists():
            continue
        try:
            directory, _identity = _safe_directory(entry_path, f"authoritative PATH entry {path_index}")
        except ValueError as exc:
            try:
                unsafe_children = tuple(entry_path.iterdir()) if entry_path.is_dir() else ()
            except OSError as observation_error:
                raise ValueError(
                    f"unsafe PATH entry {path_index} cannot be shown irrelevant to command resolution"
                ) from observation_error
            expected_names = {(command + extension).casefold() for extension in pathext}
            if any(child.name.casefold() in expected_names for child in unsafe_children):
                raise ValueError(
                    f"redirecting or malformed PATH entry {path_index} would affect the cursor-agent winner"
                ) from exc
            continue
        try:
            children = tuple(directory.iterdir())
        except OSError as exc:
            raise ValueError(f"authoritative PATH entry {path_index} cannot be enumerated: {exc}") from exc
        for extension_index, extension in enumerate(pathext):
            expected_name = (command + extension).casefold()
            matches = tuple(child for child in children if child.name.casefold() == expected_name)
            if not matches:
                continue
            if not entry:
                raise ValueError("an empty PATH component would affect the cursor-agent winner")
            observed = tuple(
                _canonical_backend_file(child, "deterministic PATH command candidate")
                for child in sorted(matches, key=lambda item: (item.name.casefold(), item.name))
            )
            first = observed[0]
            if any(not _same_file_authority(first, item) for item in observed[1:]):
                raise ValueError("multiple case variants at one PATH/PATHEXT precedence position have conflicting identities")
            material = tuple(
                WindowsPathCandidate(path_index, extension_index, entry, extension, item).validated()
                for item in observed
            )
            return DeterministicWindowsCommandResolution(
                WINDOWS_COMMAND_RESOLUTION_SCHEMA_VERSION, command, path_entries, path_hash,
                pathext, pathext_hash, entry, path_index, extension, extension_index,
                material, first,
            ).validated()
    raise ValueError("deterministic Windows PATH/PATHEXT resolution found no cursor-agent command")


@dataclass(frozen=True)
class PowerShellCommandCandidate:
    command_type: str
    name: str
    file: NativeBackendFileAttestation

    def validated(self) -> "PowerShellCommandCandidate":
        require_nonempty_text(self.command_type, "PowerShell command type", max_bytes=128)
        require_nonempty_text(self.name, "PowerShell command name", max_bytes=1024)
        self.file.validated()
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {"command_type": self.command_type, "name": self.name, "file": self.file.to_dict()}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PowerShellCommandCandidate":
        require_exact_keys(data, set(cls.__dataclass_fields__), "PowerShell command candidate")
        return cls(
            data["command_type"], data["name"], NativeBackendFileAttestation.from_dict(data["file"]),
        ).validated()


def _powershell_candidate_key(item: PowerShellCommandCandidate) -> tuple[str, str, str]:
    return (_normalized_path(item.file.canonical_path), item.command_type.casefold(), item.name.casefold())


@dataclass(frozen=True)
class CursorWrapperChainResolution:
    """v2 command authority: deterministic PATH/PATHEXT plus independent agreement."""

    discovery_mechanism: str
    command: str
    deterministic: DeterministicWindowsCommandResolution
    shutil_which_winner: NativeBackendFileAttestation
    powershell_inventory: tuple[PowerShellCommandCandidate, ...]
    powershell_preferred: PowerShellCommandCandidate
    powershell_prefers_powershell_wrapper: bool
    wrapper_root: str
    wrapper_root_identity: NativeFilesystemIdentity

    @property
    def winning_cmd(self) -> NativeBackendFileAttestation:
        return self.deterministic.winner

    @property
    def which_path(self) -> str:
        return self.shutil_which_winner.canonical_path

    @property
    def powershell_paths(self) -> tuple[str, ...]:
        return tuple(item.file.canonical_path for item in self.powershell_inventory)

    @property
    def candidates(self) -> tuple[NativeBackendFileAttestation, ...]:
        return (self.deterministic.winner, self.shutil_which_winner, *(item.file for item in self.powershell_inventory))

    @property
    def authoritative_path_entry(self) -> str:
        return self.deterministic.authoritative_path_entry

    @property
    def authoritative_path_index(self) -> int:
        return self.deterministic.authoritative_path_index

    @property
    def path_sha256(self) -> str:
        return self.deterministic.path_sha256

    @property
    def pathext(self) -> tuple[str, ...]:
        return self.deterministic.pathext

    @property
    def pathext_sha256(self) -> str:
        return self.deterministic.pathext_sha256

    def _body(self) -> dict[str, Any]:
        return {
            "discovery_mechanism": self.discovery_mechanism, "command": self.command,
            "deterministic": self.deterministic.to_dict(),
            "shutil_which_winner": self.shutil_which_winner.to_dict(),
            "powershell_inventory": [item.to_dict() for item in self.powershell_inventory],
            "powershell_preferred": self.powershell_preferred.to_dict(),
            "powershell_prefers_powershell_wrapper": self.powershell_prefers_powershell_wrapper,
            "wrapper_root": self.wrapper_root, "wrapper_root_identity": self.wrapper_root_identity.to_dict(),
        }

    def validated(self) -> "CursorWrapperChainResolution":
        if self.discovery_mechanism != WRAPPER_CHAIN_DISCOVERY_MECHANISM or self.command != CURSOR_DISCOVERY_COMMAND:
            raise ValueError("unsupported wrapper-chain discovery mechanism")
        self.deterministic.validated(); self.shutil_which_winner.validated()
        winner = self.deterministic.winner
        if not _same_file_authority(winner, self.shutil_which_winner):
            raise ValueError("deterministic resolver and shutil.which disagree")
        winner_path = Path(winner.canonical_path)
        if winner_path.stem.casefold() != CURSOR_DISCOVERY_COMMAND or winner_path.suffix.casefold() != ".cmd":
            raise ValueError("winning cursor-agent command is not the canonical cmd wrapper")
        wrapper_root, identity = _safe_directory(self.wrapper_root, "Cursor wrapper root")
        if str(wrapper_root) != self.wrapper_root or not _same_directory_identity(identity, self.wrapper_root_identity):
            raise ValueError("Cursor wrapper root path or identity changed")
        if winner_path.parent != wrapper_root:
            raise ValueError("winning cursor-agent command is outside the attested wrapper root")
        if not isinstance(self.powershell_inventory, tuple) or not self.powershell_inventory:
            raise ValueError("PowerShell command inventory is unavailable or empty")
        if tuple(sorted(self.powershell_inventory, key=_powershell_candidate_key)) != self.powershell_inventory:
            raise ValueError("PowerShell command inventory is not canonically ordered")
        cmd_candidates: list[PowerShellCommandCandidate] = []
        ps_candidates: list[PowerShellCommandCandidate] = []
        expected_ps_path = wrapper_root / "cursor-agent.ps1"
        for item in self.powershell_inventory:
            item.validated()
            candidate_path = Path(item.file.canonical_path)
            if candidate_path.parent != wrapper_root:
                raise ValueError("PowerShell inventory contains an out-of-root candidate")
            if candidate_path.stem.casefold() != CURSOR_DISCOVERY_COMMAND:
                raise ValueError("PowerShell inventory contains an unexpected command name")
            suffix = candidate_path.suffix.casefold()
            if suffix == ".cmd" and item.command_type == "Application":
                if not _same_file_authority(item.file, winner):
                    raise ValueError("PowerShell inventory contains a contradictory cmd-compatible winner")
                cmd_candidates.append(item)
            elif suffix == ".ps1" and item.command_type == "ExternalScript":
                if candidate_path != expected_ps_path:
                    raise ValueError("PowerShell inventory contains a non-adjacent PowerShell wrapper")
                ps_candidates.append(item)
            else:
                raise ValueError("PowerShell inventory contains an alias, function, application alias, or unsupported command")
        if not cmd_candidates or not ps_candidates:
            raise ValueError("PowerShell inventory must contain the adjacent .ps1 and deterministic .cmd wrappers")
        self.powershell_preferred.validated()
        if self.powershell_preferred not in self.powershell_inventory:
            raise ValueError("PowerShell preferred command is absent from its complete inventory")
        require_bool(self.powershell_prefers_powershell_wrapper, "PowerShell wrapper preference")
        preferred_path = Path(self.powershell_preferred.file.canonical_path)
        expected_preference = preferred_path == expected_ps_path and self.powershell_preferred.command_type == "ExternalScript"
        if self.powershell_prefers_powershell_wrapper != expected_preference or not expected_preference:
            raise ValueError("PowerShell does not prefer the expected adjacent .ps1 wrapper")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self._body()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CursorWrapperChainResolution":
        require_exact_keys(data, set(cls.__dataclass_fields__), "wrapper-chain command resolution")
        return cls(
            discovery_mechanism=data["discovery_mechanism"], command=data["command"],
            deterministic=DeterministicWindowsCommandResolution.from_dict(data["deterministic"]),
            shutil_which_winner=NativeBackendFileAttestation.from_dict(data["shutil_which_winner"]),
            powershell_inventory=tuple(PowerShellCommandCandidate.from_dict(item) for item in data["powershell_inventory"]),
            powershell_preferred=PowerShellCommandCandidate.from_dict(data["powershell_preferred"]),
            powershell_prefers_powershell_wrapper=data["powershell_prefers_powershell_wrapper"],
            wrapper_root=data["wrapper_root"],
            wrapper_root_identity=NativeFilesystemIdentity.from_dict(data["wrapper_root_identity"]),
        ).validated()


class WindowsWhereDiagnosticStatus(str, Enum):
    MATCHING_RESULT = "MATCHING_RESULT"
    CONTRADICTORY_RESULT = "CONTRADICTORY_RESULT"
    EMPTY_RESULT = "EMPTY_RESULT"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class WindowsWhereDiagnostic:
    schema_version: str
    status: WindowsWhereDiagnosticStatus
    where_executable: NativeBackendFileAttestation | None
    argv: tuple[str, ...]
    exit_code: int | None
    stdout_byte_count: int
    stdout_sha256: str
    stderr_byte_count: int
    stderr_sha256: str
    parsed_candidates: tuple[str, ...]

    def validated(self) -> "WindowsWhereDiagnostic":
        if self.schema_version != WINDOWS_WHERE_DIAGNOSTIC_SCHEMA_VERSION or not isinstance(self.status, WindowsWhereDiagnosticStatus):
            raise ValueError("unsupported where.exe diagnostic")
        if self.where_executable is not None:
            self.where_executable.validated()
        _validate_argv(self.argv, "where.exe diagnostic argv")
        if self.exit_code is not None:
            require_strict_int(self.exit_code, "where.exe diagnostic exit code", minimum=0, maximum=2**31 - 1)
        require_strict_int(self.stdout_byte_count, "where.exe stdout byte count", minimum=0, maximum=2**63 - 1)
        require_strict_int(self.stderr_byte_count, "where.exe stderr byte count", minimum=0, maximum=2**63 - 1)
        require_sha256(self.stdout_sha256, "where.exe stdout sha256")
        require_sha256(self.stderr_sha256, "where.exe stderr sha256")
        if not isinstance(self.parsed_candidates, tuple) or any(not isinstance(item, str) or not item for item in self.parsed_candidates):
            raise ValueError("where.exe parsed candidates are invalid")
        if self.status in {WindowsWhereDiagnosticStatus.MATCHING_RESULT, WindowsWhereDiagnosticStatus.CONTRADICTORY_RESULT}:
            if self.where_executable is None or self.exit_code != 0 or not self.parsed_candidates:
                raise ValueError("successful where.exe diagnostic lacks executable, exit, or candidate evidence")
        if self.status is WindowsWhereDiagnosticStatus.UNAVAILABLE and (self.where_executable is not None or self.exit_code is not None):
            raise ValueError("unavailable where.exe diagnostic carries executable authority")
        if self.status is WindowsWhereDiagnosticStatus.EMPTY_RESULT and self.parsed_candidates:
            raise ValueError("empty where.exe diagnostic carries parsed candidates")
        if self.where_executable is not None and self.argv[0] != self.where_executable.canonical_path:
            raise ValueError("where.exe diagnostic argv differs from the observed executable")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {
            "schema_version": self.schema_version, "status": self.status.value,
            "where_executable": self.where_executable.to_dict() if self.where_executable else None,
            "argv": list(self.argv), "exit_code": self.exit_code,
            "stdout_byte_count": self.stdout_byte_count, "stdout_sha256": self.stdout_sha256,
            "stderr_byte_count": self.stderr_byte_count, "stderr_sha256": self.stderr_sha256,
            "parsed_candidates": list(self.parsed_candidates),
        }


class _WhereDiagnosticContradiction(ValueError):
    def __init__(self, diagnostic: WindowsWhereDiagnostic) -> None:
        super().__init__("successful where.exe result contradicts deterministic command authority")
        self.diagnostic = diagnostic


def _where_diagnostic(
    discovery: WrapperChainDiscovery, winner: NativeBackendFileAttestation,
) -> WindowsWhereDiagnostic:
    observed = discovery.where_cursor_agent()
    executable: NativeBackendFileAttestation | None = None
    if observed.executable is not None:
        try:
            executable = _canonical_backend_file(observed.executable, "where.exe diagnostic executable")
        except (OSError, ValueError):
            executable = None
    candidates = tuple(
        line.strip()
        for line in observed.stdout.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    )
    if observed.executable is None and not observed.execution_error:
        status = WindowsWhereDiagnosticStatus.UNAVAILABLE
    elif observed.execution_error:
        status = WindowsWhereDiagnosticStatus.EXECUTION_ERROR
    elif not candidates:
        status = (
            WindowsWhereDiagnosticStatus.EMPTY_RESULT
            if observed.exit_code in {0, 1} and not observed.stderr
            else WindowsWhereDiagnosticStatus.EXECUTION_ERROR
        )
    elif observed.exit_code != 0:
        status = WindowsWhereDiagnosticStatus.EXECUTION_ERROR
    else:
        matching = True
        for candidate in candidates:
            try:
                attested = _canonical_backend_file(candidate, "where.exe diagnostic candidate")
            except (OSError, ValueError):
                matching = False
                break
            if not _same_file_authority(attested, winner):
                matching = False
                break
        status = WindowsWhereDiagnosticStatus.MATCHING_RESULT if matching else WindowsWhereDiagnosticStatus.CONTRADICTORY_RESULT
    diagnostic = WindowsWhereDiagnostic(
        WINDOWS_WHERE_DIAGNOSTIC_SCHEMA_VERSION, status, executable, observed.argv, observed.exit_code,
        len(observed.stdout), hashlib.sha256(observed.stdout).hexdigest(),
        len(observed.stderr), hashlib.sha256(observed.stderr).hexdigest(), candidates,
    ).validated()
    if status is WindowsWhereDiagnosticStatus.CONTRADICTORY_RESULT:
        raise _WhereDiagnosticContradiction(diagnostic)
    return diagnostic


def _validated_semantics(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"{label} parsed semantics are missing")
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, (str, bool, int)):
            raise ValueError(f"{label} parsed semantics contain an unsupported value")
    return dict(value)


@dataclass(frozen=True)
class WrapperChainBackendAttestation:
    """LOCAL_WRAPPER_CHAIN attestation: routing and byte identity only.

    This class deliberately does not claim publisher identity, desktop-app
    ownership, package-manager ownership, payload signatures, or production
    trust.  It exists solely so one explicitly owner-authorized local
    experiment can bind the exact mechanically observed launch chain.
    """

    schema_version: str
    attestation_class: str
    backend_identity: str
    backend_protocol_version: str
    command_resolution: CursorWrapperChainResolution
    cmd_wrapper: NativeBackendFileAttestation
    cmd_semantics: Mapping[str, Any]
    powershell_wrapper: NativeBackendFileAttestation
    powershell_semantics: Mapping[str, Any]
    version_inventory: tuple[str, ...]
    selected_version: str
    selected_version_root: str
    selected_version_root_identity: NativeFilesystemIdentity
    executable: NativeBackendFileAttestation
    launcher_prefix: tuple[NativeBackendFileAttestation, ...]
    package_manifest: NativeBackendFileAttestation
    package_name: str
    manifest_declares_cursor_agent_bin: bool
    version_wrapper_copies: tuple[NativeBackendFileAttestation, ...]
    node_signature_context: str
    claims: Mapping[str, bool]
    non_claims: tuple[str, ...]
    static_argv_template: tuple[str, ...]
    selected_model: str
    environment_allowlist: tuple[str, ...]
    attestation_fingerprint: str

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "attestation_class": self.attestation_class,
            "backend_identity": self.backend_identity, "backend_protocol_version": self.backend_protocol_version,
            "command_resolution": self.command_resolution.to_dict(),
            "cmd_wrapper": self.cmd_wrapper.to_dict(), "cmd_semantics": dict(self.cmd_semantics),
            "powershell_wrapper": self.powershell_wrapper.to_dict(), "powershell_semantics": dict(self.powershell_semantics),
            "version_inventory": list(self.version_inventory), "selected_version": self.selected_version,
            "selected_version_root": self.selected_version_root,
            "selected_version_root_identity": self.selected_version_root_identity.to_dict(),
            "executable": self.executable.to_dict(),
            "launcher_prefix": [item.to_dict() for item in self.launcher_prefix],
            "package_manifest": self.package_manifest.to_dict(), "package_name": self.package_name,
            "manifest_declares_cursor_agent_bin": self.manifest_declares_cursor_agent_bin,
            "version_wrapper_copies": [item.to_dict() for item in self.version_wrapper_copies],
            "node_signature_context": self.node_signature_context,
            "claims": dict(self.claims), "non_claims": list(self.non_claims),
            "static_argv_template": list(self.static_argv_template),
            "selected_model": self.selected_model, "environment_allowlist": list(self.environment_allowlist),
        }

    def validated(self) -> "WrapperChainBackendAttestation":
        if (
            self.schema_version != WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION
            or self.attestation_class != ATTESTATION_CLASS_WRAPPER_CHAIN
            or self.backend_identity != BACKEND_IDENTITY
            or self.backend_protocol_version != BACKEND_PROTOCOL_VERSION
        ):
            raise ValueError("unsupported wrapper-chain backend attestation")
        self.command_resolution.validated()
        wrapper_root = Path(self.command_resolution.wrapper_root)
        self.cmd_wrapper.validated(); self.powershell_wrapper.validated()
        if Path(self.cmd_wrapper.canonical_path) != Path(self.command_resolution.winning_cmd.canonical_path):
            raise ValueError("attested cmd wrapper differs from the winning command resolution")
        cmd_path = Path(self.cmd_wrapper.canonical_path)
        cmd_semantics = _parse_cmd_wrapper(cmd_path.read_bytes(), wrapper_name=cmd_path.name)
        if _validated_semantics(self.cmd_semantics, "cmd wrapper") != cmd_semantics:
            raise ValueError("cmd wrapper parsed semantics changed")
        expected_ps = wrapper_root / cmd_semantics["adjacent_powershell_target"]
        if Path(self.powershell_wrapper.canonical_path) != expected_ps:
            raise ValueError("attested PowerShell wrapper is not the cmd wrapper's adjacent target")
        ps_semantics = _parse_powershell_wrapper(expected_ps.read_bytes())
        if _validated_semantics(self.powershell_semantics, "PowerShell wrapper") != ps_semantics:
            raise ValueError("PowerShell wrapper parsed semantics changed")
        if (wrapper_root / "node.exe").exists():
            raise ValueError("wrapper root contains an adjacent node.exe shortcut outside the attested version chain")
        inventory, selected = _select_wrapper_version(wrapper_root)
        if inventory != self.version_inventory or selected != self.selected_version:
            raise ValueError("Cursor version inventory or selection changed after attestation")
        selected_root, selected_identity = _safe_directory(wrapper_root / "versions" / selected, "selected Cursor version root")
        if str(selected_root) != self.selected_version_root or not _same_directory_identity(selected_identity, self.selected_version_root_identity):
            raise ValueError("selected Cursor version root path or identity changed")
        self.executable.validated(); self.package_manifest.validated()
        if Path(self.executable.canonical_path) != selected_root / "node.exe":
            raise ValueError("attested runtime is not the selected version's node.exe")
        if len(self.launcher_prefix) != 1 or Path(self.launcher_prefix[0].validated().canonical_path) != selected_root / "index.js":
            raise ValueError("attested entry is not the selected version's index.js")
        if Path(self.package_manifest.canonical_path) != selected_root / "package.json":
            raise ValueError("attested manifest is not the selected version's package.json")
        for item in (self.executable, self.launcher_prefix[0], self.package_manifest):
            if not _inside(Path(item.canonical_path), selected_root):
                raise ValueError("an authoritative launcher file escapes the selected version root")
        if not _inside(selected_root, wrapper_root):
            raise ValueError("selected version root escapes the canonical wrapper root")
        try:
            manifest = json.loads(Path(self.package_manifest.canonical_path).read_text(encoding="utf-8"))
        except (OSError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"selected version manifest is unreadable: {exc}") from exc
        if not isinstance(manifest, Mapping) or manifest.get("name") != self.package_name:
            raise ValueError("selected version manifest identity differs from the attestation")
        if self.package_name != EXPECTED_CURSOR_PACKAGE_NAME:
            raise ValueError("selected version package is not the observed local Agent CLI runtime package")
        declared_bin = manifest.get("bin")
        declares = isinstance(declared_bin, Mapping) and CURSOR_DISCOVERY_COMMAND in declared_bin or isinstance(declared_bin, str)
        require_bool(self.manifest_declares_cursor_agent_bin, "manifest bin declaration record")
        if self.manifest_declares_cursor_agent_bin != bool(declares):
            raise ValueError("manifest bin declaration record is untruthful")
        for item in self.version_wrapper_copies:
            item.validated()
            copy_path = Path(item.canonical_path)
            if copy_path.parent != selected_root:
                raise ValueError("a version wrapper copy escapes the selected version root")
            source = wrapper_root / copy_path.name
            if not source.is_file() or _sha256_file(source) != item.sha256:
                raise ValueError("selected-version wrapper copy differs from the winning top-level wrapper")
        require_nonempty_text(self.node_signature_context, "node signature context", max_bytes=1024)
        if dict(self.claims) != WRAPPER_CHAIN_CLAIMS:
            raise ValueError("wrapper-chain claim set differs from the audited non-overclaiming claims")
        if tuple(self.non_claims) != WRAPPER_CHAIN_NON_CLAIMS:
            raise ValueError("wrapper-chain explicit non-claims differ from the audited set")
        _validate_argv(self.static_argv_template, "wrapper-chain static argv template")
        if self.static_argv_template[-1] != "{prompt}":
            raise ValueError("wrapper-chain attestation prompt placeholder must be final")
        if self.static_argv_template[0] != self.executable.canonical_path or self.static_argv_template[1] != self.launcher_prefix[0].canonical_path:
            raise ValueError("wrapper-chain argv template differs from the attested runtime and entry")
        require_nonempty_text(self.selected_model, "attested selected model", max_bytes=256)
        if not isinstance(self.environment_allowlist, tuple) or not self.environment_allowlist:
            raise ValueError("attested environment allowlist is invalid")
        require_sha256(self.attestation_fingerprint, "wrapper-chain attestation fingerprint")
        if fingerprint(self._body()) != self.attestation_fingerprint:
            raise ValueError("wrapper-chain attestation fingerprint mismatch")
        return self

    def argv(self, *, prompt: str) -> tuple[str, ...]:
        require_nonempty_text(prompt, "native agent prompt")
        if not prompt.startswith(NATIVE_PROMPT_HEADER):
            raise NativeEvidenceInvalid("native prompt lacks the harness-controlled header")
        return (*self.static_argv_template[:-1], prompt)

    def to_dict(self) -> dict[str, Any]:
        result = self._body(); result["attestation_fingerprint"] = self.attestation_fingerprint; return result

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WrapperChainBackendAttestation":
        require_exact_keys(data, set(cls.__dataclass_fields__), "wrapper-chain backend attestation")
        values = dict(data)
        values["command_resolution"] = CursorWrapperChainResolution.from_dict(data["command_resolution"])
        for key in ("cmd_wrapper", "powershell_wrapper", "executable", "package_manifest"):
            values[key] = NativeBackendFileAttestation.from_dict(data[key])
        values["launcher_prefix"] = tuple(NativeBackendFileAttestation.from_dict(item) for item in data["launcher_prefix"])
        values["version_wrapper_copies"] = tuple(NativeBackendFileAttestation.from_dict(item) for item in data["version_wrapper_copies"])
        values["selected_version_root_identity"] = NativeFilesystemIdentity.from_dict(data["selected_version_root_identity"])
        values["cmd_semantics"] = _validated_semantics(data["cmd_semantics"], "cmd wrapper")
        values["powershell_semantics"] = _validated_semantics(data["powershell_semantics"], "PowerShell wrapper")
        values["claims"] = dict(data["claims"]) if isinstance(data["claims"], Mapping) else data["claims"]
        for key in ("version_inventory", "static_argv_template", "environment_allowlist", "non_claims"):
            values[key] = require_string_list(data[key], key)
        return cls(**values).validated()


def _attest_wrapper_chain_cursor_observed(
    config: CursorNativeBackendConfig, *, discovery: WrapperChainDiscovery | None = None,
) -> tuple[WrapperChainBackendAttestation, WindowsWhereDiagnostic]:
    """Attest v2 authority and return separate non-authoritative diagnostics."""
    if config.attestation_class != ATTESTATION_CLASS_WRAPPER_CHAIN:
        raise ValueError("wrapper-chain attestation requires the explicitly configured LOCAL_WRAPPER_CHAIN class")
    discovery = discovery or HostWrapperChainDiscovery()
    path_value = discovery.path_value()
    pathext_value = discovery.pathext_value()

    def require_environment_unchanged(stage: str) -> None:
        if discovery.path_value() != path_value or discovery.pathext_value() != pathext_value:
            raise ValueError(f"PATH or PATHEXT changed during wrapper-chain {stage}")

    deterministic = _deterministic_windows_resolve(
        command=CURSOR_DISCOVERY_COMMAND, path_value=path_value, pathext_value=pathext_value,
    )
    which_path = discovery.which_cursor_agent(path_value=path_value, pathext_value=pathext_value)
    if which_path is None:
        raise ValueError("shutil.which found no cursor-agent command while deterministic resolution succeeded")
    which_winner = _canonical_backend_file(which_path, "shutil.which cursor-agent winner")
    if not _same_file_authority(deterministic.winner, which_winner):
        raise ValueError("deterministic resolver and shutil.which disagree")
    winner_path = Path(deterministic.winner.canonical_path)
    wrapper_root, wrapper_root_identity = _safe_directory(winner_path.parent, "Cursor wrapper root")
    powershell = discovery.powershell_cursor_agent()
    require_environment_unchanged("PowerShell inventory")
    if powershell is None or not powershell.candidates or powershell.preferred is None:
        raise ValueError("PowerShell command inventory is unavailable or empty")

    def bind_powershell(raw: tuple[str, str, str]) -> PowerShellCommandCandidate:
        command_type, name, path = raw
        if command_type not in {"Application", "ExternalScript"} or not path:
            raise ValueError("PowerShell inventory contains an alias, function, application alias, or pathless command")
        return PowerShellCommandCandidate(
            command_type, name, _canonical_backend_file(path, "PowerShell cursor-agent candidate"),
        ).validated()

    powershell_inventory = tuple(sorted(
        (bind_powershell(item) for item in powershell.candidates), key=_powershell_candidate_key,
    ))
    powershell_preferred = bind_powershell(powershell.preferred)
    resolution = CursorWrapperChainResolution(
        discovery_mechanism=WRAPPER_CHAIN_DISCOVERY_MECHANISM, command=CURSOR_DISCOVERY_COMMAND,
        deterministic=deterministic, shutil_which_winner=which_winner,
        powershell_inventory=powershell_inventory, powershell_preferred=powershell_preferred,
        powershell_prefers_powershell_wrapper=(
            Path(powershell_preferred.file.canonical_path) == wrapper_root / "cursor-agent.ps1"
            and powershell_preferred.command_type == "ExternalScript"
        ),
        wrapper_root=str(wrapper_root), wrapper_root_identity=wrapper_root_identity,
    ).validated()
    where_diagnostic = _where_diagnostic(discovery, resolution.winning_cmd)
    require_environment_unchanged("where.exe diagnostic")
    cmd_semantics = _parse_cmd_wrapper(winner_path.read_bytes(), wrapper_name=winner_path.name)
    ps_path, _ = _safe_file(wrapper_root / cmd_semantics["adjacent_powershell_target"], "adjacent PowerShell wrapper")
    ps_semantics = _parse_powershell_wrapper(ps_path.read_bytes())
    if (wrapper_root / "node.exe").exists():
        raise ValueError("wrapper root contains an adjacent node.exe shortcut outside the attested version chain")
    inventory, selected = _select_wrapper_version(wrapper_root)
    selected_root, selected_identity = _safe_directory(wrapper_root / "versions" / selected, "selected Cursor version root")
    node = NativeBackendFileAttestation.observe(selected_root / "node.exe", "selected version node.exe")
    entry = NativeBackendFileAttestation.observe(selected_root / "index.js", "selected version index.js")
    manifest_file = NativeBackendFileAttestation.observe(selected_root / "package.json", "selected version manifest")
    try:
        manifest = json.loads((selected_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"selected version manifest is unreadable: {exc}") from exc
    if not isinstance(manifest, Mapping) or manifest.get("name") != EXPECTED_CURSOR_PACKAGE_NAME:
        raise ValueError("selected version package is not the observed local Agent CLI runtime package")
    declared_bin = manifest.get("bin")
    declares = bool(isinstance(declared_bin, Mapping) and CURSOR_DISCOVERY_COMMAND in declared_bin or isinstance(declared_bin, str))
    copies: list[NativeBackendFileAttestation] = []
    for name in (winner_path.name, ps_path.name):
        copy_path = selected_root / name
        if copy_path.exists():
            copy = NativeBackendFileAttestation.observe(copy_path, "selected version wrapper copy")
            if copy.sha256 != _sha256_file(wrapper_root / name):
                raise ValueError("selected-version wrapper copy differs from the winning top-level wrapper")
            copies.append(copy)
    template = (node.canonical_path, entry.canonical_path, "--print", "--output-format", "stream-json", "--force", "--trust", "--model", config.model, "{prompt}")
    node_signature_context = discovery.node_signature_context(Path(node.canonical_path))
    require_environment_unchanged("static attestation")
    provisional = WrapperChainBackendAttestation(
        schema_version=WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION, attestation_class=ATTESTATION_CLASS_WRAPPER_CHAIN,
        backend_identity=BACKEND_IDENTITY, backend_protocol_version=BACKEND_PROTOCOL_VERSION,
        command_resolution=resolution,
        cmd_wrapper=resolution.winning_cmd, cmd_semantics=cmd_semantics,
        powershell_wrapper=NativeBackendFileAttestation.observe(ps_path, "adjacent PowerShell wrapper"),
        powershell_semantics=ps_semantics,
        version_inventory=inventory, selected_version=selected,
        selected_version_root=str(selected_root), selected_version_root_identity=selected_identity,
        executable=node, launcher_prefix=(entry,), package_manifest=manifest_file,
        package_name=EXPECTED_CURSOR_PACKAGE_NAME, manifest_declares_cursor_agent_bin=declares,
        version_wrapper_copies=tuple(copies),
        node_signature_context=node_signature_context,
        claims=dict(WRAPPER_CHAIN_CLAIMS), non_claims=WRAPPER_CHAIN_NON_CLAIMS,
        static_argv_template=template, selected_model=config.model,
        environment_allowlist=config.environment_allowlist, attestation_fingerprint="0" * 64,
    )
    attestation = WrapperChainBackendAttestation(
        **{**provisional.__dict__, "attestation_fingerprint": fingerprint(provisional._body())}
    ).validated()
    return attestation, where_diagnostic


def _attest_wrapper_chain_cursor(
    config: CursorNativeBackendConfig, *, discovery: WrapperChainDiscovery | None = None,
) -> WrapperChainBackendAttestation:
    """Return only authority; where.exe diagnostics are deliberately excluded."""

    return _attest_wrapper_chain_cursor_observed(config, discovery=discovery)[0]


def _bounded_probe(argv: tuple[str, ...], environment: Mapping[str, str]) -> tuple[int | None, bytes, bytes]:
    try:
        completed = subprocess.run(
            list(argv), shell=False, check=False, capture_output=True, timeout=15,
            env=dict(environment), stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, b"", b""
    return completed.returncode, completed.stdout[:_PROBE_LIMIT], completed.stderr[:_PROBE_LIMIT]


@dataclass(frozen=True)
class NativeBackendAttestation:
    schema_version: str
    backend_identity: str
    backend_protocol_version: str
    executable: NativeBackendFileAttestation
    launcher_prefix: tuple[NativeBackendFileAttestation, ...]
    provenance: CursorInstallationProvenance
    version_probe_argv: tuple[str, ...]
    help_probe_argv: tuple[str, ...]
    version_probe_exit_code: int
    help_probe_exit_code: int
    version_stdout_sha256: str
    version_stderr_sha256: str
    help_stdout_sha256: str
    help_stderr_sha256: str
    advertised_flags: tuple[str, ...]
    static_argv_template: tuple[str, ...]
    selected_model: str
    environment_allowlist: tuple[str, ...]
    attestation_fingerprint: str

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "backend_identity": self.backend_identity,
            "backend_protocol_version": self.backend_protocol_version, "executable": self.executable.to_dict(),
            "launcher_prefix": [item.to_dict() for item in self.launcher_prefix],
            "provenance": self.provenance.to_dict(),
            "version_probe_argv": list(self.version_probe_argv), "help_probe_argv": list(self.help_probe_argv),
            "version_probe_exit_code": self.version_probe_exit_code, "help_probe_exit_code": self.help_probe_exit_code,
            "version_stdout_sha256": self.version_stdout_sha256, "version_stderr_sha256": self.version_stderr_sha256,
            "help_stdout_sha256": self.help_stdout_sha256, "help_stderr_sha256": self.help_stderr_sha256,
            "advertised_flags": list(self.advertised_flags), "static_argv_template": list(self.static_argv_template),
            "selected_model": self.selected_model, "environment_allowlist": list(self.environment_allowlist),
        }

    def validated(self) -> "NativeBackendAttestation":
        if self.schema_version != ATTESTATION_SCHEMA_VERSION or self.backend_identity != BACKEND_IDENTITY or self.backend_protocol_version != BACKEND_PROTOCOL_VERSION:
            raise ValueError("unsupported native backend attestation")
        self.executable.validated()
        for item in self.launcher_prefix:
            item.validated()
        self.provenance.validated()
        if self.executable != self.provenance.discovered_shim and self.executable.canonical_path != self.provenance.launcher.canonical_path:
            # The normal Node invocation is ``node.exe index.js``.  Its first
            # argv item is the package-local runtime, while the discovered shim
            # remains provenance only.  The executable check below covers that
            # form without accepting unrelated prefix files.
            executable_path = Path(self.executable.canonical_path)
            package_root = Path(self.provenance.package_root)
            if not _inside(executable_path, package_root):
                raise ValueError("Cursor executable is outside the attested package root")
        if not self.launcher_prefix or self.launcher_prefix[0] != self.provenance.launcher:
            raise ValueError("Cursor launcher prefix does not begin with the manifest-mapped launcher")
        _validate_argv(self.version_probe_argv, "version probe argv")
        _validate_argv(self.help_probe_argv, "help probe argv")
        _validate_argv(self.static_argv_template, "static native argv template")
        if self.version_probe_argv[-1] != "--version" or self.help_probe_argv[-1] != "--help":
            raise ValueError("backend attestation has an unsupported probe argv")
        if self.static_argv_template[-1] != "{prompt}":
            raise ValueError("backend attestation prompt placeholder must be final")
        for label, value in (("version_probe_exit_code", self.version_probe_exit_code), ("help_probe_exit_code", self.help_probe_exit_code)):
            require_strict_int(value, label, minimum=0, maximum=255)
        for label, value in (("version_stdout_sha256", self.version_stdout_sha256), ("version_stderr_sha256", self.version_stderr_sha256), ("help_stdout_sha256", self.help_stdout_sha256), ("help_stderr_sha256", self.help_stderr_sha256), ("attestation_fingerprint", self.attestation_fingerprint)):
            require_sha256(value, label)
        if not isinstance(self.advertised_flags, tuple) or tuple(sorted(set(self.advertised_flags))) != self.advertised_flags:
            raise ValueError("advertised flags must be a sorted immutable unique tuple")
        if not isinstance(self.environment_allowlist, tuple) or not self.environment_allowlist:
            raise ValueError("attested environment allowlist is invalid")
        require_nonempty_text(self.selected_model, "attested selected model", max_bytes=256)
        if fingerprint(self._body()) != self.attestation_fingerprint:
            raise ValueError("native backend attestation fingerprint mismatch")
        return self

    @property
    def attestation_class(self) -> str:
        return ATTESTATION_CLASS_PACKAGE_BIN

    @property
    def non_claims(self) -> tuple[str, ...]:
        return PACKAGE_BIN_NON_CLAIMS

    def argv(self, *, prompt: str) -> tuple[str, ...]:
        require_nonempty_text(prompt, "native agent prompt")
        if not prompt.startswith(NATIVE_PROMPT_HEADER):
            raise NativeEvidenceInvalid("native prompt lacks the harness-controlled header")
        return (*self.static_argv_template[:-1], prompt)

    def to_dict(self) -> dict[str, Any]:
        result = self._body(); result["attestation_fingerprint"] = self.attestation_fingerprint; return result

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeBackendAttestation":
        keys = set(cls.__dataclass_fields__)
        require_exact_keys(data, keys, "native backend attestation")
        values = dict(data)
        values["executable"] = NativeBackendFileAttestation.from_dict(data["executable"])
        values["launcher_prefix"] = tuple(NativeBackendFileAttestation.from_dict(item) for item in data["launcher_prefix"])
        values["provenance"] = CursorInstallationProvenance.from_dict(data["provenance"])
        for key in ("version_probe_argv", "help_probe_argv", "static_argv_template", "advertised_flags", "environment_allowlist"):
            values[key] = require_string_list(data[key], key)
        return cls(**values).validated()


@dataclass(frozen=True)
class NativePreflightDecision:
    status: NativePreflightStatus
    reason_code: str
    detail: str
    attestation: "BackendAttestation | None"
    where_diagnostic: WindowsWhereDiagnostic | None = None

    @property
    def ready(self) -> bool:
        return self.status is NativePreflightStatus.PREFLIGHT_READY

    @property
    def backend_fingerprint(self) -> str | None:
        return self.attestation.attestation_fingerprint if self.attestation else None

    @property
    def resolved_executable(self) -> str | None:
        return self.attestation.executable.canonical_path if self.attestation else None


def _resolve_executable(config: CursorNativeBackendConfig) -> Path:
    supplied = Path(config.executable)
    if supplied.is_absolute():
        return _safe_file(supplied, "native executable")[0]
    if supplied.parent != Path("."):
        raise ValueError("a path-like native executable must be absolute")
    located = shutil.which(config.executable)
    if located is None:
        raise ValueError("configured native executable was not found on PATH")
    return _safe_file(located, "native executable")[0]


def _discover_cursor_agent_shim() -> Path:
    """Resolve the one host-discovered local Cursor Agent command.

    This deliberately does not honour an arbitrary caller path.  The supplied
    executable/launcher must be proven to belong to the installation rooted at
    this command, rather than merely claiming to be Cursor in probe output.
    """

    located = shutil.which(CURSOR_DISCOVERY_COMMAND)
    if located is None:
        raise ValueError("canonical local cursor-agent discovery found no command")
    shim, _ = _safe_file(located, "discovered cursor-agent shim")
    if shim.stem.lower() != CURSOR_DISCOVERY_COMMAND:
        raise ValueError("canonical cursor-agent discovery resolved an unexpected shim name")
    return shim


def _cursor_provenance(config: CursorNativeBackendConfig) -> tuple[NativeBackendFileAttestation, tuple[NativeBackendFileAttestation, ...], CursorInstallationProvenance]:
    shim_path = _discover_cursor_agent_shim()
    executable_path = _resolve_executable(config)
    if not config.launcher_prefix:
        raise ValueError("Cursor native execution requires the manifest-mapped launcher prefix")
    prefix = tuple(NativeBackendFileAttestation.observe(item, "native launcher prefix") for item in config.launcher_prefix)
    launcher_path = Path(prefix[0].canonical_path)
    package_root, package_root_identity = _safe_directory(launcher_path.parent, "Cursor package root")
    installation_root, installation_root_identity = _safe_directory(shim_path.parent, "Cursor installation root")
    if not _inside(package_root, installation_root):
        raise ValueError("configured Cursor package root is outside the discovered installation root")
    executable, executable_identity = _safe_file(executable_path, "native executable")
    if not _inside(executable, package_root):
        raise ValueError("configured native executable is outside the discovered Cursor package root")
    for item in prefix:
        if not _inside(Path(item.canonical_path), package_root):
            raise ValueError("configured native launcher prefix is outside the Cursor package root")
    manifest_path = package_root / "package.json"
    manifest = NativeBackendFileAttestation.observe(manifest_path, "Cursor package manifest")
    try:
        parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cursor package manifest is unreadable: {exc}") from exc
    if not isinstance(parsed, Mapping) or parsed.get("name") != EXPECTED_CURSOR_PACKAGE_NAME:
        raise ValueError("Cursor package manifest does not identify the expected local Agent CLI package")
    declared_bin = parsed.get("bin")
    if isinstance(declared_bin, str):
        mapping = {CURSOR_DISCOVERY_COMMAND: declared_bin}
    elif isinstance(declared_bin, Mapping):
        mapping = dict(declared_bin)
    else:
        raise ValueError("Cursor package manifest lacks the required cursor-agent bin mapping")
    relative = mapping.get(CURSOR_DISCOVERY_COMMAND)
    if not isinstance(relative, str):
        raise ValueError("Cursor package manifest lacks the canonical cursor-agent bin entry")
    require_safe_relative_path(relative, "Cursor package bin path")
    resolved_launcher, _ = _safe_file(package_root / relative, "Cursor package bin launcher")
    if resolved_launcher != launcher_path:
        raise ValueError("Cursor package bin mapping does not resolve to the configured launcher")
    provenance = CursorInstallationProvenance(
        discovery_mechanism=CURSOR_DISCOVERY_MECHANISM,
        discovered_shim=NativeBackendFileAttestation.observe(shim_path, "discovered cursor-agent shim"),
        installation_root=str(installation_root), installation_root_identity=installation_root_identity,
        package_root=str(package_root), package_root_identity=package_root_identity,
        package_manifest=manifest, package_name=EXPECTED_CURSOR_PACKAGE_NAME,
        bin_command=CURSOR_DISCOVERY_COMMAND, bin_relative_path=relative,
        launcher=prefix[0],
    ).validated()
    # ``executable_identity`` is deliberately observed above to reject a
    # non-regular/reparse executable before any probe; the full attestation
    # records the same identity in ``executable``.
    del executable_identity
    return NativeBackendFileAttestation.observe(executable_path, "native executable"), prefix, provenance


def _attest_native_cursor(config: CursorNativeBackendConfig) -> NativeBackendAttestation:
    if config.attestation_class != ATTESTATION_CLASS_PACKAGE_BIN:
        raise ValueError("package-bin attestation requires the PACKAGE_BIN_PROVENANCE class")
    executable, prefix, provenance = _cursor_provenance(config)
    launcher = (executable.canonical_path, *(item.canonical_path for item in prefix))
    version_argv = (*launcher, "--version")
    help_argv = (*launcher, "--help")
    environment = config.build_environment()
    version_code, version_out, version_err = _bounded_probe(version_argv, environment)
    help_code, help_out, help_err = _bounded_probe(help_argv, environment)
    if version_code is None or help_code is None:
        raise ValueError("local capability probe could not complete")
    advertised = tuple(sorted(set(_FLAG_PATTERN.findall((help_out + b"\n" + help_err).decode("utf-8", "replace")))))
    required = {"--print", "--force", "--output-format", "--trust", "--model"}
    text = (help_out + b"\n" + help_err).decode("utf-8", "replace")
    if version_code != 0 or help_code != 0:
        raise ValueError("local version or help capability probe returned a nonzero exit")
    if "cursor" not in (version_out + b"\n" + version_err).decode("utf-8", "replace").lower():
        raise ValueError("local version probe does not identify the Cursor CLI")
    if not required.issubset(advertised) or "stream-json" not in text:
        raise ValueError("local Cursor help does not advertise every required native capability")
    template = (*launcher, "--print", "--output-format", "stream-json", "--force", "--trust", "--model", config.model, "{prompt}")
    provisional = NativeBackendAttestation(
        schema_version=ATTESTATION_SCHEMA_VERSION, backend_identity=BACKEND_IDENTITY,
        backend_protocol_version=BACKEND_PROTOCOL_VERSION, executable=executable, launcher_prefix=prefix, provenance=provenance,
        version_probe_argv=version_argv, help_probe_argv=help_argv, version_probe_exit_code=version_code,
        help_probe_exit_code=help_code, version_stdout_sha256=hashlib.sha256(version_out).hexdigest(),
        version_stderr_sha256=hashlib.sha256(version_err).hexdigest(), help_stdout_sha256=hashlib.sha256(help_out).hexdigest(),
        help_stderr_sha256=hashlib.sha256(help_err).hexdigest(), advertised_flags=advertised,
        static_argv_template=template, selected_model=config.model, environment_allowlist=config.environment_allowlist,
        attestation_fingerprint="0" * 64,
    )
    return NativeBackendAttestation(**{**provisional.__dict__, "attestation_fingerprint": fingerprint(provisional._body())}).validated()


BackendAttestation = NativeBackendAttestation | WrapperChainBackendAttestation


def attestation_from_dict(data: Mapping[str, Any]) -> BackendAttestation:
    """Class-preserving deserialization; the class can never be reinterpreted."""

    if not isinstance(data, Mapping):
        raise ValueError("backend attestation payload must be a mapping")
    schema_version = data.get("schema_version")
    if schema_version == WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION_LEGACY_V1:
        raise ValueError("legacy wrapper-chain v1 attestation is inert and cannot authorize new execution")
    if schema_version == WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION:
        return WrapperChainBackendAttestation.from_dict(data)
    return NativeBackendAttestation.from_dict(data)


def _attest_local_backend(config: CursorNativeBackendConfig) -> BackendAttestation:
    """Attest exactly the explicitly configured class; failures never downgrade.

    A blocked PACKAGE_BIN_PROVENANCE attestation raises; it is never silently
    reinterpreted as the weaker LOCAL_WRAPPER_CHAIN class, which requires its
    own explicit configuration and owner authorization.
    """

    if config.attestation_class == ATTESTATION_CLASS_WRAPPER_CHAIN:
        return _attest_wrapper_chain_cursor(config)
    return _attest_native_cursor(config)


def preflight_native_cursor(*, config: CursorNativeBackendConfig, work_workspace: str | Path | None = None) -> NativePreflightDecision:
    """Package-bin mode runs local ``--version``/``--help`` probes only.

    Wrapper-chain mode performs static discovery/parse attestation and never
    executes the launcher bundle at all; capability behavior stays unproven.
    """

    wrapper_chain = config.attestation_class == ATTESTATION_CLASS_WRAPPER_CHAIN
    try:
        if work_workspace is not None:
            _safe_directory(work_workspace, "preflight work workspace")
        if wrapper_chain:
            attestation, where_diagnostic = _attest_wrapper_chain_cursor_observed(config)
            return NativePreflightDecision(
                NativePreflightStatus.PREFLIGHT_READY, WRAPPER_CHAIN_READY_REASON,
                "Deterministic Windows PATH/PATHEXT authority, shutil.which agreement, PowerShell inventory, wrapper bytes, deterministic version selection, and runtime/entry identity attested. where.exe is diagnostic only unless a successful result contradicts authority. Publisher provenance, Cursor desktop ownership, payload signature, and CLI capability behavior are explicitly NOT established; suitable only for an owner-authorized local experiment.",
                attestation, where_diagnostic,
            )
        attestation = _attest_local_backend(config)
        return NativePreflightDecision(NativePreflightStatus.PREFLIGHT_READY, "LOCAL_CURSOR_CAPABILITIES_ATTESTED", "Local Cursor version/help probes advertised the required bounded experiment flags.", attestation)
    except _WhereDiagnosticContradiction as exc:
        return NativePreflightDecision(
            NativePreflightStatus.PREFLIGHT_BLOCKED, WRAPPER_CHAIN_BLOCKED_REASON,
            str(exc), None, exc.diagnostic,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return NativePreflightDecision(NativePreflightStatus.PREFLIGHT_BLOCKED, WRAPPER_CHAIN_BLOCKED_REASON if wrapper_chain else "LOCAL_CAPABILITY_ATTESTATION_BLOCKED", str(exc), None)


@dataclass(frozen=True)
class NativeExecutionRequest:
    schema_version: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    mission_fingerprint: str
    gate_contract_fingerprint: str
    work_workspace: str
    work_workspace_identity: NativeFilesystemIdentity
    evidence_store_root: str
    evidence_store_identity: NativeFilesystemIdentity
    artifact_directory: str
    artifact_directory_identity: NativeFilesystemIdentity
    executable: str
    launcher_prefix: tuple[str, ...]
    backend_identity: str
    backend_attestation: BackendAttestation
    backend_attestation_fingerprint: str
    timeout_seconds: int
    stdout_byte_limit: int
    stderr_byte_limit: int
    process_tree_cleanup_policy: str
    prompt_fingerprint: str
    request_fingerprint: str

    @classmethod
    def create(cls, *, session_id: str, gate_id: str, execution_attempt_index: int, mission_fingerprint: str, gate_contract_fingerprint: str, work_workspace: str | Path, evidence_store_root: str | Path, artifact_directory: str | Path, attestation: BackendAttestation, prompt: str, timeout_seconds: int, stdout_byte_limit: int, stderr_byte_limit: int) -> "NativeExecutionRequest":
        workspace, identity = _safe_directory(work_workspace, "work_workspace")
        evidence_root, evidence_identity = _safe_directory(evidence_store_root, "execution evidence root")
        artifacts, artifacts_identity = _safe_artifact_directory(evidence_root, artifact_directory)
        _require_disjoint_roots(("work workspace", workspace), ("execution evidence root", evidence_root))
        _require_disjoint_roots(("work workspace", workspace), ("native artifact directory", artifacts))
        attestation = attestation.validated()
        provisional = cls(
            REQUEST_SCHEMA_VERSION, session_id, gate_id, execution_attempt_index, mission_fingerprint,
            gate_contract_fingerprint, str(workspace), identity, str(evidence_root), evidence_identity,
            str(artifacts), artifacts_identity, attestation.executable.canonical_path,
            tuple(item.canonical_path for item in attestation.launcher_prefix), BACKEND_IDENTITY, attestation,
            attestation.attestation_fingerprint, timeout_seconds, stdout_byte_limit, stderr_byte_limit,
            PROCESS_TREE_CLEANUP_POLICY, hashlib.sha256(prompt.encode("utf-8")).hexdigest(), "0" * 64,
        )
        return cls(**{**provisional.__dict__, "request_fingerprint": fingerprint(provisional._body())}).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "session_id": self.session_id, "gate_id": self.gate_id,
            "execution_attempt_index": self.execution_attempt_index, "mission_fingerprint": self.mission_fingerprint,
            "gate_contract_fingerprint": self.gate_contract_fingerprint, "work_workspace": self.work_workspace,
            "work_workspace_identity": self.work_workspace_identity.to_dict(), "evidence_store_root": self.evidence_store_root,
            "evidence_store_identity": self.evidence_store_identity.to_dict(), "artifact_directory": self.artifact_directory,
            "artifact_directory_identity": self.artifact_directory_identity.to_dict(), "executable": self.executable,
            "launcher_prefix": list(self.launcher_prefix), "backend_identity": self.backend_identity,
            "backend_attestation": self.backend_attestation.to_dict(), "backend_attestation_fingerprint": self.backend_attestation_fingerprint,
            "timeout_seconds": self.timeout_seconds, "stdout_byte_limit": self.stdout_byte_limit,
            "stderr_byte_limit": self.stderr_byte_limit, "process_tree_cleanup_policy": self.process_tree_cleanup_policy,
            "prompt_fingerprint": self.prompt_fingerprint,
        }

    def validated(self) -> "NativeExecutionRequest":
        if self.schema_version != REQUEST_SCHEMA_VERSION:
            raise ValueError("unsupported native execution request schema")
        require_identifier(self.session_id, "request session_id"); require_identifier(self.gate_id, "request gate_id")
        require_strict_int(self.execution_attempt_index, "execution_attempt_index", minimum=0, maximum=0)
        require_sha256(self.mission_fingerprint, "mission_fingerprint"); require_sha256(self.gate_contract_fingerprint, "gate_contract_fingerprint")
        workspace, identity = _safe_directory(self.work_workspace, "work_workspace")
        if str(workspace) != self.work_workspace or not _same_mutable_directory_entry(identity, self.work_workspace_identity):
            raise ValueError("work workspace path or identity changed")
        self.work_workspace_identity.validated()
        evidence_root, evidence_identity = _safe_directory(self.evidence_store_root, "execution evidence root")
        if str(evidence_root) != self.evidence_store_root or not _same_mutable_directory_entry(evidence_identity, self.evidence_store_identity):
            raise ValueError("execution evidence root path or identity changed")
        artifacts, artifacts_identity = _safe_artifact_directory(evidence_root, self.artifact_directory)
        if str(artifacts) != self.artifact_directory or not _same_mutable_directory_entry(artifacts_identity, self.artifact_directory_identity):
            raise ValueError("native artifact directory path or identity changed")
        _require_disjoint_roots(("work workspace", workspace), ("execution evidence root", evidence_root))
        _require_disjoint_roots(("work workspace", workspace), ("native artifact directory", artifacts))
        self.evidence_store_identity.validated(); self.artifact_directory_identity.validated()
        self.backend_attestation.validated()
        if self.backend_identity != BACKEND_IDENTITY or self.backend_attestation_fingerprint != self.backend_attestation.attestation_fingerprint:
            raise ValueError("request backend attestation binding differs")
        if self.executable != self.backend_attestation.executable.canonical_path or self.launcher_prefix != tuple(item.canonical_path for item in self.backend_attestation.launcher_prefix):
            raise ValueError("request executable or launcher differs from attestation")
        require_strict_int(self.timeout_seconds, "timeout_seconds", minimum=1, maximum=3600)
        require_strict_int(self.stdout_byte_limit, "stdout_byte_limit", minimum=1, maximum=16 * 1024 * 1024)
        require_strict_int(self.stderr_byte_limit, "stderr_byte_limit", minimum=1, maximum=16 * 1024 * 1024)
        if self.process_tree_cleanup_policy != PROCESS_TREE_CLEANUP_POLICY:
            raise ValueError("unsupported cleanup policy")
        require_sha256(self.prompt_fingerprint, "prompt_fingerprint"); require_sha256(self.request_fingerprint, "request_fingerprint")
        if fingerprint(self._body()) != self.request_fingerprint:
            raise ValueError("native execution request fingerprint mismatch")
        return self

    def validated_for_execution(self, *, current_attestation: BackendAttestation) -> "NativeExecutionRequest":
        """Make an inert parsed request executable only after fresh local proof."""

        self.validated()
        current_attestation = current_attestation.validated()
        if current_attestation != self.backend_attestation:
            raise NativeEvidenceInvalid("persisted request differs from the freshly attested local Cursor backend")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body(); data["request_fingerprint"] = self.request_fingerprint; return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeExecutionRequest":
        require_exact_keys(data, set(cls.__dataclass_fields__), "native execution request")
        values = dict(data)
        values["work_workspace_identity"] = NativeFilesystemIdentity.from_dict(data["work_workspace_identity"])
        values["evidence_store_identity"] = NativeFilesystemIdentity.from_dict(data["evidence_store_identity"])
        values["artifact_directory_identity"] = NativeFilesystemIdentity.from_dict(data["artifact_directory_identity"])
        values["launcher_prefix"] = require_string_list(data["launcher_prefix"], "launcher_prefix")
        values["backend_attestation"] = attestation_from_dict(data["backend_attestation"])
        return cls(**values).validated()


@dataclass(frozen=True)
class NativeExecutionRequestBinding:
    """Inert structural binding for post-spawn evidence publication.

    This type deliberately carries no ``argv`` builder and no execution
    validation method.  It validates the canonical durable request bytes and
    their immutable fingerprints without consulting the mutable live backend.
    """

    session_id: str
    gate_id: str
    execution_attempt_index: int
    request_fingerprint: str
    mission_fingerprint: str
    gate_contract_fingerprint: str
    backend_attestation_fingerprint: str
    executable: str
    launcher_prefix: tuple[str, ...]
    work_workspace: str
    evidence_store_root: str
    artifact_directory: str
    prompt_fingerprint: str
    timeout_seconds: int
    stdout_byte_limit: int
    stderr_byte_limit: int
    selected_model: str


def _structural_request_binding(data: Mapping[str, Any]) -> NativeExecutionRequestBinding:
    """Validate an inert request snapshot without re-reading backend files."""

    require_exact_keys(data, set(NativeExecutionRequest.__dataclass_fields__), "native execution request")
    if data.get("schema_version") != REQUEST_SCHEMA_VERSION:
        raise ValueError("unsupported native execution request schema")
    body = dict(data); claimed = body.pop("request_fingerprint", None)
    require_sha256(claimed, "request fingerprint")
    if fingerprint(body) != claimed:
        raise ValueError("native execution request fingerprint mismatch")
    require_identifier(data["session_id"], "request session_id")
    require_identifier(data["gate_id"], "request gate_id")
    require_strict_int(data["execution_attempt_index"], "execution_attempt_index", minimum=0, maximum=0)
    require_sha256(data["mission_fingerprint"], "mission_fingerprint")
    require_sha256(data["gate_contract_fingerprint"], "gate_contract_fingerprint")
    require_sha256(data["backend_attestation_fingerprint"], "backend attestation fingerprint")
    require_sha256(data["prompt_fingerprint"], "prompt fingerprint")
    require_nonempty_text(data["executable"], "request executable", max_bytes=4096)
    launcher = require_string_list(data["launcher_prefix"], "request launcher prefix")
    if not launcher:
        raise ValueError("request launcher prefix is empty")
    for value, label in (
        (data["work_workspace"], "request workspace"),
        (data["evidence_store_root"], "request evidence root"),
        (data["artifact_directory"], "request artifact directory"),
    ):
        require_nonempty_text(value, label, max_bytes=4096)
    for key, maximum in (("timeout_seconds", 3600), ("stdout_byte_limit", 16 * 1024 * 1024), ("stderr_byte_limit", 16 * 1024 * 1024)):
        require_strict_int(data[key], key, minimum=1, maximum=maximum)
    attestation = data.get("backend_attestation")
    if not isinstance(attestation, Mapping):
        raise ValueError("request backend attestation is not an object")
    attestation_body = dict(attestation)
    attestation_fingerprint = attestation_body.pop("attestation_fingerprint", None)
    require_sha256(attestation_fingerprint, "embedded backend attestation fingerprint")
    if fingerprint(attestation_body) != attestation_fingerprint:
        raise ValueError("embedded backend attestation fingerprint mismatch")
    if attestation_fingerprint != data["backend_attestation_fingerprint"]:
        raise ValueError("request backend attestation binding differs")
    if data.get("backend_identity") != BACKEND_IDENTITY:
        raise ValueError("request backend identity differs")
    if data.get("process_tree_cleanup_policy") != PROCESS_TREE_CLEANUP_POLICY:
        raise ValueError("unsupported cleanup policy")
    selected_model = attestation.get("selected_model")
    require_nonempty_text(selected_model, "attested selected model", max_bytes=256)
    # Validate persisted filesystem snapshots as data only.  No path is opened.
    for key in ("work_workspace_identity", "evidence_store_identity", "artifact_directory_identity"):
        if not isinstance(data[key], Mapping):
            raise ValueError(f"{key} is not an object")
        NativeFilesystemIdentity.from_dict(data[key])
    return NativeExecutionRequestBinding(
        data["session_id"], data["gate_id"], data["execution_attempt_index"], claimed,
        data["mission_fingerprint"], data["gate_contract_fingerprint"],
        data["backend_attestation_fingerprint"], data["executable"], launcher,
        data["work_workspace"], data["evidence_store_root"], data["artifact_directory"],
        data["prompt_fingerprint"], data["timeout_seconds"], data["stdout_byte_limit"],
        data["stderr_byte_limit"], selected_model,
    )


@dataclass(frozen=True)
class NativeAttemptReserved:
    schema_version: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    request_fingerprint: str
    mission_fingerprint: str
    gate_contract_fingerprint: str
    backend_attestation_fingerprint: str
    executable: str
    launcher_prefix: tuple[str, ...]
    argv_fingerprint: str
    cwd: str
    reserved_at: str
    authorized_model: str
    provider_invocation_budget: int
    native_attempt_budget: int
    timeout_seconds: int
    stdout_byte_limit: int
    stderr_byte_limit: int
    reservation_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__); data["launcher_prefix"] = list(self.launcher_prefix); data.pop("reservation_fingerprint"); return data

    def validated(self) -> "NativeAttemptReserved":
        if self.schema_version != ATTEMPT_RESERVED_SCHEMA_VERSION: raise ValueError("unsupported attempt-reserved schema")
        require_identifier(self.session_id, "reservation session ID"); require_identifier(self.gate_id, "reservation gate ID")
        require_strict_int(self.execution_attempt_index, "reservation attempt", minimum=0, maximum=0)
        for label, value in (("request fingerprint", self.request_fingerprint), ("mission fingerprint", self.mission_fingerprint), ("gate fingerprint", self.gate_contract_fingerprint), ("backend fingerprint", self.backend_attestation_fingerprint), ("argv fingerprint", self.argv_fingerprint), ("reservation fingerprint", self.reservation_fingerprint)): require_sha256(value, label)
        require_nonempty_text(self.executable, "reserved executable", max_bytes=4096); _validate_argv((self.executable, *self.launcher_prefix), "reserved launcher")
        require_nonempty_text(self.cwd, "reserved cwd", max_bytes=4096); _validate_timestamp(self.reserved_at, "reserved_at")
        require_nonempty_text(self.authorized_model, "authorized model", max_bytes=256)
        require_strict_int(self.provider_invocation_budget, "provider invocation budget", minimum=1, maximum=1)
        require_strict_int(self.native_attempt_budget, "native attempt budget", minimum=1, maximum=1)
        require_strict_int(self.timeout_seconds, "reserved timeout", minimum=1, maximum=3600)
        require_strict_int(self.stdout_byte_limit, "reserved stdout limit", minimum=1, maximum=16 * 1024 * 1024)
        require_strict_int(self.stderr_byte_limit, "reserved stderr limit", minimum=1, maximum=16 * 1024 * 1024)
        if fingerprint(self._body()) != self.reservation_fingerprint: raise ValueError("attempt-reserved fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]: data=self._body(); data["reservation_fingerprint"]=self.reservation_fingerprint; return data
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeAttemptReserved":
        require_exact_keys(data,set(cls.__dataclass_fields__),"attempt reservation"); values=dict(data); values["launcher_prefix"]=require_string_list(data["launcher_prefix"],"reserved launcher prefix"); return cls(**values).validated()


@dataclass(frozen=True)
class NativeProcessStarted:
    schema_version: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    request_fingerprint: str
    reservation_fingerprint: str
    process_started_at: str
    process_id: int | None
    executable: str
    launcher_prefix: tuple[str, ...]
    process_started_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data=dict(self.__dict__); data["launcher_prefix"]=list(self.launcher_prefix); data.pop("process_started_fingerprint"); return data
    def validated(self) -> "NativeProcessStarted":
        if self.schema_version != PROCESS_STARTED_SCHEMA_VERSION: raise ValueError("unsupported process-started schema")
        require_identifier(self.session_id,"process-start session ID"); require_identifier(self.gate_id,"process-start gate ID"); require_strict_int(self.execution_attempt_index,"process-start attempt",minimum=0,maximum=0)
        require_sha256(self.request_fingerprint,"process-start request fingerprint"); require_sha256(self.reservation_fingerprint,"process-start reservation fingerprint"); require_sha256(self.process_started_fingerprint,"process-start fingerprint")
        _validate_timestamp(self.process_started_at,"process_started_at")
        if self.process_id is not None: require_strict_int(self.process_id,"process ID",minimum=1,maximum=2**63-1)
        require_nonempty_text(self.executable,"started executable",max_bytes=4096); _validate_argv((self.executable,*self.launcher_prefix),"started launcher")
        if fingerprint(self._body()) != self.process_started_fingerprint: raise ValueError("process-started fingerprint mismatch")
        return self
    def to_dict(self) -> dict[str, Any]: data=self._body(); data["process_started_fingerprint"]=self.process_started_fingerprint; return data
    @classmethod
    def from_dict(cls,data: Mapping[str,Any])->"NativeProcessStarted":
        require_exact_keys(data,set(cls.__dataclass_fields__),"process started"); values=dict(data); values["launcher_prefix"]=require_string_list(data["launcher_prefix"],"started launcher prefix"); return cls(**values).validated()


def _validate_string_mapping(value: Any, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping): raise ValueError(f"{label} is not an object")
    require_exact_keys(value, keys, label)
    return dict(value)


@dataclass(frozen=True)
class NativeProcessObservation:
    schema_version: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    request_fingerprint: str
    reservation_fingerprint: str
    process_started_fingerprint: str
    process_completion_observed: bool
    process: Mapping[str, Any]
    stdout_artifact: NativeArtifactReference
    stderr_artifact: NativeArtifactReference
    initial_workspace: Mapping[str, Any]
    final_workspace: Mapping[str, Any]
    source_observation: Mapping[str, Any]
    parent_observation: Mapping[str, Any]
    observation_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data=dict(self.__dict__); data["process"]=dict(self.process); data["initial_workspace"]=dict(self.initial_workspace); data["final_workspace"]=dict(self.final_workspace); data["source_observation"]=dict(self.source_observation); data["parent_observation"]=dict(self.parent_observation); data["stdout_artifact"]=self.stdout_artifact.to_dict(); data["stderr_artifact"]=self.stderr_artifact.to_dict(); data.pop("observation_fingerprint"); return data
    def validated(self) -> "NativeProcessObservation":
        if self.schema_version != PROCESS_OBSERVATION_SCHEMA_VERSION: raise ValueError("unsupported process-observation schema")
        require_identifier(self.session_id,"observation session ID"); require_identifier(self.gate_id,"observation gate ID"); require_strict_int(self.execution_attempt_index,"observation attempt",minimum=0,maximum=0)
        for label,value in (("request",self.request_fingerprint),("reservation",self.reservation_fingerprint),("process start",self.process_started_fingerprint),("observation",self.observation_fingerprint)): require_sha256(value,f"{label} fingerprint")
        require_bool(self.process_completion_observed,"process completion observed")
        if not self.process_completion_observed: raise ValueError("published process observation must establish completion")
        process=_validate_string_mapping(self.process,"process observation",{"started_at","ended_at","process_id","executable","launcher_prefix","argv_fingerprint","cwd","exit_code","timed_out","termination_reason","cleanup_confirmed","cleanup_observation","orphan_process_ids","output_truncation_occurred"})
        _validate_timestamp(process["started_at"],"observation started_at"); _validate_timestamp(process["ended_at"],"observation ended_at")
        if datetime.fromisoformat(process["ended_at"].replace("Z","+00:00")) < datetime.fromisoformat(process["started_at"].replace("Z","+00:00")): raise ValueError("observation ended_at precedes started_at")
        if process["process_id"] is not None: require_strict_int(process["process_id"],"observed process ID",minimum=1,maximum=2**63-1)
        require_nonempty_text(process["executable"],"observed executable",max_bytes=4096); require_string_list(process["launcher_prefix"],"observed launcher prefix"); require_sha256(process["argv_fingerprint"],"observed argv fingerprint"); require_nonempty_text(process["cwd"],"observed cwd",max_bytes=4096)
        if process["exit_code"] is not None and (isinstance(process["exit_code"],bool) or not isinstance(process["exit_code"],int)): raise ValueError("observed exit code is invalid")
        require_bool(process["timed_out"],"observed timeout"); require_nonempty_text(process["termination_reason"],"observed termination reason",max_bytes=256); require_bool(process["cleanup_confirmed"],"observed cleanup confirmation"); require_nonempty_text(process["cleanup_observation"],"observed cleanup state",max_bytes=256); require_bool(process["output_truncation_occurred"],"observed truncation")
        pids=process["orphan_process_ids"]
        if not isinstance(pids,list) or any(isinstance(pid,bool) or not isinstance(pid,int) or pid<=0 for pid in pids): raise ValueError("observed orphan process IDs are invalid")
        expected_cleanup=process["cleanup_observation"]==OBSERVATION_PROVEN_EMPTY and not pids
        if process["cleanup_confirmed"]!=expected_cleanup: raise ValueError("observed cleanup confirmation contradicts raw cleanup evidence")
        self.stdout_artifact.validated(); self.stderr_artifact.validated()
        if (self.stdout_artifact.purpose,self.stderr_artifact.purpose)!=("stdout","stderr"): raise ValueError("observation artifact roles differ")
        if process["output_truncation_occurred"]!=(self.stdout_artifact.truncated or self.stderr_artifact.truncated): raise ValueError("observed truncation summary contradicts artifacts")
        workspace_keys={"material_tree_hash","git_head","git_status","git_remotes","commit_message","files"}
        for label,value in (("initial workspace",self.initial_workspace),("final workspace",self.final_workspace)):
            workspace=_validate_string_mapping(value,label,workspace_keys); require_optional_git_oid(workspace["git_head"],f"{label} Git HEAD")
            if not isinstance(workspace["git_status"],str) or "\x00" in workspace["git_status"]: raise ValueError(f"{label} Git status is invalid")
            if workspace["commit_message"] is not None and (not isinstance(workspace["commit_message"],str) or "\x00" in workspace["commit_message"]): raise ValueError(f"{label} commit message is invalid")
            for key in ("git_remotes","files"):
                if not isinstance(workspace[key],list) or any(not isinstance(item,str) or "\x00" in item for item in workspace[key]): raise ValueError(f"{label} {key} is invalid")
        source=_validate_string_mapping(self.source_observation,"source observation",{"tree_hash_before","tree_hash_after","git_head_before","git_head_after","git_status_before","git_status_after","mutated"})
        for key in ("git_head_before","git_head_after"): require_optional_git_oid(source[key],f"source {key}")
        for key in ("git_status_before","git_status_after"):
            if not isinstance(source[key],str) or "\x00" in source[key]: raise ValueError(f"source {key} is invalid")
        require_bool(source["mutated"],"source mutated")
        expected_source_mutated=source["tree_hash_before"]!=source["tree_hash_after"] or source["git_head_before"]!=source["git_head_after"] or source["git_status_before"]!=source["git_status_after"]
        if source["mutated"]!=expected_source_mutated: raise ValueError("source mutation summary contradicts observations")
        parent=_validate_string_mapping(self.parent_observation,"parent observation",{"inventory_before","inventory_after","unexpected_sibling_mutations"})
        for key in ("inventory_before","inventory_after","unexpected_sibling_mutations"):
            if not isinstance(parent[key],list) or any(not isinstance(item,str) or "\x00" in item for item in parent[key]): raise ValueError(f"parent {key} is invalid")
        expected_siblings=sorted(set(parent["inventory_before"]).symmetric_difference(parent["inventory_after"]))
        if parent["unexpected_sibling_mutations"]!=expected_siblings: raise ValueError("parent mutation summary contradicts inventories")
        for value in (self.initial_workspace["material_tree_hash"],self.final_workspace["material_tree_hash"],self.source_observation["tree_hash_before"],self.source_observation["tree_hash_after"]): require_sha256(value,"observation tree hash")
        if fingerprint(self._body()) != self.observation_fingerprint: raise ValueError("process-observation fingerprint mismatch")
        return self
    def to_dict(self)->dict[str,Any]: data=self._body(); data["observation_fingerprint"]=self.observation_fingerprint; return data
    @classmethod
    def from_dict(cls,data: Mapping[str,Any])->"NativeProcessObservation":
        require_exact_keys(data,set(cls.__dataclass_fields__),"process observation"); values=dict(data); values["stdout_artifact"]=NativeArtifactReference.from_dict(data["stdout_artifact"]); values["stderr_artifact"]=NativeArtifactReference.from_dict(data["stderr_artifact"]); return cls(**values).validated()


@dataclass(frozen=True)
class NativeExecutionEligibility:
    schema_version: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    request_fingerprint: str
    observation_fingerprint: str
    evaluated_at: str
    pinned_executable_validation: str
    pinned_launcher_validation: tuple[str, ...]
    wrapper_chain_drift: tuple[str, ...]
    catalog_validation: str
    selected_version_validation: str
    backend_drift_diagnostics: tuple[str, ...]
    process_status_eligible: bool
    commit_message_compliant: bool
    workspace_clean: bool
    remotes_absent: bool
    exactly_one_commit: bool
    material_paths_compliant: bool
    source_and_root_integrity: bool
    eligible: bool
    ineligibility_reasons: tuple[str, ...]
    eligibility_fingerprint: str

    def _body(self)->dict[str,Any]:
        data=dict(self.__dict__)
        for key in ("pinned_launcher_validation","wrapper_chain_drift","backend_drift_diagnostics","ineligibility_reasons"): data[key]=list(data[key])
        data.pop("eligibility_fingerprint"); return data
    def validated(self)->"NativeExecutionEligibility":
        if self.schema_version != EXECUTION_ELIGIBILITY_SCHEMA_VERSION: raise ValueError("unsupported execution-eligibility schema")
        require_identifier(self.session_id,"eligibility session ID"); require_identifier(self.gate_id,"eligibility gate ID"); require_strict_int(self.execution_attempt_index,"eligibility attempt",minimum=0,maximum=0); require_sha256(self.request_fingerprint,"eligibility request fingerprint"); require_sha256(self.observation_fingerprint,"eligibility observation fingerprint"); require_sha256(self.eligibility_fingerprint,"eligibility fingerprint"); _validate_timestamp(self.evaluated_at,"eligibility evaluated_at")
        allowed={"NO_DRIFT","CONTENT_DRIFT","IDENTITY_ONLY_DRIFT","METADATA_ONLY_DRIFT","MISSING","UNREADABLE","NOT_APPLICABLE","VERSION_INVENTORY_DRIFT","SELECTED_VERSION_DRIFT"}
        for value in (self.pinned_executable_validation,*self.pinned_launcher_validation,self.catalog_validation,self.selected_version_validation,*self.wrapper_chain_drift):
            if value not in allowed: raise ValueError("eligibility drift classification is invalid")
        for name in ("process_status_eligible","commit_message_compliant","workspace_clean","remotes_absent","exactly_one_commit","material_paths_compliant","source_and_root_integrity","eligible"): require_bool(getattr(self,name),name)
        if not isinstance(self.backend_drift_diagnostics,tuple) or not isinstance(self.ineligibility_reasons,tuple) or any(not isinstance(item,str) or not item for item in (*self.backend_drift_diagnostics,*self.ineligibility_reasons)): raise ValueError("eligibility diagnostics are invalid")
        drift_clean=all(value in {"NO_DRIFT","NOT_APPLICABLE"} for value in (self.pinned_executable_validation,*self.pinned_launcher_validation,*self.wrapper_chain_drift,self.catalog_validation,self.selected_version_validation))
        isolated_selected_version_mtime_diagnostic = _is_isolated_selected_version_mtime_drift(
            executable=self.pinned_executable_validation,
            launchers=self.pinned_launcher_validation,
            wrappers=self.wrapper_chain_drift,
            catalog=self.catalog_validation,
            selected_version=self.selected_version_validation,
        )
        has_refresh_marker = FUTURE_ATTESTATION_REFRESH_DIAGNOSTIC in self.backend_drift_diagnostics
        if has_refresh_marker and (
            not isolated_selected_version_mtime_diagnostic
            or SELECTED_VERSION_MTIME_DIAGNOSTIC not in self.backend_drift_diagnostics
            or self.backend_drift_diagnostics.count(FUTURE_ATTESTATION_REFRESH_DIAGNOSTIC) != 1
        ):
            raise ValueError("execution-eligibility refresh marker is not an isolated selected-version mtime diagnostic")
        post_run_backend_drift_blocking = not drift_clean and not (
            isolated_selected_version_mtime_diagnostic and has_refresh_marker
        )
        expected_reasons=[]
        if post_run_backend_drift_blocking: expected_reasons.append("post_run_backend_drift")
        if not self.process_status_eligible: expected_reasons.append("native_process_or_cleanup_ineligible")
        if not self.commit_message_compliant: expected_reasons.append("complete_commit_message_mismatch")
        if not self.workspace_clean: expected_reasons.append("final_worktree_not_clean")
        if not self.remotes_absent: expected_reasons.append("git_remote_present")
        if not self.exactly_one_commit: expected_reasons.append("exactly_one_new_commit_required")
        if not self.material_paths_compliant: expected_reasons.append("required_material_paths_missing")
        if not self.source_and_root_integrity: expected_reasons.append("source_or_parent_boundary_changed")
        if self.ineligibility_reasons!=tuple(expected_reasons): raise ValueError("eligibility reasons contradict recorded checks")
        expected = not self.ineligibility_reasons
        if self.eligible != expected: raise ValueError("eligibility decision contradicts its reasons")
        if fingerprint(self._body()) != self.eligibility_fingerprint: raise ValueError("execution-eligibility fingerprint mismatch")
        return self
    def to_dict(self)->dict[str,Any]: data=self._body(); data["eligibility_fingerprint"]=self.eligibility_fingerprint; return data
    @classmethod
    def from_dict(cls,data: Mapping[str,Any])->"NativeExecutionEligibility":
        require_exact_keys(data,set(cls.__dataclass_fields__),"execution eligibility"); values=dict(data)
        for key in ("pinned_launcher_validation","wrapper_chain_drift","backend_drift_diagnostics","ineligibility_reasons"): values[key]=require_string_list(data[key],key)
        return cls(**values).validated()


@dataclass(frozen=True)
class NativeLifecycleCounts:
    native_attempts_reserved: int = 0
    native_processes_started: int = 0
    native_processes_completed: int = 0
    process_observations_published: int = 0
    accepted_native_results_published: int = 0
    provider_invocations_started: int = 0


@dataclass(frozen=True)
class NativeArtifactReference:
    schema_version: str
    artifact_id: str
    purpose: str
    relative_path: str
    sha256: str
    byte_count: int
    truncated: bool

    def validated(self) -> "NativeArtifactReference":
        if self.schema_version != ARTIFACT_SCHEMA_VERSION: raise ValueError("unsupported artifact schema")
        require_identifier(self.artifact_id, "artifact_id")
        if self.purpose not in {"stdout", "stderr", "behavioral-script", "behavioral-stdout", "behavioral-stderr"}: raise ValueError("unsupported artifact purpose")
        require_safe_relative_path(self.relative_path, "artifact relative_path"); require_sha256(self.sha256, "artifact sha256")
        require_strict_int(self.byte_count, "artifact byte_count", minimum=0, maximum=16 * 1024 * 1024); require_bool(self.truncated, "artifact truncated")
        return self

    def to_dict(self) -> dict[str, Any]: return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeArtifactReference":
        require_exact_keys(data, set(cls.__dataclass_fields__), "native artifact reference"); return cls(**dict(data)).validated()


@dataclass(frozen=True)
class NativeExecutionResult:
    schema_version: str
    request_fingerprint: str
    invocation_id: str
    status: NativeExecutionStatus
    backend_identity: str
    backend_attestation_fingerprint: str
    started_at: str
    ended_at: str
    executable: str
    argv: tuple[str, ...]
    cwd: str
    process_exit_code: int | None
    timed_out: bool
    termination_reason: str
    cleanup_confirmed: bool
    cleanup_observation: str
    orphan_process_ids: tuple[int, ...]
    stdout_artifact: NativeArtifactReference
    stderr_artifact: NativeArtifactReference
    output_truncation_occurred: bool
    initial_material_tree_hash: str
    final_material_tree_hash: str
    initial_git_head: str | None
    final_git_head: str | None
    final_git_porcelain_status: str
    final_git_remotes: tuple[str, ...]
    final_commit_message: str | None
    commits_added: int
    changed_material_files: tuple[str, ...]
    source_tree_hash_before: str
    source_tree_hash_after: str
    source_git_head_before: str | None
    source_git_head_after: str | None
    source_git_status_before: str
    source_git_status_after: str
    source_repository_mutated: bool
    parent_inventory_before: tuple[str, ...]
    parent_inventory_after: tuple[str, ...]
    unexpected_sibling_mutations: tuple[str, ...]
    workspace_material_changed: bool
    result_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data: dict[str, Any] = dict(self.__dict__)
        data["status"] = self.status.value
        data["argv"] = list(self.argv); data["orphan_process_ids"] = list(self.orphan_process_ids)
        for key in ("final_git_remotes", "changed_material_files", "parent_inventory_before", "parent_inventory_after", "unexpected_sibling_mutations"):
            data[key] = list(data[key])
        data["stdout_artifact"] = self.stdout_artifact.to_dict(); data["stderr_artifact"] = self.stderr_artifact.to_dict()
        data.pop("result_fingerprint")
        return data

    def validated(self, *, harden_git: bool | None = None) -> "NativeExecutionResult":
        if self.schema_version != RESULT_SCHEMA_VERSION or self.backend_identity != BACKEND_IDENTITY: raise ValueError("unsupported native execution result")
        require_sha256(self.request_fingerprint, "result request fingerprint"); require_identifier(self.invocation_id, "invocation_id")
        if not isinstance(self.status, NativeExecutionStatus): raise ValueError("unknown native result status")
        require_sha256(self.backend_attestation_fingerprint, "result backend attestation fingerprint")
        _validate_timestamp(self.started_at, "started_at"); _validate_timestamp(self.ended_at, "ended_at")
        if datetime.fromisoformat(self.ended_at.replace("Z", "+00:00")) < datetime.fromisoformat(self.started_at.replace("Z", "+00:00")): raise ValueError("ended_at precedes started_at")
        _validate_argv(self.argv, "result argv")
        if self.argv[0] != self.executable: raise ValueError("result executable differs from argv")
        cwd, _ = _safe_directory(self.cwd, "result cwd")
        if str(cwd) != self.cwd: raise ValueError("result cwd must be canonical")
        if self.process_exit_code is not None and (isinstance(self.process_exit_code, bool) or not isinstance(self.process_exit_code, int)): raise ValueError("process exit code is invalid")
        require_bool(self.timed_out, "timed_out"); require_nonempty_text(self.termination_reason, "termination_reason", max_bytes=256)
        require_bool(self.cleanup_confirmed, "cleanup_confirmed"); require_nonempty_text(self.cleanup_observation, "cleanup_observation", max_bytes=256)
        if not isinstance(self.orphan_process_ids, tuple) or any(isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 for pid in self.orphan_process_ids): raise ValueError("orphan process IDs are invalid")
        expected_cleanup = self.cleanup_observation == OBSERVATION_PROVEN_EMPTY and not self.orphan_process_ids
        if self.cleanup_confirmed != expected_cleanup: raise ValueError("cleanup confirmation contradicts its raw observation")
        self.stdout_artifact.validated(); self.stderr_artifact.validated()
        if self.stdout_artifact.purpose != "stdout" or self.stderr_artifact.purpose != "stderr": raise ValueError("artifact roles are reversed")
        require_bool(self.output_truncation_occurred, "output truncation")
        if self.output_truncation_occurred != (self.stdout_artifact.truncated or self.stderr_artifact.truncated): raise ValueError("truncation summary contradicts artifacts")
        for label, value in (("initial_material_tree_hash", self.initial_material_tree_hash), ("final_material_tree_hash", self.final_material_tree_hash), ("source_tree_hash_before", self.source_tree_hash_before), ("source_tree_hash_after", self.source_tree_hash_after)):
            require_sha256(value, label)
        for label, value in (("initial_git_head", self.initial_git_head), ("final_git_head", self.final_git_head), ("source_git_head_before", self.source_git_head_before), ("source_git_head_after", self.source_git_head_after)):
            require_optional_git_oid(value, label)
        for label, value in (("final_git_porcelain_status", self.final_git_porcelain_status), ("source_git_status_before", self.source_git_status_before), ("source_git_status_after", self.source_git_status_after)):
            if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > 1024 * 1024: raise ValueError(f"{label} is invalid")
        if self.final_commit_message is not None and (not isinstance(self.final_commit_message, str) or "\x00" in self.final_commit_message or len(self.final_commit_message.encode("utf-8")) > 16 * 1024): raise ValueError("final commit message is invalid")
        require_strict_int(self.commits_added, "commits_added", minimum=0, maximum=1024)
        for label, values in (("final_git_remotes", self.final_git_remotes), ("changed_material_files", self.changed_material_files), ("parent_inventory_before", self.parent_inventory_before), ("parent_inventory_after", self.parent_inventory_after), ("unexpected_sibling_mutations", self.unexpected_sibling_mutations)):
            if not isinstance(values, tuple) or any(not isinstance(value, str) or "\x00" in value for value in values): raise ValueError(f"{label} is invalid")
        require_bool(self.source_repository_mutated, "source_repository_mutated"); require_bool(self.workspace_material_changed, "workspace_material_changed")
        expected_source_mutated = (self.source_tree_hash_before != self.source_tree_hash_after or self.source_git_head_before != self.source_git_head_after or self.source_git_status_before != self.source_git_status_after)
        if self.source_repository_mutated != expected_source_mutated: raise ValueError("source mutation flag contradicts observations")
        expected_siblings = tuple(sorted(set(self.parent_inventory_before).symmetric_difference(self.parent_inventory_after)))
        if self.unexpected_sibling_mutations != expected_siblings: raise ValueError("sibling mutation field contradicts inventories")
        expected_workspace_changed = self.initial_material_tree_hash != self.final_material_tree_hash or self.initial_git_head != self.final_git_head
        if self.workspace_material_changed != expected_workspace_changed: raise ValueError("workspace change flag contradicts observations")
        # These are success-critical Git facts.  A self-fingerprint merely says
        # a record is internally serialised; it is not authority for claims
        # that can be re-observed from the assigned workspace.
        observed_final = _repository_observation(cwd, harden_git=harden_git)
        if (
            observed_final.material_tree_hash != self.final_material_tree_hash
            or observed_final.git_head != self.final_git_head
            or observed_final.git_status != self.final_git_porcelain_status
            or observed_final.git_remotes != self.final_git_remotes
            or observed_final.commit_message != self.final_commit_message
        ):
            raise ValueError("result final workspace/Git observations no longer match the assigned repository")
        if self.initial_git_head is not None and self.final_git_head is not None and self.initial_git_head != self.final_git_head:
            if not _is_ancestor(cwd, self.initial_git_head, self.final_git_head, harden_git=harden_git):
                raise ValueError("result final Git HEAD is outside the initial HEAD ancestry")
        if self.commits_added != _commits_added(cwd, self.initial_git_head, self.final_git_head, harden_git=harden_git):
            raise ValueError("result commit count contradicts the observed Git ancestry")
        if self.changed_material_files != _changed_files(cwd, self.initial_git_head, self.final_git_head, harden_git=harden_git):
            raise ValueError("result changed paths contradict the observed Git range")
        require_sha256(self.result_fingerprint, "result fingerprint")
        if fingerprint(self._body()) != self.result_fingerprint: raise ValueError("native result fingerprint mismatch")
        expected_status = NativeExecutionStatus.CLEANUP_UNCERTAIN if not self.cleanup_confirmed else NativeExecutionStatus.TIMED_OUT if self.timed_out else NativeExecutionStatus.PROCESS_SUCCEEDED if self.process_exit_code == 0 else NativeExecutionStatus.PROCESS_FAILED
        if self.status is not expected_status: raise ValueError("result status contradicts process observations")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body(); data["result_fingerprint"] = self.result_fingerprint; return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeExecutionResult":
        require_exact_keys(data, set(cls.__dataclass_fields__), "native execution result")
        values = dict(data); values["status"] = NativeExecutionStatus(data["status"]); values["argv"] = require_string_list(data["argv"], "result argv")
        values["orphan_process_ids"] = tuple(data["orphan_process_ids"]) if isinstance(data["orphan_process_ids"], list) else data["orphan_process_ids"]
        for key in ("final_git_remotes", "changed_material_files", "parent_inventory_before", "parent_inventory_after", "unexpected_sibling_mutations"):
            values[key] = require_string_list(data[key], key)
        values["stdout_artifact"] = NativeArtifactReference.from_dict(data["stdout_artifact"]); values["stderr_artifact"] = NativeArtifactReference.from_dict(data["stderr_artifact"])
        return cls(**values).validated()


@dataclass(frozen=True)
class _NativeProcessCreationProof:
    process_id: int | None
    _authority: object

    @classmethod
    def _after_successful_spawn(cls, process_id: int | None) -> "_NativeProcessCreationProof":
        if process_id is not None: require_strict_int(process_id,"spawned process ID",minimum=1,maximum=2**63-1)
        return cls(process_id,_PROCESS_CREATION_AUTHORITY)

    def validated(self) -> "_NativeProcessCreationProof":
        if self._authority is not _PROCESS_CREATION_AUTHORITY: raise NativeEvidenceInvalid("process-start proof lacks runner authority")
        if self.process_id is not None: require_strict_int(self.process_id,"spawned process ID",minimum=1,maximum=2**63-1)
        return self


_PROCESS_CREATION_AUTHORITY = object()


@dataclass(frozen=True)
class NativeProcessInvocation:
    argv: tuple[str, ...]
    cwd: str
    env: Mapping[str, str]
    timeout_seconds: int
    max_capture_bytes: int
    process_started: Callable[[_NativeProcessCreationProof], None]


@dataclass(frozen=True)
class NativeProcessOutcome:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    cleanup_confirmed: bool
    cleanup_observation: str
    termination_reason: str
    orphan_process_ids: tuple[int, ...] = ()
    observed_stdout_bytes: int = 0
    observed_stderr_bytes: int = 0
    output_truncated: bool = False
    process_id: int | None = None


class NativeProcessRunner(Protocol):
    def run(self, invocation: NativeProcessInvocation) -> NativeProcessOutcome: ...


class ManagedNativeProcessRunner:
    """Real no-shell managed-process runner. It never retries."""
    def run(self, invocation: NativeProcessInvocation) -> NativeProcessOutcome:
        process = ManagedProcess(
            list(invocation.argv), cwd=invocation.cwd, env=dict(invocation.env),
            want_stdin=False, max_capture_bytes=invocation.max_capture_bytes,
        )
        try:
            process.start()
        except ManagedProcessError as exc:
            raise NativeProcessStartError(f"native process could not start: {exc}") from exc
        try:
            # The callback is unreachable until ManagedProcess.start() has
            # returned with an OS process.  Its CREATE_ONLY publication is the
            # only constructor path for durable PROCESS_STARTED evidence.
            invocation.process_started(_NativeProcessCreationProof._after_successful_spawn(process.pid))
        except BaseException:
            process.terminate(reason="process_start_evidence_publication_failed")
            raise
        exit_code = process.wait(timeout=invocation.timeout_seconds)
        timed_out = exit_code is None and process.poll() is None
        observed = process.terminate(reason=TERMINATION_HARD_TIMEOUT) if timed_out else process.finish(reason=TERMINATION_COMPLETED)
        return NativeProcessOutcome(
            observed.exit_code if observed.exit_code is not None else exit_code,
            process.captured_stdout(), process.captured_stderr(), timed_out,
            observed.cleanup_proven, observed.cleanup_observation,
            observed.termination_reason, tuple(observed.remaining_process_ids),
            observed.stdout_bytes, observed.stderr_bytes,
            observed.output_truncated, process.pid,
        )


@dataclass(frozen=True)
class _RepositoryObservation:
    material_tree_hash: str
    files: tuple[str, ...]
    git_head: str | None
    git_status: str
    git_remotes: tuple[str, ...]
    commit_message: str | None


def _material_snapshot(root: Path) -> tuple[str, tuple[str, ...]]:
    _safe_directory(root, "material root")
    entries: list[tuple[str, str, int, NativeFilesystemIdentity]] = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory); kept: list[str] = []
        for name in sorted(dirnames):
            path = base / name
            if name == ".git": continue
            metadata = os.lstat(path)
            if _is_redirecting_path(path, metadata): raise NativeEvidenceInvalid("redirecting material directory is outside authority")
            if not stat.S_ISDIR(metadata.st_mode): raise NativeEvidenceInvalid("material directory entry is not a directory")
            kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            path = base / name
            if name == ".git": continue
            metadata = os.lstat(path)
            if _is_redirecting_path(path, metadata) or not stat.S_ISREG(metadata.st_mode): raise NativeEvidenceInvalid("redirecting material file is outside authority")
            data = path.read_bytes(); entries.append((path.relative_to(root).as_posix(), hashlib.sha256(data).hexdigest(), len(data), NativeFilesystemIdentity.from_stat(metadata)))
    entries.sort(); digest = hashlib.sha256()
    for relative, sha256, byte_count, identity in entries:
        digest.update(f"{relative}\0{sha256}\0{byte_count}\0{identity.device}:{identity.inode}\n".encode("utf-8"))
    return digest.hexdigest(), tuple(entry[0] for entry in entries)


def _is_sanitized_local_repository(repository: Path) -> bool:
    """Recognize only the exact deterministic target config emitted by G1."""

    config = repository / ".git" / "config"
    try:
        if config.stat().st_size > 1024 * 1024:
            return False
        data = config.read_bytes()
    except OSError:
        return False
    hooks = (repository / ".git" / "hooks").as_posix()
    # Markers must byte-match the plain `\t{name} = {value}\n` lines emitted by
    # the sanitizing target-config renderer.  This helper is defense in depth
    # for callers without the runtime decision; authority-bearing runtime
    # observations pass `harden_git` explicitly instead.
    return all(
        marker in data
        for marker in (
            f"\thooksPath = {hooks}\n".encode("utf-8"),
            b"\temail = admissible-native@local.invalid\n",
            b"\tgpgSign = false\n",
        )
    )


def _git(
    repository: Path,
    *arguments: str,
    timeout: int = 30,
    harden_git: bool | None = None,
) -> subprocess.CompletedProcess[str]:
    # Git may opportunistically refresh the index during otherwise observational
    # commands.  The native evidence boundary must not depend on its caller's
    # environment for read-only repository observations.
    harden = _is_sanitized_local_repository(repository) if harden_git is None else harden_git
    if harden:
        environment = _hardened_git_environment()
    else:
        environment = dict(os.environ)
        environment["GIT_OPTIONAL_LOCKS"] = "0"
    result = subprocess.run(["git", *arguments], cwd=repository, env=environment, shell=False, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if len(result.stdout.encode("utf-8")) > 2 * 1024 * 1024 or len(result.stderr.encode("utf-8")) > 2 * 1024 * 1024: raise NativeEvidenceInvalid("Git observation exceeded its output bound")
    return result


def _repository_observation(
    repository: Path, *, harden_git: bool | None = None
) -> _RepositoryObservation:
    tree_hash, files = _material_snapshot(repository)
    root = _git(repository, "rev-parse", "--show-toplevel", harden_git=harden_git)
    if root.returncode != 0 or Path(root.stdout.strip()).resolve() != repository.resolve(): raise NativeEvidenceInvalid("observed repository is not the exact Git root")
    head_result = _git(repository, "rev-parse", "--verify", "HEAD", harden_git=harden_git); head = head_result.stdout.strip().lower() if head_result.returncode == 0 else None; require_optional_git_oid(head, "observed Git HEAD")
    status_result = _git(repository, "status", "--porcelain=v1", "--untracked-files=all", harden_git=harden_git)
    remotes_result = _git(repository, "remote", harden_git=harden_git)
    if status_result.returncode != 0 or remotes_result.returncode != 0: raise NativeEvidenceInvalid("Git observation failed")
    message: str | None = None
    if head is not None:
        message_result = _git(repository, "log", "-1", "--format=%B", harden_git=harden_git)
        if message_result.returncode != 0: raise NativeEvidenceInvalid("Git commit-message observation failed")
        message = message_result.stdout.rstrip("\r\n")
    return _RepositoryObservation(tree_hash, files, head, status_result.stdout, tuple(line for line in remotes_result.stdout.splitlines() if line), message)


def _repository_authority_fingerprint(
    repository: Path,
    observation: _RepositoryObservation,
    *,
    harden_git: bool | None = None,
) -> str:
    """Bind source material plus Git config, refs, index and remote authority.

    Native execution cannot sandbox a hostile provider globally, so the source
    repository is observed before and after the process.  Folding these Git
    control-plane bytes into the existing source-tree evidence fields detects
    config/ref/index/remote mutation without changing legacy record schemas.
    """

    def git_path(name: str) -> Path:
        result = _git(repository, "rev-parse", "--git-path", name, harden_git=harden_git)
        if result.returncode != 0 or not result.stdout.strip():
            raise NativeEvidenceInvalid(f"source Git authority path is unavailable: {name}")
        path = Path(result.stdout.strip())
        return path if path.is_absolute() else repository / path

    def file_hash_or_absent(path: Path) -> str:
        if not path.exists():
            return hashlib.sha256(b"<ABSENT>").hexdigest()
        safe, _ = _safe_file(path, "source Git authority file")
        return hashlib.sha256(safe.read_bytes()).hexdigest()

    refs = _git(repository, "for-each-ref", "--format=%(refname)%00%(objectname)", harden_git=harden_git)
    remotes = _git(repository, "remote", "-v", harden_git=harden_git)
    if refs.returncode != 0 or remotes.returncode != 0:
        raise NativeEvidenceInvalid("source Git refs/remotes observation failed")
    return fingerprint(
        {
            "material_tree_hash": observation.material_tree_hash,
            "git_head": observation.git_head,
            "git_status": observation.git_status,
            "git_remotes": list(observation.git_remotes),
            "remote_configuration": remotes.stdout.splitlines(),
            "refs_sha256": hashlib.sha256(refs.stdout.encode("utf-8")).hexdigest(),
            "config_sha256": file_hash_or_absent(git_path("config")),
            "index_sha256": file_hash_or_absent(git_path("index")),
        }
    )


def _changed_files(repository: Path, initial_head: str | None, final_head: str | None, *, harden_git: bool | None = None) -> tuple[str, ...]:
    if initial_head is None or final_head is None or initial_head == final_head: return ()
    result = _git(
        repository, "diff", "--no-ext-diff", "--no-textconv", "--name-only",
        initial_head, final_head, harden_git=harden_git,
    )
    if result.returncode != 0: raise NativeEvidenceInvalid("Git changed-file observation failed")
    return tuple(sorted(line for line in result.stdout.splitlines() if line))


def _commits_added(repository: Path, initial_head: str | None, final_head: str | None, *, harden_git: bool | None = None) -> int:
    if initial_head is None or final_head is None or initial_head == final_head: return 0
    result = _git(repository, "rev-list", "--count", f"{initial_head}..{final_head}", harden_git=harden_git)
    if result.returncode != 0: raise NativeEvidenceInvalid("Git commit-count observation failed")
    try: count = int(result.stdout.strip())
    except ValueError as exc: raise NativeEvidenceInvalid("Git commit-count observation is malformed") from exc
    if count < 0: raise NativeEvidenceInvalid("Git commit-count observation is negative")
    return count


def _is_ancestor(repository: Path, initial_head: str, final_head: str, *, harden_git: bool | None = None) -> bool:
    result = _git(repository, "merge-base", "--is-ancestor", initial_head, final_head, harden_git=harden_git)
    if result.returncode not in {0, 1}:
        raise NativeEvidenceInvalid("Git ancestry observation failed")
    return result.returncode == 0


def _parent_inventory(parent: Path, *, allowed_children: frozenset[str]) -> tuple[str, ...]:
    _safe_directory(parent, "canary parent")
    inventory: list[str] = []
    for child in sorted(parent.iterdir(), key=lambda item: item.name):
        if child.name in allowed_children: continue
        metadata = os.lstat(child)
        if _is_redirecting_path(child, metadata):
            inventory.append(f"{child.name}:redirecting:{int(metadata.st_ino)}")
        elif stat.S_ISDIR(metadata.st_mode):
            tree_hash, files = _material_snapshot(child); identity = NativeFilesystemIdentity.from_stat(metadata)
            inventory.append(f"{child.name}:directory:{identity.device}:{identity.inode}:{tree_hash}:{len(files)}")
        elif stat.S_ISREG(metadata.st_mode):
            data = child.read_bytes(); identity = NativeFilesystemIdentity.from_stat(metadata)
            inventory.append(f"{child.name}:file:{identity.device}:{identity.inode}:{hashlib.sha256(data).hexdigest()}:{len(data)}")
        else:
            inventory.append(f"{child.name}:other:{metadata.st_mode}")
    return tuple(inventory)


def _bounded(data: str, limit: int, observed_bytes: int, already_truncated: bool) -> tuple[bytes, bool]:
    encoded = data.encode("utf-8"); return encoded[:limit], already_truncated or observed_bytes > limit or len(encoded) > limit


def _write_artifact(*, store_root: Path, artifact_directory: Path, artifact_id: str, purpose: str, data: bytes, truncated: bool) -> NativeArtifactReference:
    _safe_artifact_directory(store_root, artifact_directory)
    destination = artifact_directory / f"{artifact_id}.txt"
    try:
        _publish_native_bytes(
            PlatformDurabilityAdapter(), destination, data, operation=f"{purpose} artifact"
        )
    except FileExistsError as exc:
        raise NativeExecutionStoreError("native output artifact is write-once") from exc
    _safe_file(destination, "native output artifact")
    return NativeArtifactReference(ARTIFACT_SCHEMA_VERSION, artifact_id, purpose, destination.relative_to(store_root).as_posix(), hashlib.sha256(data).hexdigest(), len(data), truncated).validated()


def _repository_observation_dict(item: _RepositoryObservation) -> dict[str, Any]:
    return {
        "material_tree_hash": item.material_tree_hash,
        "git_head": item.git_head,
        "git_status": item.git_status,
        "git_remotes": list(item.git_remotes),
        "commit_message": item.commit_message,
        "files": list(item.files),
    }


def _attested_file_drift(item: NativeBackendFileAttestation) -> str:
    """Compare one live file to its snapshot without treating drift as parse failure."""

    try:
        path, identity = _safe_file(item.canonical_path, "post-run attested backend file")
        if str(path) != item.canonical_path:
            return "IDENTITY_ONLY_DRIFT"
        data_hash = _sha256_file(path)
    except FileNotFoundError:
        return "MISSING"
    except (OSError, ValueError):
        return "UNREADABLE"
    if data_hash != item.sha256 or identity.size != item.byte_count:
        return "CONTENT_DRIFT"
    if identity == item.filesystem_identity:
        return "NO_DRIFT"
    old = item.filesystem_identity
    physical_equal = (identity.device, identity.inode, identity.mode, identity.size, identity.file_attributes) == (old.device, old.inode, old.mode, old.size, old.file_attributes)
    return "METADATA_ONLY_DRIFT" if physical_equal else "IDENTITY_ONLY_DRIFT"


def _attested_directory_drift(path_value: str, snapshot: NativeFilesystemIdentity) -> str:
    try:
        path, identity=_safe_directory(path_value,"post-run attested backend directory")
        if str(path)!=path_value: return "IDENTITY_ONLY_DRIFT"
    except FileNotFoundError: return "MISSING"
    except (OSError,ValueError): return "UNREADABLE"
    if identity==snapshot: return "NO_DRIFT"
    physical_equal=(identity.device,identity.inode,identity.mode,identity.size,identity.file_attributes)==(snapshot.device,snapshot.inode,snapshot.mode,snapshot.size,snapshot.file_attributes)
    return "METADATA_ONLY_DRIFT" if physical_equal else "IDENTITY_ONLY_DRIFT"


def _is_isolated_selected_version_mtime_drift(
    *, executable: str, launchers: tuple[str, ...], wrappers: tuple[str, ...],
    catalog: str, selected_version: str,
) -> bool:
    """The sole post-observation diagnostic-only backend condition.

    This is deliberately narrower than raw drift classification.  It is only
    true for the wrapper-chain selected-version directory after selection and
    inventory remain stable and every pinned file/launcher/wrapper comparison
    still reports ``NO_DRIFT``.
    """

    return (
        selected_version == "METADATA_ONLY_DRIFT"
        and catalog == "NO_DRIFT"
        and executable == "NO_DRIFT"
        and all(value == "NO_DRIFT" for value in (*launchers, *wrappers))
    )


@dataclass(frozen=True)
class _BackendDrift:
    executable: str
    launchers: tuple[str, ...]
    wrappers: tuple[str, ...]
    command_resolution: str
    catalog: str
    selected_version: str
    diagnostics: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return all(value in {"NO_DRIFT", "NOT_APPLICABLE"} for value in (self.executable, *self.launchers, *self.wrappers, self.command_resolution, self.catalog, self.selected_version))

    @property
    def isolated_selected_version_mtime_drift(self) -> bool:
        return _is_isolated_selected_version_mtime_drift(
            executable=self.executable,
            launchers=self.launchers,
            wrappers=(*self.wrappers, self.command_resolution),
            catalog=self.catalog,
            selected_version=self.selected_version,
        )

    @property
    def diagnostic_only_diagnostics(self) -> tuple[str, ...]:
        if not self.isolated_selected_version_mtime_drift:
            return ()
        return (FUTURE_ATTESTATION_REFRESH_DIAGNOSTIC,)

    @property
    def persisted_diagnostics(self) -> tuple[str, ...]:
        """Raw drift diagnostics plus the narrowly scoped policy marker."""

        return (*self.diagnostics, *self.diagnostic_only_diagnostics)

    @property
    def blocking_diagnostics(self) -> tuple[str, ...]:
        """Raw diagnostics that continue to make post-run eligibility fail."""

        if self.clean or self.isolated_selected_version_mtime_drift:
            return ()
        return tuple(
            diagnostic for diagnostic in self.diagnostics
            if diagnostic.rsplit(":", 1)[-1] not in {"NO_DRIFT", "NOT_APPLICABLE"}
        )

    @property
    def post_run_eligible(self) -> bool:
        return not self.blocking_diagnostics


def _observe_backend_drift(
    attestation: BackendAttestation,
    *, post_run_wrapper_chain_attestation: WrapperChainBackendAttestation | None = None,
) -> _BackendDrift:
    executable = _attested_file_drift(attestation.executable)
    launchers = tuple(_attested_file_drift(item) for item in attestation.launcher_prefix)
    wrappers: tuple[str, ...] = ()
    command_resolution = "NOT_APPLICABLE"
    catalog = "NOT_APPLICABLE"
    selected = "NOT_APPLICABLE"
    diagnostics: list[str] = [f"pinned_executable:{executable}"]
    diagnostics.extend(f"pinned_launcher_{index}:{value}" for index, value in enumerate(launchers))
    if isinstance(attestation, WrapperChainBackendAttestation):
        wrappers = (
            _attested_file_drift(attestation.cmd_wrapper),
            _attested_file_drift(attestation.powershell_wrapper),
            _attested_file_drift(attestation.package_manifest),
            *tuple(_attested_file_drift(item) for item in attestation.version_wrapper_copies),
        )
        diagnostics.extend((f"cmd_wrapper:{wrappers[0]}", f"powershell_wrapper:{wrappers[1]}",f"selected_package_manifest:{wrappers[2]}"))
        diagnostics.extend(f"selected_wrapper_copy_{index}:{value}" for index,value in enumerate(wrappers[3:]))
        if post_run_wrapper_chain_attestation is None:
            command_resolution = "UNREADABLE"
        else:
            command_resolution = (
                "NO_DRIFT"
                if post_run_wrapper_chain_attestation.command_resolution == attestation.command_resolution
                else "IDENTITY_ONLY_DRIFT"
            )
        diagnostics.append(f"command_resolution:{command_resolution}")
        try:
            inventory, selected_version = _select_wrapper_version(Path(attestation.command_resolution.wrapper_root))
            catalog = "NO_DRIFT" if inventory == attestation.version_inventory else "VERSION_INVENTORY_DRIFT"
            selected = _attested_directory_drift(attestation.selected_version_root,attestation.selected_version_root_identity) if selected_version == attestation.selected_version else "SELECTED_VERSION_DRIFT"
        except (OSError, ValueError):
            catalog = "UNREADABLE"
            selected = "UNREADABLE"
        diagnostics.extend((f"version_inventory:{catalog}", f"selected_version:{selected}"))
    else:
        # Package-bin authority includes the discovered shim, manifest and
        # mapped launcher.  Any change remains conservatively ineligible.
        package_items = (
            attestation.provenance.discovered_shim,
            attestation.provenance.package_manifest,
            attestation.provenance.launcher,
        )
        wrappers = (
            *tuple(_attested_file_drift(item) for item in package_items),
            _attested_directory_drift(attestation.provenance.installation_root,attestation.provenance.installation_root_identity),
            _attested_directory_drift(attestation.provenance.package_root,attestation.provenance.package_root_identity),
        )
        diagnostics.extend(f"package_chain_{index}:{value}" for index, value in enumerate(wrappers))
    return _BackendDrift(executable, launchers, wrappers, command_resolution, catalog, selected, tuple(diagnostics))


def _result_from_observation(observation: NativeProcessObservation, *, backend_attestation_fingerprint: str, harden_git: bool | None = None) -> NativeExecutionResult:
    process=dict(observation.process); initial=dict(observation.initial_workspace); final=dict(observation.final_workspace); source=dict(observation.source_observation); parent=dict(observation.parent_observation)
    cleanup_confirmed=process["cleanup_confirmed"]
    status=NativeExecutionStatus.CLEANUP_UNCERTAIN if not cleanup_confirmed else NativeExecutionStatus.TIMED_OUT if process["timed_out"] else NativeExecutionStatus.PROCESS_SUCCEEDED if process["exit_code"]==0 else NativeExecutionStatus.PROCESS_FAILED
    # Accepted results retain only the non-secret executable/launcher prefix.
    # The complete argv is represented by the reservation/observation
    # fingerprint and is never serialized.
    argv=(process["executable"],*tuple(process["launcher_prefix"]))
    provisional=NativeExecutionResult(
        RESULT_SCHEMA_VERSION, observation.request_fingerprint,
        f"native:{observation.session_id}:{observation.gate_id}:{observation.execution_attempt_index}",
        status, BACKEND_IDENTITY, backend_attestation_fingerprint,
        process["started_at"], process["ended_at"], process["executable"], argv,
        process["cwd"], process["exit_code"], process["timed_out"], process["termination_reason"],
        cleanup_confirmed, process["cleanup_observation"], tuple(process["orphan_process_ids"]),
        observation.stdout_artifact, observation.stderr_artifact, process["output_truncation_occurred"],
        initial["material_tree_hash"], final["material_tree_hash"], initial["git_head"], final["git_head"],
        final["git_status"], tuple(final["git_remotes"]), final["commit_message"],
        _commits_added(Path(process["cwd"]), initial["git_head"], final["git_head"], harden_git=harden_git),
        _changed_files(Path(process["cwd"]), initial["git_head"], final["git_head"], harden_git=harden_git),
        source["tree_hash_before"], source["tree_hash_after"], source["git_head_before"], source["git_head_after"],
        source["git_status_before"], source["git_status_after"], source["mutated"],
        tuple(parent["inventory_before"]), tuple(parent["inventory_after"]), tuple(parent["unexpected_sibling_mutations"]),
        initial["material_tree_hash"] != final["material_tree_hash"] or initial["git_head"] != final["git_head"], "0"*64,
    )
    return provisional


class _IssuedNativeResult:
    __slots__ = ("__weakref__",)
    def __copy__(self): raise TypeError("native result issuance is transient and non-copyable")
    def __deepcopy__(self, memo): raise TypeError("native result issuance is transient and non-copyable")
    def __reduce__(self): raise TypeError("native result issuance is transient and non-serializable")


@dataclass(frozen=True)
class _IssuedNativeResultRecord:
    handle_ref: weakref.ReferenceType[_IssuedNativeResult]
    result: NativeExecutionResult


_ISSUED_NATIVE_RESULTS: dict[int, _IssuedNativeResultRecord] = {}


def _issue_native_result(result: NativeExecutionResult, *, harden_git: bool | None = None) -> _IssuedNativeResult:
    result = result.validated(harden_git=harden_git); handle = _IssuedNativeResult(); identity = id(handle)
    def _cleanup(reference: weakref.ReferenceType[_IssuedNativeResult]) -> None:
        current = _ISSUED_NATIVE_RESULTS.get(identity)
        if current is not None and current.handle_ref is reference: del _ISSUED_NATIVE_RESULTS[identity]
    _ISSUED_NATIVE_RESULTS[identity] = _IssuedNativeResultRecord(weakref.ref(handle, _cleanup), result)
    return handle


def _issued_native_result_for(handle: object) -> _IssuedNativeResultRecord:
    if type(handle) is not _IssuedNativeResult: raise NativeEvidenceInvalid("fresh native result requires an executor-issued handle")
    record = _ISSUED_NATIVE_RESULTS.get(id(handle))
    if record is None or record.handle_ref() is not handle: raise NativeEvidenceInvalid("native result issuance authority is absent or consumed")
    return record


def _consume_issued_native_result(handle: object) -> None:
    record = _issued_native_result_for(handle); del _ISSUED_NATIVE_RESULTS[id(handle)]


class NativeDelegatedExecutor:
    """Capture one attested native process and independently observed effects."""
    def __init__(self, *, config: CursorNativeBackendConfig, process_runner: NativeProcessRunner | None = None, clock: Callable[[], str] = _utc_now, local_attestor: Callable[[CursorNativeBackendConfig], BackendAttestation] | None = None, harden_git_environment: bool = False, git_metadata_inspector: Callable[[Path, bool], None] | None = None) -> None:
        if not isinstance(harden_git_environment, bool):
            raise ValueError("Git environment hardening selection must be boolean")
        if harden_git_environment and git_metadata_inspector is None:
            raise ValueError("hardened Git execution requires a direct metadata inspector")
        if git_metadata_inspector is not None and not callable(git_metadata_inspector):
            raise ValueError("Git metadata inspector must be callable")
        self.config = config; self.process_runner = process_runner or ManagedNativeProcessRunner(); self.clock = clock
        self._local_attestor = local_attestor or _attest_local_backend
        self.harden_git_environment = harden_git_environment
        self._git_metadata_inspector = git_metadata_inspector

    def attest_local_backend(self) -> BackendAttestation:
        """Explicit authority-bearing local re-attestation; never implicit parse work."""

        try:
            return self._local_attestor(self.config).validated()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise NativeEvidenceInvalid("local backend installation/capability attestation is unavailable") from exc

    def execute(
        self, *, request: NativeExecutionRequest, prompt: str,
        source_repository: str | Path, canary_parent: str | Path,
        allowed_parent_children: frozenset[str], evidence_store_root: str | Path,
        artifact_directory: str | Path,
        required_commit_message: str | None,
        required_material_paths: frozenset[str],
        required_commits_added: int = 1,
        final_worktree_clean_required: bool = True,
        final_index_clean_required: bool = True,
        final_remotes_absent_required: bool = True,
        execution_store: "AtomicNativeExecutionStore | None" = None,
    ) -> _IssuedNativeResult:
        current = self.attest_local_backend()
        try:
            request.validated_for_execution(current_attestation=current)
        except ValueError as exc:
            raise NativeEvidenceInvalid(str(exc)) from exc
        if hashlib.sha256(prompt.encode("utf-8")).hexdigest() != request.prompt_fingerprint: raise NativeEvidenceInvalid("prompt differs from durable request")
        workspace, workspace_identity = _safe_directory(request.work_workspace, "work workspace")
        if not _same_mutable_directory_entry(workspace_identity, request.work_workspace_identity): raise NativeEvidenceInvalid("work workspace identity changed after request issuance")
        source, source_identity = _safe_directory(source_repository, "source repository"); parent, parent_identity = _safe_directory(canary_parent, "canary parent")
        evidence_root, evidence_identity = _safe_directory(evidence_store_root, "execution evidence root"); artifacts, artifacts_identity = _safe_artifact_directory(evidence_root, artifact_directory)
        if (
            str(evidence_root) != request.evidence_store_root
            or not _same_mutable_directory_entry(evidence_identity, request.evidence_store_identity)
            or str(artifacts) != request.artifact_directory
            or not _same_mutable_directory_entry(artifacts_identity, request.artifact_directory_identity)
        ):
            raise NativeEvidenceInvalid("execution evidence/artifact authority differs from the durable request")
        _require_disjoint_roots(("source repository", source), ("work workspace", workspace), ("execution evidence root", evidence_root))
        _require_disjoint_roots(("source repository", source), ("work workspace", workspace), ("native artifact directory", artifacts))
        if workspace.parent != parent: raise NativeEvidenceInvalid("work workspace must be a direct child of canary parent")
        if _inside(evidence_root, parent) is False and _inside(parent, evidence_root) is False: raise NativeEvidenceInvalid("execution evidence root must be measured under canary parent")
        if not allowed_parent_children == frozenset({workspace.name}): raise NativeEvidenceInvalid("only the exact work workspace may be excluded from sibling observations")
        store = execution_store or AtomicNativeExecutionStore(evidence_root)
        if store.directory != evidence_root or store.artifact_directory != artifacts:
            raise NativeEvidenceInvalid("executor lifecycle store differs from the durable request roots")
        if not store.has_request(request.session_id, request.gate_id, request.execution_attempt_index):
            raise NativeEvidenceInvalid("durable native request must exist before attempt reservation")
        persisted = store.load_request_verified_against_local_backend(
            request.session_id, request.gate_id, request.execution_attempt_index,
            current_attestation=current,
        )
        if persisted != request:
            raise NativeEvidenceInvalid("in-memory request differs from the strict durable pre-spawn request")
        evidence_child=evidence_root.relative_to(parent).parts[0]
        measured_parent_exclusions=allowed_parent_children | frozenset({evidence_child})
        if self._git_metadata_inspector is not None:
            self._git_metadata_inspector(workspace, True)
            self._git_metadata_inspector(source, False)
        initial = _repository_observation(workspace, harden_git=self.harden_git_environment); source_before = _repository_observation(source, harden_git=self.harden_git_environment); source_authority_before = _repository_authority_fingerprint(source, source_before, harden_git=self.harden_git_environment); parent_before = _parent_inventory(parent, allowed_children=measured_parent_exclusions)
        argv = request.backend_attestation.argv(prompt=prompt)
        argv_fingerprint = hashlib.sha256(canonical_bytes(list(argv))).hexdigest()
        reservation = store.create_attempt_reserved(
            request=request, argv_fingerprint=argv_fingerprint,
            reserved_at=self.clock(), authorized_model=current.selected_model,
        )
        started_record: NativeProcessStarted | None = None
        def process_started(proof: _NativeProcessCreationProof) -> None:
            nonlocal started_record
            started_record = store.create_process_started(
                binding=store.load_request_structural(request.session_id, request.gate_id, 0),
                reservation=reservation, proof=proof, started_at=self.clock(),
            )
        provider_environment = self.config.build_environment()
        if self.harden_git_environment:
            provider_environment = _hardened_git_environment(base=provider_environment)
        invocation = NativeProcessInvocation(
            argv, str(workspace), provider_environment, request.timeout_seconds,
            max(request.stdout_byte_limit, request.stderr_byte_limit), process_started,
        )
        outcome = self.process_runner.run(invocation)
        if started_record is None:
            raise NativeProcessStartError("native runner returned without durable process-start evidence")
        ended_at = self.clock()
        # Revalidate every root before using the post-process observations.
        post_source, post_source_identity = _safe_directory(source, "source repository post-exit"); post_workspace, post_identity = _safe_directory(workspace, "work workspace post-exit"); post_parent, post_parent_identity = _safe_directory(parent, "canary parent post-exit"); post_evidence, post_evidence_identity = _safe_directory(evidence_root, "execution evidence root post-exit"); post_artifacts, post_artifacts_identity = _safe_artifact_directory(post_evidence, artifacts)
        if post_workspace != workspace or not _same_mutable_directory_entry(post_identity, workspace_identity): raise NativeEvidenceInvalid("work workspace identity changed during execution")
        if post_source != source or not _same_directory_identity(post_source_identity, source_identity): raise NativeEvidenceInvalid("source repository identity changed during execution")
        if post_parent != parent or not _same_directory_identity(post_parent_identity, parent_identity): raise NativeEvidenceInvalid("canary parent identity changed during execution")
        if post_evidence != evidence_root or not _same_mutable_directory_entry(post_evidence_identity, evidence_identity): raise NativeEvidenceInvalid("execution evidence root identity changed during execution")
        if post_artifacts != artifacts or not _same_mutable_directory_entry(post_artifacts_identity, artifacts_identity): raise NativeEvidenceInvalid("native artifact directory identity changed during execution")
        if self._git_metadata_inspector is not None:
            self._git_metadata_inspector(workspace, True)
            self._git_metadata_inspector(source, False)
        final = _repository_observation(workspace, harden_git=self.harden_git_environment); source_after = _repository_observation(source, harden_git=self.harden_git_environment); source_authority_after = _repository_authority_fingerprint(source, source_after, harden_git=self.harden_git_environment); parent_after = _parent_inventory(parent, allowed_children=measured_parent_exclusions)
        stdout_data, stdout_truncated = _bounded(outcome.stdout, request.stdout_byte_limit, outcome.observed_stdout_bytes, outcome.output_truncated)
        stderr_data, stderr_truncated = _bounded(outcome.stderr, request.stderr_byte_limit, outcome.observed_stderr_bytes, outcome.output_truncated)
        prefix = f"{request.session_id}.{request.gate_id}.attempt-{request.execution_attempt_index}"
        stdout_ref = _write_artifact(store_root=evidence_root, artifact_directory=artifacts, artifact_id=f"{prefix}.native.stdout", purpose="stdout", data=stdout_data, truncated=stdout_truncated)
        stderr_ref = _write_artifact(store_root=evidence_root, artifact_directory=artifacts, artifact_id=f"{prefix}.native.stderr", purpose="stderr", data=stderr_data, truncated=stderr_truncated)
        cleanup_confirmed = outcome.cleanup_confirmed and outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY and not outcome.orphan_process_ids
        status = NativeExecutionStatus.CLEANUP_UNCERTAIN if not cleanup_confirmed else NativeExecutionStatus.TIMED_OUT if outcome.timed_out else NativeExecutionStatus.PROCESS_SUCCEEDED if outcome.returncode == 0 else NativeExecutionStatus.PROCESS_FAILED
        source_mutated = source_authority_before != source_authority_after
        sibling_mutations = tuple(sorted(set(parent_before).symmetric_difference(parent_after)))
        process_data = {
            "started_at": started_record.process_started_at, "ended_at": ended_at,
            "process_id": started_record.process_id, "executable": request.executable,
            "launcher_prefix": list(request.launcher_prefix), "argv_fingerprint": argv_fingerprint,
            "cwd": str(workspace), "exit_code": outcome.returncode, "timed_out": outcome.timed_out,
            "termination_reason": outcome.termination_reason, "cleanup_confirmed": cleanup_confirmed,
            "cleanup_observation": outcome.cleanup_observation, "orphan_process_ids": list(outcome.orphan_process_ids),
            "output_truncation_occurred": stdout_truncated or stderr_truncated,
        }
        provisional_observation = NativeProcessObservation(
            PROCESS_OBSERVATION_SCHEMA_VERSION, request.session_id, request.gate_id, 0,
            request.request_fingerprint, reservation.reservation_fingerprint,
            started_record.process_started_fingerprint, True, process_data, stdout_ref, stderr_ref,
            _repository_observation_dict(initial), _repository_observation_dict(final),
            {"tree_hash_before":source_authority_before,"tree_hash_after":source_authority_after,"git_head_before":source_before.git_head,"git_head_after":source_after.git_head,"git_status_before":source_before.git_status,"git_status_after":source_after.git_status,"mutated":source_mutated},
            {"inventory_before":list(parent_before),"inventory_after":list(parent_after),"unexpected_sibling_mutations":list(sibling_mutations)},
            "0"*64,
        )
        observation = NativeProcessObservation(**{**provisional_observation.__dict__,"observation_fingerprint":fingerprint(provisional_observation._body())}).validated()
        try:
            observation = store.create_process_observation(observation)
        except (NativeExecutionStoreError, NativeEvidenceInvalid) as exc:
            raise NativeProcessObservationPublicationError(f"process observation publication failed: {exc}") from exc

        post_run_wrapper_chain_attestation: WrapperChainBackendAttestation | None = None
        if isinstance(request.backend_attestation, WrapperChainBackendAttestation):
            try:
                refreshed = self.attest_local_backend()
                if isinstance(refreshed, WrapperChainBackendAttestation):
                    post_run_wrapper_chain_attestation = refreshed
            except NativeEvidenceInvalid:
                # The raw file/directory comparisons below remain durable.  A
                # failed post-run resolution refresh is conservatively surfaced
                # as an unreadable command-resolution comparison.
                pass
        drift = _observe_backend_drift(
            request.backend_attestation,
            post_run_wrapper_chain_attestation=post_run_wrapper_chain_attestation,
        )
        process_ok = status is NativeExecutionStatus.PROCESS_SUCCEEDED and not outcome.timed_out and cleanup_confirmed and not outcome.orphan_process_ids
        commit_ok = (
            required_commit_message is None or final.commit_message == required_commit_message
        )
        status_lines = tuple(line for line in final.git_status.splitlines() if line)
        worktree_is_clean = all(
            len(line) >= 2 and line[1] == " " and not line.startswith("??")
            for line in status_lines
        )
        index_is_clean = all(
            len(line) >= 2 and line[0] in {" ", "?"}
            for line in status_lines
        )
        workspace_clean = (
            (not final_worktree_clean_required or worktree_is_clean)
            and (not final_index_clean_required or index_is_clean)
        )
        remotes_absent = not final.git_remotes or not final_remotes_absent_required
        one_commit = (
            _commits_added(workspace, initial.git_head, final.git_head, harden_git=self.harden_git_environment)
            == required_commits_added
        )
        material_ok = required_material_paths.issubset(set(_changed_files(workspace, initial.git_head, final.git_head, harden_git=self.harden_git_environment)))
        boundary_ok = not source_mutated and not sibling_mutations
        reasons: list[str] = []
        if not drift.post_run_eligible: reasons.append("post_run_backend_drift")
        if not process_ok: reasons.append("native_process_or_cleanup_ineligible")
        if not commit_ok: reasons.append("complete_commit_message_mismatch")
        if not workspace_clean: reasons.append("final_worktree_not_clean")
        if not remotes_absent: reasons.append("git_remote_present")
        if not one_commit: reasons.append("exactly_one_new_commit_required")
        if not material_ok: reasons.append("required_material_paths_missing")
        if not boundary_ok: reasons.append("source_or_parent_boundary_changed")
        provisional_eligibility = NativeExecutionEligibility(
            EXECUTION_ELIGIBILITY_SCHEMA_VERSION, request.session_id, request.gate_id, 0,
            request.request_fingerprint, observation.observation_fingerprint, self.clock(),
            drift.executable, drift.launchers, (*drift.wrappers, drift.command_resolution), drift.catalog, drift.selected_version,
            drift.persisted_diagnostics, process_ok, commit_ok, workspace_clean, remotes_absent, one_commit,
            material_ok, boundary_ok, not reasons, tuple(reasons), "0"*64,
        )
        eligibility = NativeExecutionEligibility(**{**provisional_eligibility.__dict__,"eligibility_fingerprint":fingerprint(provisional_eligibility._body())}).validated()
        eligibility = store.create_execution_eligibility(eligibility)
        if not eligibility.eligible:
            raise NativeResultIneligible(eligibility)
        provisional = _result_from_observation(observation, backend_attestation_fingerprint=request.backend_attestation_fingerprint, harden_git=self.harden_git_environment)
        result = NativeExecutionResult(**{**provisional.__dict__, "result_fingerprint": fingerprint(provisional._body())}).validated(harden_git=self.harden_git_environment)
        return _issue_native_result(result, harden_git=self.harden_git_environment)


@dataclass(frozen=True)
class NativeCheckpointCaptureAttempt:
    schema_version: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    request_fingerprint: str
    result_fingerprint: str
    gate_plan_fingerprint: str
    checkpoint_contract_fingerprint: str
    behavioral_evidence_fingerprint: str | None
    required_command_ids: tuple[str, ...]
    capture_attempt_id: str
    expected_terminal_status: str
    started_at: str
    state_revision: int
    attempt_fingerprint: str
    verification_mode: str | None = None

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__); data["required_command_ids"] = list(self.required_command_ids); data.pop("attempt_fingerprint")
        if self.schema_version == CAPTURE_ATTEMPT_SCHEMA_VERSION:
            data.pop("verification_mode")
        return data
    def validated(self) -> "NativeCheckpointCaptureAttempt":
        if self.schema_version not in {CAPTURE_ATTEMPT_SCHEMA_VERSION,CAPTURE_ATTEMPT_SCHEMA_VERSION_V2}: raise ValueError("unsupported capture attempt schema")
        require_identifier(self.session_id, "capture session ID"); require_identifier(self.gate_id, "capture gate ID"); require_strict_int(self.execution_attempt_index, "capture attempt", minimum=0, maximum=0)
        for label, value in (("request_fingerprint", self.request_fingerprint), ("result_fingerprint", self.result_fingerprint), ("gate_plan_fingerprint", self.gate_plan_fingerprint), ("checkpoint_contract_fingerprint", self.checkpoint_contract_fingerprint), ("attempt_fingerprint", self.attempt_fingerprint)): require_sha256(value, label)
        if self.schema_version == CAPTURE_ATTEMPT_SCHEMA_VERSION:
            require_sha256(self.behavioral_evidence_fingerprint, "behavioral_evidence_fingerprint")
            if self.verification_mode is not None:
                raise ValueError("legacy capture attempt cannot invent verification mode")
        elif self.verification_mode == "OBSERVED_ONLY":
            if self.behavioral_evidence_fingerprint is not None:
                raise ValueError("observed-only capture cannot bind behavioral evidence")
        elif self.verification_mode == "FROZEN_BEHAVIORAL":
            require_sha256(self.behavioral_evidence_fingerprint, "behavioral_evidence_fingerprint")
        else:
            raise ValueError("runtime capture attempt verification mode is invalid")
        if not isinstance(self.required_command_ids, tuple): raise ValueError("capture attempt command identities must be a tuple")
        if self.schema_version == CAPTURE_ATTEMPT_SCHEMA_VERSION and not self.required_command_ids: raise ValueError("capture attempt requires command identities")
        for command_id in self.required_command_ids: require_identifier(command_id, "capture command ID")
        if len(set(self.required_command_ids)) != len(self.required_command_ids): raise ValueError("capture command identities must be unique")
        require_identifier(self.capture_attempt_id, "capture attempt ID")
        if self.capture_attempt_id != f"capture:{self.session_id}:{self.gate_id}:0": raise ValueError("capture attempt ID differs from its bound run")
        if self.expected_terminal_status != CAPTURE_EXPECTED_SUCCESS_STATUS: raise ValueError("capture attempt expected terminal status is invalid")
        _validate_timestamp(self.started_at, "capture started_at"); require_strict_int(self.state_revision, "capture state revision", minimum=0, maximum=2**63-1)
        if fingerprint(self._body()) != self.attempt_fingerprint: raise ValueError("capture attempt fingerprint mismatch")
        return self
    def to_dict(self) -> dict[str, Any]: data=self._body(); data["attempt_fingerprint"]=self.attempt_fingerprint; return data
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeCheckpointCaptureAttempt":
        if data.get("schema_version") == CAPTURE_ATTEMPT_SCHEMA_VERSION:
            require_exact_keys(data, set(cls.__dataclass_fields__) - {"verification_mode"}, "capture attempt")
            values=dict(data); values["verification_mode"] = None
        else:
            require_exact_keys(data, set(cls.__dataclass_fields__), "capture attempt")
            values=dict(data)
        values["required_command_ids"]=require_string_list(data["required_command_ids"], "capture command IDs")
        return cls(**values).validated()


@dataclass(frozen=True)
class NativeCanaryTerminalRecord:
    schema_version: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    request_fingerprint: str
    result_fingerprint: str | None
    status: NativeCaptureTerminalStatus
    capture_attempt_fingerprint: str | None
    created_at: str
    failure_category: str
    diagnostic: str
    attempt_reserved_fingerprint: str | None
    process_started_fingerprint: str | None
    process_observation_fingerprint: str | None
    execution_eligibility_fingerprint: str | None
    terminal_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__); data["status"] = self.status.value; data.pop("terminal_fingerprint")
        if self.schema_version == TERMINAL_SCHEMA_VERSION:
            for key in ("attempt_reserved_fingerprint","process_started_fingerprint","process_observation_fingerprint","execution_eligibility_fingerprint"): data.pop(key)
        return data
    def validated(self) -> "NativeCanaryTerminalRecord":
        if self.schema_version not in {TERMINAL_SCHEMA_VERSION,TERMINAL_SCHEMA_VERSION_V2}: raise ValueError("unsupported terminal schema")
        require_identifier(self.session_id, "terminal session ID"); require_identifier(self.gate_id, "terminal gate ID"); require_strict_int(self.execution_attempt_index, "terminal attempt", minimum=0, maximum=0)
        require_sha256(self.request_fingerprint, "terminal request fingerprint")
        if self.result_fingerprint is not None: require_sha256(self.result_fingerprint, "terminal result fingerprint")
        if self.capture_attempt_fingerprint is not None: require_sha256(self.capture_attempt_fingerprint, "terminal capture attempt fingerprint")
        for label,value in (("attempt reserved",self.attempt_reserved_fingerprint),("process started",self.process_started_fingerprint),("process observation",self.process_observation_fingerprint),("execution eligibility",self.execution_eligibility_fingerprint)):
            if value is not None: require_sha256(value,f"terminal {label} fingerprint")
        if self.schema_version == TERMINAL_SCHEMA_VERSION and any(value is not None for value in (self.attempt_reserved_fingerprint,self.process_started_fingerprint,self.process_observation_fingerprint,self.execution_eligibility_fingerprint)): raise ValueError("legacy terminal cannot invent lifecycle evidence")
        if not isinstance(self.status, NativeCaptureTerminalStatus): raise ValueError("terminal status is invalid")
        _validate_timestamp(self.created_at, "terminal created_at"); require_nonempty_text(self.failure_category, "terminal failure category", max_bytes=128); require_nonempty_text(self.diagnostic, "terminal diagnostic", max_bytes=1024); require_sha256(self.terminal_fingerprint, "terminal fingerprint")
        if fingerprint(self._body()) != self.terminal_fingerprint: raise ValueError("terminal fingerprint mismatch")
        return self
    def to_dict(self) -> dict[str, Any]: data = self._body(); data["terminal_fingerprint"] = self.terminal_fingerprint; return data
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeCanaryTerminalRecord":
        if data.get("schema_version")==TERMINAL_SCHEMA_VERSION:
            legacy=set(cls.__dataclass_fields__)-{"attempt_reserved_fingerprint","process_started_fingerprint","process_observation_fingerprint","execution_eligibility_fingerprint"}
            require_exact_keys(data,legacy,"legacy canary terminal"); values=dict(data)
            values.update({"attempt_reserved_fingerprint":None,"process_started_fingerprint":None,"process_observation_fingerprint":None,"execution_eligibility_fingerprint":None})
        else:
            require_exact_keys(data,set(cls.__dataclass_fields__),"canary terminal"); values=dict(data)
        values["status"]=NativeCaptureTerminalStatus(data["status"]); return cls(**values).validated()


def _publish_native_bytes(
    adapter: PlatformDurabilityAdapter,
    path: Path,
    data: bytes,
    *,
    operation: str,
) -> None:
    try:
        adapter.publish(path, data, mode=PublicationMode.CREATE_ONLY)
    except PublicationConflict as exc:
        raise FileExistsError(path) from exc
    except PublicationVisibleButMetadataUncertain as exc:
        raise NativeCommittedButDurabilityUncertain(
            operation=operation, path=path, original_error=exc
        ) from exc
    except PostPublicationReloadFailure as exc:
        raise NativeEvidenceInvalid(
            f"{exc.reason_code}: {operation} reload failed: {exc}"
        ) from exc
    except DurabilityAdapterError as exc:
        raise NativeExecutionStoreError(
            f"{exc.reason_code}: {operation} publication failed: {exc}"
        ) from exc


class AtomicNativeExecutionStore:
    """Locked write-once request/result/capture sidecar with explicit durability."""
    def __init__(
        self,
        directory: str | Path,
        *,
        lock_timeout: float = 5.0,
        durability_adapter: PlatformDurabilityAdapter | None = None,
    ) -> None:
        self.directory, self.directory_identity = _safe_create_directory(directory, "native execution store")
        self.artifact_directory, self.artifact_directory_identity = _safe_create_directory(self.directory / "artifacts", "native artifact directory")
        if lock_timeout <= 0: raise ValueError("lock timeout must be positive")
        self.lock_timeout = lock_timeout
        self.durability_adapter = durability_adapter or PlatformDurabilityAdapter()

    @staticmethod
    def _key(session_id: str, gate_id: str, attempt: int) -> str:
        require_identifier(session_id, "store session ID"); require_identifier(gate_id, "store gate ID"); require_strict_int(attempt, "store attempt", minimum=0, maximum=0); return f"{session_id}.{gate_id}.attempt-{attempt}"
    def _path(self, kind: str, session_id: str, gate_id: str, attempt: int) -> Path: return self.directory / f"{self._key(session_id, gate_id, attempt)}.native-{kind}.json"
    def _lock(self, session_id: str, gate_id: str, attempt: int) -> _FileLock: return _FileLock(self.directory / f".{self._key(session_id, gate_id, attempt)}.native-evidence.lock", timeout=self.lock_timeout)
    def _assert_root_identity(self) -> None:
        root, identity = _safe_directory(self.directory, "native execution store")
        if root != self.directory or not _same_mutable_directory_entry(identity, self.directory_identity): raise NativeEvidenceInvalid("native execution store root identity changed")
    def _assert_artifact_root_identity(self) -> None:
        root, identity = _safe_directory(self.artifact_directory, "native artifact directory")
        if root != self.artifact_directory or not _same_mutable_directory_entry(identity, self.artifact_directory_identity): raise NativeEvidenceInvalid("native artifact directory identity changed")
    def _atomic_create(self, path: Path, payload: Mapping[str, Any], *, operation: str) -> None:
        self._assert_root_identity()
        _publish_native_bytes(
            self.durability_adapter,
            path,
            canonical_bytes(payload) + b"\n",
            operation=operation,
        )
    def _atomic_create_bytes(self, path: Path, data: bytes, *, operation: str) -> None:
        self._assert_root_identity(); self._assert_artifact_root_identity()
        _publish_native_bytes(self.durability_adapter, path, data, operation=operation)
    def has_request(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("request", session_id, gate_id, attempt).is_file()
    def has_attempt_reserved(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("attempt-reserved", session_id, gate_id, attempt).is_file()
    def has_process_started(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("process-started", session_id, gate_id, attempt).is_file()
    def has_process_observation(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("process-observation", session_id, gate_id, attempt).is_file()
    def has_execution_eligibility(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("execution-eligibility", session_id, gate_id, attempt).is_file()
    def has_result(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("result", session_id, gate_id, attempt).is_file()
    def has_capture_attempt(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("capture-attempt", session_id, gate_id, attempt).is_file()
    def has_terminal(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("terminal", session_id, gate_id, attempt).is_file()
    def has_behavioral_evidence(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("behavioral", session_id, gate_id, attempt).is_file()
    def lifecycle_counts(self, session_id: str, gate_id: str, attempt: int) -> NativeLifecycleCounts:
        reserved=int(self.has_attempt_reserved(session_id,gate_id,attempt))
        started=int(self.has_process_started(session_id,gate_id,attempt))
        observed=int(self.has_process_observation(session_id,gate_id,attempt))
        completed=0
        if observed:
            completed=int(self.load_process_observation(session_id,gate_id,attempt).process_completion_observed)
        accepted=int(self.has_result(session_id,gate_id,attempt))
        return NativeLifecycleCounts(reserved,started,completed,observed,accepted,started)
    def assert_unique_capture_attempt(self, session_id: str, gate_id: str, attempt: int) -> None:
        expected = self._path("capture-attempt", session_id, gate_id, attempt)
        matches = tuple(self.directory.glob(f"{session_id}.{gate_id}.attempt-*.native-capture-attempt.json"))
        if matches != (expected,):
            raise NativeEvidenceInvalid("native run has an alternate or duplicate capture-attempt record")
    def create_request(self, request: NativeExecutionRequest) -> None:
        request.validated(); path=self._path("request", request.session_id, request.gate_id, request.execution_attempt_index)
        with self._lock(request.session_id, request.gate_id, request.execution_attempt_index):
            if path.exists(): raise NativeRequestAlreadyExists("native execution request is write-once")
            try: self._atomic_create(path, request.to_dict(), operation="native request")
            except FileExistsError as exc: raise NativeRequestAlreadyExists("native execution request is write-once") from exc
        if self.load_request(request.session_id, request.gate_id, request.execution_attempt_index) != request: raise NativeEvidenceInvalid("reloaded request differs")
    def _load(self, kind: str, session_id: str, gate_id: str, attempt: int, loader: Callable[[Mapping[str, Any]], Any]) -> Any:
        self._assert_root_identity(); path=self._path(kind, session_id, gate_id, attempt)
        if not path.is_file(): raise NativeEvidenceNotFound(f"native {kind} not found")
        try:
            raw=path.read_bytes(); parsed=json.loads(raw.decode("utf-8"))
            if not isinstance(parsed,Mapping) or raw != canonical_bytes(parsed)+b"\n": raise ValueError("record bytes are not canonical")
            item=loader(parsed)
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc: raise NativeEvidenceInvalid(f"native {kind} is invalid: {exc}") from exc
        if hasattr(item, "session_id") and (item.session_id, item.gate_id, item.execution_attempt_index) != (session_id, gate_id, attempt):
            raise NativeEvidenceInvalid(f"native {kind} identity differs from filename")
        return item
    def load_request(self, session_id: str, gate_id: str, attempt: int) -> NativeExecutionRequest: return self._load("request", session_id, gate_id, attempt, NativeExecutionRequest.from_dict)
    def load_request_structural(self, session_id: str, gate_id: str, attempt: int) -> NativeExecutionRequestBinding:
        return self._load("request",session_id,gate_id,attempt,_structural_request_binding)
    def load_request_verified_against_local_backend(self, session_id: str, gate_id: str, attempt: int, *, current_attestation: NativeBackendAttestation) -> NativeExecutionRequest:
        request = self.load_request(session_id, gate_id, attempt)
        return request.validated_for_execution(current_attestation=current_attestation)
    def create_attempt_reserved(self, *, request: NativeExecutionRequest, argv_fingerprint: str, reserved_at: str, authorized_model: str) -> NativeAttemptReserved:
        request.validated(); binding=self.load_request_structural(request.session_id,request.gate_id,request.execution_attempt_index)
        if binding.request_fingerprint != request.request_fingerprint: raise NativeEvidenceInvalid("reservation request binding differs")
        if any((self.has_attempt_reserved(binding.session_id,binding.gate_id,0),self.has_process_started(binding.session_id,binding.gate_id,0),self.has_process_observation(binding.session_id,binding.gate_id,0),self.has_execution_eligibility(binding.session_id,binding.gate_id,0),self.has_result(binding.session_id,binding.gate_id,0))): raise NativeResultAlreadyExists("native attempt slot is already consumed")
        provisional=NativeAttemptReserved(ATTEMPT_RESERVED_SCHEMA_VERSION,binding.session_id,binding.gate_id,0,binding.request_fingerprint,binding.mission_fingerprint,binding.gate_contract_fingerprint,binding.backend_attestation_fingerprint,binding.executable,binding.launcher_prefix,argv_fingerprint,binding.work_workspace,reserved_at,authorized_model,1,1,binding.timeout_seconds,binding.stdout_byte_limit,binding.stderr_byte_limit,"0"*64)
        item=NativeAttemptReserved(**{**provisional.__dict__,"reservation_fingerprint":fingerprint(provisional._body())}).validated(); path=self._path("attempt-reserved",item.session_id,item.gate_id,0)
        with self._lock(item.session_id,item.gate_id,0):
            if path.exists(): raise NativeResultAlreadyExists("attempt reservation is write-once")
            try: self._atomic_create(path,item.to_dict(),operation="native attempt reservation")
            except FileExistsError as exc: raise NativeResultAlreadyExists("attempt reservation is write-once") from exc
        return self.load_attempt_reserved(item.session_id,item.gate_id,0)
    def load_attempt_reserved(self,session_id: str,gate_id: str,attempt: int)->NativeAttemptReserved:
        item=self._load("attempt-reserved",session_id,gate_id,attempt,NativeAttemptReserved.from_dict); binding=self.load_request_structural(session_id,gate_id,attempt)
        if item.request_fingerprint!=binding.request_fingerprint: raise NativeEvidenceInvalid("attempt reservation differs from request")
        return item
    def create_process_started(self, *, binding: NativeExecutionRequestBinding, reservation: NativeAttemptReserved, proof: _NativeProcessCreationProof, started_at: str) -> NativeProcessStarted:
        # This method is intentionally called only by the runner's post-spawn
        # callback.  No coordinator/preflight API exposes a pre-spawn path.
        if reservation.request_fingerprint!=binding.request_fingerprint: raise NativeEvidenceInvalid("process start differs from reservation request")
        process_id=proof.validated().process_id
        if self.has_process_started(binding.session_id,binding.gate_id,0): raise NativeResultAlreadyExists("process-started record is write-once")
        provisional=NativeProcessStarted(PROCESS_STARTED_SCHEMA_VERSION,binding.session_id,binding.gate_id,0,binding.request_fingerprint,reservation.reservation_fingerprint,started_at,process_id,binding.executable,binding.launcher_prefix,"0"*64)
        item=NativeProcessStarted(**{**provisional.__dict__,"process_started_fingerprint":fingerprint(provisional._body())}).validated(); path=self._path("process-started",item.session_id,item.gate_id,0)
        with self._lock(item.session_id,item.gate_id,0):
            if path.exists(): raise NativeResultAlreadyExists("process-started record is write-once")
            self._atomic_create(path,item.to_dict(),operation="native process started")
        return self.load_process_started(item.session_id,item.gate_id,0)
    def load_process_started(self,session_id: str,gate_id: str,attempt: int)->NativeProcessStarted:
        item=self._load("process-started",session_id,gate_id,attempt,NativeProcessStarted.from_dict); reservation=self.load_attempt_reserved(session_id,gate_id,attempt)
        if item.reservation_fingerprint!=reservation.reservation_fingerprint: raise NativeEvidenceInvalid("process start differs from reservation")
        return item
    def create_process_observation(self,item: NativeProcessObservation)->NativeProcessObservation:
        item.validated(); binding=self.load_request_structural(item.session_id,item.gate_id,item.execution_attempt_index); started=self.load_process_started(item.session_id,item.gate_id,item.execution_attempt_index)
        if item.request_fingerprint!=binding.request_fingerprint or item.process_started_fingerprint!=started.process_started_fingerprint: raise NativeEvidenceInvalid("process observation lifecycle binding differs")
        self._verify_artifact(item.stdout_artifact); self._verify_artifact(item.stderr_artifact); path=self._path("process-observation",item.session_id,item.gate_id,0)
        with self._lock(item.session_id,item.gate_id,0):
            if path.exists(): raise NativeResultAlreadyExists("process observation is write-once")
            self._atomic_create(path,item.to_dict(),operation="native process observation")
        return self.load_process_observation(item.session_id,item.gate_id,0)
    def load_process_observation(self,session_id: str,gate_id: str,attempt: int)->NativeProcessObservation:
        item=self._load("process-observation",session_id,gate_id,attempt,NativeProcessObservation.from_dict); started=self.load_process_started(session_id,gate_id,attempt)
        if item.process_started_fingerprint!=started.process_started_fingerprint: raise NativeEvidenceInvalid("process observation differs from process start")
        reservation=self.load_attempt_reserved(session_id,gate_id,attempt)
        if (item.process["started_at"],item.process["process_id"],item.process["executable"],tuple(item.process["launcher_prefix"]),item.process["argv_fingerprint"])!=(started.process_started_at,started.process_id,started.executable,started.launcher_prefix,reservation.argv_fingerprint): raise NativeEvidenceInvalid("process observation contradicts reservation/process-start evidence")
        self._verify_artifact(item.stdout_artifact); self._verify_artifact(item.stderr_artifact); return item
    def create_execution_eligibility(self,item: NativeExecutionEligibility)->NativeExecutionEligibility:
        item.validated(); observation=self.load_process_observation(item.session_id,item.gate_id,item.execution_attempt_index)
        if item.observation_fingerprint!=observation.observation_fingerprint: raise NativeEvidenceInvalid("eligibility differs from process observation")
        path=self._path("execution-eligibility",item.session_id,item.gate_id,0)
        with self._lock(item.session_id,item.gate_id,0):
            if path.exists(): raise NativeResultAlreadyExists("execution eligibility is write-once")
            self._atomic_create(path,item.to_dict(),operation="native execution eligibility")
        return self.load_execution_eligibility(item.session_id,item.gate_id,0)
    def load_execution_eligibility(self,session_id: str,gate_id: str,attempt: int)->NativeExecutionEligibility:
        item=self._load("execution-eligibility",session_id,gate_id,attempt,NativeExecutionEligibility.from_dict); observation=self.load_process_observation(session_id,gate_id,attempt)
        if item.observation_fingerprint!=observation.observation_fingerprint: raise NativeEvidenceInvalid("eligibility differs from observation")
        return item
    def _verify_artifact(self, reference: NativeArtifactReference) -> None:
        reference.validated(); candidate = self.directory / reference.relative_path
        try: path, _ = _safe_file(candidate, "native artifact")
        except ValueError as exc: raise NativeEvidenceInvalid(str(exc)) from exc
        if not _inside(path, self.directory): raise NativeEvidenceInvalid("native artifact escapes evidence store")
        data=path.read_bytes()
        if len(data) != reference.byte_count or hashlib.sha256(data).hexdigest()!=reference.sha256: raise NativeEvidenceInvalid("native artifact hash or byte count mismatch")
    def verify_artifact(self, reference: NativeArtifactReference) -> None:
        self._verify_artifact(reference)
    def write_behavioral_artifact(self, *, request: NativeExecutionRequest, artifact_id: str, purpose: str, data: bytes) -> NativeArtifactReference:
        request.validated(); require_identifier(artifact_id, "behavioral artifact ID")
        if purpose not in {"behavioral-script", "behavioral-stdout", "behavioral-stderr"}:
            raise NativeEvidenceInvalid("unsupported behavioral artifact purpose")
        if not isinstance(data, bytes) or len(data) > 2 * 1024 * 1024:
            raise NativeEvidenceInvalid("behavioral artifact is invalid or oversized")
        # The harness-owned verifier is an ES module.  Its suffix is part of
        # the immutable artifact identity, so Node cannot reinterpret it as a
        # mutable repository CommonJS file.
        suffix = ".mjs" if purpose == "behavioral-script" else ".bin"
        destination = self.artifact_directory / f"{artifact_id}{suffix}"
        reference = NativeArtifactReference(
            ARTIFACT_SCHEMA_VERSION, artifact_id, purpose,
            destination.relative_to(self.directory).as_posix(), hashlib.sha256(data).hexdigest(), len(data), False,
        ).validated()
        with self._lock(request.session_id, request.gate_id, request.execution_attempt_index):
            self._atomic_create_bytes(destination, data, operation=f"{purpose} artifact")
        self._verify_artifact(reference)
        return reference
    @staticmethod
    def _validate_behavioral_binding(request: NativeExecutionRequest, evidence: Any) -> None:
        if (
            getattr(evidence, "session_id", None), getattr(evidence, "gate_id", None), getattr(evidence, "execution_attempt_index", None), getattr(evidence, "request_fingerprint", None)
        ) != (
            request.session_id, request.gate_id, request.execution_attempt_index, request.request_fingerprint
        ):
            raise NativeEvidenceInvalid("behavioral evidence differs from the native request")
        for name, purpose in (("script", "behavioral-script"), ("stdout", "behavioral-stdout"), ("stderr", "behavioral-stderr")):
            reference = getattr(evidence, name, None)
            if not isinstance(reference, NativeArtifactReference) or reference.purpose != purpose:
                raise NativeEvidenceInvalid("behavioral evidence artifact roles differ")
    def create_behavioral_evidence(self, *, request: NativeExecutionRequest, evidence: Any, loader: Callable[[Mapping[str, Any]], Any]) -> Any:
        request.validated(); evidence.validated(); self._validate_behavioral_binding(request, evidence)
        for reference in (evidence.script, evidence.stdout, evidence.stderr): self._verify_artifact(reference)
        path = self._path("behavioral", request.session_id, request.gate_id, request.execution_attempt_index)
        with self._lock(request.session_id, request.gate_id, request.execution_attempt_index):
            if path.exists(): raise NativeResultAlreadyExists("behavioral evidence is write-once")
            try: self._atomic_create(path, evidence.to_dict(), operation="behavioral evidence")
            except FileExistsError as exc: raise NativeResultAlreadyExists("behavioral evidence is write-once") from exc
        return self.load_behavioral_evidence(request.session_id, request.gate_id, request.execution_attempt_index, loader=loader)
    def load_behavioral_evidence(self, session_id: str, gate_id: str, attempt: int, *, loader: Callable[[Mapping[str, Any]], Any]) -> Any:
        evidence = self._load("behavioral", session_id, gate_id, attempt, loader)
        # Binding uses the inert structural request snapshot: loading persisted
        # behavioral evidence is never an occasion to consult the live backend.
        request = self.load_request_structural(session_id, gate_id, attempt)
        self._validate_behavioral_binding(request, evidence)
        for reference in (evidence.script, evidence.stdout, evidence.stderr): self._verify_artifact(reference)
        return evidence
    def _request_for_result(self, result: NativeExecutionResult) -> NativeExecutionRequestBinding:
        matches=[]
        for path in self.directory.glob("*.native-request.json"):
            try:
                raw=path.read_bytes(); data=json.loads(raw.decode("utf-8"))
                if raw!=canonical_bytes(data)+b"\n": raise ValueError("record bytes are not canonical")
                request=_structural_request_binding(data)
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc: raise NativeEvidenceInvalid(f"native request catalog is invalid: {exc}") from exc
            if request.request_fingerprint==result.request_fingerprint: matches.append(request)
        if len(matches)!=1: raise NativeEvidenceInvalid("result must bind exactly one request")
        request=matches[0]
        if result.invocation_id != f"native:{request.session_id}:{request.gate_id}:{request.execution_attempt_index}": raise NativeEvidenceInvalid("result invocation differs from request")
        return request
    @staticmethod
    def _validate_result_binding(request: NativeExecutionRequestBinding, result: NativeExecutionResult) -> None:
        if result.backend_attestation_fingerprint != request.backend_attestation_fingerprint or result.executable != request.executable or result.cwd != request.work_workspace: raise NativeEvidenceInvalid("result backend/executable/cwd differs from request")
        launcher=(request.executable,*request.launcher_prefix)
        if result.argv != launcher: raise NativeEvidenceInvalid("result executable/launcher prefix differs from request")
        if result.stdout_artifact.byte_count>request.stdout_byte_limit or result.stderr_artifact.byte_count>request.stderr_byte_limit: raise NativeEvidenceInvalid("result artifact exceeds request limit")
    def write_result(self, issued_result: object) -> NativeExecutionResult:
        record=_issued_native_result_for(issued_result); result=record.result.validated(); request=self._request_for_result(result); self._validate_result_binding(request,result); self._verify_artifact(result.stdout_artifact); self._verify_artifact(result.stderr_artifact)
        eligibility=self.load_execution_eligibility(request.session_id,request.gate_id,request.execution_attempt_index)
        if not eligibility.eligible: raise NativeEvidenceInvalid("accepted result requires successful execution eligibility")
        path=self._path("result",request.session_id,request.gate_id,request.execution_attempt_index)
        with self._lock(request.session_id,request.gate_id,request.execution_attempt_index):
            if path.exists(): raise NativeResultAlreadyExists("native execution result is write-once")
            try: self._atomic_create(path,result.to_dict(),operation="native result")
            except FileExistsError as exc: raise NativeResultAlreadyExists("native execution result is write-once") from exc
        reloaded=self.load_result(request.session_id,request.gate_id,request.execution_attempt_index)
        if reloaded!=result: raise NativeEvidenceInvalid("reloaded result differs")
        _consume_issued_native_result(issued_result); return reloaded
    def load_result(self, session_id: str, gate_id: str, attempt: int) -> NativeExecutionResult:
        result=self._load("result",session_id,gate_id,attempt,NativeExecutionResult.from_dict); request=self.load_request_structural(session_id,gate_id,attempt)
        if result.request_fingerprint!=request.request_fingerprint: raise NativeEvidenceInvalid("result request binding mismatch")
        eligibility=self.load_execution_eligibility(session_id,gate_id,attempt)
        if not eligibility.eligible: raise NativeEvidenceInvalid("accepted result has ineligible execution evidence")
        self._validate_result_binding(request,result); self._verify_artifact(result.stdout_artifact); self._verify_artifact(result.stderr_artifact); return result
    def create_capture_attempt(self, *, request: NativeExecutionRequest, result: NativeExecutionResult, gate_plan_fingerprint: str, checkpoint_contract_fingerprint: str, behavioral_evidence_fingerprint: str | None, required_command_ids: tuple[str, ...], state_revision: int, verification_mode: str | None = None, clock: Callable[[], str] = _utc_now) -> NativeCheckpointCaptureAttempt:
        if self.has_capture_attempt(request.session_id,request.gate_id,request.execution_attempt_index): raise NativeResultAlreadyExists("capture attempt is write-once")
        schema = CAPTURE_ATTEMPT_SCHEMA_VERSION if verification_mode is None else CAPTURE_ATTEMPT_SCHEMA_VERSION_V2
        provisional=NativeCheckpointCaptureAttempt(schema,request.session_id,request.gate_id,0,request.request_fingerprint,result.result_fingerprint,gate_plan_fingerprint,checkpoint_contract_fingerprint,behavioral_evidence_fingerprint,required_command_ids,f"capture:{request.session_id}:{request.gate_id}:0",CAPTURE_EXPECTED_SUCCESS_STATUS,clock(),state_revision,"0"*64,verification_mode)
        item=NativeCheckpointCaptureAttempt(**{**provisional.__dict__,"attempt_fingerprint":fingerprint(provisional._body())}).validated(); path=self._path("capture-attempt",item.session_id,item.gate_id,0)
        with self._lock(item.session_id,item.gate_id,0): self._atomic_create(path,item.to_dict(),operation="capture attempt")
        return self.load_capture_attempt(item.session_id,item.gate_id,0)
    def load_capture_attempt(self, session_id: str, gate_id: str, attempt: int) -> NativeCheckpointCaptureAttempt:
        self.assert_unique_capture_attempt(session_id, gate_id, attempt)
        return self._load("capture-attempt",session_id,gate_id,attempt,NativeCheckpointCaptureAttempt.from_dict)
    def create_terminal(self, *, request: NativeExecutionRequest | NativeExecutionRequestBinding, result: NativeExecutionResult | None, status: NativeCaptureTerminalStatus, failure_category: str, diagnostic: str, capture_attempt: NativeCheckpointCaptureAttempt | None = None, clock: Callable[[], str] = _utc_now) -> NativeCanaryTerminalRecord:
        binding=self.load_request_structural(request.session_id,request.gate_id,0)
        if request.request_fingerprint!=binding.request_fingerprint: raise NativeEvidenceInvalid("terminal request binding differs")
        reserved=self.load_attempt_reserved(binding.session_id,binding.gate_id,0) if self.has_attempt_reserved(binding.session_id,binding.gate_id,0) else None
        started=self.load_process_started(binding.session_id,binding.gate_id,0) if self.has_process_started(binding.session_id,binding.gate_id,0) else None
        observation=self.load_process_observation(binding.session_id,binding.gate_id,0) if self.has_process_observation(binding.session_id,binding.gate_id,0) else None
        eligibility=self.load_execution_eligibility(binding.session_id,binding.gate_id,0) if self.has_execution_eligibility(binding.session_id,binding.gate_id,0) else None
        provisional=NativeCanaryTerminalRecord(TERMINAL_SCHEMA_VERSION_V2,binding.session_id,binding.gate_id,0,binding.request_fingerprint,result.result_fingerprint if result else None,status,capture_attempt.attempt_fingerprint if capture_attempt else None,clock(),failure_category,diagnostic,reserved.reservation_fingerprint if reserved else None,started.process_started_fingerprint if started else None,observation.observation_fingerprint if observation else None,eligibility.eligibility_fingerprint if eligibility else None,"0"*64)
        item=NativeCanaryTerminalRecord(**{**provisional.__dict__,"terminal_fingerprint":fingerprint(provisional._body())}).validated(); path=self._path("terminal",item.session_id,item.gate_id,0)
        with self._lock(item.session_id,item.gate_id,0):
            if path.exists(): raise NativeResultAlreadyExists("canary terminal record is write-once")
            self._atomic_create(path,item.to_dict(),operation="canary terminal")
        return self.load_terminal(item.session_id,item.gate_id,0)
    def load_terminal(self, session_id: str, gate_id: str, attempt: int) -> NativeCanaryTerminalRecord: return self._load("terminal",session_id,gate_id,attempt,NativeCanaryTerminalRecord.from_dict)


__all__ = [
    "ARTIFACT_SCHEMA_VERSION", "ATTESTATION_CLASS_PACKAGE_BIN", "ATTESTATION_CLASS_WRAPPER_CHAIN", "ATTESTATION_SCHEMA_VERSION", "ATTEMPT_RESERVED_SCHEMA_VERSION", "BACKEND_IDENTITY", "BACKEND_PROTOCOL_VERSION", "CAPTURE_ATTEMPT_SCHEMA_VERSION", "CAPTURE_ATTEMPT_SCHEMA_VERSION_V2", "CAPTURE_EXPECTED_SUCCESS_STATUS", "CURSOR_DISCOVERY_COMMAND", "CURSOR_DISCOVERY_MECHANISM", "DEFAULT_ENVIRONMENT_ALLOWLIST", "EXECUTION_ELIGIBILITY_SCHEMA_VERSION", "EXPECTED_CURSOR_PACKAGE_NAME", "NATIVE_PROMPT_HEADER", "PACKAGE_BIN_NON_CLAIMS", "PROCESS_OBSERVATION_SCHEMA_VERSION", "PROCESS_STARTED_SCHEMA_VERSION", "REQUEST_SCHEMA_VERSION", "RESULT_SCHEMA_VERSION", "TERMINAL_SCHEMA_VERSION", "TERMINAL_SCHEMA_VERSION_V2", "WINDOWS_COMMAND_RESOLUTION_SCHEMA_VERSION", "WINDOWS_WHERE_DIAGNOSTIC_SCHEMA_VERSION", "WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION", "WRAPPER_CHAIN_ATTESTATION_SCHEMA_VERSION_LEGACY_V1", "WRAPPER_CHAIN_BLOCKED_REASON", "WRAPPER_CHAIN_CLAIMS", "WRAPPER_CHAIN_DISCOVERY_MECHANISM", "WRAPPER_CHAIN_NON_CLAIMS", "WRAPPER_CHAIN_READY_REASON",
    "AtomicNativeExecutionStore", "BackendAttestation", "CursorInstallationProvenance", "CursorNativeBackendConfig", "CursorWrapperChainResolution", "DeterministicWindowsCommandResolution", "HostWrapperChainDiscovery", "PowerShellCommandCandidate", "PowerShellCommandObservation", "WhereCommandObservation", "WindowsPathCandidate", "WindowsWhereDiagnostic", "WindowsWhereDiagnosticStatus", "WrapperChainBackendAttestation", "WrapperChainDiscovery", "attestation_from_dict", "ManagedNativeProcessRunner", "NativeArtifactReference", "NativeAttemptReserved", "NativeBackendAttestation", "NativeBackendFileAttestation", "NativeCanaryTerminalRecord", "NativeCaptureTerminalStatus", "NativeCheckpointCaptureAttempt", "NativeCommittedButDurabilityUncertain", "NativeDelegatedExecutor", "NativeEvidenceInvalid", "NativeEvidenceNotFound", "NativeExecutionEligibility", "NativeExecutionRequest", "NativeExecutionRequestBinding", "NativeExecutionResult", "NativeExecutionStatus", "NativeExecutionStoreError", "NativeFilesystemIdentity", "NativeLifecycleCounts", "NativePreflightDecision", "NativePreflightStatus", "NativeProcessInvocation", "NativeProcessObservation", "NativeProcessObservationPublicationError", "NativeProcessOutcome", "NativeProcessRunner", "NativeProcessStarted", "NativeProcessStartError", "NativeRequestAlreadyExists", "NativeResultAlreadyExists", "NativeResultIneligible", "preflight_native_cursor",
]
