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
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
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
from admissible.delegated_gate.store import _FileLock
from admissible.managed_process import (
    ManagedProcessError,
    OBSERVATION_PROVEN_EMPTY,
    run_managed_oneshot,
)


REQUEST_SCHEMA_VERSION = "admissible_native_execution_request_v2"
RESULT_SCHEMA_VERSION = "admissible_native_execution_result_v2"
ARTIFACT_SCHEMA_VERSION = "admissible_native_execution_artifact_v2"
ATTESTATION_SCHEMA_VERSION = "admissible_native_backend_attestation_v1"
CAPTURE_ATTEMPT_SCHEMA_VERSION = "admissible_native_capture_attempt_v1"
CAPTURE_EXPECTED_SUCCESS_STATUS = "CHECKPOINT_CAPTURED"
TERMINAL_SCHEMA_VERSION = "admissible_native_canary_terminal_v1"
BACKEND_IDENTITY = "cursor-agent-native-oneshot"
BACKEND_PROTOCOL_VERSION = "cursor-agent-print-force-v2"
CURSOR_DISCOVERY_MECHANISM = "shutil.which:cursor-agent"
CURSOR_DISCOVERY_COMMAND = "cursor-agent"
EXPECTED_CURSOR_PACKAGE_NAME = "@anysphere/agent-cli-runtime"
PROCESS_TREE_CLEANUP_POLICY = "managed-process-tree-hard-timeout-and-proven-empty"
NATIVE_PROMPT_HEADER = "You are the Admissible native coding agent."
DEFAULT_ENVIRONMENT_ALLOWLIST: tuple[str, ...] = (
    "APPDATA", "COMSPEC", "HOME", "HOMEDRIVE", "HOMEPATH", "LANG", "LC_ALL",
    "LOCALAPPDATA", "PATH", "PATHEXT", "SHELL", "SYSTEMROOT", "TEMP", "TMP",
    "TMPDIR", "USERPROFILE",
)
WINDOWS_SHELL_WRAPPER_SUFFIXES = (".bat", ".cmd", ".ps1")
_FLAG_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])(--[A-Za-z0-9][A-Za-z0-9-]*)")
_PROBE_LIMIT = 128 * 1024


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

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> "NativeFilesystemIdentity":
        return cls(
            device=int(metadata.st_dev),
            inode=int(metadata.st_ino),
            mode=int(metadata.st_mode),
            size=int(metadata.st_size),
            mtime_ns=int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))),
            file_attributes=int(getattr(metadata, "st_file_attributes", 0)),
        )

    def validated(self) -> "NativeFilesystemIdentity":
        for label, value in self.__dict__.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"filesystem identity {label} must be a non-negative integer")
        return self

    def to_dict(self) -> dict[str, int]:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeFilesystemIdentity":
        require_exact_keys(data, {"device", "inode", "mode", "size", "mtime_ns", "file_attributes"}, "filesystem identity")
        return cls(**dict(data)).validated()


def _same_directory_identity(left: NativeFilesystemIdentity, right: NativeFilesystemIdentity) -> bool:
    """Directory mtimes/sizes change when children are added; identity must not."""
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

    def __post_init__(self) -> None:
        if not isinstance(self.executable, str) or not self.executable or "\x00" in self.executable:
            raise ValueError("a native Cursor executable is required")
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
    attestation: NativeBackendAttestation | None

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


def preflight_native_cursor(*, config: CursorNativeBackendConfig, work_workspace: str | Path | None = None) -> NativePreflightDecision:
    """Run only local ``--version``/``--help`` probes; never send a prompt."""

    try:
        if work_workspace is not None:
            _safe_directory(work_workspace, "preflight work workspace")
        return NativePreflightDecision(NativePreflightStatus.PREFLIGHT_READY, "LOCAL_CURSOR_CAPABILITIES_ATTESTED", "Local Cursor version/help probes advertised the required bounded experiment flags.", _attest_native_cursor(config))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return NativePreflightDecision(NativePreflightStatus.PREFLIGHT_BLOCKED, "LOCAL_CAPABILITY_ATTESTATION_BLOCKED", str(exc), None)


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
    backend_attestation: NativeBackendAttestation
    backend_attestation_fingerprint: str
    timeout_seconds: int
    stdout_byte_limit: int
    stderr_byte_limit: int
    process_tree_cleanup_policy: str
    prompt_fingerprint: str
    request_fingerprint: str

    @classmethod
    def create(cls, *, session_id: str, gate_id: str, execution_attempt_index: int, mission_fingerprint: str, gate_contract_fingerprint: str, work_workspace: str | Path, evidence_store_root: str | Path, artifact_directory: str | Path, attestation: NativeBackendAttestation, prompt: str, timeout_seconds: int, stdout_byte_limit: int, stderr_byte_limit: int) -> "NativeExecutionRequest":
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
        if str(workspace) != self.work_workspace or not _same_directory_identity(identity, self.work_workspace_identity):
            raise ValueError("work workspace path or identity changed")
        self.work_workspace_identity.validated()
        evidence_root, evidence_identity = _safe_directory(self.evidence_store_root, "execution evidence root")
        if str(evidence_root) != self.evidence_store_root or not _same_directory_identity(evidence_identity, self.evidence_store_identity):
            raise ValueError("execution evidence root path or identity changed")
        artifacts, artifacts_identity = _safe_artifact_directory(evidence_root, self.artifact_directory)
        if str(artifacts) != self.artifact_directory or not _same_directory_identity(artifacts_identity, self.artifact_directory_identity):
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

    def validated_for_execution(self, *, current_attestation: NativeBackendAttestation) -> "NativeExecutionRequest":
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
        values["backend_attestation"] = NativeBackendAttestation.from_dict(data["backend_attestation"])
        return cls(**values).validated()


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

    def validated(self) -> "NativeExecutionResult":
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
        observed_final = _repository_observation(cwd)
        if (
            observed_final.material_tree_hash != self.final_material_tree_hash
            or observed_final.git_head != self.final_git_head
            or observed_final.git_status != self.final_git_porcelain_status
            or observed_final.git_remotes != self.final_git_remotes
            or observed_final.commit_message != self.final_commit_message
        ):
            raise ValueError("result final workspace/Git observations no longer match the assigned repository")
        if self.initial_git_head is not None and self.final_git_head is not None and self.initial_git_head != self.final_git_head:
            if not _is_ancestor(cwd, self.initial_git_head, self.final_git_head):
                raise ValueError("result final Git HEAD is outside the initial HEAD ancestry")
        if self.commits_added != _commits_added(cwd, self.initial_git_head, self.final_git_head):
            raise ValueError("result commit count contradicts the observed Git ancestry")
        if self.changed_material_files != _changed_files(cwd, self.initial_git_head, self.final_git_head):
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
class NativeProcessInvocation:
    argv: tuple[str, ...]
    cwd: str
    env: Mapping[str, str]
    timeout_seconds: int
    max_capture_bytes: int


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


class NativeProcessRunner(Protocol):
    def run(self, invocation: NativeProcessInvocation) -> NativeProcessOutcome: ...


class ManagedNativeProcessRunner:
    """Real no-shell managed-process runner. It never retries."""
    def run(self, invocation: NativeProcessInvocation) -> NativeProcessOutcome:
        try:
            outcome = run_managed_oneshot(list(invocation.argv), cwd=invocation.cwd, env=dict(invocation.env), timeout_seconds=invocation.timeout_seconds, max_capture_bytes=invocation.max_capture_bytes)
        except ManagedProcessError as exc:
            raise NativeProcessStartError(f"native process could not start: {exc}") from exc
        process = outcome.process_result
        return NativeProcessOutcome(outcome.returncode, outcome.stdout, outcome.stderr, outcome.timed_out, process.cleanup_proven, process.cleanup_observation, process.termination_reason, tuple(process.remaining_process_ids), process.stdout_bytes, process.stderr_bytes, process.output_truncated)


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


def _git(repository: Path, *arguments: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["git", *arguments], cwd=repository, shell=False, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if len(result.stdout.encode("utf-8")) > 2 * 1024 * 1024 or len(result.stderr.encode("utf-8")) > 2 * 1024 * 1024: raise NativeEvidenceInvalid("Git observation exceeded its output bound")
    return result


def _repository_observation(repository: Path) -> _RepositoryObservation:
    tree_hash, files = _material_snapshot(repository)
    root = _git(repository, "rev-parse", "--show-toplevel")
    if root.returncode != 0 or Path(root.stdout.strip()).resolve() != repository.resolve(): raise NativeEvidenceInvalid("observed repository is not the exact Git root")
    head_result = _git(repository, "rev-parse", "--verify", "HEAD"); head = head_result.stdout.strip().lower() if head_result.returncode == 0 else None; require_optional_git_oid(head, "observed Git HEAD")
    status_result = _git(repository, "status", "--porcelain=v1", "--untracked-files=all")
    remotes_result = _git(repository, "remote")
    if status_result.returncode != 0 or remotes_result.returncode != 0: raise NativeEvidenceInvalid("Git observation failed")
    message: str | None = None
    if head is not None:
        message_result = _git(repository, "log", "-1", "--format=%B")
        if message_result.returncode != 0: raise NativeEvidenceInvalid("Git commit-message observation failed")
        message = message_result.stdout.rstrip("\r\n")
    return _RepositoryObservation(tree_hash, files, head, status_result.stdout, tuple(line for line in remotes_result.stdout.splitlines() if line), message)


def _changed_files(repository: Path, initial_head: str | None, final_head: str | None) -> tuple[str, ...]:
    if initial_head is None or final_head is None or initial_head == final_head: return ()
    result = _git(repository, "diff", "--name-only", initial_head, final_head)
    if result.returncode != 0: raise NativeEvidenceInvalid("Git changed-file observation failed")
    return tuple(sorted(line for line in result.stdout.splitlines() if line))


def _commits_added(repository: Path, initial_head: str | None, final_head: str | None) -> int:
    if initial_head is None or final_head is None or initial_head == final_head: return 0
    result = _git(repository, "rev-list", "--count", f"{initial_head}..{final_head}")
    if result.returncode != 0: raise NativeEvidenceInvalid("Git commit-count observation failed")
    try: count = int(result.stdout.strip())
    except ValueError as exc: raise NativeEvidenceInvalid("Git commit-count observation is malformed") from exc
    if count < 0: raise NativeEvidenceInvalid("Git commit-count observation is negative")
    return count


def _is_ancestor(repository: Path, initial_head: str, final_head: str) -> bool:
    result = _git(repository, "merge-base", "--is-ancestor", initial_head, final_head)
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
            inventory.append(f"{child.name}:redirecting:{NativeFilesystemIdentity.from_stat(metadata).inode}")
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
        with destination.open("xb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
    except FileExistsError as exc: raise NativeExecutionStoreError("native output artifact is write-once") from exc
    _safe_file(destination, "native output artifact")
    return NativeArtifactReference(ARTIFACT_SCHEMA_VERSION, artifact_id, purpose, destination.relative_to(store_root).as_posix(), hashlib.sha256(data).hexdigest(), len(data), truncated).validated()


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


def _issue_native_result(result: NativeExecutionResult) -> _IssuedNativeResult:
    result = result.validated(); handle = _IssuedNativeResult(); identity = id(handle)
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
    def __init__(self, *, config: CursorNativeBackendConfig, process_runner: NativeProcessRunner | None = None, clock: Callable[[], str] = _utc_now, local_attestor: Callable[[CursorNativeBackendConfig], NativeBackendAttestation] | None = None) -> None:
        self.config = config; self.process_runner = process_runner or ManagedNativeProcessRunner(); self.clock = clock
        self._local_attestor = local_attestor or _attest_native_cursor

    def attest_local_backend(self) -> NativeBackendAttestation:
        """Explicit authority-bearing local re-attestation; never implicit parse work."""

        try:
            return self._local_attestor(self.config).validated()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise NativeEvidenceInvalid("local backend installation/capability attestation is unavailable") from exc

    def execute(self, *, request: NativeExecutionRequest, prompt: str, source_repository: str | Path, canary_parent: str | Path, allowed_parent_children: frozenset[str], evidence_store_root: str | Path, artifact_directory: str | Path) -> _IssuedNativeResult:
        current = self.attest_local_backend()
        try:
            request.validated_for_execution(current_attestation=current)
        except ValueError as exc:
            raise NativeEvidenceInvalid(str(exc)) from exc
        if hashlib.sha256(prompt.encode("utf-8")).hexdigest() != request.prompt_fingerprint: raise NativeEvidenceInvalid("prompt differs from durable request")
        workspace, workspace_identity = _safe_directory(request.work_workspace, "work workspace")
        if not _same_directory_identity(workspace_identity, request.work_workspace_identity): raise NativeEvidenceInvalid("work workspace identity changed after request issuance")
        source, source_identity = _safe_directory(source_repository, "source repository"); parent, parent_identity = _safe_directory(canary_parent, "canary parent")
        evidence_root, evidence_identity = _safe_directory(evidence_store_root, "execution evidence root"); artifacts, artifacts_identity = _safe_artifact_directory(evidence_root, artifact_directory)
        if (
            str(evidence_root) != request.evidence_store_root
            or not _same_directory_identity(evidence_identity, request.evidence_store_identity)
            or str(artifacts) != request.artifact_directory
            or not _same_directory_identity(artifacts_identity, request.artifact_directory_identity)
        ):
            raise NativeEvidenceInvalid("execution evidence/artifact authority differs from the durable request")
        _require_disjoint_roots(("source repository", source), ("work workspace", workspace), ("execution evidence root", evidence_root))
        _require_disjoint_roots(("source repository", source), ("work workspace", workspace), ("native artifact directory", artifacts))
        if workspace.parent != parent: raise NativeEvidenceInvalid("work workspace must be a direct child of canary parent")
        if _inside(evidence_root, parent) is False and _inside(parent, evidence_root) is False: raise NativeEvidenceInvalid("execution evidence root must be measured under canary parent")
        if not allowed_parent_children == frozenset({workspace.name}): raise NativeEvidenceInvalid("only the exact work workspace may be excluded from sibling observations")
        initial = _repository_observation(workspace); source_before = _repository_observation(source); parent_before = _parent_inventory(parent, allowed_children=allowed_parent_children)
        argv = request.backend_attestation.argv(prompt=prompt)
        invocation = NativeProcessInvocation(argv, str(workspace), self.config.build_environment(), request.timeout_seconds, max(request.stdout_byte_limit, request.stderr_byte_limit))
        started_at = self.clock()
        try:
            outcome = self.process_runner.run(invocation)
        except NativeProcessStartError as exc:
            outcome = NativeProcessOutcome(None, "", f"{type(exc).__name__}: {exc}\n", False, False, "unknown", "spawn_failed", observed_stderr_bytes=len(str(exc).encode("utf-8")))
        ended_at = self.clock()
        # Revalidate every root before using the post-process observations.
        post_source, post_source_identity = _safe_directory(source, "source repository post-exit"); post_workspace, post_identity = _safe_directory(workspace, "work workspace post-exit"); post_parent, post_parent_identity = _safe_directory(parent, "canary parent post-exit"); post_evidence, post_evidence_identity = _safe_directory(evidence_root, "execution evidence root post-exit"); post_artifacts, post_artifacts_identity = _safe_artifact_directory(post_evidence, artifacts)
        if post_workspace != workspace or not _same_directory_identity(post_identity, workspace_identity): raise NativeEvidenceInvalid("work workspace identity changed during execution")
        if post_source != source or not _same_directory_identity(post_source_identity, source_identity): raise NativeEvidenceInvalid("source repository identity changed during execution")
        if post_parent != parent or not _same_directory_identity(post_parent_identity, parent_identity): raise NativeEvidenceInvalid("canary parent identity changed during execution")
        if post_evidence != evidence_root or not _same_directory_identity(post_evidence_identity, evidence_identity): raise NativeEvidenceInvalid("execution evidence root identity changed during execution")
        if post_artifacts != artifacts or not _same_directory_identity(post_artifacts_identity, artifacts_identity): raise NativeEvidenceInvalid("native artifact directory identity changed during execution")
        final = _repository_observation(workspace); source_after = _repository_observation(source); parent_after = _parent_inventory(parent, allowed_children=allowed_parent_children)
        stdout_data, stdout_truncated = _bounded(outcome.stdout, request.stdout_byte_limit, outcome.observed_stdout_bytes, outcome.output_truncated)
        stderr_data, stderr_truncated = _bounded(outcome.stderr, request.stderr_byte_limit, outcome.observed_stderr_bytes, outcome.output_truncated)
        prefix = f"{request.session_id}.{request.gate_id}.attempt-{request.execution_attempt_index}"
        stdout_ref = _write_artifact(store_root=evidence_root, artifact_directory=artifacts, artifact_id=f"{prefix}.native.stdout", purpose="stdout", data=stdout_data, truncated=stdout_truncated)
        stderr_ref = _write_artifact(store_root=evidence_root, artifact_directory=artifacts, artifact_id=f"{prefix}.native.stderr", purpose="stderr", data=stderr_data, truncated=stderr_truncated)
        cleanup_confirmed = outcome.cleanup_confirmed and outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY and not outcome.orphan_process_ids
        status = NativeExecutionStatus.CLEANUP_UNCERTAIN if not cleanup_confirmed else NativeExecutionStatus.TIMED_OUT if outcome.timed_out else NativeExecutionStatus.PROCESS_SUCCEEDED if outcome.returncode == 0 else NativeExecutionStatus.PROCESS_FAILED
        provisional = NativeExecutionResult(
            RESULT_SCHEMA_VERSION, request.request_fingerprint, f"native:{request.session_id}:{request.gate_id}:{request.execution_attempt_index}", status, BACKEND_IDENTITY, request.backend_attestation_fingerprint,
            started_at, ended_at, request.executable, argv, str(workspace), outcome.returncode, outcome.timed_out, outcome.termination_reason, cleanup_confirmed, outcome.cleanup_observation, outcome.orphan_process_ids,
            stdout_ref, stderr_ref, stdout_truncated or stderr_truncated, initial.material_tree_hash, final.material_tree_hash, initial.git_head, final.git_head, final.git_status, final.git_remotes, final.commit_message,
            _commits_added(workspace, initial.git_head, final.git_head), _changed_files(workspace, initial.git_head, final.git_head), source_before.material_tree_hash, source_after.material_tree_hash, source_before.git_head, source_after.git_head, source_before.git_status, source_after.git_status,
            False, parent_before, parent_after, (), False, "0" * 64,
        )
        derived = NativeExecutionResult(**{**provisional.__dict__, "source_repository_mutated": (source_before.material_tree_hash != source_after.material_tree_hash or source_before.git_head != source_after.git_head or source_before.git_status != source_after.git_status), "unexpected_sibling_mutations": tuple(sorted(set(parent_before).symmetric_difference(parent_after))), "workspace_material_changed": initial.material_tree_hash != final.material_tree_hash or initial.git_head != final.git_head})
        result = NativeExecutionResult(**{**derived.__dict__, "result_fingerprint": fingerprint(derived._body())}).validated()
        return _issue_native_result(result)


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
    behavioral_evidence_fingerprint: str
    required_command_ids: tuple[str, ...]
    capture_attempt_id: str
    expected_terminal_status: str
    started_at: str
    state_revision: int
    attempt_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__); data["required_command_ids"] = list(self.required_command_ids); data.pop("attempt_fingerprint"); return data
    def validated(self) -> "NativeCheckpointCaptureAttempt":
        if self.schema_version != CAPTURE_ATTEMPT_SCHEMA_VERSION: raise ValueError("unsupported capture attempt schema")
        require_identifier(self.session_id, "capture session ID"); require_identifier(self.gate_id, "capture gate ID"); require_strict_int(self.execution_attempt_index, "capture attempt", minimum=0, maximum=0)
        for label, value in (("request_fingerprint", self.request_fingerprint), ("result_fingerprint", self.result_fingerprint), ("gate_plan_fingerprint", self.gate_plan_fingerprint), ("checkpoint_contract_fingerprint", self.checkpoint_contract_fingerprint), ("behavioral_evidence_fingerprint", self.behavioral_evidence_fingerprint), ("attempt_fingerprint", self.attempt_fingerprint)): require_sha256(value, label)
        if not isinstance(self.required_command_ids, tuple) or not self.required_command_ids: raise ValueError("capture attempt requires command identities")
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
        require_exact_keys(data, set(cls.__dataclass_fields__), "capture attempt")
        values=dict(data); values["required_command_ids"]=require_string_list(data["required_command_ids"], "capture command IDs")
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
    terminal_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__); data["status"] = self.status.value; data.pop("terminal_fingerprint"); return data
    def validated(self) -> "NativeCanaryTerminalRecord":
        if self.schema_version != TERMINAL_SCHEMA_VERSION: raise ValueError("unsupported terminal schema")
        require_identifier(self.session_id, "terminal session ID"); require_identifier(self.gate_id, "terminal gate ID"); require_strict_int(self.execution_attempt_index, "terminal attempt", minimum=0, maximum=0)
        require_sha256(self.request_fingerprint, "terminal request fingerprint")
        if self.result_fingerprint is not None: require_sha256(self.result_fingerprint, "terminal result fingerprint")
        if self.capture_attempt_fingerprint is not None: require_sha256(self.capture_attempt_fingerprint, "terminal capture attempt fingerprint")
        if not isinstance(self.status, NativeCaptureTerminalStatus): raise ValueError("terminal status is invalid")
        _validate_timestamp(self.created_at, "terminal created_at"); require_nonempty_text(self.failure_category, "terminal failure category", max_bytes=128); require_nonempty_text(self.diagnostic, "terminal diagnostic", max_bytes=1024); require_sha256(self.terminal_fingerprint, "terminal fingerprint")
        if fingerprint(self._body()) != self.terminal_fingerprint: raise ValueError("terminal fingerprint mismatch")
        return self
    def to_dict(self) -> dict[str, Any]: data = self._body(); data["terminal_fingerprint"] = self.terminal_fingerprint; return data
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeCanaryTerminalRecord":
        require_exact_keys(data, set(cls.__dataclass_fields__), "canary terminal"); values=dict(data); values["status"]=NativeCaptureTerminalStatus(data["status"]); return cls(**values).validated()


class AtomicNativeExecutionStore:
    """Locked write-once request/result/capture sidecar with explicit durability."""
    def __init__(self, directory: str | Path, *, lock_timeout: float = 5.0, directory_sync: Callable[[Path], None] | None = None) -> None:
        self.directory, self.directory_identity = _safe_create_directory(directory, "native execution store")
        self.artifact_directory, self.artifact_directory_identity = _safe_create_directory(self.directory / "artifacts", "native artifact directory")
        if lock_timeout <= 0: raise ValueError("lock timeout must be positive")
        self.lock_timeout = lock_timeout; self._directory_sync = directory_sync or self._default_directory_sync

    @staticmethod
    def _key(session_id: str, gate_id: str, attempt: int) -> str:
        require_identifier(session_id, "store session ID"); require_identifier(gate_id, "store gate ID"); require_strict_int(attempt, "store attempt", minimum=0, maximum=0); return f"{session_id}.{gate_id}.attempt-{attempt}"
    def _path(self, kind: str, session_id: str, gate_id: str, attempt: int) -> Path: return self.directory / f"{self._key(session_id, gate_id, attempt)}.native-{kind}.json"
    def _lock(self, session_id: str, gate_id: str, attempt: int) -> _FileLock: return _FileLock(self.directory / f".{self._key(session_id, gate_id, attempt)}.native-evidence.lock", timeout=self.lock_timeout)
    @staticmethod
    def _default_directory_sync(directory: Path) -> None:
        try:
            fd = os.open(str(directory), os.O_RDONLY)
        except OSError as exc: raise OSError(f"directory fsync cannot be opened: {exc}") from exc
        try: os.fsync(fd)
        finally: os.close(fd)
    def _assert_root_identity(self) -> None:
        root, identity = _safe_directory(self.directory, "native execution store")
        if root != self.directory or not _same_directory_identity(identity, self.directory_identity): raise NativeEvidenceInvalid("native execution store root identity changed")
    def _assert_artifact_root_identity(self) -> None:
        root, identity = _safe_directory(self.artifact_directory, "native artifact directory")
        if root != self.artifact_directory or not _same_directory_identity(identity, self.artifact_directory_identity): raise NativeEvidenceInvalid("native artifact directory identity changed")
    def _atomic_create(self, path: Path, payload: Mapping[str, Any], *, operation: str) -> None:
        self._assert_root_identity(); temporary: str | None = None; published = False
        try:
            fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=self.directory)
            with os.fdopen(fd, "wb") as handle: handle.write(canonical_bytes(payload)+b"\n"); handle.flush(); os.fsync(handle.fileno())
            # A hard link creates the final name only when it does not already
            # exist.  Unlike os.replace this cannot overwrite visible evidence
            # if an external actor races the lock-protected writer.
            os.link(temporary, path); published = True
            os.unlink(temporary); temporary = None
            self._directory_sync(self.directory)
        except FileExistsError: raise
        except OSError as exc:
            if published: raise NativeCommittedButDurabilityUncertain(operation=operation, path=path, original_error=exc) from exc
            raise NativeExecutionStoreError(f"{operation} publication failed: {exc}") from exc
        finally:
            if temporary is not None and os.path.exists(temporary): os.unlink(temporary)
    def _atomic_create_bytes(self, path: Path, data: bytes, *, operation: str) -> None:
        self._assert_root_identity(); self._assert_artifact_root_identity(); temporary: str | None = None; published = False
        try:
            fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
            with os.fdopen(fd, "wb") as handle: handle.write(data); handle.flush(); os.fsync(handle.fileno())
            os.link(temporary, path); published = True
            os.unlink(temporary); temporary = None
            self._directory_sync(path.parent)
        except FileExistsError: raise
        except OSError as exc:
            if published: raise NativeCommittedButDurabilityUncertain(operation=operation, path=path, original_error=exc) from exc
            raise NativeExecutionStoreError(f"{operation} publication failed: {exc}") from exc
        finally:
            if temporary is not None and os.path.exists(temporary): os.unlink(temporary)
    def has_request(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("request", session_id, gate_id, attempt).is_file()
    def has_result(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("result", session_id, gate_id, attempt).is_file()
    def has_capture_attempt(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("capture-attempt", session_id, gate_id, attempt).is_file()
    def has_terminal(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("terminal", session_id, gate_id, attempt).is_file()
    def has_behavioral_evidence(self, session_id: str, gate_id: str, attempt: int) -> bool: return self._path("behavioral", session_id, gate_id, attempt).is_file()
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
        try: item=loader(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc: raise NativeEvidenceInvalid(f"native {kind} is invalid: {exc}") from exc
        if hasattr(item, "session_id") and (item.session_id, item.gate_id, item.execution_attempt_index) != (session_id, gate_id, attempt):
            raise NativeEvidenceInvalid(f"native {kind} identity differs from filename")
        return item
    def load_request(self, session_id: str, gate_id: str, attempt: int) -> NativeExecutionRequest: return self._load("request", session_id, gate_id, attempt, NativeExecutionRequest.from_dict)
    def load_request_verified_against_local_backend(self, session_id: str, gate_id: str, attempt: int, *, current_attestation: NativeBackendAttestation) -> NativeExecutionRequest:
        request = self.load_request(session_id, gate_id, attempt)
        return request.validated_for_execution(current_attestation=current_attestation)
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
        request = self.load_request(session_id, gate_id, attempt)
        self._validate_behavioral_binding(request, evidence)
        for reference in (evidence.script, evidence.stdout, evidence.stderr): self._verify_artifact(reference)
        return evidence
    def _request_for_result(self, result: NativeExecutionResult) -> NativeExecutionRequest:
        matches=[]
        for path in self.directory.glob("*.native-request.json"):
            try: request=NativeExecutionRequest.from_dict(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc: raise NativeEvidenceInvalid(f"native request catalog is invalid: {exc}") from exc
            if request.request_fingerprint==result.request_fingerprint: matches.append(request)
        if len(matches)!=1: raise NativeEvidenceInvalid("result must bind exactly one request")
        request=matches[0]
        if result.invocation_id != f"native:{request.session_id}:{request.gate_id}:{request.execution_attempt_index}": raise NativeEvidenceInvalid("result invocation differs from request")
        return request
    @staticmethod
    def _validate_result_binding(request: NativeExecutionRequest, result: NativeExecutionResult) -> None:
        if result.backend_attestation_fingerprint != request.backend_attestation_fingerprint or result.executable != request.executable or result.cwd != request.work_workspace: raise NativeEvidenceInvalid("result backend/executable/cwd differs from request")
        launcher=(request.executable,*request.launcher_prefix)
        if result.argv[:len(launcher)] != launcher or hashlib.sha256(result.argv[-1].encode("utf-8")).hexdigest()!=request.prompt_fingerprint: raise NativeEvidenceInvalid("result argv differs from request")
        if result.stdout_artifact.byte_count>request.stdout_byte_limit or result.stderr_artifact.byte_count>request.stderr_byte_limit: raise NativeEvidenceInvalid("result artifact exceeds request limit")
    def write_result(self, issued_result: object) -> NativeExecutionResult:
        record=_issued_native_result_for(issued_result); result=record.result.validated(); request=self._request_for_result(result); self._validate_result_binding(request,result); self._verify_artifact(result.stdout_artifact); self._verify_artifact(result.stderr_artifact)
        path=self._path("result",request.session_id,request.gate_id,request.execution_attempt_index)
        with self._lock(request.session_id,request.gate_id,request.execution_attempt_index):
            if path.exists(): raise NativeResultAlreadyExists("native execution result is write-once")
            try: self._atomic_create(path,result.to_dict(),operation="native result")
            except FileExistsError as exc: raise NativeResultAlreadyExists("native execution result is write-once") from exc
        reloaded=self.load_result(request.session_id,request.gate_id,request.execution_attempt_index)
        if reloaded!=result: raise NativeEvidenceInvalid("reloaded result differs")
        _consume_issued_native_result(issued_result); return reloaded
    def load_result(self, session_id: str, gate_id: str, attempt: int) -> NativeExecutionResult:
        result=self._load("result",session_id,gate_id,attempt,NativeExecutionResult.from_dict); request=self.load_request(session_id,gate_id,attempt)
        if result.request_fingerprint!=request.request_fingerprint: raise NativeEvidenceInvalid("result request binding mismatch")
        self._validate_result_binding(request,result); self._verify_artifact(result.stdout_artifact); self._verify_artifact(result.stderr_artifact); return result
    def create_capture_attempt(self, *, request: NativeExecutionRequest, result: NativeExecutionResult, gate_plan_fingerprint: str, checkpoint_contract_fingerprint: str, behavioral_evidence_fingerprint: str, required_command_ids: tuple[str, ...], state_revision: int, clock: Callable[[], str] = _utc_now) -> NativeCheckpointCaptureAttempt:
        if self.has_capture_attempt(request.session_id,request.gate_id,request.execution_attempt_index): raise NativeResultAlreadyExists("capture attempt is write-once")
        provisional=NativeCheckpointCaptureAttempt(CAPTURE_ATTEMPT_SCHEMA_VERSION,request.session_id,request.gate_id,0,request.request_fingerprint,result.result_fingerprint,gate_plan_fingerprint,checkpoint_contract_fingerprint,behavioral_evidence_fingerprint,required_command_ids,f"capture:{request.session_id}:{request.gate_id}:0",CAPTURE_EXPECTED_SUCCESS_STATUS,clock(),state_revision,"0"*64)
        item=NativeCheckpointCaptureAttempt(**{**provisional.__dict__,"attempt_fingerprint":fingerprint(provisional._body())}).validated(); path=self._path("capture-attempt",item.session_id,item.gate_id,0)
        with self._lock(item.session_id,item.gate_id,0): self._atomic_create(path,item.to_dict(),operation="capture attempt")
        return self.load_capture_attempt(item.session_id,item.gate_id,0)
    def load_capture_attempt(self, session_id: str, gate_id: str, attempt: int) -> NativeCheckpointCaptureAttempt:
        self.assert_unique_capture_attempt(session_id, gate_id, attempt)
        return self._load("capture-attempt",session_id,gate_id,attempt,NativeCheckpointCaptureAttempt.from_dict)
    def create_terminal(self, *, request: NativeExecutionRequest, result: NativeExecutionResult | None, status: NativeCaptureTerminalStatus, failure_category: str, diagnostic: str, capture_attempt: NativeCheckpointCaptureAttempt | None = None, clock: Callable[[], str] = _utc_now) -> NativeCanaryTerminalRecord:
        provisional=NativeCanaryTerminalRecord(TERMINAL_SCHEMA_VERSION,request.session_id,request.gate_id,0,request.request_fingerprint,result.result_fingerprint if result else None,status,capture_attempt.attempt_fingerprint if capture_attempt else None,clock(),failure_category,diagnostic,"0"*64)
        item=NativeCanaryTerminalRecord(**{**provisional.__dict__,"terminal_fingerprint":fingerprint(provisional._body())}).validated(); path=self._path("terminal",item.session_id,item.gate_id,0)
        with self._lock(item.session_id,item.gate_id,0):
            if path.exists(): raise NativeResultAlreadyExists("canary terminal record is write-once")
            self._atomic_create(path,item.to_dict(),operation="canary terminal")
        return self.load_terminal(item.session_id,item.gate_id,0)
    def load_terminal(self, session_id: str, gate_id: str, attempt: int) -> NativeCanaryTerminalRecord: return self._load("terminal",session_id,gate_id,attempt,NativeCanaryTerminalRecord.from_dict)


__all__ = [
    "ARTIFACT_SCHEMA_VERSION", "ATTESTATION_SCHEMA_VERSION", "BACKEND_IDENTITY", "BACKEND_PROTOCOL_VERSION", "CAPTURE_ATTEMPT_SCHEMA_VERSION", "CAPTURE_EXPECTED_SUCCESS_STATUS", "CURSOR_DISCOVERY_COMMAND", "CURSOR_DISCOVERY_MECHANISM", "DEFAULT_ENVIRONMENT_ALLOWLIST", "EXPECTED_CURSOR_PACKAGE_NAME", "NATIVE_PROMPT_HEADER", "REQUEST_SCHEMA_VERSION", "RESULT_SCHEMA_VERSION", "TERMINAL_SCHEMA_VERSION",
    "AtomicNativeExecutionStore", "CursorInstallationProvenance", "CursorNativeBackendConfig", "ManagedNativeProcessRunner", "NativeArtifactReference", "NativeBackendAttestation", "NativeBackendFileAttestation", "NativeCanaryTerminalRecord", "NativeCaptureTerminalStatus", "NativeCheckpointCaptureAttempt", "NativeCommittedButDurabilityUncertain", "NativeDelegatedExecutor", "NativeEvidenceInvalid", "NativeEvidenceNotFound", "NativeExecutionRequest", "NativeExecutionResult", "NativeExecutionStatus", "NativeExecutionStoreError", "NativeFilesystemIdentity", "NativePreflightDecision", "NativePreflightStatus", "NativeProcessInvocation", "NativeProcessOutcome", "NativeProcessRunner", "NativeProcessStartError", "NativeRequestAlreadyExists", "NativeResultAlreadyExists", "preflight_native_cursor",
]
