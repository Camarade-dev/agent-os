"""Canonical bounded intake for untrusted provider output.

This adapts the semantics proven by the external, provider-free spike at
`admissible-capsule/spike-v1/finalizer-v1` (see its
`scripts/intake_validator.py` and `evidence/intake-matrix.json`) into a
mission-generic mechanism: the exact authorized file/directory set, limits,
and rejection vocabulary are parameters (`IntakeAuthority`), not hardcoded
constants. `NEON_RELAY_AUTHORITY` below is one concrete fixture instance —
the same authority set the spike exercised for the Neon Relay mission — used
by tests and demonstrations, not baked into the mechanism itself.

Intake never rules on partial information: `CanonicalIntake.observe()` walks
every entry before any rejection is finalized, and only exact accepted bytes
(re-confirmed against their observed identity) are ever copied.
"""

from __future__ import annotations

import os
import shutil
import stat
import unicodedata
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.common import (
    CrashInjected,
    atomic_json,
    fingerprint,
    fsync_directory,
    mode_type,
    portable_path_collision_key,
    require_exact_keys,
    require_nonempty_text,
    require_sha256,
    require_strict_int,
    sha256_bytes,
    WINDOWS_RESERVED_BASENAMES,
)


INTAKE_AUTHORITY_SCHEMA_VERSION = "admissible_capsule_intake_authority_v1"
INTAKE_EVIDENCE_SCHEMA_VERSION = "admissible_capsule_intake_evidence_v2"
ACCEPTED_MATERIAL_IDENTITY_SCHEMA_VERSION = "admissible_capsule_accepted_material_identity_v1"

_IDENTITY_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)

WINDOWS_RESERVED = WINDOWS_RESERVED_BASENAMES


class RejectionCode(str, Enum):
    """The closed, precise rejection vocabulary canonical intake can emit."""

    EMPTY_PATH = "EMPTY_PATH"
    ABSOLUTE_PATH = "ABSOLUTE_PATH"
    WINDOWS_SEPARATOR = "WINDOWS_SEPARATOR"
    EMPTY_PATH_COMPONENT = "EMPTY_PATH_COMPONENT"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    TRAILING_DOT_OR_SPACE = "TRAILING_DOT_OR_SPACE"
    ADS_COLON = "ADS_COLON"
    WINDOWS_RESERVED_BASENAME = "WINDOWS_RESERVED_BASENAME"
    UNICODE_NORMALIZATION_ALIAS = "UNICODE_NORMALIZATION_ALIAS"
    NON_UTF8_PATH = "NON_UTF8_PATH"
    SOURCE_MUTATED = "SOURCE_MUTATED"
    MOUNT_CROSSING = "MOUNT_CROSSING"
    SYMLINK = "SYMLINK"
    HARD_LINK = "HARD_LINK"
    SPECIAL_FILE = "SPECIAL_FILE"
    EXTRA_PATH = "EXTRA_PATH"
    EXTRA_DIRECTORY = "EXTRA_DIRECTORY"
    MISSING_PATH = "MISSING_PATH"
    EXPECTED_DIRECTORY = "EXPECTED_DIRECTORY"
    EXPECTED_REGULAR_FILE = "EXPECTED_REGULAR_FILE"
    CASE_INSENSITIVE_COLLISION = "CASE_INSENSITIVE_COLLISION"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    AGGREGATE_TOO_LARGE = "AGGREGATE_TOO_LARGE"
    OBSERVATION_BOUND_EXCEEDED = "OBSERVATION_BOUND_EXCEEDED"
    INVALID_UTF8 = "INVALID_UTF8"
    MALFORMED_PACKAGE_JSON = "MALFORMED_PACKAGE_JSON"
    PACKAGE_JSON_NOT_OBJECT = "PACKAGE_JSON_NOT_OBJECT"


class IntakePublicationState(str, Enum):
    """Durable intake states; each name describes an effect already completed."""

    REJECTED = "REJECTED"
    CANDIDATE_VALIDATED = "CANDIDATE_VALIDATED"
    PUBLICATION_PREPARED = "PUBLICATION_PREPARED"
    DESTINATION_RENAME_COMPLETED = "DESTINATION_RENAME_COMPLETED"
    ACCEPTED_INTAKE_PUBLISHED = "ACCEPTED_INTAKE_PUBLISHED"


@dataclass(frozen=True)
class IntakeAuthority:
    """The exact authorized file/directory set and bounds for one mission.

    Mission-generic by construction: nothing in `CanonicalIntake` refers to
    a concrete mission name. `NEON_RELAY_AUTHORITY` below is one instance.
    """

    schema_version: str
    authority_id: str
    authority_paths: tuple[str, ...]
    allowed_directories: tuple[str, ...]
    per_file_bytes: int
    aggregate_bytes: int
    observed_entries: int
    authority_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        authority_id: str,
        authority_paths: tuple[str, ...],
        allowed_directories: tuple[str, ...],
        per_file_bytes: int = 1024 * 1024,
        aggregate_bytes: int = 8 * 1024 * 1024,
        observed_entries: int = 256,
    ) -> "IntakeAuthority":
        body = {
            "schema_version": INTAKE_AUTHORITY_SCHEMA_VERSION,
            "authority_id": authority_id,
            "authority_paths": list(authority_paths),
            "allowed_directories": list(allowed_directories),
            "per_file_bytes": per_file_bytes,
            "aggregate_bytes": aggregate_bytes,
            "observed_entries": observed_entries,
        }
        return cls(
            schema_version=INTAKE_AUTHORITY_SCHEMA_VERSION,
            authority_id=authority_id,
            authority_paths=authority_paths,
            allowed_directories=allowed_directories,
            per_file_bytes=per_file_bytes,
            aggregate_bytes=aggregate_bytes,
            observed_entries=observed_entries,
            authority_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority_id": self.authority_id,
            "authority_paths": list(self.authority_paths),
            "allowed_directories": list(self.allowed_directories),
            "per_file_bytes": self.per_file_bytes,
            "aggregate_bytes": self.aggregate_bytes,
            "observed_entries": self.observed_entries,
        }

    def validated(self) -> "IntakeAuthority":
        if self.schema_version != INTAKE_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported intake authority schema")
        require_nonempty_text(self.authority_id, "authority_id", max_bytes=256)
        if not isinstance(self.authority_paths, tuple) or not self.authority_paths:
            raise ValueError("intake authority requires a non-empty exact path set")
        if len(set(self.authority_paths)) != len(self.authority_paths):
            raise ValueError("intake authority paths must be unique")
        if not isinstance(self.allowed_directories, tuple):
            raise ValueError("intake allowed directories must be immutable")
        if len(set(self.allowed_directories)) != len(self.allowed_directories):
            raise ValueError("intake allowed directories must be unique")
        require_strict_int(self.per_file_bytes, "per_file_bytes", minimum=1, maximum=1024 * 1024 * 1024)
        require_strict_int(self.aggregate_bytes, "aggregate_bytes", minimum=1, maximum=1024 * 1024 * 1024)
        require_strict_int(self.observed_entries, "observed_entries", minimum=1, maximum=1_000_000)
        require_sha256(self.authority_fingerprint, "authority_fingerprint")
        if fingerprint(self._body()) != self.authority_fingerprint:
            raise ValueError("intake authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["authority_fingerprint"] = self.authority_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IntakeAuthority":
        require_exact_keys(
            data,
            {
                "schema_version",
                "authority_id",
                "authority_paths",
                "allowed_directories",
                "per_file_bytes",
                "aggregate_bytes",
                "observed_entries",
                "authority_fingerprint",
            },
            "intake authority",
        )
        return cls(
            schema_version=data["schema_version"],
            authority_id=data["authority_id"],
            authority_paths=tuple(data["authority_paths"]),
            allowed_directories=tuple(data["allowed_directories"]),
            per_file_bytes=data["per_file_bytes"],
            aggregate_bytes=data["aggregate_bytes"],
            observed_entries=data["observed_entries"],
            authority_fingerprint=data["authority_fingerprint"],
        ).validated()


# The exact authority set exercised by the provider-free finalizer spike for
# the Neon Relay browser-game mission. Kept as a concrete fixture so the
# generic mechanism above has one faithful, reproducible example.
NEON_RELAY_AUTHORITY = IntakeAuthority.create(
    authority_id="neon_relay_v1",
    authority_paths=(
        "LOCAL_DEV.md",
        "index.html",
        "package.json",
        "style.css",
        "src/random.js",
        "src/state-machine.js",
        "src/entities.js",
        "src/combat.js",
        "src/upgrades.js",
        "src/game.js",
        "src/render.js",
        "src/main.js",
        "test/game.test.js",
        "test/state-machine.test.js",
    ),
    allowed_directories=("src", "test"),
)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(info, name) for name in _IDENTITY_FIELDS)


@dataclass(frozen=True)
class RejectionReason:
    code: RejectionCode
    path: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code.value, "path": self.path, "detail": self.detail}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RejectionReason":
        require_exact_keys(data, {"code", "path", "detail"}, "rejection reason")
        return cls(code=RejectionCode(data["code"]), path=data["path"], detail=data["detail"])


def path_policy_reasons(path: str) -> list[RejectionReason]:
    """Pure path-shape checks: traversal, Windows aliasing, ADS, reserved names.

    These run independent of any real filesystem entry, so hostile category
    coverage (e.g. PATH_TRAVERSAL) is testable even for shapes a real
    directory listing could never produce.
    """

    reasons: list[RejectionReason] = []
    if not path:
        reasons.append(RejectionReason(RejectionCode.EMPTY_PATH, path, "path is empty"))
        return reasons
    if path.startswith("/") or path.startswith("\\"):
        reasons.append(RejectionReason(RejectionCode.ABSOLUTE_PATH, path, "absolute paths are forbidden"))
    if "\\" in path:
        reasons.append(
            RejectionReason(RejectionCode.WINDOWS_SEPARATOR, path, "backslash path separators are forbidden")
        )
    components = path.split("/")
    if any(component == "" for component in components):
        reasons.append(
            RejectionReason(RejectionCode.EMPTY_PATH_COMPONENT, path, "empty path components are forbidden")
        )
    if any(component in {".", ".."} for component in components):
        reasons.append(RejectionReason(RejectionCode.PATH_TRAVERSAL, path, "dot traversal is forbidden"))
    for component in components:
        if not component:
            continue
        if component.endswith(".") or component.endswith(" "):
            reasons.append(
                RejectionReason(
                    RejectionCode.TRAILING_DOT_OR_SPACE,
                    path,
                    f"component has a Windows-aliased suffix: {component!r}",
                )
            )
        if ":" in component:
            reasons.append(
                RejectionReason(RejectionCode.ADS_COLON, path, "ADS-shaped colon components are forbidden")
            )
        if unicodedata.normalize("NFC", component) != component:
            reasons.append(
                RejectionReason(
                    RejectionCode.UNICODE_NORMALIZATION_ALIAS,
                    path,
                    "path components must use canonical Unicode NFC",
                )
            )
        basename = component.split(".", 1)[0].upper()
        if basename in WINDOWS_RESERVED:
            reasons.append(
                RejectionReason(
                    RejectionCode.WINDOWS_RESERVED_BASENAME,
                    path,
                    f"reserved Windows basename: {basename}",
                )
            )
    return reasons


@dataclass(frozen=True)
class IntakeFileRecord:
    relative_path: str
    size: int
    sha256: str
    git_mode: str

    def validated(self) -> "IntakeFileRecord":
        require_nonempty_text(self.relative_path, "intake file relative_path", max_bytes=4096)
        require_strict_int(self.size, "intake file size", minimum=0, maximum=1024 * 1024 * 1024)
        require_sha256(self.sha256, "intake file sha256")
        if self.git_mode not in {"100644", "100755"}:
            raise ValueError("accepted regular-file mode must be 100644 or 100755")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "size": self.size,
            "sha256": self.sha256,
            "git_mode": self.git_mode,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IntakeFileRecord":
        require_exact_keys(data, {"relative_path", "size", "sha256", "git_mode"}, "intake file record")
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class AcceptedMaterialIdentity:
    """Closed identity of the exact regular-file material accepted by intake."""

    schema_version: str
    intake_authority_fingerprint: str
    authorized_relative_paths: tuple[str, ...]
    files: tuple[IntakeFileRecord, ...]
    canonical_manifest_fingerprint: str
    intake_evidence_fingerprint: str
    material_fingerprint: str

    @classmethod
    def from_intake_evidence(cls, evidence: "IntakeEvidence") -> "AcceptedMaterialIdentity":
        evidence.validated()
        if not evidence.published:
            raise ValueError("accepted-material identity requires published accepted intake evidence")
        files = tuple(sorted(evidence.files, key=lambda item: item.relative_path))
        paths = tuple(item.relative_path for item in files)
        manifest = fingerprint([item.to_dict() for item in files])
        body = {
            "schema_version": ACCEPTED_MATERIAL_IDENTITY_SCHEMA_VERSION,
            "intake_authority_fingerprint": evidence.authority_fingerprint,
            "authorized_relative_paths": list(paths),
            "files": [item.to_dict() for item in files],
            "canonical_manifest_fingerprint": manifest,
            "intake_evidence_fingerprint": evidence.evidence_fingerprint,
        }
        return cls(
            schema_version=ACCEPTED_MATERIAL_IDENTITY_SCHEMA_VERSION,
            intake_authority_fingerprint=evidence.authority_fingerprint,
            authorized_relative_paths=paths,
            files=files,
            canonical_manifest_fingerprint=manifest,
            intake_evidence_fingerprint=evidence.evidence_fingerprint,
            material_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "intake_authority_fingerprint": self.intake_authority_fingerprint,
            "authorized_relative_paths": list(self.authorized_relative_paths),
            "files": [item.to_dict() for item in self.files],
            "canonical_manifest_fingerprint": self.canonical_manifest_fingerprint,
            "intake_evidence_fingerprint": self.intake_evidence_fingerprint,
        }

    def validated(self) -> "AcceptedMaterialIdentity":
        if self.schema_version != ACCEPTED_MATERIAL_IDENTITY_SCHEMA_VERSION:
            raise ValueError("unsupported accepted-material identity schema")
        require_sha256(self.intake_authority_fingerprint, "intake authority fingerprint")
        if not isinstance(self.authorized_relative_paths, tuple) or not self.authorized_relative_paths:
            raise ValueError("accepted-material paths must be a non-empty immutable tuple")
        if not isinstance(self.files, tuple) or not self.files:
            raise ValueError("accepted-material files must be a non-empty immutable tuple")
        for item in self.files:
            if not isinstance(item, IntakeFileRecord):
                raise ValueError("invalid accepted-material file record")
            item.validated()
        paths = tuple(item.relative_path for item in self.files)
        if paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
            raise ValueError("accepted-material files must have unique canonical path order")
        if self.authorized_relative_paths != paths:
            raise ValueError("accepted-material authorized path set differs from its files")
        require_sha256(self.canonical_manifest_fingerprint, "canonical accepted manifest fingerprint")
        if fingerprint([item.to_dict() for item in self.files]) != self.canonical_manifest_fingerprint:
            raise ValueError("canonical accepted manifest fingerprint mismatch")
        require_sha256(self.intake_evidence_fingerprint, "canonical intake evidence fingerprint")
        require_sha256(self.material_fingerprint, "accepted-material fingerprint")
        if fingerprint(self._body()) != self.material_fingerprint:
            raise ValueError("accepted-material fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "material_fingerprint": self.material_fingerprint}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AcceptedMaterialIdentity":
        require_exact_keys(
            data,
            {
                "schema_version",
                "intake_authority_fingerprint",
                "authorized_relative_paths",
                "files",
                "canonical_manifest_fingerprint",
                "intake_evidence_fingerprint",
                "material_fingerprint",
            },
            "accepted-material identity",
        )
        if not isinstance(data["authorized_relative_paths"], list) or not isinstance(data["files"], list):
            raise ValueError("accepted-material paths and files must be arrays")
        return cls(
            schema_version=data["schema_version"],
            intake_authority_fingerprint=data["intake_authority_fingerprint"],
            authorized_relative_paths=tuple(data["authorized_relative_paths"]),
            files=tuple(IntakeFileRecord.from_dict(item) for item in data["files"]),
            canonical_manifest_fingerprint=data["canonical_manifest_fingerprint"],
            intake_evidence_fingerprint=data["intake_evidence_fingerprint"],
            material_fingerprint=data["material_fingerprint"],
        ).validated()


@dataclass(frozen=True)
class IntakeEvidence:
    """Canonical, atomic, fingerprinted evidence of one intake ruling."""

    schema_version: str
    authority_fingerprint: str
    ruling: str
    rejection_reasons: tuple[RejectionReason, ...]
    files: tuple[IntakeFileRecord, ...]
    aggregate_fingerprint: str | None
    publication_state: IntakePublicationState
    evidence_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        authority_fingerprint: str,
        ruling: str,
        rejection_reasons: tuple[RejectionReason, ...],
        files: tuple[IntakeFileRecord, ...],
        aggregate_fingerprint: str | None,
        publication_state: IntakePublicationState,
    ) -> "IntakeEvidence":
        body = {
            "schema_version": INTAKE_EVIDENCE_SCHEMA_VERSION,
            "authority_fingerprint": authority_fingerprint,
            "ruling": ruling,
            "rejection_reasons": [reason.to_dict() for reason in rejection_reasons],
            "files": [record.to_dict() for record in files],
            "aggregate_fingerprint": aggregate_fingerprint,
            "publication_state": publication_state.value,
        }
        return cls(
            schema_version=INTAKE_EVIDENCE_SCHEMA_VERSION,
            authority_fingerprint=authority_fingerprint,
            ruling=ruling,
            rejection_reasons=rejection_reasons,
            files=files,
            aggregate_fingerprint=aggregate_fingerprint,
            publication_state=publication_state,
            evidence_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority_fingerprint": self.authority_fingerprint,
            "ruling": self.ruling,
            "rejection_reasons": [reason.to_dict() for reason in self.rejection_reasons],
            "files": [record.to_dict() for record in self.files],
            "aggregate_fingerprint": self.aggregate_fingerprint,
            "publication_state": self.publication_state.value,
        }

    @property
    def published(self) -> bool:
        return self.publication_state is IntakePublicationState.ACCEPTED_INTAKE_PUBLISHED

    def validated(self) -> "IntakeEvidence":
        if self.schema_version != INTAKE_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported intake evidence schema")
        require_sha256(self.authority_fingerprint, "authority_fingerprint")
        if self.ruling not in {"ACCEPTED", "REJECTED"}:
            raise ValueError("intake ruling must be ACCEPTED or REJECTED")
        if self.ruling == "ACCEPTED" and self.rejection_reasons:
            raise ValueError("ACCEPTED evidence cannot carry rejection reasons")
        if self.ruling == "REJECTED" and not self.rejection_reasons:
            raise ValueError("REJECTED evidence requires at least one rejection reason")
        if not isinstance(self.publication_state, IntakePublicationState):
            raise ValueError("unknown intake publication state")
        if self.ruling == "REJECTED" and self.publication_state is not IntakePublicationState.REJECTED:
            raise ValueError("rejected intake must use the REJECTED publication state")
        if self.ruling == "ACCEPTED" and self.publication_state is IntakePublicationState.REJECTED:
            raise ValueError("accepted intake cannot use the REJECTED publication state")
        if self.ruling == "ACCEPTED" and (not self.files or self.aggregate_fingerprint is None):
            raise ValueError("ACCEPTED evidence requires complete accepted files and an aggregate fingerprint")
        if not isinstance(self.files, tuple):
            raise ValueError("intake files must be immutable")
        for record in self.files:
            record.validated()
        paths = [record.relative_path for record in self.files]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("intake files must have unique canonical path order")
        if self.aggregate_fingerprint is not None:
            require_sha256(self.aggregate_fingerprint, "aggregate fingerprint")
            if fingerprint([record.to_dict() for record in self.files]) != self.aggregate_fingerprint:
                raise ValueError("aggregate fingerprint does not match intake files")
        require_sha256(self.evidence_fingerprint, "evidence_fingerprint")
        if fingerprint(self._body()) != self.evidence_fingerprint:
            raise ValueError("intake evidence fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["evidence_fingerprint"] = self.evidence_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IntakeEvidence":
        require_exact_keys(
            data,
            {
                "schema_version",
                "authority_fingerprint",
                "ruling",
                "rejection_reasons",
                "files",
                "aggregate_fingerprint",
                "publication_state",
                "evidence_fingerprint",
            },
            "intake evidence",
        )
        if not isinstance(data["rejection_reasons"], list) or not isinstance(data["files"], list):
            raise ValueError("intake evidence reasons and files must be arrays")
        return cls(
            schema_version=data["schema_version"],
            authority_fingerprint=data["authority_fingerprint"],
            ruling=data["ruling"],
            rejection_reasons=tuple(RejectionReason.from_dict(item) for item in data["rejection_reasons"]),
            files=tuple(IntakeFileRecord.from_dict(item) for item in data["files"]),
            aggregate_fingerprint=data["aggregate_fingerprint"],
            publication_state=IntakePublicationState(data["publication_state"]),
            evidence_fingerprint=data["evidence_fingerprint"],
        ).validated()


class CanonicalIntake:
    """Observe an untrusted source tree completely, then rule and copy.

    Mirrors the proven spike mechanism: open the source with `O_NOFOLLOW`,
    observe every entry by file descriptor (never by re-resolving a path),
    accumulate every rejection before ruling, and only copy re-confirmed
    accepted bytes.
    """

    def __init__(self, source: Path, authority: IntakeAuthority):
        self.source = Path(os.path.abspath(source))
        self.authority = authority.validated()
        self.root_fd = -1
        self.directory_fds: dict[str, int] = {}
        self.source_device: int | None = None
        self.reasons: list[RejectionReason] = []
        self.file_records: dict[str, IntakeFileRecord] = {}
        self._file_identity: dict[str, tuple[int, ...]] = {}
        self.observed_paths: set[str] = set()
        self.observed_kinds: dict[str, str] = {}
        self.directory_names: dict[str, tuple[str, ...]] = {}
        self._observed_count = 0

    def _add_reason(self, code: RejectionCode, path: str, detail: str) -> None:
        reason = RejectionReason(code, path, detail)
        if reason not in self.reasons:
            self.reasons.append(reason)

    def open(self) -> None:
        root_lstat = os.lstat(self.source)
        if stat.S_ISLNK(root_lstat.st_mode):
            raise ValueError("intake source root must not be a symlink")
        if not stat.S_ISDIR(root_lstat.st_mode):
            raise ValueError("intake source root must be a directory")
        flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        self.root_fd = os.open(self.source, flags)
        root_fstat = os.fstat(self.root_fd)
        if _identity(root_lstat) != _identity(root_fstat):
            raise ValueError("intake source root identity changed while opening")
        self.source_device = root_fstat.st_dev

    def close(self) -> None:
        for descriptor in self.directory_fds.values():
            os.close(descriptor)
        self.directory_fds.clear()
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1

    def __enter__(self) -> "CanonicalIntake":
        self.open()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def _observe_entry(self, directory_fd: int, name: str, relative: str) -> os.stat_result | None:
        self._observed_count += 1
        if self._observed_count > self.authority.observed_entries:
            self._add_reason(
                RejectionCode.OBSERVATION_BOUND_EXCEEDED,
                relative,
                f"more than {self.authority.observed_entries} entries were present",
            )
            return None
        try:
            name.encode("utf-8", "strict")
        except UnicodeEncodeError:
            self._add_reason(RejectionCode.NON_UTF8_PATH, relative, "filesystem name is not valid UTF-8")
        for reason in path_policy_reasons(relative):
            self._add_reason(reason.code, reason.path, reason.detail)
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            self._add_reason(RejectionCode.SOURCE_MUTATED, relative, "entry disappeared during observation")
            return None
        kind = mode_type(info.st_mode)
        self.observed_paths.add(relative)
        self.observed_kinds[relative] = kind
        if info.st_dev != self.source_device:
            self._add_reason(RejectionCode.MOUNT_CROSSING, relative, "entry device differs from source root")
        if kind == "symlink":
            self._add_reason(RejectionCode.SYMLINK, relative, "symbolic links are forbidden")
        elif kind in {"fifo", "socket", "block_device", "character_device", "unknown"}:
            self._add_reason(RejectionCode.SPECIAL_FILE, relative, f"{kind} filesystem entries are forbidden")
        if kind == "regular" and info.st_nlink > 1:
            self._add_reason(
                RejectionCode.HARD_LINK, relative, f"regular file link count is {info.st_nlink}, expected one"
            )
        return info

    def _read_regular(self, directory_fd: int, name: str, relative: str, observed_info: os.stat_result) -> None:
        limit = self.authority.per_file_bytes
        if observed_info.st_size > limit:
            self._add_reason(RejectionCode.FILE_TOO_LARGE, relative, f"{observed_info.st_size} exceeds {limit}")
            return
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        except OSError as error:
            self._add_reason(
                RejectionCode.SOURCE_MUTATED, relative, f"regular file could not be opened safely: errno {error.errno}"
            )
            return
        try:
            before = os.fstat(descriptor)
            if _identity(before) != _identity(observed_info) or not stat.S_ISREG(before.st_mode):
                self._add_reason(RejectionCode.SOURCE_MUTATED, relative, "file identity changed between lstat and open")
                return
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(descriptor, min(128 * 1024, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
            if _identity(before) != _identity(after):
                self._add_reason(RejectionCode.SOURCE_MUTATED, relative, "file changed while it was observed")
                return
            if len(data) > limit:
                self._add_reason(RejectionCode.FILE_TOO_LARGE, relative, f"file exceeds {limit}")
                return
            raw = bytes(data)
            if relative == "package.json":
                import json

                try:
                    text = raw.decode("utf-8", "strict")
                except UnicodeDecodeError as error:
                    self._add_reason(RejectionCode.INVALID_UTF8, relative, f"invalid UTF-8 at byte {error.start}")
                else:
                    try:
                        package = json.loads(text)
                    except json.JSONDecodeError as error:
                        self._add_reason(
                            RejectionCode.MALFORMED_PACKAGE_JSON,
                            relative,
                            f"JSON parse failed at line {error.lineno}, column {error.colno}",
                        )
                    else:
                        if not isinstance(package, dict):
                            self._add_reason(
                                RejectionCode.PACKAGE_JSON_NOT_OBJECT,
                                relative,
                                "package.json top-level value must be an object",
                            )
            self.file_records[relative] = IntakeFileRecord(
                relative_path=relative,
                size=len(raw),
                sha256=sha256_bytes(raw),
                git_mode="100755" if before.st_mode & 0o111 else "100644",
            ).validated()
            self._file_identity[relative] = _identity(before)
        finally:
            os.close(descriptor)

    def observe(self) -> None:
        """Walk the complete source tree before any rejection is final."""

        root_names = tuple(sorted(os.listdir(self.root_fd)))
        self.directory_names["."] = root_names
        for name in root_names:
            info = self._observe_entry(self.root_fd, name, name)
            if info is None:
                continue
            kind = mode_type(info.st_mode)
            if name in self.authority.allowed_directories and kind == "directory":
                flags = os.O_RDONLY | os.O_DIRECTORY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(name, flags, dir_fd=self.root_fd)
                except OSError as error:
                    self._add_reason(
                        RejectionCode.SOURCE_MUTATED, name, f"directory could not be opened safely: errno {error.errno}"
                    )
                    continue
                opened = os.fstat(descriptor)
                if _identity(opened) != _identity(info):
                    self._add_reason(RejectionCode.SOURCE_MUTATED, name, "directory identity changed while opening")
                    os.close(descriptor)
                    continue
                self.directory_fds[name] = descriptor
                child_names = tuple(sorted(os.listdir(descriptor)))
                self.directory_names[name] = child_names
                for child_name in child_names:
                    relative = f"{name}/{child_name}"
                    child_info = self._observe_entry(descriptor, child_name, relative)
                    if child_info is not None and mode_type(child_info.st_mode) == "regular":
                        self._read_regular(descriptor, child_name, relative, child_info)
            elif kind == "regular":
                self._read_regular(self.root_fd, name, name, info)

        expected = set(self.authority.authority_paths) | set(self.authority.allowed_directories)
        for path in sorted(self.observed_paths - expected):
            code = RejectionCode.EXTRA_DIRECTORY if self.observed_kinds.get(path) == "directory" else RejectionCode.EXTRA_PATH
            self._add_reason(code, path, "path is outside the exact authority")
        for path in sorted(expected - self.observed_paths):
            self._add_reason(RejectionCode.MISSING_PATH, path, "authoritative path is absent")

        for directory in self.authority.allowed_directories:
            if directory in self.observed_paths and directory not in self.directory_fds:
                self._add_reason(RejectionCode.EXPECTED_DIRECTORY, directory, "authoritative directory is not a directory")
        for path in self.authority.authority_paths:
            if path in self.observed_paths and path not in self.file_records:
                already_flagged = any(reason.path == path for reason in self.reasons)
                if not already_flagged:
                    self._add_reason(RejectionCode.EXPECTED_REGULAR_FILE, path, "authoritative material must be a regular file")

        folded: dict[str, list[str]] = {}
        for path in self.observed_paths:
            folded.setdefault(portable_path_collision_key(path), []).append(path)
        for paths in folded.values():
            unique = sorted(set(paths))
            if len(unique) > 1:
                self._add_reason(
                    RejectionCode.CASE_INSENSITIVE_COLLISION, "|".join(unique), "paths collide under Unicode case folding"
                )

        aggregate_size = sum(
            record.size for path, record in self.file_records.items() if path in self.authority.authority_paths
        )
        if aggregate_size > self.authority.aggregate_bytes:
            self._add_reason(
                RejectionCode.AGGREGATE_TOO_LARGE, ".", f"{aggregate_size} exceeds {self.authority.aggregate_bytes}"
            )

        self.reasons.sort(key=lambda item: (item.path, item.code.value, item.detail))

    def aggregate_fingerprint(self) -> str | None:
        public = []
        for path in sorted(self.authority.authority_paths):
            record = self.file_records.get(path)
            if record is None:
                return None
            public.append(record.to_dict())
        return fingerprint(public)

    def _read_confirmed(self, relative: str) -> bytes:
        record = self.file_records[relative]
        parent, name = relative.split("/", 1) if "/" in relative else (".", relative)
        directory_fd = self.root_fd if parent == "." else self.directory_fds[parent]
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or _identity(before) != self._file_identity[relative]
                or before.st_nlink != 1
                or before.st_dev != self.source_device
            ):
                raise RuntimeError(f"SOURCE_MUTATED:{relative}:identity")
            data = bytearray()
            limit = self.authority.per_file_bytes
            while len(data) <= limit:
                chunk = os.read(descriptor, min(128 * 1024, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
            raw = bytes(data)
            if _identity(after) != _identity(before):
                raise RuntimeError(f"SOURCE_MUTATED:{relative}:during-read")
            if len(raw) != record.size or sha256_bytes(raw) != record.sha256:
                raise RuntimeError(f"SOURCE_MUTATED:{relative}:bytes")
            return raw
        finally:
            os.close(descriptor)

    def _confirm_namespace(self) -> None:
        if tuple(sorted(os.listdir(self.root_fd))) != self.directory_names["."]:
            raise RuntimeError("SOURCE_MUTATED:.:directory-list")
        for directory, descriptor in self.directory_fds.items():
            if tuple(sorted(os.listdir(descriptor))) != self.directory_names[directory]:
                raise RuntimeError(f"SOURCE_MUTATED:{directory}:directory-list")
        for path in self.authority.authority_paths:
            self._read_confirmed(path)

    def evidence(
        self,
        *,
        ruling: str,
        publication_state: IntakePublicationState,
    ) -> IntakeEvidence:
        files = tuple(
            self.file_records[path]
            for path in sorted(self.authority.authority_paths)
            if path in self.file_records
        )
        return IntakeEvidence.create(
            authority_fingerprint=self.authority.authority_fingerprint,
            ruling=ruling,
            rejection_reasons=tuple(self.reasons),
            files=files if ruling == "ACCEPTED" else (),
            aggregate_fingerprint=self.aggregate_fingerprint() if ruling == "ACCEPTED" else None,
            publication_state=publication_state,
        )

    def copy_and_publish(
        self,
        destination: Path,
        evidence_path: Path,
        *,
        crash_after_copy: int | None = None,
        crash_before_evidence: bool = False,
        crash_after_preparation: bool = False,
    ) -> IntakeEvidence:
        """Copy only accepted bytes, with atomic staging and canonical evidence.

        Rejected intake never touches `destination`; evidence is always
        written, atomically, whether the ruling is ACCEPTED or REJECTED.
        """

        if destination.exists() or destination.is_symlink():
            raise FileExistsError(f"destination already exists: {destination}")
        if evidence_path.exists() or evidence_path.is_symlink():
            raise FileExistsError(f"evidence already exists: {evidence_path}")
        if self.reasons:
            evidence = self.evidence(
                ruling="REJECTED",
                publication_state=IntakePublicationState.REJECTED,
            )
            atomic_json(evidence_path, evidence.to_dict())
            return evidence
        candidate = self.evidence(
            ruling="ACCEPTED",
            publication_state=IntakePublicationState.CANDIDATE_VALIDATED,
        )
        atomic_json(evidence_path, candidate.to_dict(), crash_before_replace=crash_before_evidence)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        staging = destination.parent / f".{destination.name}.staging-{os.getpid()}-{uuid.uuid4().hex}"
        os.mkdir(staging, 0o700)
        try:
            for directory in self.authority.allowed_directories:
                os.mkdir(staging / directory, 0o755)
            copied_count = 0
            for relative in self.authority.authority_paths:
                raw = self._read_confirmed(relative)
                target = staging / relative
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    offset = 0
                    while offset < len(raw):
                        offset += os.write(descriptor, raw[offset:])
                    os.fsync(descriptor)
                    os.fchmod(
                        descriptor,
                        0o755 if self.file_records[relative].git_mode == "100755" else 0o644,
                    )
                finally:
                    os.close(descriptor)
                copied_count += 1
                if crash_after_copy == copied_count:
                    raise CrashInjected(f"crash injected after copying entry {copied_count}")
            for directory in self.authority.allowed_directories:
                fsync_directory(staging / directory)
            os.chmod(staging, 0o755)
            fsync_directory(staging)
            self._confirm_namespace()
            prepared = self.evidence(
                ruling="ACCEPTED",
                publication_state=IntakePublicationState.PUBLICATION_PREPARED,
            )
            atomic_json(evidence_path, prepared.to_dict())
            if crash_after_preparation:
                raise CrashInjected("crash injected after intake publication preparation")
            os.rename(staging, destination)
            fsync_directory(destination.parent)
            renamed = self.evidence(
                ruling="ACCEPTED",
                publication_state=IntakePublicationState.DESTINATION_RENAME_COMPLETED,
            )
            atomic_json(evidence_path, renamed.to_dict())
            published = self.evidence(
                ruling="ACCEPTED",
                publication_state=IntakePublicationState.ACCEPTED_INTAKE_PUBLISHED,
            )
            atomic_json(evidence_path, published.to_dict())
            return published
        except BaseException as error:
            if shutil.os.path.exists(staging):
                shutil.rmtree(staging, ignore_errors=True)
            if isinstance(error, RuntimeError) and str(error).startswith("SOURCE_MUTATED:"):
                parts = str(error).split(":", 2)
                self._add_reason(
                    RejectionCode.SOURCE_MUTATED,
                    parts[1] if len(parts) > 1 else ".",
                    parts[2] if len(parts) > 2 else "source changed during copy",
                )
                self.reasons.sort(key=lambda item: (item.path, item.code.value, item.detail))
                evidence = self.evidence(
                    ruling="REJECTED",
                    publication_state=IntakePublicationState.REJECTED,
                )
                atomic_json(evidence_path, evidence.to_dict())
                return evidence
            raise


def validate_and_copy(
    source: Path,
    authority: IntakeAuthority,
    destination: Path,
    evidence_path: Path,
    *,
    crash_after_copy: int | None = None,
    crash_before_evidence: bool = False,
    crash_after_preparation: bool = False,
) -> IntakeEvidence:
    with CanonicalIntake(source, authority) as intake:
        intake.observe()
        return intake.copy_and_publish(
            destination,
            evidence_path,
            crash_after_copy=crash_after_copy,
            crash_before_evidence=crash_before_evidence,
            crash_after_preparation=crash_after_preparation,
        )
