"""The exact byte identity of everything that builds and runs one capsule.

Milestone 2's capsule descriptor bound the *name* of its mechanism -- the string
``bubblewrap`` and the path ``shutil.which`` happened to resolve -- and nothing
about the bytes behind that name.  A replaced ``bwrap``, a substituted
interpreter, an edited in-capsule init, or a ``PATH`` entry shadowing the real
launcher would each have produced identical evidence while producing a
completely different boundary.  Evidence that cannot distinguish those cases is
not evidence about the boundary at all.

This module records what the capsule is actually made of:

* the launcher's canonical path, SHA-256, device, inode, owner, mode, size, and
  self-reported version;
* the interpreter's canonical path, SHA-256, device, inode, owner, mode, size;
* the in-capsule init's SHA-256 and size;
* the seccomp program's SHA-256 and the architecture it was assembled for;
* a source identity over every module of this package, so a modified substrate
  is a different capsule;
* the declared toolchain roots with their inode identities;
* the namespace, mount, and containment contract the launcher is invoked under.

The manifest is derived once at readiness and *rechecked immediately before the
proposal that authorises an effect is published*.  A recheck compares the
immutable identities again -- including re-reading the bytes -- so a replacement
that happens between readiness and the effect is refused rather than recorded.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
from typing import Any, Callable, ClassVar

from .canonical import Fingerprint, fingerprint
from .observation import (
    M2_PREFIX,
    M2_SCHEMA_VERSION,
    ObservationError,
    _decode_fp,
    _decode_strings,
    _encode_fp,
    _encode_strings,
    _M2Record,
    _require_int,
    _require_text,
    m2_schema_descriptor,
)


SCHEMA_CAPSULE_RUNTIME_MANIFEST = f"{M2_PREFIX}.capsule_runtime_manifest"
CAPSULE_RUNTIME_MANIFEST_OBJECT_KIND = "capsule-runtime-manifest"
TOOLCHAIN_MANIFEST_DOMAIN = f"{SCHEMA_CAPSULE_RUNTIME_MANIFEST}.toolchain_inputs"

#: Bound on a single executable this module will hash.  A launcher or an
#: interpreter larger than this is refused rather than hashed without limit.
MAX_HASHED_EXECUTABLE_BYTES = 512 * 1024 * 1024


class CapsuleIdentityRefused(RuntimeError):
    """A capsule input is missing, replaced, or not safely owned."""


@dataclass(frozen=True)
class FileIdentity:
    """One file's exact bytes and inode identity."""

    path: str
    sha256: str
    device: int
    inode: int
    size_bytes: int
    mode: int
    owner_uid: int
    owner_gid: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "device": self.device,
            "inode": self.inode,
            "size_bytes": self.size_bytes,
            "mode": self.mode,
            "owner_uid": self.owner_uid,
            "owner_gid": self.owner_gid,
        }


def _hash_file_identity(path: str, label: str) -> FileIdentity:
    """Hash a file through one descriptor, so the bytes and the inode agree.

    The descriptor is opened once and both ``fstat`` and the read happen on it,
    so a replacement between the stat and the read cannot produce a manifest
    that describes one file and hashes another.
    """

    canonical = os.path.realpath(path)
    try:
        handle = os.open(canonical, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise CapsuleIdentityRefused(f"the {label} at {canonical} cannot be opened: {error}") from error
    try:
        info = os.fstat(handle)
        if not stat.S_ISREG(info.st_mode):
            raise CapsuleIdentityRefused(f"the {label} at {canonical} is not a regular file")
        if info.st_size > MAX_HASHED_EXECUTABLE_BYTES:
            raise CapsuleIdentityRefused(f"the {label} at {canonical} exceeds the hashable size bound")
        # A capsule input that anyone but its owner can rewrite is not an
        # identity at all: it could be replaced between this check and its use.
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise CapsuleIdentityRefused(f"the {label} at {canonical} is group- or world-writable")
        if info.st_uid not in {0, os.getuid()}:
            raise CapsuleIdentityRefused(
                f"the {label} at {canonical} is owned by uid {info.st_uid}, which is neither root nor this user"
            )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(handle, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        return FileIdentity(
            path=canonical,
            sha256=digest.hexdigest(),
            device=info.st_dev,
            inode=info.st_ino,
            size_bytes=info.st_size,
            mode=stat.S_IMODE(info.st_mode),
            owner_uid=info.st_uid,
            owner_gid=info.st_gid,
        )
    finally:
        os.close(handle)


def package_source_identity() -> tuple[str, int]:
    """A single digest over every module of this package, plus the file count.

    A substrate whose own source changed is a different capsule even when every
    external input is identical, so the build identity is part of the manifest.
    """

    directory = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    names = sorted(entry.name for entry in directory.iterdir() if entry.suffix == ".py" and entry.is_file())
    for name in names:
        digest.update(name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(hashlib.sha256((directory / name).read_bytes()).digest())
    return digest.hexdigest(), len(names)


def toolchain_input_manifest(paths: tuple[str, ...]) -> tuple[tuple[str, ...], Fingerprint]:
    """The declared read-only roots with their inode identities.

    The roots are directory trees of arbitrary size, so they are bound by inode
    identity and mode rather than by content.  Their presence, absence, and
    replacement are all visible; their contents are the host's, not ours.
    """

    described: list[str] = []
    payload: list[dict[str, Any]] = []
    for path in paths:
        try:
            info = os.stat(path, follow_symlinks=False)
        except OSError:
            described.append(f"{path}:absent")
            payload.append({"path": path, "present": False})
            continue
        described.append(f"{path}:dev={info.st_dev}:ino={info.st_ino}:mode={stat.S_IMODE(info.st_mode):04o}")
        payload.append(
            {
                "path": path,
                "present": True,
                "device": info.st_dev,
                "inode": info.st_ino,
                "mode": stat.S_IMODE(info.st_mode),
                "owner_uid": info.st_uid,
            }
        )
    return tuple(described), fingerprint({"inputs": payload}, domain=TOOLCHAIN_MANIFEST_DOMAIN)


@dataclass(frozen=True)
class CapsuleRuntimeManifest(_M2Record):
    """Every byte identity one capsule construction depends on."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_CAPSULE_RUNTIME_MANIFEST
    LABEL: ClassVar[str] = "capsule runtime manifest"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "mechanism",
        "mechanism_version",
        "mechanism_path",
        "mechanism_sha256",
        "mechanism_device",
        "mechanism_inode",
        "mechanism_size_bytes",
        "mechanism_mode",
        "mechanism_owner_uid",
        "mechanism_owner_gid",
        "interpreter_path",
        "interpreter_sha256",
        "interpreter_device",
        "interpreter_inode",
        "interpreter_size_bytes",
        "interpreter_mode",
        "interpreter_owner_uid",
        "capsule_init_path",
        "capsule_init_sha256",
        "capsule_init_size_bytes",
        "seccomp_program_sha256",
        "seccomp_machine",
        "seccomp_instruction_count",
        "seccomp_contract",
        "package_source_sha256",
        "package_source_file_count",
        "toolchain_inputs",
        "toolchain_input_manifest_fingerprint",
        "namespace_contract",
        "mount_contract",
        "containment_mechanism",
        "containment_bounds_fingerprint",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "toolchain_inputs": _encode_strings,
        "toolchain_input_manifest_fingerprint": _encode_fp,
        "namespace_contract": _encode_strings,
        "mount_contract": _encode_strings,
        "containment_bounds_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "toolchain_inputs": _decode_strings,
        "toolchain_input_manifest_fingerprint": _decode_fp,
        "namespace_contract": _decode_strings,
        "mount_contract": _decode_strings,
        "containment_bounds_fingerprint": _decode_fp,
    }

    mechanism: str
    mechanism_version: str
    mechanism_path: str
    mechanism_sha256: str
    mechanism_device: int
    mechanism_inode: int
    mechanism_size_bytes: int
    mechanism_mode: int
    mechanism_owner_uid: int
    mechanism_owner_gid: int
    interpreter_path: str
    interpreter_sha256: str
    interpreter_device: int
    interpreter_inode: int
    interpreter_size_bytes: int
    interpreter_mode: int
    interpreter_owner_uid: int
    capsule_init_path: str
    capsule_init_sha256: str
    capsule_init_size_bytes: int
    seccomp_program_sha256: str
    seccomp_machine: str
    seccomp_instruction_count: int
    seccomp_contract: str
    package_source_sha256: str
    package_source_file_count: int
    toolchain_inputs: tuple[str, ...]
    toolchain_input_manifest_fingerprint: Fingerprint
    namespace_contract: tuple[str, ...]
    mount_contract: tuple[str, ...]
    containment_mechanism: str
    containment_bounds_fingerprint: Fingerprint
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "CapsuleRuntimeManifest":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        for name in (
            "mechanism",
            "mechanism_version",
            "mechanism_path",
            "interpreter_path",
            "capsule_init_path",
            "seccomp_machine",
            "package_source_sha256",
            "containment_mechanism",
        ):
            _require_text(getattr(self, name), name, max_bytes=4096)
        _require_text(self.seccomp_contract, "seccomp_contract", max_bytes=2048)
        for name in ("mechanism_sha256", "interpreter_sha256", "capsule_init_sha256", "seccomp_program_sha256", "package_source_sha256"):
            value = getattr(self, name)
            _require_text(value, name, max_bytes=64)
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise ObservationError(f"{name} must be a lowercase hex SHA-256 digest")
        for name in (
            "mechanism_device",
            "mechanism_inode",
            "mechanism_size_bytes",
            "mechanism_mode",
            "mechanism_owner_uid",
            "mechanism_owner_gid",
            "interpreter_device",
            "interpreter_inode",
            "interpreter_size_bytes",
            "interpreter_mode",
            "interpreter_owner_uid",
            "capsule_init_size_bytes",
            "seccomp_instruction_count",
            "package_source_file_count",
        ):
            _require_int(getattr(self, name), name)
        _encode_strings(self.toolchain_inputs)
        _encode_strings(self.namespace_contract)
        _encode_strings(self.mount_contract)
        self.toolchain_input_manifest_fingerprint.validated()
        self.containment_bounds_fingerprint.validated()

    # -- rechecking -----------------------------------------------------------

    def immutable_identity(self) -> dict[str, Any]:
        """Exactly the fields a recheck must find unchanged."""

        return {
            "mechanism_path": self.mechanism_path,
            "mechanism_sha256": self.mechanism_sha256,
            "mechanism_device": self.mechanism_device,
            "mechanism_inode": self.mechanism_inode,
            "mechanism_size_bytes": self.mechanism_size_bytes,
            "mechanism_mode": self.mechanism_mode,
            "mechanism_owner_uid": self.mechanism_owner_uid,
            "interpreter_path": self.interpreter_path,
            "interpreter_sha256": self.interpreter_sha256,
            "interpreter_device": self.interpreter_device,
            "interpreter_inode": self.interpreter_inode,
            "capsule_init_path": self.capsule_init_path,
            "capsule_init_sha256": self.capsule_init_sha256,
            "seccomp_program_sha256": self.seccomp_program_sha256,
            "package_source_sha256": self.package_source_sha256,
        }

    def recheck(self, *, resolver: Callable[[], str] | None = None) -> None:
        """Re-derive every immutable identity and refuse any difference.

        ``resolver`` supplies the path the launcher would be found at *now*, so
        a ``PATH`` entry that shadows the recorded launcher is detected as a
        substitution rather than silently followed.
        """

        if resolver is not None:
            current = resolver()
            if current is None or os.path.realpath(current) != self.mechanism_path:
                raise CapsuleIdentityRefused(
                    f"the capsule mechanism now resolves to {current!r}, not the recorded {self.mechanism_path}"
                )
        current_identity = derive_immutable_identity(
            mechanism_path=self.mechanism_path,
            interpreter_path=self.interpreter_path,
            capsule_init_path=self.capsule_init_path,
        )
        recorded = self.immutable_identity()
        for name, value in current_identity.items():
            if recorded[name] != value:
                raise CapsuleIdentityRefused(
                    f"the capsule runtime manifest no longer matches the host: {name} changed"
                )


def derive_immutable_identity(
    *, mechanism_path: str, interpreter_path: str, capsule_init_path: str
) -> dict[str, Any]:
    """The subset of the manifest a recheck re-derives from the filesystem."""

    from .capsule_seccomp import describe as describe_seccomp  # local: keeps imports acyclic

    mechanism = _hash_file_identity(mechanism_path, "capsule mechanism")
    interpreter = _hash_file_identity(interpreter_path, "capsule interpreter")
    init = _hash_file_identity(capsule_init_path, "in-capsule init")
    source_digest, _ = package_source_identity()
    return {
        "mechanism_path": mechanism.path,
        "mechanism_sha256": mechanism.sha256,
        "mechanism_device": mechanism.device,
        "mechanism_inode": mechanism.inode,
        "mechanism_size_bytes": mechanism.size_bytes,
        "mechanism_mode": mechanism.mode,
        "mechanism_owner_uid": mechanism.owner_uid,
        "interpreter_path": interpreter.path,
        "interpreter_sha256": interpreter.sha256,
        "interpreter_device": interpreter.device,
        "interpreter_inode": interpreter.inode,
        "capsule_init_path": init.path,
        "capsule_init_sha256": init.sha256,
        "seccomp_program_sha256": describe_seccomp()["program_sha256"],
        "package_source_sha256": source_digest,
    }


def build_runtime_manifest(
    *,
    mechanism: str,
    mechanism_version: str,
    mechanism_path: str,
    interpreter_path: str,
    capsule_init_path: str,
    toolchain_inputs: tuple[str, ...],
    namespace_contract: tuple[str, ...],
    mount_contract: tuple[str, ...],
    containment_mechanism: str,
    containment_bounds: dict[str, Any],
) -> CapsuleRuntimeManifest:
    """Derive the complete manifest from the host as it is right now."""

    from .capsule_seccomp import describe as describe_seccomp

    launcher = _hash_file_identity(mechanism_path, "capsule mechanism")
    interpreter = _hash_file_identity(interpreter_path, "capsule interpreter")
    init = _hash_file_identity(capsule_init_path, "in-capsule init")
    seccomp = describe_seccomp()
    source_digest, source_count = package_source_identity()
    described_inputs, inputs_fingerprint = toolchain_input_manifest(toolchain_inputs)
    return CapsuleRuntimeManifest.create(
        mechanism=mechanism,
        mechanism_version=mechanism_version,
        mechanism_path=launcher.path,
        mechanism_sha256=launcher.sha256,
        mechanism_device=launcher.device,
        mechanism_inode=launcher.inode,
        mechanism_size_bytes=launcher.size_bytes,
        mechanism_mode=launcher.mode,
        mechanism_owner_uid=launcher.owner_uid,
        mechanism_owner_gid=launcher.owner_gid,
        interpreter_path=interpreter.path,
        interpreter_sha256=interpreter.sha256,
        interpreter_device=interpreter.device,
        interpreter_inode=interpreter.inode,
        interpreter_size_bytes=interpreter.size_bytes,
        interpreter_mode=interpreter.mode,
        interpreter_owner_uid=interpreter.owner_uid,
        capsule_init_path=init.path,
        capsule_init_sha256=init.sha256,
        capsule_init_size_bytes=init.size_bytes,
        seccomp_program_sha256=str(seccomp["program_sha256"]),
        seccomp_machine=str(seccomp["machine"]),
        seccomp_instruction_count=int(seccomp["instruction_count"]),
        seccomp_contract=str(seccomp["contract"]),
        package_source_sha256=source_digest,
        package_source_file_count=source_count,
        toolchain_inputs=described_inputs,
        toolchain_input_manifest_fingerprint=inputs_fingerprint,
        namespace_contract=namespace_contract,
        mount_contract=mount_contract,
        containment_mechanism=containment_mechanism,
        containment_bounds_fingerprint=fingerprint(
            containment_bounds, domain=f"{SCHEMA_CAPSULE_RUNTIME_MANIFEST}.containment_bounds"
        ),
    )


M2_CAPSULE_IDENTITY_SCHEMAS = {
    CapsuleRuntimeManifest.SCHEMA_ID: m2_schema_descriptor(
        CapsuleRuntimeManifest.SCHEMA_ID,
        "CapsuleRuntimeManifest",
        ("schema_id", "schema_version") + CapsuleRuntimeManifest.FIELDS + ("record_fingerprint",),
    )
}
for _descriptor in M2_CAPSULE_IDENTITY_SCHEMAS.values():
    object.__setattr__(_descriptor, "owning_module", "admissible.paired_runner.capsule_identity")


__all__ = [
    "CAPSULE_RUNTIME_MANIFEST_OBJECT_KIND",
    "CapsuleIdentityRefused",
    "CapsuleRuntimeManifest",
    "FileIdentity",
    "M2_CAPSULE_IDENTITY_SCHEMAS",
    "M2_SCHEMA_VERSION",
    "SCHEMA_CAPSULE_RUNTIME_MANIFEST",
    "build_runtime_manifest",
    "derive_immutable_identity",
    "package_source_identity",
    "toolchain_input_manifest",
]
