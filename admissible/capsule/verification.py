"""Independent checkpoint and behavioral verification.

Two distinct concerns are kept structurally separate here:

- checkpoint verification: does the accepted intake tree exist, unmodified,
  in the shape the checkpoint identity expects?
- behavioral verification: does the accepted material actually behave
  correctly, per a frozen behavioral verifier?

A checkpoint PASS must never imply behavioral acceptance. This module does
not merely document that rule — it enforces it structurally:
`IndependentVerificationResult` requires both results to reference distinct
`VerificationCopy` instances (different copy identities), so a behavioral
verdict can never be synthesized from, or silently reuse, the checkpoint's
copy or verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from admissible.capsule.common import (
    fingerprint,
    require_bool,
    require_exact_keys,
    require_identifier,
    require_sha256,
    require_strict_int,
)


CHECKPOINT_IDENTITY_SCHEMA_VERSION = "admissible_capsule_checkpoint_identity_v1"
BEHAVIORAL_VERIFIER_IDENTITY_SCHEMA_VERSION = "admissible_capsule_behavioral_verifier_identity_v1"
VERIFICATION_COPY_SCHEMA_VERSION = "admissible_capsule_verification_copy_v1"
COMMAND_CAPTURE_SCHEMA_VERSION = "admissible_capsule_command_capture_v1"


class CheckpointRefusalCode(str, Enum):
    """Precise, closed refusal vocabulary for checkpoint verification."""

    NONZERO_EXIT = "CHECKPOINT_NONZERO_EXIT"
    TIMEOUT = "CHECKPOINT_TIMEOUT"
    OUTPUT_TRUNCATED_UNSAFE = "CHECKPOINT_OUTPUT_TRUNCATED_UNSAFE"
    TREE_MUTATED = "CHECKPOINT_TREE_MUTATED"
    COPY_IDENTITY_MISMATCH = "CHECKPOINT_COPY_IDENTITY_MISMATCH"


class BehaviorRefusalCode(str, Enum):
    """Precise, closed refusal vocabulary for behavioral verification."""

    NONZERO_EXIT = "BEHAVIOR_NONZERO_EXIT"
    TIMEOUT = "BEHAVIOR_TIMEOUT"
    ASSERTION_FAILED = "BEHAVIOR_ASSERTION_FAILED"
    VERIFIER_CRASHED = "BEHAVIOR_VERIFIER_CRASHED"
    OUTPUT_TRUNCATED_UNSAFE = "BEHAVIOR_OUTPUT_TRUNCATED_UNSAFE"


@dataclass(frozen=True)
class CheckpointIdentity:
    """The frozen identity a checkpoint verification run is bound to."""

    schema_version: str
    tree_hash: str
    identity_fingerprint: str

    @classmethod
    def create(cls, *, tree_hash: str) -> "CheckpointIdentity":
        body = {"schema_version": CHECKPOINT_IDENTITY_SCHEMA_VERSION, "tree_hash": tree_hash}
        return cls(
            schema_version=CHECKPOINT_IDENTITY_SCHEMA_VERSION,
            tree_hash=tree_hash,
            identity_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "tree_hash": self.tree_hash}

    def validated(self) -> "CheckpointIdentity":
        if self.schema_version != CHECKPOINT_IDENTITY_SCHEMA_VERSION:
            raise ValueError("unsupported checkpoint identity schema")
        require_sha256(self.tree_hash, "tree_hash")
        require_sha256(self.identity_fingerprint, "identity_fingerprint")
        if fingerprint(self._body()) != self.identity_fingerprint:
            raise ValueError("checkpoint identity fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["identity_fingerprint"] = self.identity_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CheckpointIdentity":
        require_exact_keys(data, {"schema_version", "tree_hash", "identity_fingerprint"}, "checkpoint identity")
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class BehavioralVerifierIdentity:
    """The frozen identity of the behavioral verifier itself.

    Binding a verdict to `verifier_source_sha256` prevents silently swapping
    in a different (weaker) verifier between runs.
    """

    schema_version: str
    verifier_source_sha256: str
    identity_fingerprint: str

    @classmethod
    def create(cls, *, verifier_source_sha256: str) -> "BehavioralVerifierIdentity":
        body = {
            "schema_version": BEHAVIORAL_VERIFIER_IDENTITY_SCHEMA_VERSION,
            "verifier_source_sha256": verifier_source_sha256,
        }
        return cls(
            schema_version=BEHAVIORAL_VERIFIER_IDENTITY_SCHEMA_VERSION,
            verifier_source_sha256=verifier_source_sha256,
            identity_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "verifier_source_sha256": self.verifier_source_sha256,
        }

    def validated(self) -> "BehavioralVerifierIdentity":
        if self.schema_version != BEHAVIORAL_VERIFIER_IDENTITY_SCHEMA_VERSION:
            raise ValueError("unsupported behavioral verifier identity schema")
        require_sha256(self.verifier_source_sha256, "verifier_source_sha256")
        require_sha256(self.identity_fingerprint, "identity_fingerprint")
        if fingerprint(self._body()) != self.identity_fingerprint:
            raise ValueError("behavioral verifier identity fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["identity_fingerprint"] = self.identity_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BehavioralVerifierIdentity":
        require_exact_keys(
            data,
            {"schema_version", "verifier_source_sha256", "identity_fingerprint"},
            "behavioral verifier identity",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class VerificationCopy:
    """A separate, materially independent copy used for one verification pass.

    `purpose` distinguishes a checkpoint copy from a behavior copy; the two
    must never share a `copy_id` or `root_fingerprint` — see
    `require_independent_copies`.
    """

    schema_version: str
    copy_id: str
    purpose: str
    root_fingerprint: str
    copy_fingerprint: str

    @classmethod
    def create(cls, *, copy_id: str, purpose: str, root_fingerprint: str) -> "VerificationCopy":
        if purpose not in {"checkpoint", "behavior"}:
            raise ValueError("verification copy purpose must be checkpoint or behavior")
        body = {
            "schema_version": VERIFICATION_COPY_SCHEMA_VERSION,
            "copy_id": copy_id,
            "purpose": purpose,
            "root_fingerprint": root_fingerprint,
        }
        return cls(
            schema_version=VERIFICATION_COPY_SCHEMA_VERSION,
            copy_id=copy_id,
            purpose=purpose,
            root_fingerprint=root_fingerprint,
            copy_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "copy_id": self.copy_id,
            "purpose": self.purpose,
            "root_fingerprint": self.root_fingerprint,
        }

    def validated(self) -> "VerificationCopy":
        if self.schema_version != VERIFICATION_COPY_SCHEMA_VERSION:
            raise ValueError("unsupported verification copy schema")
        require_identifier(self.copy_id, "copy_id")
        if self.purpose not in {"checkpoint", "behavior"}:
            raise ValueError("verification copy purpose must be checkpoint or behavior")
        require_sha256(self.root_fingerprint, "root_fingerprint")
        require_sha256(self.copy_fingerprint, "copy_fingerprint")
        if fingerprint(self._body()) != self.copy_fingerprint:
            raise ValueError("verification copy fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["copy_fingerprint"] = self.copy_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationCopy":
        require_exact_keys(
            data,
            {"schema_version", "copy_id", "purpose", "root_fingerprint", "copy_fingerprint"},
            "verification copy",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class CommandCapture:
    """stdout/stderr/exit-code/timeout/output-limit evidence for one command run."""

    schema_version: str
    argv: tuple[str, ...]
    exit_code: int | None
    timed_out: bool
    stdout_sha256: str
    stderr_sha256: str
    stdout_truncated: bool
    stderr_truncated: bool

    @classmethod
    def create(
        cls,
        *,
        argv: tuple[str, ...],
        exit_code: int | None,
        timed_out: bool,
        stdout_sha256: str,
        stderr_sha256: str,
        stdout_truncated: bool,
        stderr_truncated: bool,
    ) -> "CommandCapture":
        return cls(
            schema_version=COMMAND_CAPTURE_SCHEMA_VERSION,
            argv=argv,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout_sha256=stdout_sha256,
            stderr_sha256=stderr_sha256,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        ).validated()

    def validated(self) -> "CommandCapture":
        if self.schema_version != COMMAND_CAPTURE_SCHEMA_VERSION:
            raise ValueError("unsupported command capture schema")
        if not isinstance(self.argv, tuple) or not self.argv:
            raise ValueError("command capture argv must be a non-empty tuple")
        if self.exit_code is not None:
            require_strict_int(self.exit_code, "exit_code", minimum=-2**31, maximum=2**31 - 1)
        require_bool(self.timed_out, "timed_out")
        require_sha256(self.stdout_sha256, "stdout_sha256")
        require_sha256(self.stderr_sha256, "stderr_sha256")
        require_bool(self.stdout_truncated, "stdout_truncated")
        require_bool(self.stderr_truncated, "stderr_truncated")
        if self.timed_out and self.exit_code is not None:
            raise ValueError("a timed-out command cannot also report a clean exit code")
        return self

    @property
    def output_safe(self) -> bool:
        return not self.stdout_truncated and not self.stderr_truncated

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CommandCapture":
        require_exact_keys(
            data,
            {
                "schema_version",
                "argv",
                "exit_code",
                "timed_out",
                "stdout_sha256",
                "stderr_sha256",
                "stdout_truncated",
                "stderr_truncated",
            },
            "command capture",
        )
        if not isinstance(data["argv"], list):
            raise ValueError("command capture argv must be an array")
        return cls(**{**data, "argv": tuple(data["argv"])}).validated()


@dataclass(frozen=True)
class ByteHashPair:
    """Before/after byte hashes bracketing a verification command run."""

    before_hash: str
    after_hash: str

    def validated(self) -> "ByteHashPair":
        require_sha256(self.before_hash, "before_hash")
        require_sha256(self.after_hash, "after_hash")
        return self

    @property
    def mutated(self) -> bool:
        return self.before_hash != self.after_hash

    def to_dict(self) -> dict[str, str]:
        return {"before_hash": self.before_hash, "after_hash": self.after_hash}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ByteHashPair":
        require_exact_keys(data, {"before_hash", "after_hash"}, "byte hash pair")
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class CheckpointResult:
    identity: CheckpointIdentity
    copy: VerificationCopy
    capture: CommandCapture
    byte_hashes: ByteHashPair
    passed: bool
    refusal_code: CheckpointRefusalCode | None

    def validated(self) -> "CheckpointResult":
        self.identity.validated()
        self.copy.validated()
        if self.copy.purpose != "checkpoint":
            raise ValueError("checkpoint result must use a checkpoint-purpose copy")
        self.capture.validated()
        self.byte_hashes.validated()
        require_bool(self.passed, "passed")
        if self.passed and self.refusal_code is not None:
            raise ValueError("a passed checkpoint cannot carry a refusal code")
        if not self.passed and self.refusal_code is None:
            raise ValueError("a refused checkpoint requires a refusal code")
        if self.passed and (
            self.capture.exit_code != 0
            or self.capture.timed_out
            or not self.capture.output_safe
            or self.byte_hashes.mutated
        ):
            raise ValueError("passed checkpoint evidence contradicts its captured process result")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "copy": self.copy.to_dict(),
            "capture": self.capture.to_dict(),
            "byte_hashes": self.byte_hashes.to_dict(),
            "passed": self.passed,
            "refusal_code": self.refusal_code.value if self.refusal_code is not None else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CheckpointResult":
        require_exact_keys(
            data, {"identity", "copy", "capture", "byte_hashes", "passed", "refusal_code"}, "checkpoint result"
        )
        return cls(
            identity=CheckpointIdentity.from_dict(data["identity"]),
            copy=VerificationCopy.from_dict(data["copy"]),
            capture=CommandCapture.from_dict(data["capture"]),
            byte_hashes=ByteHashPair.from_dict(data["byte_hashes"]),
            passed=data["passed"],
            refusal_code=(CheckpointRefusalCode(data["refusal_code"]) if data["refusal_code"] is not None else None),
        ).validated()


@dataclass(frozen=True)
class BehaviorResult:
    identity: BehavioralVerifierIdentity
    copy: VerificationCopy
    capture: CommandCapture
    byte_hashes: ByteHashPair
    passed: bool
    refusal_code: BehaviorRefusalCode | None

    def validated(self) -> "BehaviorResult":
        self.identity.validated()
        self.copy.validated()
        if self.copy.purpose != "behavior":
            raise ValueError("behavior result must use a behavior-purpose copy")
        self.capture.validated()
        self.byte_hashes.validated()
        require_bool(self.passed, "passed")
        if self.passed and self.refusal_code is not None:
            raise ValueError("a passed behavioral run cannot carry a refusal code")
        if not self.passed and self.refusal_code is None:
            raise ValueError("a refused behavioral run requires a refusal code")
        if self.passed and (self.capture.exit_code != 0 or self.capture.timed_out or not self.capture.output_safe):
            raise ValueError("passed behavioral evidence contradicts its captured process result")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "copy": self.copy.to_dict(),
            "capture": self.capture.to_dict(),
            "byte_hashes": self.byte_hashes.to_dict(),
            "passed": self.passed,
            "refusal_code": self.refusal_code.value if self.refusal_code is not None else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BehaviorResult":
        require_exact_keys(
            data, {"identity", "copy", "capture", "byte_hashes", "passed", "refusal_code"}, "behavior result"
        )
        return cls(
            identity=BehavioralVerifierIdentity.from_dict(data["identity"]),
            copy=VerificationCopy.from_dict(data["copy"]),
            capture=CommandCapture.from_dict(data["capture"]),
            byte_hashes=ByteHashPair.from_dict(data["byte_hashes"]),
            passed=data["passed"],
            refusal_code=(BehaviorRefusalCode(data["refusal_code"]) if data["refusal_code"] is not None else None),
        ).validated()


def require_independent_copies(checkpoint_copy: VerificationCopy, behavior_copy: VerificationCopy) -> None:
    """Fail closed unless checkpoint and behavior ran on materially separate copies."""

    checkpoint_copy.validated()
    behavior_copy.validated()
    if checkpoint_copy.purpose != "checkpoint" or behavior_copy.purpose != "behavior":
        raise ValueError("independence check requires one checkpoint copy and one behavior copy")
    if checkpoint_copy.copy_id == behavior_copy.copy_id:
        raise ValueError("checkpoint and behavior verification must not share a copy identity")
    if checkpoint_copy.root_fingerprint != behavior_copy.root_fingerprint:
        raise ValueError("checkpoint and behavior copies must observe the same accepted material")


@dataclass(frozen=True)
class IndependentVerificationResult:
    """The combined, structurally-independent outcome of both verification passes.

    A checkpoint PASS never implies behavioral acceptance: `behavior` is a
    fully separate `BehaviorResult` bound to its own `VerificationCopy`, and
    `admissible` requires both to explicitly PASS.
    """

    checkpoint: CheckpointResult
    behavior: BehaviorResult | None

    def validated(self) -> "IndependentVerificationResult":
        self.checkpoint.validated()
        if self.behavior is not None:
            self.behavior.validated()
            require_independent_copies(self.checkpoint.copy, self.behavior.copy)
        return self

    @property
    def admissible(self) -> bool:
        return self.checkpoint.passed and self.behavior is not None and self.behavior.passed
