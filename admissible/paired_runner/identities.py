"""Run, session, and component identities for the paired specification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import (
    Fingerprint,
    canonical_bytes,
    fingerprint,
    require_exact_keys,
)
from .schemas import (
    CONDITIONS,
    DIRECT,
    GOVERNED,
    SCHEMA_IDENTITY_REFERENCE,
    SCHEMA_RUN_IDENTITY,
    SCHEMA_SESSION_IDENTITY,
    SCHEMA_VERSION,
)


IDENTITY_KINDS = frozenset(
    {
        "model",
        "executable",
        "transport",
        "tool_grammar",
        "environment",
        "dependency_toolchain",
        "filesystem_network_process_policy",
        "evaluator",
        "working_root",
        "scope",
        "prompt",
        "effect_executor",
        "initial_state",
        "task",
    }
)
IDENTITY_SEMANTICS = frozenset({"CONTENT", "INSTANCE"})
_IDENTIFIER_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-")


def _require_identifier(value: Any, label: str, *, max_length: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or value[0] not in _IDENTIFIER_CHARS
        or any(character not in _IDENTIFIER_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be a stable identifier")
    return value


def _require_text(value: Any, label: str, *, max_bytes: int = 256) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} must be non-empty text without NUL")
    if len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{label} exceeds its byte bound")
    return value


def _require_condition(value: Any, label: str = "condition_id") -> str:
    if value not in CONDITIONS:
        raise ValueError(f"{label} must be DIRECT or GOVERNED")
    return value


def _require_fp(value: Any, label: str) -> Fingerprint:
    if not isinstance(value, Fingerprint):
        raise ValueError(f"{label} must be a Fingerprint")
    return value.validated()


@dataclass(frozen=True)
class IdentityReference:
    """A named content or instance identity with a self-describing digest."""

    schema_id: str
    schema_version: int
    kind: str
    name: str
    version: str
    identity_semantics: str
    content_fingerprint: Fingerprint
    identity_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        kind: str,
        name: str,
        version: str,
        material: Any,
        identity_semantics: str = "CONTENT",
    ) -> "IdentityReference":
        if kind not in IDENTITY_KINDS:
            raise ValueError(f"unknown identity kind {kind!r}")
        _require_identifier(name, "identity name")
        _require_text(version, "identity version")
        if identity_semantics not in IDENTITY_SEMANTICS:
            raise ValueError("identity semantics must be CONTENT or INSTANCE")
        content_body = {
            "kind": kind,
            "name": name,
            "version": version,
            "material": material,
        }
        content_fp = fingerprint(
            content_body,
            domain=f"admissible.paired_runner.identity.content.{kind}",
        )
        body = {
            "schema_id": SCHEMA_IDENTITY_REFERENCE,
            "schema_version": SCHEMA_VERSION,
            "kind": kind,
            "name": name,
            "version": version,
            "identity_semantics": identity_semantics,
            "content_fingerprint": content_fp.to_dict(),
        }
        return cls(
            schema_id=SCHEMA_IDENTITY_REFERENCE,
            schema_version=SCHEMA_VERSION,
            kind=kind,
            name=name,
            version=version,
            identity_semantics=identity_semantics,
            content_fingerprint=content_fp,
            identity_fingerprint=fingerprint(
                body, domain=f"{SCHEMA_IDENTITY_REFERENCE}.fingerprint"
            ),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "kind": self.kind,
            "name": self.name,
            "version": self.version,
            "identity_semantics": self.identity_semantics,
            "content_fingerprint": self.content_fingerprint.to_dict(),
        }

    def validated(self) -> "IdentityReference":
        if self.schema_id != SCHEMA_IDENTITY_REFERENCE or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported identity reference schema")
        if self.kind not in IDENTITY_KINDS:
            raise ValueError("unknown identity reference kind")
        _require_identifier(self.name, "identity name")
        _require_text(self.version, "identity version")
        if self.identity_semantics not in IDENTITY_SEMANTICS:
            raise ValueError("unknown identity semantics")
        _require_fp(self.content_fingerprint, "content_fingerprint")
        _require_fp(self.identity_fingerprint, "identity_fingerprint")
        if self.content_fingerprint.domain != f"admissible.paired_runner.identity.content.{self.kind}":
            raise ValueError("identity content fingerprint has the wrong domain")
        if self.identity_fingerprint.domain != f"{SCHEMA_IDENTITY_REFERENCE}.fingerprint":
            raise ValueError("identity reference fingerprint has the wrong domain")
        if fingerprint(self._body(), domain=self.identity_fingerprint.domain) != self.identity_fingerprint:
            raise ValueError("identity reference fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "identity_fingerprint": self.identity_fingerprint.to_dict()}

    def normative_dict(self) -> dict[str, Any]:
        """Return content identity fields without the derived object digest."""

        return self._body()

    @classmethod
    def from_dict(cls, data: Any) -> "IdentityReference":
        require_exact_keys(
            data,
            {
                "schema_id",
                "schema_version",
                "kind",
                "name",
                "version",
                "identity_semantics",
                "content_fingerprint",
                "identity_fingerprint",
            },
            label="identity reference",
        )
        return cls(
            schema_id=data["schema_id"],
            schema_version=data["schema_version"],
            kind=data["kind"],
            name=data["name"],
            version=data["version"],
            identity_semantics=data["identity_semantics"],
            content_fingerprint=Fingerprint.from_dict(data["content_fingerprint"], label="content_fingerprint"),
            identity_fingerprint=Fingerprint.from_dict(data["identity_fingerprint"], label="identity_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class RunIdentity:
    """An instance identity bound to exactly one experiment and condition."""

    schema_id: str
    schema_version: int
    experiment_id: str
    condition_id: str
    run_id: str
    identity_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, experiment_id: str, condition_id: str, run_id: str) -> "RunIdentity":
        _require_identifier(experiment_id, "experiment_id")
        _require_condition(condition_id)
        _require_identifier(run_id, "run_id")
        body = {
            "schema_id": SCHEMA_RUN_IDENTITY,
            "schema_version": SCHEMA_VERSION,
            "experiment_id": experiment_id,
            "condition_id": condition_id,
            "run_id": run_id,
        }
        return cls(
            **body,
            identity_fingerprint=fingerprint(
                body, domain=f"{SCHEMA_RUN_IDENTITY}.fingerprint"
            ),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "condition_id": self.condition_id,
            "run_id": self.run_id,
        }

    def validated(self) -> "RunIdentity":
        if self.schema_id != SCHEMA_RUN_IDENTITY or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported run identity schema")
        _require_identifier(self.experiment_id, "experiment_id")
        _require_condition(self.condition_id)
        _require_identifier(self.run_id, "run_id")
        _require_fp(self.identity_fingerprint, "run identity fingerprint")
        if self.identity_fingerprint.domain != f"{SCHEMA_RUN_IDENTITY}.fingerprint":
            raise ValueError("run identity fingerprint has the wrong domain")
        if fingerprint(self._body(), domain=self.identity_fingerprint.domain) != self.identity_fingerprint:
            raise ValueError("run identity fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "identity_fingerprint": self.identity_fingerprint.to_dict()}

    def normative_dict(self) -> dict[str, Any]:
        return self._body()

    @classmethod
    def from_dict(cls, data: Any) -> "RunIdentity":
        require_exact_keys(
            data,
            {
                "schema_id",
                "schema_version",
                "experiment_id",
                "condition_id",
                "run_id",
                "identity_fingerprint",
            },
            label="run identity",
        )
        return cls(
            schema_id=data["schema_id"],
            schema_version=data["schema_version"],
            experiment_id=data["experiment_id"],
            condition_id=data["condition_id"],
            run_id=data["run_id"],
            identity_fingerprint=Fingerprint.from_dict(data["identity_fingerprint"], label="run identity fingerprint"),
        ).validated()


@dataclass(frozen=True)
class SessionIdentity:
    """A continuation-capable session that cannot cross run or condition."""

    schema_id: str
    schema_version: int
    experiment_id: str
    condition_id: str
    run_id: str
    session_id: str
    continuation_index: int
    predecessor_session_id: str | None
    identity_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        run: RunIdentity,
        session_id: str,
        continuation_index: int = 0,
        predecessor_session_id: str | None = None,
    ) -> "SessionIdentity":
        run.validated()
        _require_identifier(session_id, "session_id")
        if isinstance(continuation_index, bool) or not isinstance(continuation_index, int) or continuation_index < 0:
            raise ValueError("continuation_index must be a non-negative integer")
        if continuation_index == 0 and predecessor_session_id is not None:
            raise ValueError("the first session cannot have a predecessor")
        if continuation_index > 0:
            _require_identifier(predecessor_session_id, "predecessor_session_id")
            if predecessor_session_id == session_id:
                raise ValueError("a session cannot precede itself")
        body = {
            "schema_id": SCHEMA_SESSION_IDENTITY,
            "schema_version": SCHEMA_VERSION,
            "experiment_id": run.experiment_id,
            "condition_id": run.condition_id,
            "run_id": run.run_id,
            "session_id": session_id,
            "continuation_index": continuation_index,
            "predecessor_session_id": predecessor_session_id,
        }
        return cls(
            **body,
            identity_fingerprint=fingerprint(
                body, domain=f"{SCHEMA_SESSION_IDENTITY}.fingerprint"
            ),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "condition_id": self.condition_id,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "continuation_index": self.continuation_index,
            "predecessor_session_id": self.predecessor_session_id,
        }

    def validated(self) -> "SessionIdentity":
        if self.schema_id != SCHEMA_SESSION_IDENTITY or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported session identity schema")
        _require_identifier(self.experiment_id, "experiment_id")
        _require_condition(self.condition_id)
        _require_identifier(self.run_id, "run_id")
        _require_identifier(self.session_id, "session_id")
        if isinstance(self.continuation_index, bool) or not isinstance(self.continuation_index, int) or self.continuation_index < 0:
            raise ValueError("continuation_index must be a non-negative integer")
        if self.continuation_index == 0 and self.predecessor_session_id is not None:
            raise ValueError("the first session cannot have a predecessor")
        if self.continuation_index > 0:
            _require_identifier(self.predecessor_session_id, "predecessor_session_id")
            if self.predecessor_session_id == self.session_id:
                raise ValueError("a session cannot precede itself")
        _require_fp(self.identity_fingerprint, "session identity fingerprint")
        if self.identity_fingerprint.domain != f"{SCHEMA_SESSION_IDENTITY}.fingerprint":
            raise ValueError("session identity fingerprint has the wrong domain")
        if fingerprint(self._body(), domain=self.identity_fingerprint.domain) != self.identity_fingerprint:
            raise ValueError("session identity fingerprint mismatch")
        return self

    def validate_for_run(self, run: RunIdentity) -> "SessionIdentity":
        run.validated()
        if (
            self.experiment_id != run.experiment_id
            or self.condition_id != run.condition_id
            or self.run_id != run.run_id
        ):
            raise ValueError("session identity belongs to another run or condition")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "identity_fingerprint": self.identity_fingerprint.to_dict()}

    def normative_dict(self) -> dict[str, Any]:
        return self._body()

    @classmethod
    def from_dict(cls, data: Any) -> "SessionIdentity":
        require_exact_keys(
            data,
            {
                "schema_id",
                "schema_version",
                "experiment_id",
                "condition_id",
                "run_id",
                "session_id",
                "continuation_index",
                "predecessor_session_id",
                "identity_fingerprint",
            },
            label="session identity",
        )
        return cls(
            schema_id=data["schema_id"],
            schema_version=data["schema_version"],
            experiment_id=data["experiment_id"],
            condition_id=data["condition_id"],
            run_id=data["run_id"],
            session_id=data["session_id"],
            continuation_index=data["continuation_index"],
            predecessor_session_id=data["predecessor_session_id"],
            identity_fingerprint=Fingerprint.from_dict(data["identity_fingerprint"], label="session identity fingerprint"),
        ).validated()


def canonical_identity_bytes(identity: IdentityReference | RunIdentity | SessionIdentity) -> bytes:
    """Expose canonical identity bytes for tests and future archival code."""

    return canonical_bytes(identity.to_dict())
