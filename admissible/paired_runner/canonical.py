"""Canonical bytes and domain-separated fingerprints for the paired spec.

The implementation intentionally accepts a small JSON value algebra instead
of relying on a serializer's implicit coercions.  Persisted records use the
canonical bytes returned here; typed objects perform the strict field checks
before calling this module.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Iterator


MAX_SAFE_INTEGER = 2**63 - 1
MIN_SAFE_INTEGER = -(2**63)
_DOMAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_FRAME_PREFIX = b"admissible.paired_runner.fingerprint.v1\0"


class CanonicalizationError(ValueError):
    """The value cannot be represented by the M1 canonical contract."""


class DuplicateKeyError(CanonicalizationError):
    """A raw JSON object contains a duplicate key."""


class NonCanonicalEncodingError(CanonicalizationError):
    """Raw JSON is valid but is not the one canonical byte encoding."""


def _validate_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"{path}: integer exceeds signed 64-bit range")
        return
    if isinstance(value, float):
        raise CanonicalizationError(
            f"{path}: floating-point values are forbidden; use scaled integers"
        )
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise CanonicalizationError(f"{path}: string is not valid UTF-8") from error
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _validate_value(item, f"{path}.{key}")
        return
    raise CanonicalizationError(
        f"{path}: unsupported value type {type(value).__name__}; no implicit coercion"
    )


def canonical_bytes(value: Any) -> bytes:
    """Return the sole canonical UTF-8 JSON encoding for *value*.

    Object keys are sorted lexicographically by Python's Unicode code-point
    ordering, arrays retain their normative order, separators contain no
    insignificant whitespace, and all floating-point/non-JSON values are
    rejected.  The UTF-8 encode is explicit so locale and environment cannot
    influence the result.
    """

    _validate_value(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CanonicalizationError("value has no canonical UTF-8 JSON encoding") from error


def _reject_constant(token: str) -> None:
    raise CanonicalizationError(f"non-finite numeric token {token!r} is forbidden")


def _parse_int(token: str) -> int:
    value = int(token, 10)
    if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise CanonicalizationError("integer exceeds signed 64-bit range")
    return value


def _reject_float(token: str) -> float:
    raise CanonicalizationError(
        f"floating-point token {token!r} is forbidden; use scaled integers"
    )


def strict_json_loads(data: bytes | str, *, label: str = "JSON") -> Any:
    """Parse JSON without duplicate keys, non-finite values, or wide integers."""

    if isinstance(data, str):
        try:
            raw = data.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise CanonicalizationError(f"{label} is not valid UTF-8") from error
    elif isinstance(data, bytes):
        raw = data
    else:
        raise CanonicalizationError(f"{label} must be bytes or str")

    def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateKeyError(f"{label} contains duplicate object key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(
            raw,
            object_pairs_hook=closed_object,
            parse_int=_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except DuplicateKeyError:
        raise
    except CanonicalizationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanonicalizationError(f"invalid {label}") from error


def parse_canonical_json(data: bytes | str, *, label: str = "JSON") -> Any:
    """Parse and require that *data* is byte-for-byte canonical JSON."""

    if isinstance(data, str):
        raw = data.encode("utf-8", "strict")
    elif isinstance(data, bytes):
        raw = data
    else:
        raise CanonicalizationError(f"{label} must be bytes or str")
    value = strict_json_loads(raw, label=label)
    if canonical_bytes(value) != raw:
        raise NonCanonicalEncodingError(f"{label} is not canonically encoded")
    return value


def _validate_domain(domain: str) -> str:
    if not isinstance(domain, str) or not _DOMAIN.fullmatch(domain):
        raise CanonicalizationError("fingerprint domain must be a stable identifier")
    return domain


def _framed_digest(data: bytes, domain: str) -> str:
    domain_bytes = _validate_domain(domain).encode("ascii")
    framed = (
        _FRAME_PREFIX
        + len(domain_bytes).to_bytes(2, "big")
        + domain_bytes
        + len(data).to_bytes(8, "big")
        + data
    )
    return hashlib.sha256(framed).hexdigest()


@dataclass(frozen=True)
class Fingerprint:
    """A self-describing SHA-256 content or instance fingerprint."""

    algorithm: str
    domain: str
    value: str

    def validated(self) -> "Fingerprint":
        if self.algorithm != "sha256":
            raise CanonicalizationError("only sha256 fingerprints are supported")
        _validate_domain(self.domain)
        if (
            not isinstance(self.value, str)
            or len(self.value) != 64
            or self.value != self.value.lower()
            or any(character not in "0123456789abcdef" for character in self.value)
        ):
            raise CanonicalizationError("fingerprint value must be lowercase SHA-256")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {
            "algorithm": self.algorithm,
            "domain": self.domain,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, value: Any, *, label: str = "fingerprint") -> "Fingerprint":
        if not isinstance(value, dict) or set(value) != {"algorithm", "domain", "value"}:
            raise CanonicalizationError(f"{label} has unknown, missing, or extra fields")
        return cls(
            algorithm=value["algorithm"],
            domain=value["domain"],
            value=value["value"],
        ).validated()


def fingerprint(value: Any, *, domain: str) -> Fingerprint:
    """Fingerprint a canonical JSON value with explicit domain separation."""

    data = canonical_bytes(value)
    return Fingerprint("sha256", _validate_domain(domain), _framed_digest(data, domain)).validated()


def fingerprint_bytes(data: bytes, *, domain: str) -> Fingerprint:
    """Fingerprint exact bytes by first placing them in a canonical hex object."""

    if not isinstance(data, bytes):
        raise CanonicalizationError("fingerprint_bytes requires bytes")
    return fingerprint({"bytes_hex": data.hex()}, domain=domain)


def require_exact_keys(value: Any, keys: set[str], *, label: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        present = set(value) if isinstance(value, dict) else set()
        missing = sorted(keys - present)
        extra = sorted(present - keys)
        raise CanonicalizationError(
            f"{label} fields are not exact (missing={missing}, extra={extra})"
        )


def iter_field_paths(value: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Yield deterministic leaf paths for parity diagnostics."""

    if isinstance(value, dict):
        for key in sorted(value):
            path = f"{prefix}.{key}" if prefix else key
            yield from iter_field_paths(value[key], path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_field_paths(item, f"{prefix}[{index}]")
    else:
        yield prefix, value


def is_canonical_json(data: bytes | str) -> bool:
    try:
        parse_canonical_json(data)
    except (CanonicalizationError, UnicodeEncodeError):
        return False
    return True
