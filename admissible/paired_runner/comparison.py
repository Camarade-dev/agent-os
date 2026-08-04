"""Deterministic, fail-closed comparison of two condition specifications."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import (
    Fingerprint,
    canonical_bytes,
    fingerprint,
    iter_field_paths,
    parse_canonical_json,
    require_exact_keys,
)
from .schemas import SCHEMA_PARITY_REPORT, SCHEMA_VERSION
from .specification import AllowedConditionDifferences, ExperimentSpecification
from .schemas import DIRECT, GOVERNED


def _report_fp(body: dict[str, Any]) -> Fingerprint:
    return fingerprint(body, domain=f"{SCHEMA_PARITY_REPORT}.fingerprint")


@dataclass(frozen=True)
class ParityMismatch:
    path: str
    category: str
    left_value: Any
    right_value: Any

    def to_dict(self) -> dict[str, Any]:
        if not isinstance(self.path, str) or not self.path:
            raise ValueError("parity mismatch path must be non-empty")
        if self.category not in {"UNAUTHORIZED_DIFFERENCE", "PAIRING_ERROR", "MALFORMED_INPUT"}:
            raise ValueError("unknown parity mismatch category")
        # Validate values without coercing them.  This also rejects NaN and
        # non-JSON values in a report produced from a malformed input.
        canonical_bytes({"left": self.left_value, "right": self.right_value})
        return {
            "path": self.path,
            "category": self.category,
            "left_value": self.left_value,
            "right_value": self.right_value,
        }


@dataclass(frozen=True)
class ParityReport:
    schema_id: str
    schema_version: int
    passed: bool
    refusal_code: str
    experiment_id: str | None
    condition_ids: tuple[str, ...]
    mismatches: tuple[ParityMismatch, ...]
    normalization_paths: tuple[str, ...]
    report_fingerprint: Fingerprint

    @classmethod
    def build(
        cls,
        *,
        passed: bool,
        refusal_code: str,
        experiment_id: str | None,
        condition_ids: tuple[str, ...],
        mismatches: tuple[ParityMismatch, ...],
        normalization_paths: tuple[str, ...],
    ) -> "ParityReport":
        if tuple(sorted(condition_ids)) != condition_ids:
            raise ValueError("condition_ids must be sorted for deterministic reports")
        if tuple(sorted(normalization_paths)) != normalization_paths:
            raise ValueError("normalization paths must be sorted for deterministic reports")
        body = {
            "schema_id": SCHEMA_PARITY_REPORT,
            "schema_version": SCHEMA_VERSION,
            "passed": passed,
            "refusal_code": refusal_code,
            "experiment_id": experiment_id,
            "condition_ids": list(condition_ids),
            "mismatches": [item.to_dict() for item in mismatches],
            "normalization_paths": list(normalization_paths),
        }
        return cls(
            schema_id=SCHEMA_PARITY_REPORT,
            schema_version=SCHEMA_VERSION,
            passed=passed,
            refusal_code=refusal_code,
            experiment_id=experiment_id,
            condition_ids=condition_ids,
            mismatches=mismatches,
            normalization_paths=normalization_paths,
            report_fingerprint=_report_fp(body),
        ).validated()

    @classmethod
    def refused(
        cls,
        *,
        code: str,
        path: str = "$",
        left_value: Any = None,
        right_value: Any = None,
        experiment_id: str | None = None,
        condition_ids: tuple[str, ...] = (),
        normalization_paths: tuple[str, ...] = (),
    ) -> "ParityReport":
        mismatch = ParityMismatch(path, "MALFORMED_INPUT" if code.startswith("MALFORMED") else "PAIRING_ERROR", left_value, right_value)
        return cls.build(
            passed=False,
            refusal_code=code,
            experiment_id=experiment_id,
            condition_ids=tuple(sorted(condition_ids)),
            mismatches=(mismatch,),
            normalization_paths=tuple(sorted(normalization_paths)),
        )

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "passed": self.passed,
            "refusal_code": self.refusal_code,
            "experiment_id": self.experiment_id,
            "condition_ids": list(self.condition_ids),
            "mismatches": [item.to_dict() for item in self.mismatches],
            "normalization_paths": list(self.normalization_paths),
        }

    def validated(self) -> "ParityReport":
        if self.schema_id != SCHEMA_PARITY_REPORT or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported parity report schema")
        if not isinstance(self.passed, bool):
            raise ValueError("parity report passed must be boolean")
        if not isinstance(self.refusal_code, str) or not self.refusal_code:
            raise ValueError("parity refusal code must be non-empty")
        if tuple(sorted(self.condition_ids)) != self.condition_ids:
            raise ValueError("parity condition IDs are not deterministic")
        if tuple(sorted(self.normalization_paths)) != self.normalization_paths:
            raise ValueError("parity normalization paths are not deterministic")
        for mismatch in self.mismatches:
            mismatch.to_dict()
        if self.passed and (self.refusal_code != "NONE" or self.mismatches):
            raise ValueError("a passing parity report cannot contain refusal or mismatches")
        if not self.passed and self.refusal_code == "NONE":
            raise ValueError("a refused parity report requires a refusal code")
        if _report_fp(self._body()) != self.report_fingerprint:
            raise ValueError("parity report fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "report_fingerprint": self.report_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "ParityReport":
        fields = {
            "schema_id", "schema_version", "passed", "refusal_code", "experiment_id", "condition_ids",
            "mismatches", "normalization_paths", "report_fingerprint",
        }
        require_exact_keys(data, fields, label="parity report")
        if data["schema_id"] != SCHEMA_PARITY_REPORT or data["schema_version"] != SCHEMA_VERSION:
            raise ValueError("unsupported parity report schema")
        if not isinstance(data["condition_ids"], list) or not isinstance(data["normalization_paths"], list):
            raise ValueError("parity arrays must be arrays")
        mismatches: list[ParityMismatch] = []
        for raw in data["mismatches"]:
            require_exact_keys(raw, {"path", "category", "left_value", "right_value"}, label="parity mismatch")
            mismatches.append(ParityMismatch(raw["path"], raw["category"], raw["left_value"], raw["right_value"]))
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], passed=data["passed"],
            refusal_code=data["refusal_code"], experiment_id=data["experiment_id"],
            condition_ids=tuple(data["condition_ids"]), mismatches=tuple(mismatches),
            normalization_paths=tuple(data["normalization_paths"]),
            report_fingerprint=Fingerprint.from_dict(data["report_fingerprint"], label="report_fingerprint"),
        ).validated()


class ParityRefused(ValueError):
    """Raised by ``require_parity`` when the mechanical gate refuses."""

    def __init__(self, report: ParityReport):
        self.report = report
        super().__init__(f"paired parity refused: {report.refusal_code}")


def _coerce_spec(value: Any, label: str) -> ExperimentSpecification:
    if isinstance(value, ExperimentSpecification):
        return value.validated()
    if isinstance(value, (bytes, str)):
        parsed = parse_canonical_json(value, label=label)
        return ExperimentSpecification.from_dict(parsed)
    if isinstance(value, dict):
        # A mapping has no original byte order, but strict typed validation and
        # canonical re-serialization still reject non-JSON values/coercions.
        canonical_bytes(value)
        return ExperimentSpecification.from_dict(value)
    raise ValueError(f"{label} must be an ExperimentSpecification or canonical JSON")


def _coerce_manifest(value: Any) -> AllowedConditionDifferences:
    if isinstance(value, AllowedConditionDifferences):
        return value.validated()
    if isinstance(value, (bytes, str)):
        return AllowedConditionDifferences.from_dict(parse_canonical_json(value, label="difference manifest"))
    if isinstance(value, dict):
        canonical_bytes(value)
        return AllowedConditionDifferences.from_dict(value)
    raise ValueError("difference manifest has an unsupported type")


def _compare_values(
    left: Any,
    right: Any,
    path: str,
    allowed_paths: frozenset[str],
    output: list[ParityMismatch],
) -> None:
    if path in allowed_paths:
        return
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            child_path = f"{path}.{key}" if path else key
            if key not in left or key not in right:
                output.append(
                    ParityMismatch(child_path, "UNAUTHORIZED_DIFFERENCE", left.get(key), right.get(key))
                )
            else:
                _compare_values(left[key], right[key], child_path, allowed_paths, output)
        return
    if isinstance(left, list) and isinstance(right, list):
        if left != right:
            output.append(ParityMismatch(path, "UNAUTHORIZED_DIFFERENCE", left, right))
        return
    if left != right:
        output.append(ParityMismatch(path, "UNAUTHORIZED_DIFFERENCE", left, right))


def check_parity(
    direct_or_governed_left: Any,
    direct_or_governed_right: Any,
    *,
    allowed_differences: Any = None,
) -> ParityReport:
    """Compare all normative specification fields and refuse closed by default.

    Derived object fingerprints are removed by ``ExperimentSpecification``'s
    explicit ``normative_dict`` method.  No other field is ignored: the only
    paths skipped by this function come from the validated difference
    manifest, including the two non-semantic run-instance binding paths.
    """

    try:
        left = _coerce_spec(direct_or_governed_left, "left condition specification")
        right = _coerce_spec(direct_or_governed_right, "right condition specification")
    except Exception as error:
        return ParityReport.refused(code="MALFORMED_NON_CANONICAL_INPUT", left_value=str(error))

    try:
        manifest = _coerce_manifest(
            AllowedConditionDifferences.create() if allowed_differences is None else allowed_differences
        )
    except Exception as error:
        code = "UNKNOWN_DIFFERENCE_CATEGORY" if "difference" in str(error).lower() or "unknown" in str(error).lower() else "MALFORMED_DIFFERENCE_MANIFEST"
        return ParityReport.refused(code=code, left_value=str(error))

    condition_ids = (left.condition.condition_id, right.condition.condition_id)
    if set(condition_ids) != {DIRECT, GOVERNED} or left.condition.condition_id == right.condition.condition_id:
        return ParityReport.refused(
            code="CONDITION_PAIR_INVALID",
            path="condition.condition_id",
            left_value=left.condition.condition_id,
            right_value=right.condition.condition_id,
            experiment_id=left.experiment_id if left.experiment_id == right.experiment_id else None,
            condition_ids=condition_ids,
            normalization_paths=tuple(sorted(manifest.allowed_condition_differences + manifest.instance_binding_exceptions)),
        )
    if left.experiment_id != right.experiment_id:
        return ParityReport.refused(
            code="UNRELATED_EXPERIMENT_IDS",
            path="experiment_id",
            left_value=left.experiment_id,
            right_value=right.experiment_id,
            condition_ids=condition_ids,
            normalization_paths=tuple(sorted(manifest.allowed_condition_differences + manifest.instance_binding_exceptions)),
        )
    if left.run_identity.run_id == right.run_identity.run_id:
        return ParityReport.refused(
            code="RUN_ID_REUSE",
            path="run_identity.run_id",
            left_value=left.run_identity.run_id,
            right_value=right.run_identity.run_id,
            experiment_id=left.experiment_id,
            condition_ids=condition_ids,
            normalization_paths=tuple(sorted(manifest.allowed_condition_differences + manifest.instance_binding_exceptions)),
        )

    normalized_paths = tuple(sorted(manifest.allowed_condition_differences + manifest.instance_binding_exceptions))
    mismatches: list[ParityMismatch] = []
    _compare_values(
        left.normative_dict(),
        right.normative_dict(),
        "",
        frozenset(normalized_paths),
        mismatches,
    )
    mismatches.sort(key=lambda mismatch: (mismatch.path, mismatch.category, repr(mismatch.left_value), repr(mismatch.right_value)))
    if mismatches:
        return ParityReport.build(
            passed=False,
            refusal_code="UNAUTHORIZED_DIFFERENCE",
            experiment_id=left.experiment_id,
            condition_ids=tuple(sorted(condition_ids)),
            mismatches=tuple(mismatches),
            normalization_paths=normalized_paths,
        )
    return ParityReport.build(
        passed=True,
        refusal_code="NONE",
        experiment_id=left.experiment_id,
        condition_ids=tuple(sorted(condition_ids)),
        mismatches=(),
        normalization_paths=normalized_paths,
    )


def require_parity(left: Any, right: Any, *, allowed_differences: Any = None) -> ParityReport:
    report = check_parity(left, right, allowed_differences=allowed_differences)
    if not report.passed:
        raise ParityRefused(report)
    return report
