"""The authoritative-truth seam for the product read model.

This lane is NOT a reconstruction authority. It never decides whether a run
succeeded. It only defines a narrow protocol through which an *already
authoritative* reconstruction can be supplied later by the audited G1
implementation.

Three concrete providers are shipped:

* :class:`FakeTruthProvider` - deterministic canned truth for tests;
* :class:`LegacyPersistedFactsProvider` - returns raw persisted historical facts
  and never claims a product admission verdict;
* :class:`G1ReconstructionAdapter` - a documented placeholder that will wrap the
  future ``reconstruct_completed_native_mission(...)`` function. It contains no
  reconstruction logic of its own.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol, runtime_checkable

from . import evidence_reader

LEGACY_FACTS_SCHEMA = "admissible_product_read_model_legacy_persisted_facts_v1"


class TruthProviderError(RuntimeError):
    """Base class for truth-provider failures surfaced to the read model."""


class TruthProviderUnavailable(TruthProviderError):
    """Raised by the G1 adapter placeholder when no reconstruct function is wired."""


@runtime_checkable
class RunTruthProvider(Protocol):
    """Supplies an already-authoritative, JSON-compatible reconstruction.

    Implementations must not be called by this lane to *perform* execution,
    verification or checkpointing. They return a mapping that the product
    extractor reads. Returning a mapping with no product-verdict keys correctly
    leaves the product verdict ``UNKNOWN``.
    """

    def reconstruct(self, run_root: Path) -> Mapping[str, object]:
        ...


class FakeTruthProvider:
    """Deterministic truth provider for tests.

    Constructed with either a single mapping (returned for every root) or a
    mapping keyed by resolved run-root string. It performs no I/O beyond
    resolving the root for keyed lookups.
    """

    def __init__(
        self,
        payload: Mapping[str, object] | None = None,
        *,
        by_root: Mapping[str, Mapping[str, object]] | None = None,
        default: Mapping[str, object] | None = None,
    ) -> None:
        self._payload = payload
        self._by_root = dict(by_root) if by_root else {}
        self._default = default

    def reconstruct(self, run_root: Path) -> Mapping[str, object]:
        if self._by_root:
            key = str(evidence_reader.resolve_root(run_root))
            if key in self._by_root:
                return dict(self._by_root[key])
            if self._default is not None:
                return dict(self._default)
            return {}
        if self._payload is not None:
            return dict(self._payload)
        return {}


class RaisingTruthProvider:
    """Test double whose ``reconstruct`` always raises, exercising fault paths."""

    def __init__(self, exc: Exception | None = None) -> None:
        self._exc = exc or TruthProviderError("synthetic truth-provider failure")

    def reconstruct(self, run_root: Path) -> Mapping[str, object]:
        raise self._exc


class LegacyPersistedFactsProvider:
    """Returns raw persisted facts for legacy/incomplete runs.

    Crucially it emits NO ``verdict`` / ``verification_mode`` / product keys, so
    the extractor keeps the product verdict ``UNKNOWN``. It preserves only the
    exact persisted canonical classification and final-status detail as facts.
    """

    def __init__(self, *, max_bytes: int = evidence_reader.DEFAULT_MAX_JSON_BYTES) -> None:
        self._max_bytes = max_bytes

    def reconstruct(self, run_root: Path) -> Mapping[str, object]:
        root_real = evidence_reader.resolve_root(run_root)
        read = evidence_reader.read_json(
            root_real, "evidence/final-status.json", max_bytes=self._max_bytes
        )
        facts: dict[str, object] = {
            "schema_version": LEGACY_FACTS_SCHEMA,
            "source": "persisted_facts_only",
            "product_verdict_supplied": False,
            "final_status_presence": read.presence.value,
        }
        if read.ok and isinstance(read.data, Mapping):
            data = read.data
            for key in (
                "session_id",
                "status",
                "detail",
                "phase",
                "canary_success",
                "request_fingerprint",
                "result_fingerprint",
                "checkpoint_fingerprint",
                "behavioral_evidence_fingerprint",
            ):
                if key in data:
                    facts[key] = data[key]
        elif read.presence is evidence_reader.PresenceState.INCONSISTENT:
            facts["final_status_reason"] = read.reason
        return facts


class G1ReconstructionAdapter:
    """Documented placeholder for the future audited G1 reconstruction seam.

    When G1 is audited and committed, wire its authoritative function here::

        from admissible.delegated_gate.native_canary import (
            reconstruct_completed_native_mission,
        )
        provider = G1ReconstructionAdapter(reconstruct_completed_native_mission)

    The adapter deliberately implements NO reconstruction logic. It only calls
    the supplied authoritative function and returns its already-authoritative,
    JSON-compatible mapping. Integration therefore changes this module and the
    product extractor only, never the presentation types.
    """

    def __init__(
        self,
        reconstruct_fn: Callable[..., Mapping[str, object]] | None = None,
        *,
        to_mapping: Callable[[object], Mapping[str, object]] | None = None,
        **call_kwargs: object,
    ) -> None:
        self._reconstruct_fn = reconstruct_fn
        self._to_mapping = to_mapping
        self._call_kwargs = call_kwargs

    def reconstruct(self, run_root: Path) -> Mapping[str, object]:
        if self._reconstruct_fn is None:
            raise TruthProviderUnavailable(
                "G1 reconstruct_completed_native_mission is not wired into this seam yet"
            )
        result = self._reconstruct_fn(run_root, **self._call_kwargs)
        if self._to_mapping is not None:
            result = self._to_mapping(result)
        if not isinstance(result, Mapping):
            raise TruthProviderError(
                f"authoritative reconstruction returned a non-mapping: {type(result).__name__}"
            )
        return result
