"""The authoritative-truth seam for the product read model.

This lane is NOT a reconstruction authority. It never decides whether a run
succeeded. It only defines a narrow protocol through which an *already
authoritative* reconstruction can be supplied by the audited G1
implementation.

Three concrete providers are shipped:

* :class:`FakeTruthProvider` - deterministic canned truth for tests;
* :class:`LegacyPersistedFactsProvider` - returns raw persisted historical facts
  and never claims a product admission verdict;
* :class:`G1ReconstructionAdapter` - the integration boundary that calls
  ``reconstruct_completed_native_mission(...)`` and returns its canonical
  mapping. It contains no reconstruction logic of its own.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol, runtime_checkable

from . import evidence_reader

LEGACY_FACTS_SCHEMA = "admissible_product_read_model_legacy_persisted_facts_v1"


class TruthProviderError(RuntimeError):
    """Base class for truth-provider failures surfaced to the read model."""


class TruthProviderUnavailable(TruthProviderError):
    """Raised when the G1 seam is unwired or the run root is structurally unsupported."""


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


def _resolve_session_id(root_real: Path) -> str | None:
    """Resolve the durable session id from persisted run-root evidence only."""

    final_status = evidence_reader.read_json(root_real, "evidence/final-status.json")
    if final_status.ok and isinstance(final_status.data, Mapping):
        candidate = final_status.data.get("session_id")
        if isinstance(candidate, str) and candidate:
            return candidate

    preflight = evidence_reader.read_json(root_real, "evidence/canary-preflight.json")
    if preflight.ok and isinstance(preflight.data, Mapping):
        payload = preflight.data.get("authorization_payload")
        if isinstance(payload, Mapping):
            candidate = payload.get("session_id")
            if isinstance(candidate, str) and candidate:
                return candidate

    delegated_dir = evidence_reader.safe_child_path(root_real, "evidence/delegated-state")
    if delegated_dir is not None and delegated_dir.is_dir():
        for path in sorted(delegated_dir.glob("*.delegated-gate.json")):
            try:
                parsed = evidence_reader.read_json(
                    root_real, f"evidence/delegated-state/{path.name}"
                )
            except OSError:
                continue
            if parsed.ok and isinstance(parsed.data, Mapping):
                candidate = parsed.data.get("session_id")
                if isinstance(candidate, str) and candidate:
                    return candidate
    return None


def _call_canonical_g1_reconstruction(run_root: Path) -> Mapping[str, object]:
    """Open durable stores under ``run_root`` and call audited G1 reconstruction.

    G1 symbols are resolved through ``importlib`` at call time so this module
    stays free of static production imports, import-time side effects, and
    circular-import pressure. Exception messages from G1 are not forwarded:
    they may contain persisted workspace or authorization detail.
    """

    native_canary = importlib.import_module("admissible.delegated_gate.native_canary")
    native_executor = importlib.import_module("admissible.delegated_gate.native_executor")
    delegated_store = importlib.import_module("admissible.delegated_gate.store")
    reconstruct_completed_native_mission = native_canary.reconstruct_completed_native_mission
    AtomicNativeExecutionStore = native_executor.AtomicNativeExecutionStore
    NativeEvidenceInvalid = native_executor.NativeEvidenceInvalid
    NativeEvidenceNotFound = native_executor.NativeEvidenceNotFound
    NativeExecutionStoreError = native_executor.NativeExecutionStoreError
    AtomicDelegatedSessionStore = delegated_store.AtomicDelegatedSessionStore
    DelegatedGateStoreError = delegated_store.DelegatedGateStoreError

    root_real = evidence_reader.resolve_root(run_root)
    evidence = evidence_reader.safe_child_path(root_real, "evidence")
    if evidence is None or not evidence.is_dir():
        raise TruthProviderUnavailable("G1 reconstruction requires an evidence directory")

    session_dir = evidence / "delegated-state"
    execution_dir = evidence / "native-execution"
    artifacts_dir = execution_dir / "artifacts"
    if not session_dir.is_dir() or not execution_dir.is_dir() or not artifacts_dir.is_dir():
        raise TruthProviderUnavailable(
            "G1 reconstruction requires durable delegated-state, native-execution, and artifacts directories"
        )

    session_id = _resolve_session_id(root_real)
    if session_id is None:
        raise TruthProviderUnavailable("G1 reconstruction could not resolve a session id")

    try:
        outcome = reconstruct_completed_native_mission(
            session_store=AtomicDelegatedSessionStore(session_dir),
            execution_store=AtomicNativeExecutionStore(execution_dir),
            evidence_directory=evidence,
            session_id=session_id,
        )
    except NativeEvidenceInvalid:
        # Evidence present but not reconstructable under the audited G1 contract
        # (incomplete, inconsistent, or non-runtime-v2). Never invent admission.
        raise TruthProviderError(
            "authoritative G1 reconstruction rejected persisted evidence"
        ) from None
    except (NativeEvidenceNotFound, NativeExecutionStoreError, DelegatedGateStoreError, OSError, ValueError, TypeError):
        raise TruthProviderError(
            "authoritative G1 reconstruction could not load persisted evidence"
        ) from None

    mapping = outcome.to_dict()
    if not isinstance(mapping, Mapping):
        raise TruthProviderError(
            f"authoritative reconstruction returned a non-mapping: {type(mapping).__name__}"
        )
    return mapping


def create_g1_reconstruction_provider() -> G1ReconstructionAdapter:
    """Construct the production G1 truth provider without injecting a function."""

    return G1ReconstructionAdapter.from_canonical_g1()


class G1ReconstructionAdapter:
    """Integration boundary for the audited G1 reconstruction seam.

    Production construction::

        provider = G1ReconstructionAdapter.from_canonical_g1()
        # or
        provider = create_g1_reconstruction_provider()

    Tests may still inject an explicit ``reconstruct_fn`` / ``to_mapping`` pair.
    Explicit injection is never silently replaced by the canonical G1 wiring.

    The adapter implements NO reconstruction logic. It only resolves durable
    store roots from the run directory, calls the authoritative G1 function, and
    returns that function's canonical ``to_dict()`` mapping.
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

    @classmethod
    def from_canonical_g1(cls) -> G1ReconstructionAdapter:
        """Wire the audited ``reconstruct_completed_native_mission`` seam."""

        return cls(_call_canonical_g1_reconstruction)

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
