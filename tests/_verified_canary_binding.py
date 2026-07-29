"""Session-local provider-free verified canary binding for regression tests."""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
import threading
from pathlib import Path

from admissible.capsule.execution_authority import ExecutableFileIdentity
from admissible.capsule.model_authority import (
    canary_model_authority,
    canary_model_binding_policy,
)
from admissible.capsule.serialization_witness import (
    TrustedSerializationWitnessStore,
)


_lock = threading.Lock()
_binding = None
_owned_root: Path | None = None


def _pinned_codex() -> Path:
    override = os.environ.get("ADMISSIBLE_PINNED_CODEX")
    candidates = []
    if override:
        candidates.append(Path(override))
    releases = Path.home() / ".codex" / "packages" / "standalone" / "releases"
    if releases.is_dir():
        candidates.extend(
            sorted(
                item / "bin" / "codex"
                for item in releases.iterdir()
                if item.name.startswith("0.145.0-")
            )
        )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("pinned Codex 0.145.0 is required for verified binding tests")


def verified_canary_binding():
    """Return one real-binary receipt shared only by this pytest process."""

    global _binding, _owned_root
    with _lock:
        if _binding is not None:
            return _binding
        _owned_root = Path(
            tempfile.mkdtemp(prefix="admissible-test-witness-store-")
        )
        _binding = create_verified_canary_binding(
            _owned_root / "evidence"
        )
        return _binding


def create_verified_canary_binding(root: Path):
    """Create an independently anchored real-binary binding for one test."""

    codex = _pinned_codex()
    identity = ExecutableFileIdentity.attest(
        codex, label="test-session pinned Codex witness"
    )
    policy = canary_model_binding_policy(
        codex_executable_identity=identity.to_dict()
    )
    store = TrustedSerializationWitnessStore(root)
    receipt = store.verify_canary(
        policy=policy,
        codex_executable=codex,
    )
    authority = canary_model_authority(
        model_binding_policy=policy,
        verified_witness_receipt=receipt,
        trusted_witness_store=store,
    )
    return {
        "codex": codex,
        "identity": identity,
        "policy": policy,
        "store": store,
        "receipt": receipt,
        "authority": authority,
    }


def _cleanup() -> None:
    if _owned_root is not None:
        shutil.rmtree(_owned_root, ignore_errors=True)


atexit.register(_cleanup)
