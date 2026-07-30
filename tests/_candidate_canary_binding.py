"""Session-local provider-free candidate and owner-bound canary bindings.

The candidate binding runs the real pinned Codex 0.145.0 executable in a private
routeless namespace and produces *candidate* witness evidence.  The owner-bound
binding continues through the whole future authorization order using a synthetic
owner phrase delivered on a dedicated descriptor, and yields the only object that
may authorize a production effect.

Nothing here contacts a public provider, model or API, and no real
authentication content is read, copied, displayed or hashed.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path

from admissible.capsule.boundary_authority import DestinationManifest
from admissible.capsule.boundary_launcher import (
    boundary_launcher_component_identity,
)
from admissible.capsule.common import fingerprint, sha256_bytes
from admissible.capsule.execution_authority import ExecutableFileIdentity
from admissible.capsule.host_codex_backend import dynamic_tools_grammar
from admissible.capsule.model_authority import (
    canary_model_authority,
    canary_model_binding_policy,
)
from admissible.capsule.owner_authorization import (
    OwnerAuthorizationPayload,
    OwnerAuthorizationStateStore,
    authorize_owner_bound_serialization_receipt,
    owner_authorization_digest,
)
from admissible.capsule.preflight_seal import (
    RetainedPreparationSealIdentity,
    publish_future_preflight_seal,
)
from admissible.capsule.serialization_witness import (
    CandidateSerializationWitnessStore,
)


#: A synthetic owner phrase.  It authorizes nothing outside this test session and
#: is never the real canary phrase.
SYNTHETIC_OWNER_PHRASE = "synthetic-provider-free-owner-phrase-not-the-real-one"

SYNTHETIC_MISSION_BYTES = b"synthetic provider-free owner-bound canary mission\n"

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
    raise RuntimeError("pinned Codex 0.145.0 is required for candidate binding tests")


def candidate_canary_binding():
    """Return one real-binary candidate binding shared only by this process."""

    global _binding, _owned_root
    with _lock:
        if _binding is not None:
            return _binding
        _owned_root = Path(
            tempfile.mkdtemp(prefix="admissible-test-witness-store-")
        )
        _binding = create_candidate_canary_binding(_owned_root / "evidence")
        return _binding


def create_candidate_canary_binding(root: Path):
    """Create an independently rooted real-binary candidate binding."""

    codex = _pinned_codex()
    identity = ExecutableFileIdentity.attest(
        codex, label="test-session pinned Codex witness"
    )
    policy = canary_model_binding_policy(
        codex_executable_identity=identity.to_dict()
    )
    store = CandidateSerializationWitnessStore(root)
    receipt = store.record_candidate_witness(
        policy=policy,
        codex_executable=codex,
    )
    authority = canary_model_authority(
        model_binding_policy=policy,
        candidate_witness_receipt=receipt,
        candidate_witness_store=store,
    )
    return {
        "codex": codex,
        "identity": identity,
        "policy": policy,
        "store": store,
        "receipt": receipt,
        "authority": authority,
    }


def _repository_head() -> str:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        ("git", "-C", os.fspath(root), "rev-parse", "HEAD"),
        capture_output=True,
        check=True,
        text=True,
    )
    return completed.stdout.strip()


def write_owner_payload_file(
    *,
    path: Path,
    policy,
    receipt,
    classification: str = "PREPARED_NOT_CONSUMED",
) -> None:
    """Write the in-preparation owner payload the closed-world manifest covers."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": "future_owner_payload_v1",
                "classification": classification,
                "model_binding_policy_fingerprint": policy.policy_fingerprint,
                "candidate_serialization_witness_receipt_identity": (
                    receipt.receipt_identity
                ),
                "candidate_serialization_witness_run_identity": (
                    receipt.witness_run_identity
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def build_sealed_candidate_preparation(
    workspace: Path,
    *,
    binding=None,
    preparation_id: str | None = None,
    run_id: str | None = None,
    extra_files: dict[str, bytes] | None = None,
):
    """Create a sealed-candidate preparation awaiting owner authorization."""

    binding = binding or candidate_canary_binding()
    token = uuid.uuid4().hex
    preparation_id = preparation_id or f"canary-preparation-{token}"
    run_id = run_id or f"canary-run-{token}"
    root = workspace / "preparation"
    (root / "evidence").mkdir(parents=True)
    (root / "CANARY.txt").write_bytes(b"admissible-chatgpt-codex-canary-v1\n")
    for relative, payload in (extra_files or {}).items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    write_owner_payload_file(
        path=root / "evidence" / "owner-payload.json",
        policy=binding["policy"],
        receipt=binding["receipt"],
    )
    retained_seal_path = workspace / "retained" / "expected-seal-identity.json"
    sealed = publish_future_preflight_seal(
        root=root,
        owner_payload_path="evidence/owner-payload.json",
        preparation_id=preparation_id,
        run_id=run_id,
        retained_seal_path=retained_seal_path,
        model_binding_policy=binding["policy"],
        candidate_witness_receipt=binding["receipt"],
        candidate_witness_store=binding["store"],
    )
    retained = RetainedPreparationSealIdentity.load(
        retention_path=retained_seal_path,
        root=root,
    )
    return {
        **binding,
        "preparation_root": root,
        "preparation_id": preparation_id,
        "run_id": run_id,
        "retained_seal_path": retained_seal_path,
        "retained_seal_identity": retained,
        "sealed": sealed,
    }


def build_owner_payload(prepared, *, mission_bytes: bytes = SYNTHETIC_MISSION_BYTES):
    """Build the canonical external owner payload for a sealed candidate."""

    store = prepared["store"]
    receipt = prepared["receipt"]
    bundle = store.load_current_candidate_evidence(
        expected_policy=prepared["policy"],
        expected_executable_identity=prepared["identity"].to_dict(),
    )
    head = _repository_head()
    return OwnerAuthorizationPayload.create(
        repository_root=Path(__file__).resolve().parents[1],
        repository_head=head,
        implementation_head=head,
        run_id=prepared["run_id"],
        preparation_id=prepared["preparation_id"],
        preparation_root_identity=prepared["sealed"]["preparation_root_identity"],
        candidate_store_root_identity=dict(bundle.store_root_identity),
        candidate_store_anchor_fingerprint=bundle.store_anchor_fingerprint,
        candidate_evidence_pack_fingerprint=(
            bundle.pack.evidence_pack_fingerprint
        ),
        candidate_receipt_identity=receipt.receipt_identity,
        candidate_witness_run_identity=receipt.witness_run_identity,
        candidate_witness_run_nonce=receipt.witness_run_nonce,
        candidate_store_tail_identity=bundle.tail_identity,
        model_binding_policy=prepared["policy"],
        boundary_launcher_identity=boundary_launcher_component_identity(),
        destination_manifest_identity=(
            DestinationManifest.load_packaged().manifest_fingerprint
        ),
        mission_fingerprint=sha256_bytes(mission_bytes),
        tool_authority_identity=fingerprint(dynamic_tools_grammar()),
        budgets={
            "event_timeout_ms": 2000,
            "capsule_pids": 64,
            "capsule_output_bytes": 65536,
        },
        preflight_manifest_fingerprint=prepared["sealed"]["manifest_fingerprint"],
        preflight_seal_fingerprint=prepared["sealed"]["seal_fingerprint"],
        retained_seal_identity=prepared["retained_seal_identity"].retained_identity,
    )


def retain_synthetic_authorization(
    prepared,
    payload,
    *,
    workspace: Path,
    phrase: str = SYNTHETIC_OWNER_PHRASE,
):
    """Retain the expected synthetic owner digest outside the preparation."""

    state = OwnerAuthorizationStateStore(
        workspace / "owner-authorization",
        preparation_root=prepared["preparation_root"],
    )
    state.retain_expected_digest(
        expected_owner_authorization_digest=owner_authorization_digest(
            phrase=phrase,
            payload_bytes=payload.canonical_payload_bytes(),
        ),
        payload_fingerprint=payload.payload_fingerprint,
        retained_seal=prepared["retained_seal_identity"],
    )
    return state


def owner_phrase_descriptor(phrase: str = SYNTHETIC_OWNER_PHRASE) -> int:
    """Return a read descriptor for a dedicated single-use phrase pipe."""

    read_end, write_end = os.pipe()
    try:
        os.write(write_end, phrase.encode("utf-8"))
    finally:
        os.close(write_end)
    return read_end


def authorize_synthetic_owner_binding(
    prepared,
    payload,
    state,
    *,
    phrase: str = SYNTHETIC_OWNER_PHRASE,
):
    """Run the trusted authorization path with a synthetic phrase over a pipe."""

    descriptor = owner_phrase_descriptor(phrase)
    try:
        return authorize_owner_bound_serialization_receipt(
            owner_payload=payload,
            owner_phrase_descriptor=descriptor,
            authorization_state=state,
            candidate_witness_store=prepared["store"],
            candidate_witness_receipt=prepared["receipt"],
            preparation_root=prepared["preparation_root"],
            retained_seal_identity=prepared["retained_seal_identity"],
            boundary_launcher_identity=boundary_launcher_component_identity(),
        )
    finally:
        os.close(descriptor)


def create_owner_bound_canary_binding(
    workspace: Path,
    *,
    binding=None,
    mission_bytes: bytes = SYNTHETIC_MISSION_BYTES,
    extra_files: dict[str, bytes] | None = None,
):
    """Run the complete provider-free order up to the owner-bound receipt."""

    prepared = build_sealed_candidate_preparation(
        workspace,
        binding=binding,
        extra_files=extra_files,
    )
    payload = build_owner_payload(prepared, mission_bytes=mission_bytes)
    state = retain_synthetic_authorization(
        prepared, payload, workspace=workspace
    )
    owner_bound = authorize_synthetic_owner_binding(prepared, payload, state)
    return {
        **prepared,
        "payload": payload,
        "authorization_state": state,
        "owner_bound_receipt": owner_bound,
        "mission_bytes": mission_bytes,
    }


def _cleanup() -> None:
    if _owned_root is not None:
        shutil.rmtree(_owned_root, ignore_errors=True)


atexit.register(_cleanup)
