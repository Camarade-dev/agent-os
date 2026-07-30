"""Session-local provider-free candidate and owner-authority canary bindings.

The candidate binding runs the real pinned Codex 0.145.0 executable in a private
routeless namespace and produces *candidate* witness evidence, which carries no
authority at all.

The owner-authority binding continues through the whole external order: it
installs a disposable **synthetic** owner-authority world with a real Ed25519
signing identity, provisions one launch as the privileged owner, and then has
the unprivileged launcher path verify the phrase and consume it through the
broker to obtain a signed receipt.  The synthetic world is explicitly not a
production installation and no production acceptance point accepts it.

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
from admissible.capsule.owner_authority import (
    OwnerAuthorityBroker,
    OwnerAuthorityBrokerClient,
    attest_synthetic_non_production_installation,
    perform_installation,
    provision_authorization,
    synthetic_non_production_layout,
)
from admissible.capsule.owner_authorization import (
    OwnerAuthorizationPayload,
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


#: The synthetic privilege witness needs a genuine uid-0 identity.  A user
#: namespace supplies one without touching the host; see
#: ``tests/run_capsule_suite_in_namespace.sh``.
PRIVILEGED_IDENTITY_REASON = (
    "the external owner-authority world requires a privileged installer "
    "identity; run this suite inside a disposable user namespace, for example "
    "`unshare -Urm python3 -m pytest ...`"
)


def privileged_identity_available() -> bool:
    """Whether this process can act as the privileged installer identity."""

    return os.geteuid() == 0


def owner_phrase_descriptor(phrase: str = SYNTHETIC_OWNER_PHRASE) -> int:
    """Return a read descriptor for a dedicated single-use phrase pipe."""

    read_end, write_end = os.pipe()
    try:
        os.write(write_end, phrase.encode("utf-8"))
    finally:
        os.close(write_end)
    return read_end


def synthetic_owner_authority_world(
    workspace: Path,
    *,
    authorized_launcher_uid: int | None = None,
    authorized_launcher_gid: int | None = None,
    start_broker: bool = True,
):
    """Install a disposable synthetic owner-authority world and start its broker.

    This is *not* a production installation: the layout classification says so,
    it lives under a temporary directory, and no production acceptance point
    accepts what it produces.  It does exercise the real installer, the real
    Ed25519 signing identity, the real broker protocol, the real peer-credential
    check and the real durable state machine.
    """

    # AF_UNIX paths are capped near 108 bytes, and pytest's tmp_path is deep, so
    # the disposable world gets a short root of its own.  It is cleaned up with
    # the rest of the session state.
    workspace.mkdir(parents=True, exist_ok=True)
    layout = synthetic_non_production_layout(
        Path(tempfile.mkdtemp(prefix="oa-"))
    )
    perform_installation(
        layout=layout,
        installation_id=f"synthetic-{uuid.uuid4().hex[:16]}",
        authorized_launcher_uid=(
            os.getuid() if authorized_launcher_uid is None
            else authorized_launcher_uid
        ),
        authorized_launcher_gid=(
            os.getgid() if authorized_launcher_gid is None
            else authorized_launcher_gid
        ),
        install_unit=False,
    )
    installation = attest_synthetic_non_production_installation(layout)
    world = {
        "layout": layout,
        "installation": installation,
        "broker": None,
        "thread": None,
        "client": OwnerAuthorityBrokerClient(installation),
    }
    if start_broker:
        broker = OwnerAuthorityBroker(installation)
        broker.bind()
        thread = threading.Thread(target=broker.serve_forever, daemon=True)
        thread.start()
        world["broker"] = broker
        world["thread"] = thread
        _register_world(world)
    return world


_started_worlds: list[dict] = []


def _register_world(world) -> None:
    with _lock:
        _started_worlds.append(world)


def stop_owner_authority_world(world) -> None:
    """Close a synthetic broker so its socket and thread do not leak."""

    broker = world.get("broker")
    if broker is not None:
        broker.close()
        world["broker"] = None
    root = world.get("layout")
    if root is not None:
        shutil.rmtree(root.configuration_root.parent, ignore_errors=True)


def provision_synthetic_authorization(
    world,
    payload,
    *,
    phrase: str = SYNTHETIC_OWNER_PHRASE,
):
    """Provision one launch as the privileged owner in a synthetic world."""

    return provision_authorization(
        installation=world["installation"],
        owner_payload=dict(payload.body),
        owner_phrase=phrase,
    )


def consume_synthetic_authorization(
    world,
    provisioned,
    *,
    phrase: str = SYNTHETIC_OWNER_PHRASE,
):
    """Verify the phrase and atomically consume, obtaining the signed receipt."""

    return world["client"].verify_and_consume(
        authorization_record_id=provisioned["authorization_record_id"],
        owner_payload_fingerprint=provisioned["owner_payload_fingerprint"],
        owner_phrase=phrase,
    )


def create_owner_bound_canary_binding(
    workspace: Path,
    *,
    binding=None,
    mission_bytes: bytes = SYNTHETIC_MISSION_BYTES,
    extra_files: dict[str, bytes] | None = None,
    phrase: str = SYNTHETIC_OWNER_PHRASE,
):
    """Run the complete provider-free order up to the broker-signed receipt.

    The order is the production order: seal a candidate preparation, build the
    canonical owner payload, provision it as the privileged owner, then have the
    launcher verify the phrase and consume through the broker.  The launcher
    never sees the expected digest and never touches the signing key.
    """

    from admissible.capsule.host_codex_backend import (
        SyntheticOwnerAuthorityWitness,
    )

    prepared = build_sealed_candidate_preparation(
        workspace,
        binding=binding,
        extra_files=extra_files,
    )
    payload = build_owner_payload(prepared, mission_bytes=mission_bytes)
    world = synthetic_owner_authority_world(workspace)
    provisioned = provision_synthetic_authorization(world, payload, phrase=phrase)
    signed_receipt = consume_synthetic_authorization(
        world, provisioned, phrase=phrase
    )
    witness = SyntheticOwnerAuthorityWitness(
        signed_receipt=signed_receipt,
        installation=world["installation"],
        broker_client=world["client"],
        preparation_root=prepared["preparation_root"],
        retained_seal_identity=prepared["retained_seal_identity"],
    )
    return {
        **prepared,
        "payload": payload,
        "owner_authority_world": world,
        "provisioned": provisioned,
        "signed_receipt": signed_receipt,
        "owner_authority_witness": witness,
        "mission_bytes": mission_bytes,
    }


def _cleanup() -> None:
    for world in list(_started_worlds):
        try:
            stop_owner_authority_world(world)
        except OSError:  # pragma: no cover - best-effort teardown
            pass
    if _owned_root is not None:
        shutil.rmtree(_owned_root, ignore_errors=True)


atexit.register(_cleanup)
