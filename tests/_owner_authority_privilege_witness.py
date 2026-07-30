"""Driver for the provider-free synthetic privileged-boundary witness.

This module is executed *inside a disposable user and mount namespace*, where
it genuinely runs as uid 0.  It models, without touching the real host:

* a privileged installer identity that creates the fixed state and the signing
  key;
* root-owned state and a private key at mode 0600;
* an unprivileged launcher view in which the signing key is mechanically
  unreachable;
* a fixed broker socket with peer-credential validation;
* a signed, one-time receipt;
* refusal of the complete fake-owner world.

What it is **not**
------------------

It is *not* the real production installation.  Two honest limits, both asserted
rather than hidden:

1. The synthetic layout is a temporary directory, not ``/etc``, ``/var/lib``
   and ``/run``.  The production attestation entry point takes no arguments and
   can never be pointed at it.
2. This host has no ``newuidmap``/``newgidmap``, so a user namespace here can
   map exactly one uid.  The installer and launcher therefore share a *kernel*
   uid, and the key's inaccessibility to the launcher is demonstrated by mount
   namespace isolation rather than by DAC ownership.  A real installation gets
   both: distinct kernel uids *and* a root-owned 0700 state directory.

Nothing here contacts a public provider, model or API.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from admissible.capsule.common import canonical_bytes, fingerprint  # noqa: E402
from admissible.capsule.owner_authority import (  # noqa: E402
    FORBIDDEN_BROKER_OPERATIONS,
    OwnerAuthorityBroker,
    OwnerAuthorityBrokerClient,
    OwnerAuthorityError,
    attest_synthetic_non_production_installation,
    discover_system_openssl,
    perform_installation,
    provision_authorization,
    synthetic_non_production_layout,
    verify_signed_receipt,
)
from admissible.capsule.owner_authority.broker import (  # noqa: E402
    BROKER_PROTOCOL_VERSION,
)
from admissible.capsule.owner_authority.layout import (  # noqa: E402
    CONSUMED_LAUNCH_COMMITTED,
    PHRASE_VERIFIED,
    PROVISIONED_PENDING,
    RECEIPT_ISSUED,
)
from admissible.capsule.owner_authority.records import (  # noqa: E402
    SignedOwnerAuthorizationReceipt,
    external_owner_authorization_digest,
    new_authorization_record_id,
)
from admissible.capsule.owner_authority.signing import (  # noqa: E402
    generate_signing_identity,
    sign_message,
)
from admissible.capsule.owner_authority.state import (  # noqa: E402
    AuthorizationStateDirectory,
    consumption_body,
)

PHRASE = "synthetic-privilege-witness-owner-phrase"

PAYLOAD = {
    "schema_version": "synthetic_privilege_witness_payload_v1",
    "mission": "provider-free synthetic privileged-boundary witness",
    "run_id": "privilege-witness-run-1",
    "model_binding_policy": {
        "configured_model": "gpt-5.3-codex",
        "configured_reasoning_effort": "high",
    },
    "budgets": {"wall_clock_seconds": 60},
}


class WitnessFailure(AssertionError):
    """A synthetic privilege witness expectation was not met."""


def expect(condition: bool, detail: str) -> None:
    if not condition:
        raise WitnessFailure(detail)


def expect_refusal(callable_, classifications, detail):
    """Assert a call refuses with one of the expected classifications."""

    try:
        callable_()
    except OwnerAuthorityError as error:
        expect(
            error.classification in classifications,
            f"{detail}: unexpected classification {error.classification}",
        )
        return error.classification
    raise WitnessFailure(f"{detail}: the call was not refused")


def _install(root: Path, *, launcher_uid: int, launcher_gid: int):
    layout = synthetic_non_production_layout(root)
    perform_installation(
        layout=layout,
        installation_id=f"witness{os.getpid():08d}",
        authorized_launcher_uid=launcher_uid,
        authorized_launcher_gid=launcher_gid,
        install_unit=False,
    )
    return layout, attest_synthetic_non_production_installation(layout)


def _root_owned_state_checks(layout, findings: dict) -> None:
    """The installer's ownership and mode contract, as actually observed."""

    private_key = layout.private_key_path
    info = private_key.stat()
    expect(info.st_uid == 0, "the private signing key is not owned by uid 0")
    expect(
        stat.S_IMODE(info.st_mode) == 0o600,
        f"the private signing key mode is {oct(stat.S_IMODE(info.st_mode))}",
    )
    state_mode = stat.S_IMODE(layout.state_root.stat().st_mode)
    expect(state_mode == 0o700, f"the state root mode is {oct(state_mode)}")
    private_dir_mode = stat.S_IMODE(layout.private_directory.stat().st_mode)
    expect(
        private_dir_mode == 0o700,
        f"the private directory mode is {oct(private_dir_mode)}",
    )
    record_mode = stat.S_IMODE(layout.installation_record_path.stat().st_mode)
    expect(record_mode == 0o444, f"the installation record mode is {oct(record_mode)}")
    findings["root_owned_state"] = {
        "private_key_uid": info.st_uid,
        "private_key_mode": oct(stat.S_IMODE(info.st_mode)),
        "state_root_mode": oct(state_mode),
        "installation_record_mode": oct(record_mode),
    }


def _key_invisible_to_launcher(layout, findings: dict) -> None:
    """Show the launcher view in which the signing key has no path at all.

    The child runs in its own mount namespace with an empty tmpfs over the
    private directory.  This is the synthetic stand-in for the DAC barrier a
    real root-owned 0700 directory provides against a distinct launcher uid.
    """

    probe = (
        "import json,os,sys;"
        f"p={str(layout.private_key_path)!r};"
        "print(json.dumps({'exists': os.path.exists(p),"
        " 'listing': sorted(os.listdir(os.path.dirname(p)))}))"
    )
    completed = subprocess.run(
        [
            "unshare",
            "--mount",
            "sh",
            "-c",
            f"mount -t tmpfs tmpfs {layout.private_directory} && "
            f"{sys.executable} -c \"{probe}\"",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    expect(
        completed.returncode == 0,
        f"the launcher-view probe failed: {completed.stderr}",
    )
    observed = json.loads(completed.stdout.strip().splitlines()[-1])
    expect(
        observed["exists"] is False,
        "the signing key was still visible in the launcher view",
    )
    expect(
        observed["listing"] == [],
        f"the launcher view still lists private material: {observed['listing']}",
    )
    # And in the broker's own view the key is still there.
    expect(
        layout.private_key_path.exists(),
        "the broker lost its own view of the signing key",
    )
    findings["key_invisible_to_launcher"] = observed


def _peer_credentials_are_enforced(layout, findings: dict) -> None:
    """A broker that authorizes another launcher uid refuses this peer."""

    foreign_root = Path(tempfile.mkdtemp(prefix="oa-foreign-"))
    try:
        foreign_layout, foreign_installation = _install(
            foreign_root,
            launcher_uid=os.getuid() + 4242,
            launcher_gid=os.getgid(),
        )
        broker = OwnerAuthorityBroker(foreign_installation)
        broker.bind()
        thread = threading.Thread(target=broker.serve_forever, daemon=True)
        thread.start()
        try:
            client = OwnerAuthorityBrokerClient(foreign_installation)
            classification = expect_refusal(
                client.attest_installation,
                {"OWNER_AUTHORITY_PEER_CREDENTIAL_REFUSED"},
                "a broker authorizing another launcher uid accepted this peer",
            )
        finally:
            broker.close()
        findings["peer_credential_refusal"] = classification
    finally:
        shutil.rmtree(foreign_root, ignore_errors=True)


def _fake_owner_world_is_refused(layout, installation, findings: dict) -> None:
    """The complete audit attack, run with the attacker's own key material."""

    attacker_root = Path(tempfile.mkdtemp(prefix="oa-attacker-"))
    results: dict = {}
    try:
        executable = discover_system_openssl()
        attacker_private = attacker_root / "attacker.pem"
        attacker_public = attacker_root / "attacker.pub.pem"
        generate_signing_identity(
            executable=executable,
            private_key_path=attacker_private,
            public_key_path=attacker_public,
        )

        # 1-6. the attacker chooses a phrase, computes a digest for a record id
        #      it invented, and tries to write production-shaped state.
        forged_record_id = new_authorization_record_id()
        forged_digest = external_owner_authorization_digest(
            phrase="attacker-chosen-phrase",
            payload_bytes=canonical_bytes(PAYLOAD),
            authorization_record_id=forged_record_id,
        )
        results["attacker_can_compute_a_digest"] = len(forged_digest) == 64

        # 7. the attacker signs a receipt payload with its own key.  The bytes
        #    are a perfectly well-formed receipt; only the key is wrong.
        genuine_record_id = new_authorization_record_id()
        directory = AuthorizationStateDirectory(layout, genuine_record_id)
        forged_payload = {
            "schema_version": (
                "admissible_owner_authority_signed_authorization_receipt_v1"
            ),
            "broker_protocol": BROKER_PROTOCOL_VERSION,
            "signature_construction": (
                "admissible_owner_authority_ed25519_over_canonical_receipt_payload_v1"
            ),
            "digest_construction": (
                "admissible_external_owner_authority_phrase_nul_payload_nul_"
                "record_sha256_v3"
            ),
            "installation_id": installation.installation_id,
            "installation_identity": installation.installation_identity,
            "signing_key_fingerprint": installation.signing_key_fingerprint,
            "crypto_attestation_revision": installation.crypto_attestation_revision(),
            "authorization_record_id": forged_record_id,
            "authorization_record_identity": fingerprint({"forged": True}),
            "owner_payload": dict(PAYLOAD),
            "owner_payload_fingerprint": fingerprint(dict(PAYLOAD)),
            "authorization_consumption_identity": forged_digest,
            "consumption_state": CONSUMED_LAUNCH_COMMITTED,
            "consumption_record_identity": forged_digest,
            "launches_authorized": 1,
            "retries_authorized": 0,
            "repairs_authorized": 0,
            "broker_terminal_evidence": {
                "schema_version": (
                    "admissible_owner_authority_broker_terminal_evidence_v1"
                ),
                "commit_rule": (
                    "CONSUMPTION_IS_DURABLE_BEFORE_ANY_SIGNATURE_IS_PRODUCED"
                ),
                "observed_state_sequence": [PROVISIONED_PENDING],
                "consumption_marker_identity": {
                    "path": "/forged",
                    "sha256": forged_digest,
                    "device": 1,
                    "inode": 1,
                    "owner_uid": 0,
                    "owner_gid": 0,
                    "mode": 0o400,
                    "size": 1,
                    "file_type": "regular",
                    "link_count": 1,
                },
                "cryptographic_executable_identity": dict(executable),
                "broker_protocol": BROKER_PROTOCOL_VERSION,
                "peer_uid": os.getuid(),
            },
        }
        forged_signature = sign_message(
            executable=executable,
            private_key_path=attacker_private,
            message=canonical_bytes(forged_payload),
        )
        forged_receipt = SignedOwnerAuthorizationReceipt.create(
            payload=forged_payload, signature=forged_signature
        )
        # 8. the receipt is structurally perfect and cryptographically valid
        #    under the attacker's key --- and useless.
        results["attacker_signature_refused"] = expect_refusal(
            lambda: verify_signed_receipt(
                receipt=forged_receipt, installation=installation
            ),
            {"OWNER_AUTHORITY_SIGNATURE_REFUSED"},
            "a receipt signed with the attacker key verified",
        )

        # The attacker cannot provision through the broker: there is no
        # provisioning operation at all.
        client = OwnerAuthorityBrokerClient(installation)
        results["no_provisioning_rpc"] = sorted(FORBIDDEN_BROKER_OPERATIONS)
        for operation in ("PROVISION_AUTHORIZATION", "SIGN_MESSAGE"):
            expect_refusal(
                lambda operation=operation: client._call({"operation": operation}),
                {"OWNER_AUTHORITY_BROKER_OPERATION_REFUSED"},
                f"the broker implemented the forbidden operation {operation}",
            )

        # And it cannot make the broker act on an authorization it invented.
        results["unprovisioned_record_refused"] = expect_refusal(
            lambda: client.verify_and_consume(
                authorization_record_id=forged_record_id,
                owner_payload_fingerprint=fingerprint(dict(PAYLOAD)),
                owner_phrase="attacker-chosen-phrase",
            ),
            {"OWNER_AUTHORITY_AUTHORIZATION_ABSENT"},
            "the broker acted on an authorization the attacker invented",
        )
        expect(
            directory.current_state() == "AUTHORIZATION_ABSENT",
            "the attacker created durable authorization state",
        )
    finally:
        shutil.rmtree(attacker_root, ignore_errors=True)
    findings["fake_owner_world"] = results


def _one_time_ordering(layout, installation, client, findings: dict) -> None:
    """Concurrency and the crash window around the commit point."""

    results: dict = {}

    # Two concurrent launchers, one authorization: exactly one receipt.
    provisioned = provision_authorization(
        installation=installation, owner_payload=PAYLOAD, owner_phrase=PHRASE
    )
    outcomes: list = []
    lock = threading.Lock()

    def race() -> None:
        try:
            receipt = client.verify_and_consume(
                authorization_record_id=provisioned["authorization_record_id"],
                owner_payload_fingerprint=provisioned["owner_payload_fingerprint"],
                owner_phrase=PHRASE,
            )
            with lock:
                outcomes.append(("receipt", receipt.receipt_identity))
        except OwnerAuthorityError as error:
            with lock:
                outcomes.append(("refused", error.classification))

    threads = [threading.Thread(target=race) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=90)
    receipts = [item for item in outcomes if item[0] == "receipt"]
    refusals = [item for item in outcomes if item[0] == "refused"]
    expect(
        len(receipts) == 1,
        f"concurrent launchers produced {len(receipts)} receipts, expected 1",
    )
    expect(
        len(refusals) == 1,
        f"concurrent launchers produced {len(refusals)} refusals, expected 1",
    )
    results["concurrent_consumption"] = {
        "receipts": len(receipts),
        "refusals": [item[1] for item in refusals],
    }

    # A crash between the durable consumption commit and receipt issuance must
    # leave the authorization permanently unlaunchable.  The commit is written
    # here exactly as the broker writes it, and then nothing else happens ---
    # which is precisely what a crash looks like on restart.
    crashed = provision_authorization(
        installation=installation, owner_payload=PAYLOAD, owner_phrase=PHRASE
    )
    directory = AuthorizationStateDirectory(
        layout, crashed["authorization_record_id"]
    )
    directory.record_phrase_verified(
        {
            "schema_version": "admissible_owner_authority_phrase_verified_v1",
            "state": PHRASE_VERIFIED,
            "authorization_record_id": crashed["authorization_record_id"],
            "owner_payload_fingerprint": crashed["owner_payload_fingerprint"],
            "peer_uid": os.getuid(),
        }
    )
    directory.commit_consumption(
        consumption_body(
            record_id=crashed["authorization_record_id"],
            consumption_identity=fingerprint({"crash": True}),
            owner_payload_fingerprint=crashed["owner_payload_fingerprint"],
            installation_identity=installation.installation_identity,
            peer_uid=os.getuid(),
        )
    )
    expect(
        directory.current_state() == CONSUMED_LAUNCH_COMMITTED,
        "the simulated crash did not leave a durable consumption",
    )
    results["crash_between_commit_and_receipt"] = expect_refusal(
        lambda: client.verify_and_consume(
            authorization_record_id=crashed["authorization_record_id"],
            owner_payload_fingerprint=crashed["owner_payload_fingerprint"],
            owner_phrase=PHRASE,
        ),
        {"OWNER_AUTHORITY_ALREADY_CONSUMED"},
        "a crashed consumption was restored to a launchable state",
    )
    expect(
        directory.current_state() == CONSUMED_LAUNCH_COMMITTED,
        "the refused retry advanced the crashed record",
    )
    findings["one_time_ordering"] = results


def _socket_and_impersonation(layout, installation, findings: dict) -> None:
    """A rogue broker elsewhere is unreachable; one here still cannot sign."""

    results: dict = {}
    rogue_root = Path(tempfile.mkdtemp(prefix="oa-rogue-"))
    try:
        # A rogue broker at another socket: the client has no path parameter, so
        # it never even looks there.
        rogue_layout, rogue_installation = _install(
            rogue_root, launcher_uid=os.getuid(), launcher_gid=os.getgid()
        )
        expect(
            rogue_installation.installation_identity
            != installation.installation_identity,
            "the rogue installation collided with the genuine one",
        )
        expect(
            OwnerAuthorityBrokerClient(installation).socket_path
            == layout.broker_socket_path,
            "the client can be pointed at another socket",
        )
        results["rogue_socket_unreachable"] = str(rogue_layout.broker_socket_path)

        # A receipt issued by the rogue broker does not verify under the
        # genuine installation, even though both are structurally valid.
        rogue_broker = OwnerAuthorityBroker(rogue_installation)
        rogue_broker.bind()
        thread = threading.Thread(target=rogue_broker.serve_forever, daemon=True)
        thread.start()
        try:
            rogue_provisioned = provision_authorization(
                installation=rogue_installation,
                owner_payload=PAYLOAD,
                owner_phrase=PHRASE,
            )
            rogue_receipt = OwnerAuthorityBrokerClient(
                rogue_installation
            ).verify_and_consume(
                authorization_record_id=rogue_provisioned[
                    "authorization_record_id"
                ],
                owner_payload_fingerprint=rogue_provisioned[
                    "owner_payload_fingerprint"
                ],
                owner_phrase=PHRASE,
            )
            results["rogue_receipt_refused"] = expect_refusal(
                lambda: verify_signed_receipt(
                    receipt=rogue_receipt, installation=installation
                ),
                {"OWNER_AUTHORITY_RECEIPT_FOREIGN_INSTALLATION"},
                "a rogue broker's receipt verified under the genuine installation",
            )
        finally:
            rogue_broker.close()

        # A copied root-owned public record under another installation attests
        # to a different installation identity.
        copied = Path(tempfile.mkdtemp(prefix="oa-copied-"))
        try:
            copied_layout = synthetic_non_production_layout(copied)
            copied_layout.configuration_root.mkdir(parents=True, mode=0o755)
            shutil.copy2(
                layout.installation_record_path,
                copied_layout.installation_record_path,
            )
            shutil.copy2(layout.public_key_path, copied_layout.public_key_path)
            results["copied_public_record_refused"] = expect_refusal(
                lambda: attest_synthetic_non_production_installation(copied_layout),
                {
                    "OWNER_AUTHORITY_INSTALLATION_PATHS_DIFFER",
                    "OWNER_AUTHORITY_INSTALLATION_RECORD_INVALID",
                },
                "a copied installation record attested as its original",
            )
        finally:
            shutil.rmtree(copied, ignore_errors=True)
    finally:
        shutil.rmtree(rogue_root, ignore_errors=True)
    findings["socket_and_impersonation"] = results


def main() -> int:
    findings: dict = {
        "classification": "SYNTHETIC_NON_PRODUCTION_PRIVILEGE_WITNESS",
        "is_real_privileged_installation": False,
        "namespace_identity": {
            "euid": os.geteuid(),
            "uid": os.getuid(),
            "distinct_kernel_uids_available": shutil.which("newuidmap") is not None,
        },
    }
    expect(os.geteuid() == 0, "the privilege witness must run as uid 0")
    root = Path(tempfile.mkdtemp(prefix="oa-witness-"))
    broker = None
    try:
        layout, installation = _install(
            root, launcher_uid=os.getuid(), launcher_gid=os.getgid()
        )
        findings["installation_identity"] = installation.installation_identity
        findings["signing_key_fingerprint"] = installation.signing_key_fingerprint
        findings["is_production_installation"] = installation.is_production
        expect(
            installation.is_production is False,
            "the synthetic installation claimed to be production",
        )

        _root_owned_state_checks(layout, findings)
        _key_invisible_to_launcher(layout, findings)

        broker = OwnerAuthorityBroker(installation)
        socket_path = broker.bind()
        socket_info = socket_path.stat()
        expect(
            stat.S_ISSOCK(socket_info.st_mode)
            and socket_info.st_uid == 0
            and stat.S_IMODE(socket_info.st_mode) == 0o660,
            "the broker socket is not root-owned and mode 0660",
        )
        findings["broker_socket"] = {
            "path": str(socket_path),
            "owner_uid": socket_info.st_uid,
            "mode": oct(stat.S_IMODE(socket_info.st_mode)),
        }
        thread = threading.Thread(target=broker.serve_forever, daemon=True)
        thread.start()
        client = OwnerAuthorityBrokerClient(installation)

        # The signed one-time receipt, end to end.
        provisioned = provision_authorization(
            installation=installation, owner_payload=PAYLOAD, owner_phrase=PHRASE
        )
        expect(
            provisioned["phrase_retained"] is False,
            "the provisioner claimed to retain the phrase",
        )
        receipt = client.verify_and_consume(
            authorization_record_id=provisioned["authorization_record_id"],
            owner_payload_fingerprint=provisioned["owner_payload_fingerprint"],
            owner_phrase=PHRASE,
        )
        verification = verify_signed_receipt(
            receipt=receipt, installation=installation
        )
        expect(
            verification["classification"] == "OWNER_AUTHORITY_SIGNATURE_VERIFIED",
            "the genuine receipt did not verify",
        )
        status = client.authorization_status(
            provisioned["authorization_record_id"]
        )
        expect(
            status["state"] == RECEIPT_ISSUED,
            f"unexpected state after issuance: {status['state']}",
        )
        findings["signed_receipt"] = {
            "receipt_identity": receipt.receipt_identity,
            "state": status["state"],
            "observed_state_sequence": list(
                receipt.payload["broker_terminal_evidence"][
                    "observed_state_sequence"
                ]
            ),
        }

        _peer_credentials_are_enforced(layout, findings)
        _fake_owner_world_is_refused(layout, installation, findings)
        _one_time_ordering(layout, installation, client, findings)
        _socket_and_impersonation(layout, installation, findings)
        findings["result"] = "SYNTHETIC_PRIVILEGE_WITNESS_PASS"
    except (WitnessFailure, OwnerAuthorityError, OSError) as error:
        findings["result"] = "SYNTHETIC_PRIVILEGE_WITNESS_FAIL"
        findings["failure"] = f"{type(error).__name__}: {error}"
    finally:
        if broker is not None:
            broker.close()
        shutil.rmtree(root, ignore_errors=True)
    print(json.dumps(findings, indent=2, sort_keys=True))
    return 0 if findings["result"] == "SYNTHETIC_PRIVILEGE_WITNESS_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
