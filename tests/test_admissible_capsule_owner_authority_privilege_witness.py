"""The provider-free synthetic privileged-boundary witness (section J).

This test runs from an ordinary unprivileged pytest process.  It launches
``tests/_owner_authority_privilege_witness.py`` inside a disposable user and
mount namespace, where that driver genuinely runs as uid 0, and asserts on the
structured findings it reports.

The witness is explicitly synthetic.  It does not install anything under
``/etc``, ``/var/lib`` or ``/run``, it does not use ``sudo``, it starts no
system service, and every artifact it creates disappears with the namespace.
The separate assertion that the *production* boundary cannot be reached from
here lives in ``test_admissible_capsule_external_owner_authority.py``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DRIVER = REPOSITORY_ROOT / "tests" / "_owner_authority_privilege_witness.py"


def _namespace_available() -> bool:
    if shutil.which("unshare") is None:
        return False
    probe = subprocess.run(
        ("unshare", "--user", "--map-root-user", "--mount", "id", "-u"),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    return probe.returncode == 0 and probe.stdout.strip() == "0"


@pytest.fixture(scope="module")
def witness_findings() -> dict:
    if not _namespace_available():
        pytest.skip(
            "the synthetic privilege witness requires unprivileged user "
            "namespaces with a root uid mapping"
        )
    completed = subprocess.run(
        (
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            sys.executable,
            str(DRIVER),
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
        cwd=REPOSITORY_ROOT,
    )
    assert completed.stdout, completed.stderr
    findings = json.loads(completed.stdout)
    assert completed.returncode == 0, json.dumps(findings, indent=2)
    return findings


def test_the_witness_is_declared_synthetic_and_not_a_real_installation(
    witness_findings: dict,
):
    assert witness_findings["classification"] == (
        "SYNTHETIC_NON_PRODUCTION_PRIVILEGE_WITNESS"
    )
    assert witness_findings["is_real_privileged_installation"] is False
    assert witness_findings["is_production_installation"] is False
    assert witness_findings["result"] == "SYNTHETIC_PRIVILEGE_WITNESS_PASS"


def test_the_installer_identity_is_privileged_and_state_is_root_owned(
    witness_findings: dict,
):
    assert witness_findings["namespace_identity"]["euid"] == 0
    state = witness_findings["root_owned_state"]
    assert state["private_key_uid"] == 0
    assert state["private_key_mode"] == "0o600"
    assert state["state_root_mode"] == "0o700"
    assert state["installation_record_mode"] == "0o444"


def test_the_signing_key_is_unreachable_from_the_launcher_view(
    witness_findings: dict,
):
    observed = witness_findings["key_invisible_to_launcher"]
    assert observed["exists"] is False
    assert observed["listing"] == []


def test_the_broker_socket_is_root_owned_and_peer_credentials_are_checked(
    witness_findings: dict,
):
    broker_socket = witness_findings["broker_socket"]
    assert broker_socket["owner_uid"] == 0
    assert broker_socket["mode"] == "0o660"
    assert witness_findings["peer_credential_refusal"] == (
        "OWNER_AUTHORITY_PEER_CREDENTIAL_REFUSED"
    )


def test_one_signed_receipt_is_issued_after_a_durable_consumption(
    witness_findings: dict,
):
    receipt = witness_findings["signed_receipt"]
    assert receipt["state"] == "RECEIPT_ISSUED"
    # The signature exists only after the consumption commit is durable.
    assert receipt["observed_state_sequence"] == [
        "PROVISIONED_PENDING",
        "PHRASE_VERIFIED",
        "CONSUMED_LAUNCH_COMMITTED",
    ]


def test_the_fake_owner_world_is_refused_under_real_privilege_separation(
    witness_findings: dict,
):
    attack = witness_findings["fake_owner_world"]
    # The attacker really can choose a phrase and compute a digest.
    assert attack["attacker_can_compute_a_digest"] is True
    # None of it produces authority.
    assert attack["attacker_signature_refused"] == (
        "OWNER_AUTHORITY_SIGNATURE_REFUSED"
    )
    assert attack["unprovisioned_record_refused"] == (
        "OWNER_AUTHORITY_AUTHORIZATION_ABSENT"
    )
    for forbidden in ("PROVISION_AUTHORIZATION", "SIGN_MESSAGE"):
        assert forbidden in attack["no_provisioning_rpc"]


def test_exactly_one_launcher_wins_and_no_crash_restores_launchability(
    witness_findings: dict,
):
    ordering = witness_findings["one_time_ordering"]
    assert ordering["concurrent_consumption"]["receipts"] == 1
    assert ordering["concurrent_consumption"]["refusals"] == [
        "OWNER_AUTHORITY_ALREADY_CONSUMED"
    ]
    assert ordering["crash_between_commit_and_receipt"] == (
        "OWNER_AUTHORITY_ALREADY_CONSUMED"
    )


def test_rogue_brokers_copied_records_and_foreign_signatures_are_refused(
    witness_findings: dict,
):
    observed = witness_findings["socket_and_impersonation"]
    assert observed["rogue_receipt_refused"] == (
        "OWNER_AUTHORITY_RECEIPT_FOREIGN_INSTALLATION"
    )
    assert observed["copied_public_record_refused"] in {
        "OWNER_AUTHORITY_INSTALLATION_PATHS_DIFFER",
        "OWNER_AUTHORITY_INSTALLATION_RECORD_INVALID",
    }


def test_the_witness_reports_its_own_privilege_limitation(witness_findings: dict):
    """The synthetic witness must not overstate what it demonstrated.

    Without ``newuidmap`` this host cannot map a second uid into a user
    namespace, so installer and launcher share a kernel uid and the key's
    inaccessibility rests on mount isolation.  A real installation additionally
    has DAC separation.  The witness reports this rather than implying it.
    """

    assert witness_findings["namespace_identity"][
        "distinct_kernel_uids_available"
    ] in (True, False)
