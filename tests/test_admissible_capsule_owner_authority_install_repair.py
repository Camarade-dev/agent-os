"""Install-repair coverage for the external owner-authority launch blockers.

Provider-free.  No public model/API.  No real Codex authentication content.
Privileged mutation tests skip outside a disposable user namespace.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest

from admissible.capsule.common import fingerprint
from admissible.capsule.owner_authority import (
    BROKER_OPERATIONS,
    DEPLOYMENT_ARTIFACT_PATH,
    OwnerAuthorityInstallation,
    OwnerAuthorityInstallerError,
    PRODUCTION_CONFIGURATION_ROOT,
    PRODUCTION_LAYOUT,
    PRODUCTION_RUNTIME_ROOT,
    PRODUCTION_STATE_ROOT,
    RECOMMENDED_LAUNCHER_USERNAME,
    attest_synthetic_non_production_installation,
    auth_boundary_identity_integration_note,
    broker_unit_definition,
    build_broker_deployment_artifact,
    build_installation_record,
    host_readiness_report,
    launcher_account_creation_commands,
    perform_installation,
    perform_rollback_failed_install,
    perform_uninstall,
    production_layout,
    refuse_symlink_or_special_targets,
    synthetic_non_production_layout,
    validate_authorized_launcher,
    validate_service_unit_text,
    verify_deployment_artifact,
)
from admissible.capsule.owner_authority.installer import (
    _remove_tree_no_follow,
    installation_plan,
)
from admissible.capsule.owner_authority.installation import (
    INITIAL_CRYPTO_ATTESTATION_REVISION,
)
from admissible.capsule.owner_authority.provisioner import (
    OwnerAuthorityProvisioningError,
    owner_payload_summary,
    phrase_fd_from_ask_password,
    read_owner_phrase_from_descriptor,
)
from admissible.capsule.owner_authorization import zero_retry_policy
from admissible.capsule.owner_authority.signing import discover_system_openssl
from tests._candidate_canary_binding import PRIVILEGED_IDENTITY_REASON

privileged = pytest.mark.skipif(
    os.geteuid() != 0, reason=PRIVILEGED_IDENTITY_REASON
)




def test_configuration_root_symlink_attack_is_refused(tmp_path: Path):
    root = tmp_path / "world"
    root.mkdir()
    real = tmp_path / "attacker-controlled"
    real.mkdir()
    layout = synthetic_non_production_layout(root)
    # Plant a symlink at the configuration root before install.
    layout.configuration_root.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(real, layout.configuration_root)
    with pytest.raises(OwnerAuthorityInstallerError, match="symlink"):
        refuse_symlink_or_special_targets(layout)


def test_validated_production_ignores_overridable_is_production(tmp_path: Path):
    class FakeLayout:
        classification = PRODUCTION_LAYOUT
        configuration_root = tmp_path / "etc"
        state_root = tmp_path / "var"
        runtime_root = tmp_path / "run"

        @property
        def is_production(self) -> bool:
            return True

        @property
        def installation_record_path(self):
            return self.configuration_root / "installation-v1.json"

        @property
        def public_key_path(self):
            return self.configuration_root / "key.pub"

        def validated(self):
            return self

    # Even a subclass claiming is_production cannot satisfy validated_production
    # unless the fixed production paths and record agree.
    openssl = discover_system_openssl()
    layout = production_layout()
    record = build_installation_record(
        layout=layout,
        installation_id="a" * 16,
        signing_key_fingerprint="b" * 64,
        public_key_sha256="c" * 64,
        cryptographic_executable_identity=openssl,
        authorized_launcher_uid=1000,
        authorized_launcher_gid=1000,
        installer_uid=0,
    )
    fake = OwnerAuthorityInstallation(
        layout=FakeLayout(),  # type: ignore[arg-type]
        record=record,
        record_file_identity={
            "path": str(layout.installation_record_path),
            "sha256": "d" * 64,
            "device": 1,
            "inode": 1,
            "owner_uid": 0,
            "owner_gid": 0,
            "mode": 0o444,
            "size": 10,
            "file_type": "regular",
            "link_count": 1,
        },
        public_key_file_identity={
            "path": str(layout.public_key_path),
            "sha256": "c" * 64,
            "device": 1,
            "inode": 2,
            "owner_uid": 0,
            "owner_gid": 0,
            "mode": 0o444,
            "size": 10,
            "file_type": "regular",
            "link_count": 1,
        },
        public_key_pem=b"-----BEGIN PUBLIC KEY-----\nM\n-----END PUBLIC KEY-----\n",
        installation_identity="e" * 64,
    )
    with pytest.raises(Exception):
        fake.validated_production()


def test_service_unit_static_validation_requires_artifact_and_restart():
    unit = broker_unit_definition(production_layout())
    assert validate_service_unit_text(unit)["valid"] is True
    assert str(DEPLOYMENT_ARTIFACT_PATH) in unit
    with pytest.raises(OwnerAuthorityInstallerError):
        validate_service_unit_text("Type=simple\nRestart=no\n")


def test_deployment_artifact_contains_no_secrets(tmp_path: Path):
    output = tmp_path / "broker.pyz"
    result = build_broker_deployment_artifact(output)
    assert result["sha256"]
    verified = verify_deployment_artifact(output, expected_sha256=result["sha256"])
    assert verified["verified"] is True
    import zipfile

    names = "\n".join(zipfile.ZipFile(output).namelist()).lower()
    assert "owner-authority-signing-key.v1.pem" not in names
    assert "/auth.json" not in names
    assert "_agent-runs" not in names


def test_owner_summary_refuses_missing_fields():
    with pytest.raises(OwnerAuthorityProvisioningError, match="SUMMARY_INCOMPLETE"):
        owner_payload_summary({"run_id": "only-run"})
    with pytest.raises(Exception, match="uid 0"):
        validate_authorized_launcher(
            username="root",
            uid=0,
            gid=0,
            shell="/usr/sbin/nologin",
            allow_interactive_shell=False,
        )
    with pytest.raises(Exception, match="privileged groups"):
        validate_authorized_launcher(
            username="stris",
            uid=1000,
            gid=1000,
            shell="/usr/sbin/nologin",
            allow_interactive_shell=False,
            privileged_groups=("sudo", "docker"),
            group_names={"sudo", "users"},
        )
    commands = launcher_account_creation_commands()
    assert any(RECOMMENDED_LAUNCHER_USERNAME in item for item in commands)
    note = auth_boundary_identity_integration_note()
    assert note["credential_bytes_exposed_to_launcher"] is False
    assert note["status"] == "RUNBOOK_EXECUTABLE_REQUIRES_HOST_SETUP"
    assert note["never_run_as"] == ["stris"]


def test_phrase_channel_refuses_empty_nul_and_oversized():
    read_end, write_end = os.pipe()
    os.close(write_end)
    with pytest.raises(OwnerAuthorityProvisioningError):
        read_owner_phrase_from_descriptor(read_end)

    read_end, write_end = os.pipe()
    os.write(write_end, b"has\x00nulllll")
    os.close(write_end)
    with pytest.raises(OwnerAuthorityProvisioningError):
        read_owner_phrase_from_descriptor(read_end)

    read_end, write_end = os.pipe()
    os.write(write_end, b"x" * 5000)
    os.close(write_end)
    with pytest.raises(OwnerAuthorityProvisioningError):
        read_owner_phrase_from_descriptor(read_end)


def _valid_owner_payload() -> dict:
    return {
        "schema_version": "synthetic_external_owner_authority_payload_v1",
        "repository_head": "a" * 40,
        "repository_canonical_path_sha256": "1" * 64,
        "implementation_head": "b" * 40,
        "run_id": "external-owner-authority-run-1",
        "mission_fingerprint": "c" * 64,
        "model_binding_policy": {
            "configured_model": "gpt-5.3-codex",
            "configured_reasoning_effort": "high",
        },
        "destination_manifest_identity": "d" * 64,
        "tool_authority_identity": "e" * 64,
        "budgets": {"wall_clock_seconds": 600, "capsule_pids": 64},
        "zero_retry_policy": zero_retry_policy(),
    }


def test_owner_summary_requires_repository_identity_and_zero_retry_policy():
    summary = owner_payload_summary(_valid_owner_payload())
    assert summary["repository_identity"] == "1" * 64
    assert summary["payload_fingerprint"]
    assert summary["retries_authorized"] == 0
    assert summary["repairs_authorized"] == 0
    assert summary["launches_authorized"] == 1

def test_remove_tree_no_follow_does_not_follow_directory_symlink(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("must-not-delete", encoding="utf-8")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "inside.txt").write_text("remove-me", encoding="utf-8")
    link = tree / "escape"
    os.symlink(outside, link)
    _remove_tree_no_follow(tree)
    assert not tree.exists()
    assert secret.read_text(encoding="utf-8") == "must-not-delete"


@privileged
def test_rollback_failed_install_removes_incomplete_state_and_refuses_complete(
    tmp_path: Path,
):
    root = Path(tempfile.mkdtemp(prefix="oa-rb-failed-"))
    layout = synthetic_non_production_layout(root)

    class FakeServiceManager:
        def __init__(self):
            self.calls = []

        def stop_broker_unit(self, unit_name="admissible-owner-authority-broker-v1.service"):
            self.calls.append("stop")
            return {"action": "stop", "skipped": True}

        def disable_broker_unit(self, unit_name="admissible-owner-authority-broker-v1.service"):
            self.calls.append("disable")
            return {"action": "disable", "skipped": True}

        def reload_systemd(self):
            self.calls.append("reload")
            return {"action": "daemon-reload", "skipped": True}

    manager = FakeServiceManager()
    noop = perform_rollback_failed_install(layout=layout, service_manager=manager)
    assert noop["idempotent_noop"] is True

    layout.private_directory.mkdir(parents=True)
    layout.private_key_path.write_text("private", encoding="utf-8")
    rolled = perform_rollback_failed_install(layout=layout, service_manager=manager)
    assert rolled["rolled_back"] is True
    assert not layout.private_key_path.exists()

    perform_installation(
        layout=layout,
        installation_id="rollbackrefuse01",
        authorized_launcher_uid=os.getuid(),
        authorized_launcher_gid=os.getgid(),
        install_unit=False,
    )
    with pytest.raises(OwnerAuthorityInstallerError, match="complete installation"):
        perform_rollback_failed_install(layout=layout, service_manager=manager)


@privileged
def test_transactional_install_injects_failure_at_every_checkpoint(tmp_path: Path):
    checkpoints = (
        "after_directory:private",
        "after_signing_identity",
        "before_publication",
        "after_record_published",
        "after_final_attestation",
    )
    for checkpoint in checkpoints:
        root = Path(tempfile.mkdtemp(prefix="oa-crash-"))
        layout = synthetic_non_production_layout(root)

        def crash(name: str, expected: str = checkpoint) -> None:
            if name == expected:
                raise RuntimeError(f"injected crash at {expected}")

        with pytest.raises(RuntimeError, match="injected crash"):
            perform_installation(
                layout=layout,
                installation_id=f"crash-{checkpoint[:8]}",
                authorized_launcher_uid=os.getuid(),
                authorized_launcher_gid=os.getgid(),
                install_unit=False,
                crash_hook=crash,
            )
        assert not layout.installation_record_path.exists()
        assert not layout.private_key_path.exists()


@privileged
def test_transactional_install_rolls_back_after_injected_failure(tmp_path: Path):
    root = Path(tempfile.mkdtemp(prefix="oa-rb-"))
    layout = synthetic_non_production_layout(root)

    def crash(checkpoint: str) -> None:
        if checkpoint == "after_signing_identity":
            raise RuntimeError("injected crash after signing identity")

    with pytest.raises(RuntimeError, match="injected crash"):
        perform_installation(
            layout=layout,
            installation_id="rollbacktest0001",
            authorized_launcher_uid=os.getuid(),
            authorized_launcher_gid=os.getgid(),
            install_unit=False,
            crash_hook=crash,
        )
    assert not layout.installation_record_path.exists()
    assert not layout.private_key_path.exists()
    assert not layout.public_key_path.exists()


@privileged
def test_transactional_install_and_uninstall_preserve_or_destroy(tmp_path: Path):
    root = Path(tempfile.mkdtemp(prefix="oa-un-"))
    layout = synthetic_non_production_layout(root)
    perform_installation(
        layout=layout,
        installation_id="uninstalltest0001",
        authorized_launcher_uid=os.getuid(),
        authorized_launcher_gid=os.getgid(),
        install_unit=False,
    )
    installation = attest_synthetic_non_production_installation(layout)
    assert installation.crypto_attestation_revision() == (
        INITIAL_CRYPTO_ATTESTATION_REVISION
    )
    pending_dir = layout.authorizations_root / ("cd" * 32)
    pending_dir.mkdir()
    (pending_dir / "pending.json").write_text("{}", encoding="utf-8")
    with pytest.raises(OwnerAuthorityInstallerError, match="pending"):
        perform_uninstall(
            layout=layout,
            mode="PRESERVE_SIGNING_IDENTITY",
            acknowledge_destructive_pending_state=False,
            remove_unit=False,
        )
    result = perform_uninstall(
        layout=layout,
        mode="DESTROY_SIGNING_IDENTITY",
        acknowledge_destructive_pending_state=True,
        remove_unit=False,
    )
    assert result["physical_media_sanitization_performed"] is False
    assert result["authorization_inventory"]["pending"] == [pending_dir.name]
    assert "signing_key_destroyed_note" in result
    assert not layout.private_key_path.exists()


def test_host_readiness_distinguishes_code_defects_from_host_prerequisites():
    report = host_readiness_report()
    assert report["schema_version"] == "admissible_owner_authority_host_readiness_v1"
    assert report["overall"] in {
        "PASS",
        "HOST_PREREQUISITES_MISSING",
        "CODE_DEFECT",
    }
    assert "phrase_entry_recipe" in {item["id"] for item in report["canary_conditions"]}
    recipe = next(
        item
        for item in report["canary_conditions"]
        if item["id"] == "phrase_entry_recipe"
    )
    assert recipe["status"] == "PASS"
    assert "3<&0" not in phrase_fd_from_ask_password(owner_payload_path="/tmp/p.json")
    assert "3< <(cat)" not in phrase_fd_from_ask_password(
        owner_payload_path="/tmp/p.json"
    )


@privileged
def test_broker_request_stop_and_fatal_serve_error(tmp_path: Path):
    from admissible.capsule.owner_authority.broker import OwnerAuthorityBroker

    root = Path(tempfile.mkdtemp(prefix="oa-broker-life-"))
    layout = synthetic_non_production_layout(root)
    perform_installation(
        layout=layout,
        installation_id="brokerlifetest01",
        authorized_launcher_uid=os.getuid(),
        authorized_launcher_gid=os.getgid(),
        install_unit=False,
    )
    installation = attest_synthetic_non_production_installation(layout)
    broker = OwnerAuthorityBroker(installation)
    broker.bind()
    broker.request_stop()
    broker.serve_forever()
    broker.close()


def test_crypto_revision_refuses_arbitrary_executable_path():
    from admissible.capsule.owner_authority.crypto_revision import (
        OwnerAuthorityCryptoRevisionError,
        attest_candidate_executable,
    )

    with pytest.raises(
        OwnerAuthorityCryptoRevisionError, match="not one of the fixed candidate"
    ):
        attest_candidate_executable(Path("/bin/ls"))


def test_crypto_revision_refuses_a_byte_identical_copy_at_another_path(
    tmp_path: Path,
):
    """A copy of the real openssl elsewhere never validates: only the fixed
    candidate path is ever attested, regardless of the bytes at another path.
    """

    from admissible.capsule.owner_authority.crypto_revision import (
        OwnerAuthorityCryptoRevisionError,
        attest_candidate_executable,
    )

    real = Path("/usr/bin/openssl")
    copy_path = tmp_path / "openssl"
    copy_path.write_bytes(real.read_bytes())
    copy_path.chmod(0o755)
    with pytest.raises(
        OwnerAuthorityCryptoRevisionError, match="not one of the fixed candidate"
    ):
        attest_candidate_executable(copy_path)


def test_crypto_revision_probes_real_ed25519_capability():
    from admissible.capsule.owner_authority.crypto_revision import (
        attest_candidate_executable,
        probe_ed25519_capability,
    )

    candidate = attest_candidate_executable(Path("/usr/bin/openssl"))
    probe = probe_ed25519_capability(candidate)
    assert probe["verified"] is True
    assert probe["algorithm"] == "ed25519"


def test_crypto_revision_validate_rejects_a_tampered_revision():
    from admissible.capsule.common import fingerprint
    from admissible.capsule.owner_authority.crypto_revision import (
        CRYPTO_ATTESTATION_REVISION_SCHEMA_VERSION,
        OwnerAuthorityCryptoRevisionError,
        attest_candidate_executable,
        probe_ed25519_capability,
        validate_crypto_attestation_revision,
    )

    candidate = attest_candidate_executable(Path("/usr/bin/openssl"))
    body = {
        "schema_version": CRYPTO_ATTESTATION_REVISION_SCHEMA_VERSION,
        "revision_id": "crypto-attestation-" + "a" * 32,
        "installation_id": "f" * 16,
        "installation_identity": "1" * 64,
        "signing_key_fingerprint": "2" * 64,
        "public_key_sha256": "3" * 64,
        "previous_crypto_attestation_revision": INITIAL_CRYPTO_ATTESTATION_REVISION,
        "owner_confirmed_sha256": candidate["sha256"],
        "owner_confirmed_version": "3.0.0",
        "cryptographic_executable_identity": candidate,
        "ed25519_capability_probe": probe_ed25519_capability(candidate),
    }
    revision = {**body, "revision_identity": fingerprint(body)}
    # An unmodified, well-formed revision validates.
    assert validate_crypto_attestation_revision(revision)["revision_id"] == (
        body["revision_id"]
    )
    # An attacker who rewrites so much as the confirmed version after the
    # fact --- without recomputing the fingerprint --- is caught.
    tampered = dict(revision)
    tampered["owner_confirmed_version"] = "9.9.9-attacker"
    with pytest.raises(OwnerAuthorityCryptoRevisionError, match="fingerprint"):
        validate_crypto_attestation_revision(tampered)


def test_broker_has_no_crypto_attestation_revision_rpc():
    """No runtime broker operation can request, propose or commit a revision.

    A concurrently-running broker only ever reads the one committed
    ``crypto_attestation_revision`` field off the installation record it
    re-attests on every use; there is no operation in the closed broker
    vocabulary that lets any caller --- including a legitimate launcher ---
    ask the broker to revise, rotate or otherwise touch it.
    """

    for name in BROKER_OPERATIONS:
        assert "CRYPTO" not in name
        assert "REVIS" not in name
        assert "OPENSSL" not in name


@privileged
def test_crypto_revision_commits_and_refuses_rollback_and_foreign_installation(
    tmp_path: Path,
):
    from admissible.capsule.owner_authority.crypto_revision import (
        OwnerAuthorityCryptoRevisionError,
        build_crypto_attestation_revision,
        update_installation_cryptographic_identity,
    )

    openssl = discover_system_openssl()

    def _install(prefix: str):
        root = Path(tempfile.mkdtemp(prefix=prefix))
        layout = synthetic_non_production_layout(root)
        perform_installation(
            layout=layout,
            installation_id=(prefix.replace("-", "")[:16]).ljust(16, "0"),
            authorized_launcher_uid=os.getuid(),
            authorized_launcher_gid=os.getgid(),
            install_unit=False,
        )
        return layout, attest_synthetic_non_production_installation(layout)

    layout, installation = _install("oa-crypto-a-")
    other_layout, other_installation = _install("oa-crypto-b-")

    sha256 = openssl["sha256"]
    revision_1 = build_crypto_attestation_revision(
        installation=installation,
        new_executable_path=Path("/usr/bin/openssl"),
        owner_confirmed_sha256=sha256,
        owner_confirmed_version="3.0.0-test-revision-1",
    )
    committed = update_installation_cryptographic_identity(
        layout=layout, installation=installation, revision=revision_1
    )
    assert committed["crypto_attestation_revision"] == revision_1["revision_id"]

    reattested = attest_synthetic_non_production_installation(layout)
    assert reattested.crypto_attestation_revision() == revision_1["revision_id"]
    assert reattested.signing_key_fingerprint == installation.signing_key_fingerprint
    assert reattested.installation_identity == installation.installation_identity

    # Rollback attack: replay the *first* revision (whose "previous" points at
    # the initial revision) against the now-updated installation.  It no
    # longer chains from the currently committed revision, so it is refused.
    with pytest.raises(OwnerAuthorityCryptoRevisionError, match="stale|rollback"):
        update_installation_cryptographic_identity(
            layout=layout, installation=reattested, revision=revision_1
        )

    # Foreign-installation attack: a revision honestly built for a *different*
    # installation must never apply to this one.
    foreign_revision = build_crypto_attestation_revision(
        installation=other_installation,
        new_executable_path=Path("/usr/bin/openssl"),
        owner_confirmed_sha256=sha256,
        owner_confirmed_version="3.0.0-test-foreign",
    )
    with pytest.raises(
        OwnerAuthorityCryptoRevisionError, match="another installation"
    ):
        update_installation_cryptographic_identity(
            layout=layout, installation=reattested, revision=foreign_revision
        )

    # Pending-authorization attack: once an authorization is in flight, no
    # revision may publish underneath it even if otherwise well-formed.
    pending_dir = layout.authorizations_root / ("ab" * 32)
    pending_dir.mkdir()
    (pending_dir / "pending.json").write_text("{}", encoding="utf-8")
    revision_2 = build_crypto_attestation_revision(
        installation=reattested,
        new_executable_path=Path("/usr/bin/openssl"),
        owner_confirmed_sha256=sha256,
        owner_confirmed_version="3.0.0-test-revision-2",
    )
    with pytest.raises(OwnerAuthorityCryptoRevisionError, match="pending"):
        update_installation_cryptographic_identity(
            layout=layout, installation=reattested, revision=revision_2
        )


def test_phrase_fd_preserves_stdin_for_fingerprint_confirmation():
    from admissible.capsule.owner_authority.provisioner import (
        ASK_PASSWORD_PROMPT,
        phrase_fd_from_ask_password,
    )

    command = phrase_fd_from_ask_password(owner_payload_path="/tmp/payload.json")
    assert "exec 3<" in command
    assert "--phrase-fd 3" in command
    assert "--echo=no" in command
    assert ASK_PASSWORD_PROMPT in command
    assert "--phrase-fd 0" not in command
    assert "--no-tty" not in command
    assert "| sudo" not in command


def test_phrase_and_confirmation_use_separate_streams(tmp_path: Path):
    """Fingerprint confirmation reads stdin; phrase arrives on a dedicated FD."""

    from admissible.capsule.owner_authority.provisioner import (
        read_owner_phrase_from_descriptor,
    )

    phrase = "owner-phrase-for-separate-stream-test"
    read_end, write_end = os.pipe()
    os.write(write_end, (phrase + "\n").encode("utf-8"))
    os.close(write_end)
    # Stdin remains free for a confirmation stream.
    confirmation = "confirmed-fingerprint\n"
    confirmation_read, confirmation_write = os.pipe()
    os.write(confirmation_write, confirmation.encode("utf-8"))
    os.close(confirmation_write)
    observed_phrase = read_owner_phrase_from_descriptor(read_end)
    observed_confirmation = os.read(confirmation_read, 4096).decode("utf-8")
    os.close(confirmation_read)
    assert observed_phrase == phrase
    assert observed_confirmation == confirmation


def test_generated_plan_commands_parse_against_real_cli():
    from admissible.capsule.owner_authority.installer import installation_plan
    import argparse

    plan = installation_plan(
        authorized_launcher_uid=1001,
        authorized_launcher_gid=1001,
        launcher_username="admissible-launcher",
        launcher_group="admissible-launcher",
        deployment_artifact_path="/tmp/admissible-broker.pyz",
        deployment_artifact_sha256="a" * 64,
    )
    install_cmd = plan["install_commands"][2]
    parts = install_cmd.split()
    parser_argv = parts[parts.index("-m") + 2 :]
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install")
    install_parser.add_argument("--authorized-launcher", required=True)
    install_parser.add_argument("--installation-id", default=None)
    install_parser.add_argument("--deployment-artifact", required=True, type=Path)
    install_parser.add_argument("--deployment-artifact-sha256", required=True)
    args = parser.parse_args(parser_argv)
    assert args.command == "install"
    assert args.authorized_launcher == "admissible-launcher"
    assert args.deployment_artifact_sha256 == "a" * 64

    rollback_cmd = plan["uninstall_commands"][2]
    rollback_parts = rollback_cmd.split()
    rollback_argv = rollback_parts[rollback_parts.index("-m") + 2 :]
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("rollback-failed-install")
    rargs = parser.parse_args(rollback_argv)
    assert rargs.command == "rollback-failed-install"

    uninstall_cmd = plan["uninstall_commands"][3]
    uninstall_parts = uninstall_cmd.split()
    uninstall_argv = uninstall_parts[uninstall_parts.index("-m") + 2 :]
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    uninstall_parser = commands.add_parser("uninstall")
    mode = uninstall_parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preserve-signing-identity", action="store_true")
    mode.add_argument("--destroy-signing-identity", action="store_true")
    uninstall_parser.add_argument(
        "--acknowledge-destructive-pending-state", action="store_true"
    )
    uargs = parser.parse_args(uninstall_argv)
    assert uargs.preserve_signing_identity is True
    assert uargs.acknowledge_destructive_pending_state is True

    assert "--phrase-fd 3" in plan["provisioning_command"]
    assert "daemon-reload" in plan["broker_commands"]


def test_auth_wrapper_runbook_never_falls_back_to_stris():
    from admissible.capsule.owner_authority.auth_wrapper import (
        auth_wrapper_runbook,
        validate_auth_wrapper_plan,
        AuthWrapperError,
    )

    runbook = auth_wrapper_runbook()
    assert "stris" in runbook["never_run_as"]
    assert runbook["credential_bytes_exposed_to_launcher"] is False
    with pytest.raises(AuthWrapperError, match="stris"):
        validate_auth_wrapper_plan(
            durable_auth_source=Path("/tmp/missing-auth.json"),
            launcher_username="stris",
        )
