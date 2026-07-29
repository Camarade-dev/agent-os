"""Provider-free unit tests for capsule backend and provider-output contracts.

No provider, model, Docker, or network transport is invoked anywhere in
this module: every object is constructed directly from in-memory values.
"""

from __future__ import annotations

import dataclasses

import pytest

from admissible.capsule.backend import CapsuleAuthority, CapsuleBackend, CapsuleTerminalClassification
from admissible.capsule.models import (
    ByteTreeObservation,
    CleanupResult,
    ObservedEntry,
    ProcessResult,
    ProviderCompletionClaim,
    ProviderOutput,
    ProviderTerminalClassification,
    TransportResult,
    WorkspaceReference,
)


def _authority() -> CapsuleAuthority:
    return CapsuleAuthority.create(
        backend_kind="linux_capsule_v1",
        capsule_image_identity="sha256:" + "a" * 64,
        mission_fingerprint="b" * 64,
    )


def _workspace(authority: CapsuleAuthority) -> WorkspaceReference:
    return WorkspaceReference.create(
        workspace_id="workspace-001",
        capsule_authority_fingerprint=authority.authority_fingerprint,
        host_owned=False,
    )


def _observation() -> ByteTreeObservation:
    entries = (
        ObservedEntry(relative_path="index.html", kind="regular", size=12, sha256="c" * 64),
        ObservedEntry(relative_path="src", kind="directory", size=0, sha256=None),
    )
    return ByteTreeObservation.create(entries=entries)


def _clean_output(authority: CapsuleAuthority, *, exit_code: int = 0, timed_out: bool = False) -> ProviderOutput:
    return ProviderOutput.create(
        capsule_authority_fingerprint=authority.authority_fingerprint,
        workspace=_workspace(authority),
        observation=_observation(),
        process_result=ProcessResult(
            schema_version="admissible_capsule_process_result_v1",
            exit_code=None if timed_out else exit_code,
            timed_out=timed_out,
            signal=None,
        ),
        transport_result=TransportResult(
            schema_version="admissible_capsule_transport_result_v1",
            transport_kind="loopback_relay_v1",
            connected=True,
            closed_cleanly=True,
        ),
        cleanup_result=CleanupResult(
            schema_version="admissible_capsule_cleanup_result_v1",
            workspace_removed=True,
            processes_reaped=True,
        ),
        completion_claim=ProviderCompletionClaim(
            schema_version="admissible_capsule_provider_completion_claim_v1",
            claimed_complete=True,
            claim_text="provider claims the mission is complete",
        ),
    )


def test_capsule_authority_is_immutable_and_fingerprinted():
    authority = _authority()
    with pytest.raises(dataclasses.FrozenInstanceError):
        authority.backend_kind = "other"  # type: ignore[misc]
    assert CapsuleAuthority.from_dict(authority.to_dict()) == authority


def test_capsule_backend_is_an_abstract_interface_with_no_provider_coupling():
    assert CapsuleBackend.__abstractmethods__ >= {"authority", "prepare_workspace", "run", "cleanup"}
    import inspect

    text = inspect.getsource(__import__("admissible.capsule.backend", fromlist=["CapsuleBackend"]))
    for forbidden in ("docker", "neon", "cursor", "openai", "codex"):
        assert forbidden not in text.lower(), f"backend interface must stay provider/transport-agnostic ({forbidden})"


def test_provider_output_has_no_git_commit_field():
    field_names = {field.name for field in dataclasses.fields(ProviderOutput)}
    assert not any("commit" in name or "git" in name for name in field_names)


def test_provider_output_workspace_must_match_capsule_authority():
    authority = _authority()
    other_authority = CapsuleAuthority.create(
        backend_kind="linux_capsule_v1", capsule_image_identity="sha256:" + "d" * 64, mission_fingerprint="e" * 64
    )
    with pytest.raises(ValueError):
        ProviderOutput.create(
            capsule_authority_fingerprint=other_authority.authority_fingerprint,
            workspace=_workspace(authority),
            observation=_observation(),
            process_result=ProcessResult(
                schema_version="admissible_capsule_process_result_v1", exit_code=0, timed_out=False, signal=None
            ),
            transport_result=TransportResult(
                schema_version="admissible_capsule_transport_result_v1",
                transport_kind="loopback_relay_v1",
                connected=True,
                closed_cleanly=True,
            ),
            cleanup_result=CleanupResult(
                schema_version="admissible_capsule_cleanup_result_v1", workspace_removed=True, processes_reaped=True
            ),
            completion_claim=ProviderCompletionClaim(
                schema_version="admissible_capsule_provider_completion_claim_v1",
                claimed_complete=True,
                claim_text="x",
            ),
        )


def test_provider_completion_claim_is_never_authoritative_on_its_own():
    authority = _authority()
    output = _clean_output(authority, exit_code=1)
    assert output.completion_claim.claimed_complete is True
    # The provider's own claim disagrees with the observed nonzero exit code;
    # the frozen record preserves both without letting the claim win.
    assert output.terminal_classification == ProviderTerminalClassification.EXITED_NONZERO


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        ({}, ProviderTerminalClassification.RAN_TO_COMPLETION_CLAIM),
        ({"exit_code": 1}, ProviderTerminalClassification.EXITED_NONZERO),
        ({"timed_out": True}, ProviderTerminalClassification.TIMED_OUT),
    ],
)
def test_provider_output_terminal_classification(kwargs, expected):
    authority = _authority()
    output = _clean_output(authority, **kwargs)
    assert output.terminal_classification == expected


def test_provider_output_transport_lost_classification():
    authority = _authority()
    output = ProviderOutput.create(
        capsule_authority_fingerprint=authority.authority_fingerprint,
        workspace=_workspace(authority),
        observation=_observation(),
        process_result=ProcessResult(
            schema_version="admissible_capsule_process_result_v1", exit_code=0, timed_out=False, signal=None
        ),
        transport_result=TransportResult(
            schema_version="admissible_capsule_transport_result_v1",
            transport_kind="loopback_relay_v1",
            connected=True,
            closed_cleanly=False,
        ),
        cleanup_result=CleanupResult(
            schema_version="admissible_capsule_cleanup_result_v1", workspace_removed=True, processes_reaped=True
        ),
        completion_claim=ProviderCompletionClaim(
            schema_version="admissible_capsule_provider_completion_claim_v1", claimed_complete=True, claim_text="x"
        ),
    )
    assert output.terminal_classification == ProviderTerminalClassification.TRANSPORT_LOST


def test_provider_output_cleanup_unconfirmed_classification():
    authority = _authority()
    output = ProviderOutput.create(
        capsule_authority_fingerprint=authority.authority_fingerprint,
        workspace=_workspace(authority),
        observation=_observation(),
        process_result=ProcessResult(
            schema_version="admissible_capsule_process_result_v1", exit_code=0, timed_out=False, signal=None
        ),
        transport_result=TransportResult(
            schema_version="admissible_capsule_transport_result_v1",
            transport_kind="loopback_relay_v1",
            connected=True,
            closed_cleanly=True,
        ),
        cleanup_result=CleanupResult(
            schema_version="admissible_capsule_cleanup_result_v1", workspace_removed=False, processes_reaped=True
        ),
        completion_claim=ProviderCompletionClaim(
            schema_version="admissible_capsule_provider_completion_claim_v1", claimed_complete=True, claim_text="x"
        ),
    )
    assert output.terminal_classification == ProviderTerminalClassification.CLEANUP_UNCONFIRMED


def test_provider_output_round_trips_through_evidence_only_dict():
    authority = _authority()
    output = _clean_output(authority)
    reconstructed = ProviderOutput.from_dict(output.to_dict())
    assert reconstructed == output
    assert reconstructed.output_fingerprint == output.output_fingerprint


def test_provider_output_rejects_tampered_evidence():
    authority = _authority()
    output = _clean_output(authority)
    tampered = output.to_dict()
    tampered["process_result"]["exit_code"] = 1
    with pytest.raises(ValueError):
        ProviderOutput.from_dict(tampered)
