"""Untrusted Codex request observations and *candidate* witness evidence.

Everything in this module is candidate evidence.  A store, its store anchor,
its run anchors, its evidence packs, its receipts and its tail are all
self-produced: an ordinary caller who can write a directory can build a
completely fabricated but internally self-consistent store.  Nothing here is
therefore production authority, and the naming says so.

``SerializationWitnessRecord`` is deliberately only an observation.  Its
constructor is public because parsing captured request metadata is not a trust
operation.  No model authority or backend accepts a record, its fingerprint,
or the result of ``evaluate_serialization_witness`` as proof.

``CandidateSerializationWitnessStore.record_candidate_witness`` creates a run
anchor before execution, runs the content-attested Codex executable in a
private routeless bubblewrap namespace, validates the minimal child
observation, durably publishes and rereads the evidence pack, advances the
store tail, and returns an opaque ``CandidateSerializationWitnessReceipt``
alongside its ``CandidateSerializationWitnessPack``.  Loading a receipt always
reopens the pack and revalidates every identity.

None of that creates production authority.  The store cannot be its own trust
root: an internally generated hash or nonce is not an external anchor.  The
only production authority over this evidence is
``OwnerBoundVerifiedSerializationReceipt`` in
``admissible.capsule.owner_authorization``, which exists only after an owner
phrase delivered on its dedicated descriptor verifies an external owner payload
that canonically binds this store, this pack, this receipt, this tail, this
model policy, this preparation root and this run.
"""

from __future__ import annotations

import fcntl
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from admissible.capsule.common import (
    atomic_json,
    canonical_bytes,
    fingerprint,
    fsync_directory,
    require_bool,
    require_exact_keys,
    require_identifier,
    require_sha256,
    require_strict_int,
    sha256_bytes,
    strict_json_loads,
)
from admissible.capsule.execution_authority import (
    ExecutableFileIdentity,
    validate_component_identity_metadata,
)
from admissible.capsule.model_authority import (
    ModelConfigurationError,
    require_exact_model,
    require_exact_reasoning_effort,
)

if TYPE_CHECKING:
    from admissible.capsule.model_authority import ModelBindingPolicy


SERIALIZATION_WITNESS_SCHEMA_VERSION = (
    "admissible_codex_provider_free_serialization_observation_v2"
)
CANDIDATE_WITNESS_EVIDENCE_SCHEMA_VERSION = (
    "admissible_codex_candidate_serialization_evidence_pack_v2"
)
CANDIDATE_WITNESS_RECEIPT_SCHEMA_VERSION = (
    "admissible_codex_candidate_serialization_receipt_v2"
)
WITNESS_STORE_ANCHOR_SCHEMA_VERSION = (
    "admissible_codex_candidate_witness_store_anchor_v2"
)
WITNESS_RUN_ANCHOR_SCHEMA_VERSION = "admissible_codex_candidate_witness_run_anchor_v2"
WITNESS_STORE_TAIL_SCHEMA_VERSION = "admissible_codex_candidate_witness_store_tail_v2"
WITNESS_DURABILITY_RECEIPT_SCHEMA_VERSION = (
    "admissible_codex_candidate_witness_durability_receipt_v2"
)
ZERO_FINGERPRINT = "0" * 64

#: Every document this module writes carries this trust state.  It is the
#: module's own statement that its contents are candidate evidence and that no
#: production effect may be authorized by them alone.
CANDIDATE_WITNESS_TRUST_STATE = "UNTRUSTED_CANDIDATE_REQUIRES_OWNER_BINDING"

CAPTURED_FIELDS = (
    "request_path",
    "serialized_model",
    "serialized_reasoning_effort",
)
DENIED_CAPTURE = (
    "http_authorization",
    "prompt_text",
    "request_input_items",
    "request_instructions",
    "response_body",
    "unrelated_http_headers",
    "synthetic_token_contents",
)
WITNESS_REQUEST_PATH_SUFFIX = "/responses"
TRUSTED_WITNESS_EXACT_REQUEST_PATH = "/v1/responses"
SYNTHETIC_ENDPOINT_POLICY_IDENTITY = fingerprint(
    {
        "schema_version": "admissible_local_witness_endpoint_policy_v1",
        "address": "loopback_ephemeral_port_only",
        "transport": "cleartext_confined_to_private_routeless_namespace",
        "response": "terminal_synthetic_response_failed_event",
        "public_destination": False,
        "capture": list(CAPTURED_FIELDS),
        "denied_capture": list(DENIED_CAPTURE),
    }
)


class SerializationWitnessError(ValueError):
    """A classified failure to establish or reload trusted witness evidence."""

    def __init__(self, detail: str, *, classification: str = "WITNESS_REFUSED"):
        self.classification = require_identifier(
            classification, "witness failure classification"
        )
        super().__init__(f"{self.classification}: {detail}")


def witness_capture_policy() -> dict[str, Any]:
    return {
        "schema_version": SERIALIZATION_WITNESS_SCHEMA_VERSION,
        "trust_state": "UNTRUSTED_OBSERVATION_ONLY",
        "captured_fields": list(CAPTURED_FIELDS),
        "denied_capture": list(DENIED_CAPTURE),
        "request_path_suffix": WITNESS_REQUEST_PATH_SUFFIX,
        "executable": "content_attested_pinned_codex_0_145_0_only",
        "authentication": "synthetic_per_run_only",
        "namespace": "private_routeless_loopback",
        "endpoint_policy_identity": SYNTHETIC_ENDPOINT_POLICY_IDENTITY,
        "public_dns_or_endpoint": False,
        "real_model_or_provider_execution": False,
        "proves": "nothing_without_owner_bound_serialization_receipt",
    }


def serialization_witness_identity() -> str:
    """Identity of the observation/capture policy, not a successful witness."""

    return fingerprint(witness_capture_policy())


def trusted_witness_verifier_identity() -> str:
    """Content identity of the fixed parent and confined child verifier."""

    runtime = Path(__file__).with_name("serialization_witness_runtime.py")
    body = {
        "schema_version": "admissible_codex_candidate_witness_verifier_v2",
        "parent_source_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "runtime_source_sha256": sha256_bytes(runtime.read_bytes()),
        "capture_policy_identity": serialization_witness_identity(),
        "endpoint_policy_identity": SYNTHETIC_ENDPOINT_POLICY_IDENTITY,
        "receipt_schema_version": CANDIDATE_WITNESS_RECEIPT_SCHEMA_VERSION,
    }
    return fingerprint(body)


class SerializationWitnessRecord:
    """One immutable but explicitly untrusted request observation."""

    __slots__ = ("_body", "_fingerprint")

    def __init__(self, body: Mapping[str, Any], record_fingerprint: str):
        object.__setattr__(self, "_body", MappingProxyType(dict(body)))
        object.__setattr__(self, "_fingerprint", record_fingerprint)

    def __setattr__(self, name: str, value: Any) -> None:  # pragma: no cover
        raise AttributeError("SerializationWitnessRecord is immutable")

    @classmethod
    def create(
        cls,
        *,
        request_path: str,
        serialized_model: str,
        serialized_reasoning_effort: str,
    ) -> "SerializationWitnessRecord":
        if not isinstance(request_path, str) or not request_path.startswith("/"):
            raise SerializationWitnessError("observation path is not a URL path")
        if len(request_path) > 256 or "?" in request_path:
            raise SerializationWitnessError("observation path is out of bounds")
        body = {
            "schema_version": SERIALIZATION_WITNESS_SCHEMA_VERSION,
            "trust_state": "UNTRUSTED_OBSERVATION_ONLY",
            "witness_policy_identity": serialization_witness_identity(),
            "request_path": request_path,
            "serialized_model": serialized_model,
            "serialized_reasoning_effort": serialized_reasoning_effort,
        }
        return cls(body, fingerprint(body)).validated()

    @property
    def record_fingerprint(self) -> str:
        return self._fingerprint

    @property
    def request_path(self) -> str:
        return self._body["request_path"]

    @property
    def serialized_model(self) -> str:
        return self._body["serialized_model"]

    @property
    def serialized_reasoning_effort(self) -> str:
        return self._body["serialized_reasoning_effort"]

    def validated(self) -> "SerializationWitnessRecord":
        require_exact_keys(
            self._body,
            {
                "schema_version",
                "trust_state",
                "witness_policy_identity",
                "request_path",
                "serialized_model",
                "serialized_reasoning_effort",
            },
            "serialization observation",
        )
        if self._body["schema_version"] != SERIALIZATION_WITNESS_SCHEMA_VERSION:
            raise SerializationWitnessError("unsupported observation schema")
        if self._body["trust_state"] != "UNTRUSTED_OBSERVATION_ONLY":
            raise SerializationWitnessError("observation asserted a trusted state")
        if self._body["witness_policy_identity"] != serialization_witness_identity():
            raise SerializationWitnessError("observation policy changed")
        if (
            not isinstance(self.request_path, str)
            or not self.request_path.startswith("/")
            or len(self.request_path) > 256
            or "?" in self.request_path
        ):
            raise SerializationWitnessError("observation path is invalid")
        for label, value in (
            ("serialized model", self.serialized_model),
            ("serialized reasoning effort", self.serialized_reasoning_effort),
        ):
            if not isinstance(value, str) or not value or len(value) > 128:
                raise SerializationWitnessError(f"{label} is not exact text")
        require_sha256(self._fingerprint, "observation fingerprint")
        if fingerprint(dict(self._body)) != self._fingerprint:
            raise SerializationWitnessError("observation fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**dict(self._body), "record_fingerprint": self._fingerprint}


def extract_witness_record(
    *,
    request_path: str,
    request_body: Mapping[str, Any],
) -> SerializationWitnessRecord:
    """Extract minimal untrusted metadata; never produce an attestation."""

    if not isinstance(request_body, Mapping):
        raise SerializationWitnessError("captured body is not an object")
    reasoning = request_body.get("reasoning")
    return SerializationWitnessRecord.create(
        request_path=request_path,
        serialized_model=request_body.get("model"),
        serialized_reasoning_effort=(
            reasoning.get("effort") if isinstance(reasoning, Mapping) else None
        ),
    )


def evaluate_serialization_witness(
    records: Sequence[SerializationWitnessRecord],
    authority: Any,
) -> dict[str, Any]:
    """Compare observations without conferring trust or creating a receipt."""

    if not records:
        raise SerializationWitnessError("no request observation was supplied")
    configured_model = require_exact_model(authority.configured_model)
    configured_effort = require_exact_reasoning_effort(
        authority.configured_reasoning_effort
    )
    for record in records:
        record.validated()
        if not record.request_path.endswith(WITNESS_REQUEST_PATH_SUFFIX):
            raise SerializationWitnessError("observation is outside responses")
        if record.serialized_model != configured_model:
            raise SerializationWitnessError("observed model differs")
        if record.serialized_reasoning_effort != configured_effort:
            raise SerializationWitnessError("observed effort differs")
    return {
        "trust_state": "UNTRUSTED_OBSERVATION_ONLY",
        "configured_model": configured_model,
        "configured_reasoning_effort": configured_effort,
        "observed_requests": len(records),
        "record_fingerprints": [record.record_fingerprint for record in records],
        "candidate_receipt": False,
        "owner_bound_receipt": False,
    }


_CANDIDATE_CONSTRUCTION_TOKEN = object()

_RECEIPT_KEYS = {
    "schema_version",
    "trust_state",
    "store_anchor_fingerprint",
    "run_anchor_fingerprint",
    "witness_run_identity",
    "witness_run_nonce",
    "sequence",
    "model_binding_policy_fingerprint",
    "witness_policy_identity",
    "trusted_witness_verifier_identity",
    "codex_executable_identity",
    "codex_executable_sha256",
    "executable_stat_before",
    "executable_stat_after",
    "protocol_schema_identity",
    "canonical_configuration_fingerprint",
    "configured_model",
    "configured_reasoning_effort",
    "thread_start_allow_provider_model_fallback",
    "captured_request_path",
    "captured_serialized_model",
    "captured_serialized_reasoning_effort",
    "effective_thread_start_model",
    "effective_thread_start_reasoning_effort",
    "namespace_network_witness_identity",
    "no_public_route_proven",
    "no_resolver_proven",
    "synthetic_endpoint_policy_identity",
    "witness_process_terminal_result",
    "captured_request_evidence_fingerprint",
    "evidence_pack_relative_path",
    "evidence_pack_sha256",
    "evidence_pack_size",
    "evidence_pack_fingerprint",
    "complete_witness_evidence_pack_fingerprint",
    "durable_evidence_receipt_identity",
    "receipt_identity",
}

_EVIDENCE_PACK_KEYS = {
    "schema_version",
    "trust_state",
    "store_anchor_fingerprint",
    "run_anchor_fingerprint",
    "witness_run_identity",
    "witness_run_nonce",
    "sequence",
    "previous_tail_identity",
    "model_binding_policy_fingerprint",
    "witness_policy_identity",
    "trusted_witness_verifier_identity",
    "codex_executable_identity",
    "codex_executable_sha256",
    "executable_stat_before",
    "executable_stat_after",
    "protocol_schema_identity",
    "canonical_configuration_fingerprint",
    "configured_model",
    "configured_reasoning_effort",
    "thread_start_allow_provider_model_fallback",
    "captured_request_path",
    "captured_serialized_model",
    "captured_serialized_reasoning_effort",
    "effective_thread_start_model",
    "effective_thread_start_reasoning_effort",
    "namespace_network_witness_identity",
    "namespace_network_evidence",
    "no_public_route_proven",
    "no_resolver_proven",
    "synthetic_endpoint_policy_identity",
    "witness_process_terminal_result",
    "captured_request_evidence_fingerprint",
    "evidence_pack_fingerprint",
}


def _validated_terminal_result(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SerializationWitnessError("witness terminal result is not an object")
    require_exact_keys(
        value,
        {"returncode", "verifier_forced_kill", "classification"},
        "witness process terminal result",
    )
    if (
        value["returncode"] != -15
        or require_bool(
            value["verifier_forced_kill"],
            "witness verifier-forced-kill truth",
        )
        or value["classification"] != "TERMINATED_AFTER_SYNTHETIC_REFUSAL"
    ):
        raise SerializationWitnessError(
            "witness process terminal result differs from policy",
            classification="WITNESS_TERMINAL_POLICY_FAILED",
        )
    return dict(value)


def _validated_namespace_evidence(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SerializationWitnessError("namespace evidence is not an object")
    require_exact_keys(
        value,
        {"confinement_policy", "observed_network_state"},
        "namespace/network evidence",
    )
    policy = value["confinement_policy"]
    observation = value["observed_network_state"]
    if not isinstance(policy, Mapping) or not isinstance(observation, Mapping):
        raise SerializationWitnessError("namespace evidence has invalid records")
    require_exact_keys(
        policy,
        {
            "schema_version",
            "unshare_network",
            "unshare_pid",
            "unshare_user",
            "loopback_only",
            "resolver_file",
            "public_route",
            "runtime_source_sha256",
            "bwrap_identity",
        },
        "witness namespace confinement policy",
    )
    require_exact_keys(
        observation,
        {
            "loopback_bind_succeeded",
            "non_loopback_interfaces",
            "non_loopback_route_entries",
            "public_route_available",
            "resolver_available",
            "resolver_file_size",
            "resolver_policy_files_only",
        },
        "witness observed network state",
    )
    require_strict_int(
        observation["non_loopback_route_entries"],
        "witness non-loopback route count",
        minimum=0,
        maximum=0,
    )
    require_strict_int(
        observation["resolver_file_size"],
        "witness resolver-file size",
        minimum=0,
        maximum=0,
    )
    if (
        policy["schema_version"] != "admissible_codex_witness_namespace_v1"
        or policy["unshare_network"] is not True
        or policy["unshare_pid"] is not True
        or policy["unshare_user"] is not True
        or policy["loopback_only"] is not True
        or policy["resolver_file"] != "empty_read_only"
        or policy["public_route"] is not False
        or observation["loopback_bind_succeeded"] is not True
        or observation["non_loopback_interfaces"] != []
        or observation["non_loopback_route_entries"] != 0
        or observation["public_route_available"] is not False
        or observation["resolver_available"] is not False
        or observation["resolver_file_size"] != 0
        or observation["resolver_policy_files_only"] is not True
    ):
        raise SerializationWitnessError(
            "namespace evidence does not prove routeless loopback confinement",
            classification="WITNESS_NETWORK_POLICY_FAILED",
        )
    require_sha256(
        policy["runtime_source_sha256"],
        "witness runtime source identity",
    )
    runtime = Path(__file__).with_name("serialization_witness_runtime.py")
    if policy["runtime_source_sha256"] != sha256_bytes(runtime.read_bytes()):
        raise SerializationWitnessError(
            "namespace evidence binds another witness runtime",
            classification="WITNESS_VERIFIER_SUBSTITUTED",
        )
    bwrap = ExecutableFileIdentity.from_dict(
        policy["bwrap_identity"],
    )
    bwrap.reattest(label="trusted witness bubblewrap")
    return {
        "confinement_policy": dict(policy),
        "observed_network_state": dict(observation),
    }


def _captured_request_fingerprint(value: Mapping[str, Any]) -> str:
    return fingerprint(
        {
            "request_path": value["captured_request_path"],
            "serialized_model": value["captured_serialized_model"],
            "serialized_reasoning_effort": (
                value["captured_serialized_reasoning_effort"]
            ),
        }
    )


def _durability_identity_from_receipt(value: Mapping[str, Any]) -> str:
    return fingerprint(
        {
            "schema_version": WITNESS_DURABILITY_RECEIPT_SCHEMA_VERSION,
            "store_anchor_fingerprint": value["store_anchor_fingerprint"],
            "run_anchor_fingerprint": value["run_anchor_fingerprint"],
            "witness_run_identity": value["witness_run_identity"],
            "witness_run_nonce": value["witness_run_nonce"],
            "sequence": value["sequence"],
            "evidence_pack_relative_path": value[
                "evidence_pack_relative_path"
            ],
            "evidence_pack_sha256": value["evidence_pack_sha256"],
            "evidence_pack_size": value["evidence_pack_size"],
            "evidence_pack_fingerprint": value[
                "evidence_pack_fingerprint"
            ],
            "file_and_parent_fsynced": True,
            "durable_readback_completed": True,
        }
    )


class CandidateSerializationWitnessReceipt:
    """Opaque *candidate* receipt reread from its own store's durable pack.

    Holding one proves only that some store on this filesystem contains a
    self-consistent pack, receipt and tail.  It never authorizes an effect: the
    production pre-effect gate accepts only
    ``OwnerBoundVerifiedSerializationReceipt``.
    """

    __slots__ = ("_body",)

    def __init__(self, body: Mapping[str, Any], token: object):
        if token is not _CANDIDATE_CONSTRUCTION_TOKEN:
            raise SerializationWitnessError(
                "candidate receipts may only be loaded by their store",
                classification="UNTRUSTED_RECEIPT_CONSTRUCTION",
            )
        object.__setattr__(self, "_body", MappingProxyType(dict(body)))

    def __setattr__(self, name: str, value: Any) -> None:  # pragma: no cover
        raise AttributeError("CandidateSerializationWitnessReceipt is immutable")

    def __delattr__(self, name: str) -> None:  # pragma: no cover
        raise AttributeError("CandidateSerializationWitnessReceipt is immutable")

    @property
    def trust_state(self) -> str:
        return self._body["trust_state"]

    @property
    def receipt_identity(self) -> str:
        return self._body["receipt_identity"]

    @property
    def witness_run_identity(self) -> str:
        return self._body["witness_run_identity"]

    @property
    def witness_run_nonce(self) -> str:
        return self._body["witness_run_nonce"]

    @property
    def model_binding_policy_fingerprint(self) -> str:
        return self._body["model_binding_policy_fingerprint"]

    @property
    def configured_model(self) -> str:
        return self._body["configured_model"]

    @property
    def configured_reasoning_effort(self) -> str:
        return self._body["configured_reasoning_effort"]

    @property
    def executable_identity(self) -> Mapping[str, Any]:
        return dict(self._body["codex_executable_identity"])

    @property
    def evidence_pack_fingerprint(self) -> str:
        return self._body["evidence_pack_fingerprint"]

    @property
    def durable_evidence_receipt_identity(self) -> str:
        return self._body["durable_evidence_receipt_identity"]

    @property
    def store_anchor_fingerprint(self) -> str:
        return self._body["store_anchor_fingerprint"]

    @property
    def sequence(self) -> int:
        return self._body["sequence"]

    def to_dict(self) -> dict[str, Any]:
        return dict(self._body)


class CandidateSerializationWitnessPack:
    """The complete durable evidence pack behind one candidate receipt.

    The pack, not the receipt, carries the real-binary witness evidence: the
    executable attestations taken before and after the confined run, the
    namespace/network observation, the captured request and the terminal
    result.  ``revalidated`` re-checks that evidence independently of any
    receipt so the trusted authorization path never has to trust a summary.
    """

    __slots__ = ("_body",)

    def __init__(self, body: Mapping[str, Any], token: object):
        if token is not _CANDIDATE_CONSTRUCTION_TOKEN:
            raise SerializationWitnessError(
                "candidate evidence packs may only be loaded by their store",
                classification="UNTRUSTED_PACK_CONSTRUCTION",
            )
        object.__setattr__(self, "_body", MappingProxyType(dict(body)))

    def __setattr__(self, name: str, value: Any) -> None:  # pragma: no cover
        raise AttributeError("CandidateSerializationWitnessPack is immutable")

    def __delattr__(self, name: str) -> None:  # pragma: no cover
        raise AttributeError("CandidateSerializationWitnessPack is immutable")

    @property
    def trust_state(self) -> str:
        return self._body["trust_state"]

    @property
    def evidence_pack_fingerprint(self) -> str:
        return self._body["evidence_pack_fingerprint"]

    @property
    def store_anchor_fingerprint(self) -> str:
        return self._body["store_anchor_fingerprint"]

    @property
    def witness_run_identity(self) -> str:
        return self._body["witness_run_identity"]

    @property
    def witness_run_nonce(self) -> str:
        return self._body["witness_run_nonce"]

    @property
    def executable_identity(self) -> Mapping[str, Any]:
        return dict(self._body["codex_executable_identity"])

    def to_dict(self) -> dict[str, Any]:
        return dict(self._body)

    def revalidated(
        self,
        *,
        expected_policy: "ModelBindingPolicy",
        expected_executable_identity: Mapping[str, Any],
    ) -> "CandidateSerializationWitnessPack":
        """Independently re-check every real-binary witness claim in the pack."""

        body = dict(self._body)
        require_exact_keys(body, _EVIDENCE_PACK_KEYS, "candidate evidence pack")
        if (
            body["schema_version"] != CANDIDATE_WITNESS_EVIDENCE_SCHEMA_VERSION
            or body["trust_state"] != CANDIDATE_WITNESS_TRUST_STATE
        ):
            raise SerializationWitnessError(
                "candidate evidence pack does not declare candidate trust",
                classification="WITNESS_EVIDENCE_CHANGED",
            )
        namespace_evidence = _validated_namespace_evidence(
            body["namespace_network_evidence"]
        )
        _validated_terminal_result(body["witness_process_terminal_result"])
        expected_identity = dict(expected_executable_identity)
        for label in (
            "codex_executable_identity",
            "executable_stat_before",
            "executable_stat_after",
        ):
            validate_component_identity_metadata(body[label], f"pack {label}")
            if dict(body[label]) != expected_identity:
                raise SerializationWitnessError(
                    f"candidate pack {label} binds another executable",
                    classification="WITNESS_EXECUTABLE_SUBSTITUTED",
                )
        if (
            body["codex_executable_sha256"] != expected_identity.get("sha256")
            or body["model_binding_policy_fingerprint"]
            != expected_policy.policy_fingerprint
            or body["witness_policy_identity"]
            != expected_policy.witness_policy_identity
            or body["trusted_witness_verifier_identity"]
            != trusted_witness_verifier_identity()
            or body["protocol_schema_identity"]
            != expected_policy.protocol_schema_identity
            or body["canonical_configuration_fingerprint"]
            != expected_policy.configuration_fingerprint
            or body["configured_model"] != expected_policy.configured_model
            or body["configured_reasoning_effort"]
            != expected_policy.configured_reasoning_effort
            or body["thread_start_allow_provider_model_fallback"] is not False
            or body["captured_request_path"]
            != TRUSTED_WITNESS_EXACT_REQUEST_PATH
            or body["captured_serialized_model"]
            != expected_policy.configured_model
            or body["captured_serialized_reasoning_effort"]
            != expected_policy.configured_reasoning_effort
            or body["effective_thread_start_model"]
            != expected_policy.configured_model
            or body["effective_thread_start_reasoning_effort"]
            != expected_policy.configured_reasoning_effort
            or body["captured_request_evidence_fingerprint"]
            != _captured_request_fingerprint(body)
            or body["namespace_network_witness_identity"]
            != fingerprint(namespace_evidence)
            or body["synthetic_endpoint_policy_identity"]
            != SYNTHETIC_ENDPOINT_POLICY_IDENTITY
            or body["no_public_route_proven"] is not True
            or body["no_resolver_proven"] is not True
        ):
            raise SerializationWitnessError(
                "candidate pack real-binary evidence differs from its policy",
                classification="WITNESS_EVIDENCE_CHANGED",
            )
        pack_body = {
            key: item
            for key, item in body.items()
            if key != "evidence_pack_fingerprint"
        }
        if fingerprint(pack_body) != body["evidence_pack_fingerprint"]:
            raise SerializationWitnessError(
                "candidate pack fingerprint mismatch",
                classification="WITNESS_EVIDENCE_CHANGED",
            )
        return self


@dataclass(frozen=True)
class CandidateEvidenceBundle:
    """One store's revalidated receipt, pack, anchor, tail and root identity.

    The trusted authorization path needs all five together: a receipt alone
    cannot say which store produced it, and a store alone cannot say which tail
    an owner authorized.
    """

    receipt: CandidateSerializationWitnessReceipt
    pack: CandidateSerializationWitnessPack
    store_anchor_fingerprint: str
    tail_identity: str
    store_root_identity: Mapping[str, Any]


def validate_candidate_receipt_metadata(
    value: Mapping[str, Any],
    *,
    expected_policy: "ModelBindingPolicy",
    expected_executable_identity: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Structural check only; this never restores candidate receipt provenance."""

    if not isinstance(value, Mapping):
        raise SerializationWitnessError("candidate receipt metadata is not an object")
    require_exact_keys(value, _RECEIPT_KEYS, "candidate witness receipt")
    body = {key: item for key, item in value.items() if key != "receipt_identity"}
    if (
        value.get("schema_version") != CANDIDATE_WITNESS_RECEIPT_SCHEMA_VERSION
        or value.get("trust_state") != CANDIDATE_WITNESS_TRUST_STATE
        or not isinstance(value.get("receipt_identity"), str)
        or fingerprint(body) != value.get("receipt_identity")
        or value.get("model_binding_policy_fingerprint")
        != expected_policy.policy_fingerprint
        or value.get("codex_executable_identity")
        != dict(expected_executable_identity)
        or value.get("protocol_schema_identity")
        != expected_policy.protocol_schema_identity
        or value.get("canonical_configuration_fingerprint")
        != expected_policy.configuration_fingerprint
        or value.get("configured_model") != expected_policy.configured_model
        or value.get("configured_reasoning_effort")
        != expected_policy.configured_reasoning_effort
        or value.get("thread_start_allow_provider_model_fallback") is not False
        or value.get("captured_serialized_model")
        != expected_policy.configured_model
        or value.get("captured_serialized_reasoning_effort")
        != expected_policy.configured_reasoning_effort
        or value.get("effective_thread_start_model")
        != expected_policy.configured_model
        or value.get("effective_thread_start_reasoning_effort")
        != expected_policy.configured_reasoning_effort
        or value.get("no_public_route_proven") is not True
        or value.get("no_resolver_proven") is not True
        or value.get("witness_policy_identity")
        != expected_policy.witness_policy_identity
        or value.get("trusted_witness_verifier_identity")
        != trusted_witness_verifier_identity()
        or value.get("synthetic_endpoint_policy_identity")
        != SYNTHETIC_ENDPOINT_POLICY_IDENTITY
        or value.get("codex_executable_sha256")
        != expected_executable_identity.get("sha256")
        or value.get("executable_stat_before")
        != dict(expected_executable_identity)
        or value.get("executable_stat_after")
        != dict(expected_executable_identity)
        or value.get("captured_request_evidence_fingerprint")
        != _captured_request_fingerprint(value)
        or value.get("durable_evidence_receipt_identity")
        != _durability_identity_from_receipt(value)
    ):
        raise SerializationWitnessError(
            "candidate receipt metadata differs from its policy",
            classification="WITNESS_RECEIPT_INVALID",
        )
    for key in (
        "receipt_identity",
        "store_anchor_fingerprint",
        "run_anchor_fingerprint",
        "witness_run_nonce",
        "model_binding_policy_fingerprint",
        "witness_policy_identity",
        "trusted_witness_verifier_identity",
        "codex_executable_sha256",
        "protocol_schema_identity",
        "canonical_configuration_fingerprint",
        "namespace_network_witness_identity",
        "synthetic_endpoint_policy_identity",
        "captured_request_evidence_fingerprint",
        "evidence_pack_sha256",
        "evidence_pack_fingerprint",
        "complete_witness_evidence_pack_fingerprint",
        "durable_evidence_receipt_identity",
    ):
        require_sha256(value.get(key), f"candidate receipt {key}")
    require_identifier(
        value.get("witness_run_identity"), "candidate receipt witness run"
    )
    require_strict_int(
        value.get("sequence"),
        "candidate receipt sequence",
        minimum=1,
        maximum=1_000_000,
    )
    require_strict_int(
        value.get("evidence_pack_size"),
        "candidate receipt evidence-pack size",
        minimum=1,
        maximum=64 * 1024 * 1024,
    )
    path = value.get("captured_request_path")
    if (
        not isinstance(path, str)
        or path != TRUSTED_WITNESS_EXACT_REQUEST_PATH
        or "?" in path
    ):
        raise SerializationWitnessError(
            "candidate receipt captured an unauthorized request path"
        )
    _validated_terminal_result(value["witness_process_terminal_result"])
    validate_component_identity_metadata(
        value["codex_executable_identity"],
        "candidate receipt Codex executable",
    )
    denied = {
        "prompt",
        "prompt_text",
        "authorization",
        "authorization_header",
        "credential",
        "synthetic_credential",
        "response_body",
    }
    if denied & set(value):
        raise SerializationWitnessError("candidate receipt contains denied material")
    return dict(value)


def _reject_symlink_components(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode):
            raise SerializationWitnessError(
                f"{label} has a symlinked component",
                classification="WITNESS_STORE_PATH_REFUSED",
            )


class CandidateSerializationWitnessStore:
    """Path-bound, single-writer store of *candidate* witness evidence.

    The store creates its own store anchor, so creating one -- or creating a
    self-consistent pack, receipt and tail inside one -- proves nothing.  The
    anchor exists to detect copying, moving and tail rewinding within a store,
    not to establish that the store deserves trust.
    """

    def __init__(
        self,
        root: Path,
        *,
        trusted_anchor_root: Path | None = None,
    ):
        if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
            raise SerializationWitnessError(
                "trusted witness-store root must be an absolute canonical path",
                classification="WITNESS_STORE_PATH_REFUSED",
            )
        _reject_symlink_components(root, "trusted witness store")
        self.root = root
        created = not root.exists()
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _reject_symlink_components(root, "trusted witness store")
        if created:
            fsync_directory(root.parent)
        self.trusted_anchor_root = (
            trusted_anchor_root
            if trusted_anchor_root is not None
            else root.parent / f"{root.name}.trusted-authority"
        )
        if (
            not isinstance(self.trusted_anchor_root, Path)
            or not self.trusted_anchor_root.is_absolute()
            or ".." in self.trusted_anchor_root.parts
            or self.trusted_anchor_root == self.root
            or self.trusted_anchor_root.is_relative_to(self.root)
            or self.root.is_relative_to(self.trusted_anchor_root)
        ):
            raise SerializationWitnessError(
                "witness trusted-anchor root must be external and canonical",
                classification="WITNESS_STORE_PATH_REFUSED",
            )
        _reject_symlink_components(
            self.trusted_anchor_root,
            "witness trusted-anchor root",
        )
        anchor_root_created = not self.trusted_anchor_root.exists()
        self.trusted_anchor_root.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )
        _reject_symlink_components(
            self.trusted_anchor_root,
            "witness trusted-anchor root",
        )
        if anchor_root_created:
            fsync_directory(self.trusted_anchor_root.parent)
        self._anchors = self.trusted_anchor_root / "run-anchors"
        self._packs = root / "evidence-packs"
        self._receipts = root / "receipts"
        for directory in (self._packs, self._receipts):
            made = not directory.exists()
            directory.mkdir(mode=0o700, exist_ok=True)
            if made:
                fsync_directory(root)
        anchors_made = not self._anchors.exists()
        self._anchors.mkdir(mode=0o700, exist_ok=True)
        if anchors_made:
            fsync_directory(self.trusted_anchor_root)
        self._lock_path = self.trusted_anchor_root / "writer.lock"
        self._store_anchor_path = (
            self.trusted_anchor_root / "store-anchor.json"
        )
        self._tail_path = self.trusted_anchor_root / "tail.json"
        self._ensure_store_anchor()

    def _root_identity(self) -> dict[str, Any]:
        info = os.stat(self.root, follow_symlinks=False)
        return {
            "canonical_path_sha256": sha256_bytes(
                os.fsencode(os.fspath(self.root.resolve()))
            ),
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode),
        }

    def _anchor_root_identity(self) -> dict[str, Any]:
        info = os.stat(self.trusted_anchor_root, follow_symlinks=False)
        return {
            "canonical_path_sha256": sha256_bytes(
                os.fsencode(os.fspath(self.trusted_anchor_root.resolve()))
            ),
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode),
        }

    def _ensure_store_anchor(self) -> None:
        if not self._store_anchor_path.exists():
            body = {
                "schema_version": WITNESS_STORE_ANCHOR_SCHEMA_VERSION,
                "trust_state": CANDIDATE_WITNESS_TRUST_STATE,
                "store_root_identity": self._root_identity(),
                "trusted_anchor_root_identity": (
                    self._anchor_root_identity()
                ),
                "store_nonce": secrets.token_hex(32),
                "trusted_verifier_identity": trusted_witness_verifier_identity(),
                "single_writer": True,
            }
            descriptor = os.open(
                self._store_anchor_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                encoded = canonical_bytes(
                    {**body, "store_anchor_fingerprint": fingerprint(body)}
                )
                offset = 0
                while offset < len(encoded):
                    offset += os.write(descriptor, encoded[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            fsync_directory(self.trusted_anchor_root)
        self._read_store_anchor()

    def _read_store_anchor(self) -> Mapping[str, Any]:
        try:
            value = strict_json_loads(
                self._store_anchor_path.read_bytes(),
                label="trusted witness-store anchor",
            )
        except (FileNotFoundError, ValueError) as error:
            raise SerializationWitnessError(
                "trusted witness-store anchor is missing or invalid",
                classification="WITNESS_STORE_ANCHOR_INVALID",
            ) from error
        require_exact_keys(
            value,
            {
                "schema_version",
                "trust_state",
                "store_root_identity",
                "trusted_anchor_root_identity",
                "store_nonce",
                "trusted_verifier_identity",
                "single_writer",
                "store_anchor_fingerprint",
            },
            "trusted witness-store anchor",
        )
        if (
            value["schema_version"] != WITNESS_STORE_ANCHOR_SCHEMA_VERSION
            or value["trust_state"] != CANDIDATE_WITNESS_TRUST_STATE
        ):
            raise SerializationWitnessError(
                "candidate witness-store anchor is unsupported or claims trust",
                classification="WITNESS_STORE_ANCHOR_INVALID",
            )
        if value["store_root_identity"] != self._root_identity():
            raise SerializationWitnessError(
                "witness store was copied or moved",
                classification="WITNESS_STORE_PATH_SUBSTITUTED",
            )
        if (
            value["trusted_anchor_root_identity"]
            != self._anchor_root_identity()
        ):
            raise SerializationWitnessError(
                "witness trusted-anchor root was copied or moved",
                classification="WITNESS_STORE_PATH_SUBSTITUTED",
            )
        require_sha256(value["store_nonce"], "witness-store nonce")
        if value["trusted_verifier_identity"] != trusted_witness_verifier_identity():
            raise SerializationWitnessError(
                "trusted verifier implementation changed",
                classification="WITNESS_VERIFIER_SUBSTITUTED",
            )
        if value["single_writer"] is not True:
            raise SerializationWitnessError("witness store is not single-writer")
        body = {key: item for key, item in value.items() if key != "store_anchor_fingerprint"}
        if fingerprint(body) != value["store_anchor_fingerprint"]:
            raise SerializationWitnessError("witness-store anchor fingerprint mismatch")
        return value

    def anchor_reference(self) -> Mapping[str, Any]:
        """Public path-bound reference to this candidate store.

        A reference identifies which store a session is talking to.  It confers
        no trust on that store's contents.
        """

        anchor = self._read_store_anchor()
        body = {
            "schema_version": "admissible_codex_candidate_witness_store_reference_v2",
            "canonical_root": os.fspath(self.root.resolve()),
            "canonical_trusted_anchor_root": os.fspath(
                self.trusted_anchor_root.resolve()
            ),
            "store_root_identity": self._root_identity(),
            "trusted_anchor_root_identity": self._anchor_root_identity(),
            "store_anchor_fingerprint": anchor["store_anchor_fingerprint"],
            "trusted_verifier_identity": trusted_witness_verifier_identity(),
        }
        return {**body, "reference_identity": fingerprint(body)}

    @contextmanager
    def _writer_lock(self):
        descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read_tail(self) -> Mapping[str, Any] | None:
        if not self._tail_path.exists():
            return None
        value = strict_json_loads(
            self._tail_path.read_bytes(), label="trusted witness-store tail"
        )
        require_exact_keys(
            value,
            {
                "schema_version",
                "trust_state",
                "store_anchor_fingerprint",
                "sequence",
                "witness_run_identity",
                "receipt_identity",
                "evidence_pack_fingerprint",
                "previous_tail_identity",
                "tail_identity",
            },
            "trusted witness-store tail",
        )
        if (
            value["schema_version"] != WITNESS_STORE_TAIL_SCHEMA_VERSION
            or value["trust_state"] != CANDIDATE_WITNESS_TRUST_STATE
        ):
            raise SerializationWitnessError(
                "candidate witness-store tail is unsupported or claims trust"
            )
        anchor = self._read_store_anchor()
        if value["store_anchor_fingerprint"] != anchor["store_anchor_fingerprint"]:
            raise SerializationWitnessError("witness tail belongs to another store")
        require_strict_int(
            value["sequence"], "witness tail sequence", minimum=1, maximum=1_000_000
        )
        require_identifier(value["witness_run_identity"], "witness tail run")
        for key in (
            "receipt_identity",
            "evidence_pack_fingerprint",
            "previous_tail_identity",
            "tail_identity",
        ):
            require_sha256(value[key], key)
        body = {key: item for key, item in value.items() if key != "tail_identity"}
        if fingerprint(body) != value["tail_identity"]:
            raise SerializationWitnessError("witness-store tail fingerprint mismatch")
        return value

    def _create_run_anchor(
        self,
        *,
        policy: "ModelBindingPolicy",
        executable_identity: ExecutableFileIdentity,
        run_identity: str,
        run_nonce: str,
        sequence: int,
        previous_tail_identity: str,
    ) -> Mapping[str, Any]:
        store_anchor = self._read_store_anchor()
        body = {
            "schema_version": WITNESS_RUN_ANCHOR_SCHEMA_VERSION,
            "trust_state": CANDIDATE_WITNESS_TRUST_STATE,
            "store_anchor_fingerprint": store_anchor["store_anchor_fingerprint"],
            "witness_run_identity": run_identity,
            "witness_run_nonce": run_nonce,
            "sequence": sequence,
            "previous_tail_identity": previous_tail_identity,
            "model_binding_policy_fingerprint": policy.policy_fingerprint,
            "trusted_verifier_identity": trusted_witness_verifier_identity(),
            "codex_executable_identity": executable_identity.to_dict(),
            "configuration_fingerprint": policy.configuration_fingerprint,
            "state": "ANCHORED_BEFORE_EXECUTION",
        }
        anchor = {**body, "run_anchor_fingerprint": fingerprint(body)}
        path = self._anchors / f"{run_identity}.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            encoded = canonical_bytes(anchor)
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(self._anchors)
        return anchor

    @staticmethod
    def _interpreter_bindings() -> tuple[str, ...]:
        bindings: list[str] = []
        for root in {Path(sys.prefix).resolve(), Path(sys.executable).resolve().parent}:
            if root.is_relative_to(Path("/tmp")):
                bindings.extend(("--ro-bind", os.fspath(root), os.fspath(root)))
        return tuple(bindings)

    def _execute_witness(
        self,
        *,
        policy: "ModelBindingPolicy",
        executable_identity: ExecutableFileIdentity,
        run_identity: str,
        run_nonce: str,
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        bwrap_identity = ExecutableFileIdentity.attest(
            Path("/usr/bin/bwrap"), label="trusted witness bubblewrap"
        )
        scratch = Path(
            tempfile.mkdtemp(prefix=".witness-execution-", dir=self.root)
        )
        try:
            request_path = scratch / "request.json"
            output_path = scratch / "observation.json"
            minimal_etc = scratch / "minimal-etc"
            minimal_etc.mkdir(mode=0o700)
            (minimal_etc / "resolv.conf").write_bytes(b"")
            (minimal_etc / "hosts").write_bytes(b"")
            (minimal_etc / "nsswitch.conf").write_bytes(b"hosts: files\n")
            request = {
                "witness_run_identity": run_identity,
                "witness_run_nonce": run_nonce,
                "codex_executable": executable_identity.canonical_path,
                "codex_home": os.fspath(scratch / "codex-home"),
                "workspace": os.fspath(scratch / "workspace"),
                "synthetic_credential": secrets.token_urlsafe(48),
                "canonical_configuration": policy.ephemeral_config_bytes.decode("utf-8"),
                "initialize_params": {
                    "clientInfo": {
                        "name": "admissible_host_capsule",
                        "title": "Admissible Host Capsule Controller",
                        "version": "1.0.0",
                    },
                    "capabilities": {"experimentalApi": True},
                },
                "thread_start_params": {
                    "approvalPolicy": "never",
                    "sandbox": "read-only",
                    "ephemeral": True,
                    **policy.thread_start_fields,
                    "environments": [],
                    "runtimeWorkspaceRoots": [],
                    "selectedCapabilityRoots": [],
                },
                "turn_start_params": policy.turn_start_fields,
                "timeout_seconds": 40,
            }
            request_path.write_bytes(canonical_bytes(request))
            runtime = Path(__file__).with_name("serialization_witness_runtime.py")
            command = (
                "/usr/bin/bwrap",
                "--unshare-net",
                "--unshare-pid",
                "--unshare-user",
                "--new-session",
                "--die-with-parent",
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--tmpfs",
                "/tmp",
                *self._interpreter_bindings(),
                "--bind",
                os.fspath(scratch),
                os.fspath(scratch),
                "--ro-bind",
                os.fspath(minimal_etc),
                "/etc",
                "--clearenv",
                "--setenv",
                "LANG",
                "C.UTF-8",
                "--setenv",
                "LC_ALL",
                "C.UTF-8",
                "--chdir",
                os.fspath(scratch),
                sys.executable,
                os.fspath(runtime),
                os.fspath(request_path),
                os.fspath(output_path),
            )
            argv_policy = {
                "schema_version": "admissible_codex_witness_namespace_v1",
                "unshare_network": True,
                "unshare_pid": True,
                "unshare_user": True,
                "loopback_only": True,
                "resolver_file": "empty_read_only",
                "public_route": False,
                "runtime_source_sha256": sha256_bytes(runtime.read_bytes()),
                "bwrap_identity": bwrap_identity.to_dict(),
            }
            completed = subprocess.run(
                command,
                executable=bwrap_identity.canonical_path,
                capture_output=True,
                check=False,
                timeout=90,
                env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
                cwd=os.fspath(self.root),
            )
            if completed.returncode != 0 or not output_path.is_file():
                diagnostic = completed.stderr.decode("utf-8", "replace")[-1200:]
                raise SerializationWitnessError(
                    "confined witness failed with exit "
                    f"{completed.returncode}: {diagnostic}",
                    classification="WITNESS_EXECUTION_FAILED",
                )
            observation = strict_json_loads(
                output_path.read_bytes(), label="confined witness observation"
            )
            return observation, argv_policy
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
            fsync_directory(self.root)

    def _validate_observation(
        self,
        *,
        observation: Mapping[str, Any],
        policy: "ModelBindingPolicy",
        run_identity: str,
        run_nonce: str,
    ) -> Mapping[str, Any]:
        require_exact_keys(
            observation,
            {
                "witness_run_identity",
                "witness_run_nonce",
                "network_observation",
                "codex_process_pid",
                "effective_thread_start_model",
                "effective_thread_start_reasoning_effort",
                "captured_request",
                "synthetic_refusal_sent",
                "process_terminal",
            },
            "confined witness observation",
        )
        if (
            observation["witness_run_identity"] != run_identity
            or observation["witness_run_nonce"] != run_nonce
        ):
            raise SerializationWitnessError(
                "confined observation belongs to another witness run",
                classification="WITNESS_RUN_SUBSTITUTED",
            )
        network = observation["network_observation"]
        require_exact_keys(
            network,
            {
                "loopback_bind_succeeded",
                "non_loopback_interfaces",
                "non_loopback_route_entries",
                "public_route_available",
                "resolver_available",
                "resolver_file_size",
                "resolver_policy_files_only",
            },
            "witness network observation",
        )
        require_strict_int(
            network["non_loopback_route_entries"],
            "witness non-loopback route count",
            minimum=0,
            maximum=0,
        )
        require_strict_int(
            network["resolver_file_size"],
            "witness resolver-file size",
            minimum=0,
            maximum=0,
        )
        if (
            network["loopback_bind_succeeded"] is not True
            or network["non_loopback_interfaces"] != []
            or network["non_loopback_route_entries"] != 0
            or network["public_route_available"] is not False
            or network["resolver_available"] is not False
            or network["resolver_file_size"] != 0
            or network["resolver_policy_files_only"] is not True
        ):
            raise SerializationWitnessError(
                "witness namespace had a public route or resolver",
                classification="WITNESS_NETWORK_POLICY_FAILED",
            )
        capture = observation["captured_request"]
        require_exact_keys(
            capture,
            {
                "request_path",
                "serialized_model",
                "serialized_reasoning_effort",
            },
            "captured request evidence",
        )
        if (
            not isinstance(capture["request_path"], str)
            or capture["request_path"] != TRUSTED_WITNESS_EXACT_REQUEST_PATH
            or capture["serialized_model"] != policy.configured_model
            or capture["serialized_reasoning_effort"]
            != policy.configured_reasoning_effort
        ):
            raise SerializationWitnessError(
                "captured request differs from the sealed model policy",
                classification="WITNESS_SERIALIZATION_MISMATCH",
            )
        if (
            observation["effective_thread_start_model"] != policy.configured_model
            or observation["effective_thread_start_reasoning_effort"]
            != policy.configured_reasoning_effort
        ):
            raise SerializationWitnessError(
                "effective thread configuration differs from policy",
                classification="WITNESS_EFFECTIVE_RESPONSE_MISMATCH",
            )
        if observation["synthetic_refusal_sent"] is not True:
            raise SerializationWitnessError(
                "synthetic endpoint refusal was not observed",
                classification="WITNESS_TERMINAL_POLICY_FAILED",
            )
        _validated_terminal_result(observation["process_terminal"])
        return observation

    def record_candidate_witness(
        self,
        *,
        policy: "ModelBindingPolicy",
        codex_executable: Path,
    ) -> CandidateSerializationWitnessReceipt:
        """Execute, persist and reread one *candidate* witness receipt.

        Success here means the pinned executable really ran and really
        serialized the sealed tuple to a routeless loopback endpoint.  It does
        not make the result authoritative: an owner must still bind this exact
        store, pack, receipt and tail before any production effect.
        """

        policy.validated_canary()
        before = ExecutableFileIdentity.attest(
            codex_executable, label="canary pinned Codex executable"
        )
        if before.to_dict() != dict(policy.codex_executable_identity):
            raise SerializationWitnessError(
                "witness executable differs from the sealed canary policy",
                classification="WITNESS_EXECUTABLE_SUBSTITUTED",
            )
        with self._writer_lock():
            tail = self._read_tail()
            sequence = 1 if tail is None else tail["sequence"] + 1
            previous_tail = ZERO_FINGERPRINT if tail is None else tail["tail_identity"]
            run_identity = f"codex-witness-{secrets.token_hex(16)}"
            run_nonce = secrets.token_hex(32)
            run_anchor = self._create_run_anchor(
                policy=policy,
                executable_identity=before,
                run_identity=run_identity,
                run_nonce=run_nonce,
                sequence=sequence,
                previous_tail_identity=previous_tail,
            )
            observation, namespace = self._execute_witness(
                policy=policy,
                executable_identity=before,
                run_identity=run_identity,
                run_nonce=run_nonce,
            )
            observation = self._validate_observation(
                observation=observation,
                policy=policy,
                run_identity=run_identity,
                run_nonce=run_nonce,
            )
            after = ExecutableFileIdentity.attest(
                codex_executable, label="canary pinned Codex executable after witness"
            )
            if before != after:
                raise SerializationWitnessError(
                    "pinned executable changed during witness execution",
                    classification="WITNESS_EXECUTABLE_CHANGED",
                )
            capture = observation["captured_request"]
            captured_request_fingerprint = fingerprint(capture)
            namespace_evidence = {
                "confinement_policy": dict(namespace),
                "observed_network_state": dict(
                    observation["network_observation"]
                ),
            }
            _validated_namespace_evidence(namespace_evidence)
            namespace_identity = fingerprint(namespace_evidence)
            evidence_body = {
                "schema_version": CANDIDATE_WITNESS_EVIDENCE_SCHEMA_VERSION,
                "trust_state": CANDIDATE_WITNESS_TRUST_STATE,
                "store_anchor_fingerprint": run_anchor["store_anchor_fingerprint"],
                "run_anchor_fingerprint": run_anchor["run_anchor_fingerprint"],
                "witness_run_identity": run_identity,
                "witness_run_nonce": run_nonce,
                "sequence": sequence,
                "previous_tail_identity": previous_tail,
                "model_binding_policy_fingerprint": policy.policy_fingerprint,
                "witness_policy_identity": serialization_witness_identity(),
                "trusted_witness_verifier_identity": trusted_witness_verifier_identity(),
                "codex_executable_identity": before.to_dict(),
                "codex_executable_sha256": before.sha256,
                "executable_stat_before": before.to_dict(),
                "executable_stat_after": after.to_dict(),
                "protocol_schema_identity": policy.protocol_schema_identity,
                "canonical_configuration_fingerprint": (
                    policy.configuration_fingerprint
                ),
                "configured_model": policy.configured_model,
                "configured_reasoning_effort": policy.configured_reasoning_effort,
                "thread_start_allow_provider_model_fallback": (
                    policy.allow_provider_model_fallback
                ),
                "captured_request_path": capture["request_path"],
                "captured_serialized_model": capture["serialized_model"],
                "captured_serialized_reasoning_effort": (
                    capture["serialized_reasoning_effort"]
                ),
                "effective_thread_start_model": observation[
                    "effective_thread_start_model"
                ],
                "effective_thread_start_reasoning_effort": observation[
                    "effective_thread_start_reasoning_effort"
                ],
                "namespace_network_witness_identity": namespace_identity,
                "namespace_network_evidence": namespace_evidence,
                "no_public_route_proven": True,
                "no_resolver_proven": True,
                "synthetic_endpoint_policy_identity": (
                    SYNTHETIC_ENDPOINT_POLICY_IDENTITY
                ),
                "witness_process_terminal_result": observation["process_terminal"],
                "captured_request_evidence_fingerprint": (
                    captured_request_fingerprint
                ),
            }
            evidence = {
                **evidence_body,
                "evidence_pack_fingerprint": fingerprint(evidence_body),
            }
            pack_path = self._packs / f"{run_identity}.json"
            atomic_json(pack_path, evidence, mode=0o600)
            persisted_pack = pack_path.read_bytes()
            pack_sha256 = sha256_bytes(persisted_pack)
            durability_body = {
                "schema_version": WITNESS_DURABILITY_RECEIPT_SCHEMA_VERSION,
                "store_anchor_fingerprint": run_anchor["store_anchor_fingerprint"],
                "run_anchor_fingerprint": run_anchor["run_anchor_fingerprint"],
                "witness_run_identity": run_identity,
                "witness_run_nonce": run_nonce,
                "sequence": sequence,
                "evidence_pack_relative_path": f"evidence-packs/{run_identity}.json",
                "evidence_pack_sha256": pack_sha256,
                "evidence_pack_size": len(persisted_pack),
                "evidence_pack_fingerprint": evidence[
                    "evidence_pack_fingerprint"
                ],
                "file_and_parent_fsynced": True,
                "durable_readback_completed": True,
            }
            durability_identity = fingerprint(durability_body)
            receipt_body = {
                "schema_version": CANDIDATE_WITNESS_RECEIPT_SCHEMA_VERSION,
                "trust_state": CANDIDATE_WITNESS_TRUST_STATE,
                "store_anchor_fingerprint": run_anchor["store_anchor_fingerprint"],
                "run_anchor_fingerprint": run_anchor["run_anchor_fingerprint"],
                "witness_run_identity": run_identity,
                "witness_run_nonce": run_nonce,
                "sequence": sequence,
                "model_binding_policy_fingerprint": policy.policy_fingerprint,
                "witness_policy_identity": serialization_witness_identity(),
                "trusted_witness_verifier_identity": trusted_witness_verifier_identity(),
                "codex_executable_identity": before.to_dict(),
                "codex_executable_sha256": before.sha256,
                "executable_stat_before": before.to_dict(),
                "executable_stat_after": after.to_dict(),
                "protocol_schema_identity": policy.protocol_schema_identity,
                "canonical_configuration_fingerprint": (
                    policy.configuration_fingerprint
                ),
                "configured_model": policy.configured_model,
                "configured_reasoning_effort": policy.configured_reasoning_effort,
                "thread_start_allow_provider_model_fallback": False,
                "captured_request_path": capture["request_path"],
                "captured_serialized_model": capture["serialized_model"],
                "captured_serialized_reasoning_effort": (
                    capture["serialized_reasoning_effort"]
                ),
                "effective_thread_start_model": observation[
                    "effective_thread_start_model"
                ],
                "effective_thread_start_reasoning_effort": observation[
                    "effective_thread_start_reasoning_effort"
                ],
                "namespace_network_witness_identity": namespace_identity,
                "no_public_route_proven": True,
                "no_resolver_proven": True,
                "synthetic_endpoint_policy_identity": (
                    SYNTHETIC_ENDPOINT_POLICY_IDENTITY
                ),
                "witness_process_terminal_result": observation["process_terminal"],
                "captured_request_evidence_fingerprint": (
                    captured_request_fingerprint
                ),
                "evidence_pack_relative_path": durability_body[
                    "evidence_pack_relative_path"
                ],
                "evidence_pack_sha256": pack_sha256,
                "evidence_pack_size": len(persisted_pack),
                "evidence_pack_fingerprint": evidence[
                    "evidence_pack_fingerprint"
                ],
                "complete_witness_evidence_pack_fingerprint": evidence[
                    "evidence_pack_fingerprint"
                ],
                "durable_evidence_receipt_identity": durability_identity,
            }
            receipt = {**receipt_body, "receipt_identity": fingerprint(receipt_body)}
            atomic_json(
                self._receipts / f"{run_identity}.json", receipt, mode=0o600
            )
            tail_body = {
                "schema_version": WITNESS_STORE_TAIL_SCHEMA_VERSION,
                "trust_state": CANDIDATE_WITNESS_TRUST_STATE,
                "store_anchor_fingerprint": run_anchor["store_anchor_fingerprint"],
                "sequence": sequence,
                "witness_run_identity": run_identity,
                "receipt_identity": receipt["receipt_identity"],
                "evidence_pack_fingerprint": evidence[
                    "evidence_pack_fingerprint"
                ],
                "previous_tail_identity": previous_tail,
            }
            atomic_json(
                self._tail_path,
                {**tail_body, "tail_identity": fingerprint(tail_body)},
                mode=0o600,
            )
            return self.load_candidate_receipt(
                receipt_identity=receipt["receipt_identity"],
                witness_run_identity=run_identity,
                expected_policy=policy,
                expected_executable_identity=before.to_dict(),
            )

    def load_candidate_evidence(
        self,
        *,
        receipt_identity: str,
        witness_run_identity: str,
        expected_policy: "ModelBindingPolicy",
        expected_executable_identity: Mapping[str, Any],
    ) -> "CandidateEvidenceBundle":
        """Reopen and revalidate the current receipt and its exact durable pack."""

        expected_policy.validated()
        require_sha256(receipt_identity, "candidate witness receipt identity")
        require_identifier(witness_run_identity, "candidate witness run identity")
        store_anchor = self._read_store_anchor()
        tail = self._read_tail()
        if tail is None:
            raise SerializationWitnessError(
                "trusted witness-store tail is missing",
                classification="WITNESS_EVIDENCE_MISSING",
            )
        if (
            tail["receipt_identity"] != receipt_identity
            or tail["witness_run_identity"] != witness_run_identity
        ):
            raise SerializationWitnessError(
                "receipt is not the externally anchored current witness",
                classification="WITNESS_TAIL_SUBSTITUTED",
            )
        anchor_path = self._anchors / f"{witness_run_identity}.json"
        receipt_path = self._receipts / f"{witness_run_identity}.json"
        try:
            run_anchor = strict_json_loads(
                anchor_path.read_bytes(), label="trusted witness-run anchor"
            )
            receipt = strict_json_loads(
                receipt_path.read_bytes(), label="candidate witness receipt"
            )
        except (FileNotFoundError, ValueError) as error:
            raise SerializationWitnessError(
                "candidate witness anchor or receipt is missing",
                classification="WITNESS_EVIDENCE_MISSING",
            ) from error
        require_exact_keys(
            run_anchor,
            {
                "schema_version",
                "trust_state",
                "store_anchor_fingerprint",
                "witness_run_identity",
                "witness_run_nonce",
                "sequence",
                "previous_tail_identity",
                "model_binding_policy_fingerprint",
                "trusted_verifier_identity",
                "codex_executable_identity",
                "configuration_fingerprint",
                "state",
                "run_anchor_fingerprint",
            },
            "trusted witness-run anchor",
        )
        anchor_body = {
            key: item for key, item in run_anchor.items()
            if key != "run_anchor_fingerprint"
        }
        require_identifier(
            run_anchor["witness_run_identity"],
            "witness-run anchor identity",
        )
        require_sha256(run_anchor["witness_run_nonce"], "witness-run nonce")
        require_strict_int(
            run_anchor["sequence"],
            "witness-run sequence",
            minimum=1,
            maximum=1_000_000,
        )
        for key in (
            "store_anchor_fingerprint",
            "previous_tail_identity",
            "model_binding_policy_fingerprint",
            "trusted_verifier_identity",
            "configuration_fingerprint",
            "run_anchor_fingerprint",
        ):
            require_sha256(run_anchor[key], f"witness-run anchor {key}")
        validate_component_identity_metadata(
            run_anchor["codex_executable_identity"],
            "witness-run anchor Codex executable",
        )
        if (
            run_anchor["schema_version"] != WITNESS_RUN_ANCHOR_SCHEMA_VERSION
            or run_anchor["trust_state"] != CANDIDATE_WITNESS_TRUST_STATE
            or run_anchor["store_anchor_fingerprint"]
            != store_anchor["store_anchor_fingerprint"]
            or run_anchor["witness_run_identity"] != witness_run_identity
            or run_anchor["sequence"] != tail["sequence"]
            or run_anchor["previous_tail_identity"]
            != tail["previous_tail_identity"]
            or run_anchor["model_binding_policy_fingerprint"]
            != expected_policy.policy_fingerprint
            or run_anchor["trusted_verifier_identity"]
            != trusted_witness_verifier_identity()
            or run_anchor["codex_executable_identity"]
            != dict(expected_executable_identity)
            or run_anchor["configuration_fingerprint"]
            != expected_policy.configuration_fingerprint
            or run_anchor["state"] != "ANCHORED_BEFORE_EXECUTION"
            or fingerprint(anchor_body) != run_anchor["run_anchor_fingerprint"]
        ):
            raise SerializationWitnessError(
                "trusted witness-run anchor differs",
                classification="WITNESS_RUN_ANCHOR_INVALID",
            )
        if not isinstance(receipt, Mapping):
            raise SerializationWitnessError("candidate receipt is not an object")
        receipt = validate_candidate_receipt_metadata(
            receipt,
            expected_policy=expected_policy,
            expected_executable_identity=expected_executable_identity,
        )
        receipt_body = {
            key: item for key, item in receipt.items() if key != "receipt_identity"
        }
        if (
            receipt.get("schema_version") != CANDIDATE_WITNESS_RECEIPT_SCHEMA_VERSION
            or receipt.get("receipt_identity") != receipt_identity
            or fingerprint(receipt_body) != receipt_identity
            or receipt.get("store_anchor_fingerprint")
            != store_anchor["store_anchor_fingerprint"]
            or receipt.get("run_anchor_fingerprint")
            != run_anchor["run_anchor_fingerprint"]
            or receipt.get("witness_run_identity") != witness_run_identity
            or receipt.get("witness_run_nonce") != run_anchor["witness_run_nonce"]
            or receipt.get("sequence") != tail["sequence"]
            or receipt.get("model_binding_policy_fingerprint")
            != expected_policy.policy_fingerprint
            or receipt.get("trusted_witness_verifier_identity")
            != trusted_witness_verifier_identity()
            or receipt.get("codex_executable_identity")
            != dict(expected_executable_identity)
            or receipt.get("protocol_schema_identity")
            != expected_policy.protocol_schema_identity
            or receipt.get("canonical_configuration_fingerprint")
            != expected_policy.configuration_fingerprint
            or receipt.get("configured_model") != expected_policy.configured_model
            or receipt.get("configured_reasoning_effort")
            != expected_policy.configured_reasoning_effort
            or receipt.get("thread_start_allow_provider_model_fallback") is not False
            or receipt.get("captured_serialized_model")
            != expected_policy.configured_model
            or receipt.get("captured_serialized_reasoning_effort")
            != expected_policy.configured_reasoning_effort
            or receipt.get("effective_thread_start_model")
            != expected_policy.configured_model
            or receipt.get("effective_thread_start_reasoning_effort")
            != expected_policy.configured_reasoning_effort
            or receipt.get("no_public_route_proven") is not True
            or receipt.get("no_resolver_proven") is not True
            or receipt.get("synthetic_endpoint_policy_identity")
            != SYNTHETIC_ENDPOINT_POLICY_IDENTITY
            or receipt.get("complete_witness_evidence_pack_fingerprint")
            != receipt.get("evidence_pack_fingerprint")
        ):
            raise SerializationWitnessError(
                "candidate receipt differs from its recorded bindings",
                classification="WITNESS_RECEIPT_INVALID",
            )
        relative_pack = receipt.get("evidence_pack_relative_path")
        if relative_pack != f"evidence-packs/{witness_run_identity}.json":
            raise SerializationWitnessError(
                "receipt selected an unauthorized evidence-pack path",
                classification="WITNESS_PACK_PATH_SUBSTITUTED",
            )
        pack_path = self.root / relative_pack
        try:
            pack_bytes = pack_path.read_bytes()
        except FileNotFoundError as error:
            raise SerializationWitnessError(
                "durable witness evidence pack is missing",
                classification="WITNESS_EVIDENCE_MISSING",
            ) from error
        if (
            sha256_bytes(pack_bytes) != receipt.get("evidence_pack_sha256")
            or len(pack_bytes) != receipt.get("evidence_pack_size")
        ):
            raise SerializationWitnessError(
                "durable witness evidence bytes changed",
                classification="WITNESS_EVIDENCE_CHANGED",
            )
        try:
            pack = strict_json_loads(pack_bytes, label="durable witness evidence pack")
        except ValueError as error:
            raise SerializationWitnessError(
                "durable witness evidence pack is invalid",
                classification="WITNESS_EVIDENCE_CHANGED",
            ) from error
        if not isinstance(pack, Mapping):
            raise SerializationWitnessError(
                "durable witness evidence pack is not an object",
                classification="WITNESS_EVIDENCE_CHANGED",
            )
        require_exact_keys(
            pack,
            _EVIDENCE_PACK_KEYS,
            "durable witness evidence pack",
        )
        namespace_evidence = _validated_namespace_evidence(
            pack["namespace_network_evidence"]
        )
        _validated_terminal_result(pack["witness_process_terminal_result"])
        validate_component_identity_metadata(
            pack["codex_executable_identity"],
            "durable evidence Codex executable",
        )
        validate_component_identity_metadata(
            pack["executable_stat_before"],
            "durable evidence executable before",
        )
        validate_component_identity_metadata(
            pack["executable_stat_after"],
            "durable evidence executable after",
        )
        require_strict_int(
            pack["sequence"],
            "durable evidence sequence",
            minimum=1,
            maximum=1_000_000,
        )
        for key in (
            "store_anchor_fingerprint",
            "run_anchor_fingerprint",
            "witness_run_nonce",
            "previous_tail_identity",
            "model_binding_policy_fingerprint",
            "witness_policy_identity",
            "trusted_witness_verifier_identity",
            "codex_executable_sha256",
            "protocol_schema_identity",
            "canonical_configuration_fingerprint",
            "namespace_network_witness_identity",
            "synthetic_endpoint_policy_identity",
            "captured_request_evidence_fingerprint",
            "evidence_pack_fingerprint",
        ):
            require_sha256(pack[key], f"durable evidence {key}")
        pack_body = {
            key: item for key, item in pack.items()
            if key != "evidence_pack_fingerprint"
        }
        if (
            pack.get("schema_version") != CANDIDATE_WITNESS_EVIDENCE_SCHEMA_VERSION
            or pack.get("evidence_pack_fingerprint")
            != receipt.get("evidence_pack_fingerprint")
            or fingerprint(pack_body) != pack.get("evidence_pack_fingerprint")
            or pack.get("store_anchor_fingerprint")
            != store_anchor["store_anchor_fingerprint"]
            or pack.get("run_anchor_fingerprint")
            != run_anchor["run_anchor_fingerprint"]
            or pack.get("witness_run_identity") != witness_run_identity
            or pack.get("witness_run_nonce") != run_anchor["witness_run_nonce"]
            or pack.get("model_binding_policy_fingerprint")
            != expected_policy.policy_fingerprint
            or pack.get("witness_policy_identity")
            != expected_policy.witness_policy_identity
            or pack.get("trusted_witness_verifier_identity")
            != trusted_witness_verifier_identity()
            or pack.get("codex_executable_identity")
            != dict(expected_executable_identity)
            or pack.get("codex_executable_sha256")
            != expected_executable_identity.get("sha256")
            or pack.get("executable_stat_before")
            != dict(expected_executable_identity)
            or pack.get("executable_stat_after")
            != dict(expected_executable_identity)
            or pack.get("protocol_schema_identity")
            != expected_policy.protocol_schema_identity
            or pack.get("canonical_configuration_fingerprint")
            != expected_policy.configuration_fingerprint
            or pack.get("configured_model") != expected_policy.configured_model
            or pack.get("configured_reasoning_effort")
            != expected_policy.configured_reasoning_effort
            or pack.get("captured_serialized_model")
            != expected_policy.configured_model
            or pack.get("captured_serialized_reasoning_effort")
            != expected_policy.configured_reasoning_effort
            or pack.get("effective_thread_start_model")
            != expected_policy.configured_model
            or pack.get("effective_thread_start_reasoning_effort")
            != expected_policy.configured_reasoning_effort
            or pack.get("thread_start_allow_provider_model_fallback") is not False
            or pack.get("captured_request_path")
            != TRUSTED_WITNESS_EXACT_REQUEST_PATH
            or pack.get("captured_request_evidence_fingerprint")
            != _captured_request_fingerprint(pack)
            or pack.get("namespace_network_witness_identity")
            != fingerprint(namespace_evidence)
            or pack.get("synthetic_endpoint_policy_identity")
            != SYNTHETIC_ENDPOINT_POLICY_IDENTITY
            or pack.get("no_public_route_proven") is not True
            or pack.get("no_resolver_proven") is not True
            or pack.get("witness_process_terminal_result")
            != receipt.get("witness_process_terminal_result")
            or pack.get("namespace_network_witness_identity")
            != receipt.get("namespace_network_witness_identity")
            or pack.get("captured_request_evidence_fingerprint")
            != receipt.get("captured_request_evidence_fingerprint")
            or pack.get("captured_request_path")
            != receipt.get("captured_request_path")
            or pack.get("sequence") != receipt.get("sequence")
            or pack.get("previous_tail_identity")
            != run_anchor.get("previous_tail_identity")
        ):
            raise SerializationWitnessError(
                "durable evidence pack differs from the receipt or policy",
                classification="WITNESS_EVIDENCE_CHANGED",
            )
        if (
            tail["evidence_pack_fingerprint"]
            != pack["evidence_pack_fingerprint"]
        ):
            raise SerializationWitnessError(
                "store tail differs from the evidence pack",
                classification="WITNESS_TAIL_SUBSTITUTED",
            )
        typed_pack = CandidateSerializationWitnessPack(
            pack, _CANDIDATE_CONSTRUCTION_TOKEN
        ).revalidated(
            expected_policy=expected_policy,
            expected_executable_identity=expected_executable_identity,
        )
        return CandidateEvidenceBundle(
            receipt=CandidateSerializationWitnessReceipt(
                receipt, _CANDIDATE_CONSTRUCTION_TOKEN
            ),
            pack=typed_pack,
            store_anchor_fingerprint=store_anchor["store_anchor_fingerprint"],
            tail_identity=tail["tail_identity"],
            store_root_identity=MappingProxyType(self._root_identity()),
        )

    def load_candidate_receipt(
        self,
        *,
        receipt_identity: str,
        witness_run_identity: str,
        expected_policy: "ModelBindingPolicy",
        expected_executable_identity: Mapping[str, Any],
    ) -> CandidateSerializationWitnessReceipt:
        """Return only the candidate receipt half of the revalidated bundle."""

        return self.load_candidate_evidence(
            receipt_identity=receipt_identity,
            witness_run_identity=witness_run_identity,
            expected_policy=expected_policy,
            expected_executable_identity=expected_executable_identity,
        ).receipt

    def current_tail_identity(self) -> str | None:
        """Return the current candidate tail identity, or ``None`` if absent."""

        tail = self._read_tail()
        return None if tail is None else tail["tail_identity"]

    def store_root_identity(self) -> Mapping[str, Any]:
        """Return the live path/device/inode identity of this candidate root."""

        return MappingProxyType(self._root_identity())

    def load_current_candidate_evidence(
        self,
        *,
        expected_policy: "ModelBindingPolicy",
        expected_executable_identity: Mapping[str, Any],
    ) -> "CandidateEvidenceBundle":
        """Load the current candidate bundle named by this store's own tail."""

        tail = self._read_tail()
        if tail is None:
            raise SerializationWitnessError(
                "no candidate witness receipt is recorded",
                classification="WITNESS_EVIDENCE_MISSING",
            )
        return self.load_candidate_evidence(
            receipt_identity=tail["receipt_identity"],
            witness_run_identity=tail["witness_run_identity"],
            expected_policy=expected_policy,
            expected_executable_identity=expected_executable_identity,
        )

    def load_current_candidate_receipt(
        self,
        *,
        expected_policy: "ModelBindingPolicy",
        expected_executable_identity: Mapping[str, Any],
    ) -> CandidateSerializationWitnessReceipt:
        """Load the current candidate receipt named by this store's own tail.

        The caller selects nothing and the store confirms nothing external.
        This is candidate evidence, never production authority.
        """

        return self.load_current_candidate_evidence(
            expected_policy=expected_policy,
            expected_executable_identity=expected_executable_identity,
        ).receipt
