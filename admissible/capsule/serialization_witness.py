"""Provider-free serialization witness for the pinned Codex model binding.

The witness answers exactly one question: *did the content-pinned Codex
0.145.0 executable serialize the bound model and reasoning effort onto its
outbound request?*  It answers that question with the real binary, synthetic
authentication and a loopback synthetic ChatGPT-compatible endpoint inside a
private routeless namespace.  No public DNS name, no public endpoint and no
real model or provider execution is involved.

Capture policy
--------------

Only the minimum non-secret request metadata necessary to prove the assertion
is captured:

* the request path (to prove the assertion came from the responses endpoint);
* the serialized ``model``;
* the serialized ``reasoning.effort``.

Prompt contents, request input items, instructions, synthetic token contents,
HTTP authorization, unrelated headers and response bodies are never recorded.
``extract_witness_record`` is the only supported extraction path and reads
exactly those three values out of an already-parsed request body.

Transport honesty
-----------------

Pinned Codex 0.145.0 compiles its TLS trust anchors in.  It ignores
``SSL_CERT_FILE``, ``SSL_CERT_DIR``, ``CODEX_CA_CERT`` and
``NODE_EXTRA_CA_CERTS``, and 0.145.0 accepts no configuration key for an
additional certificate authority, so a synthetic TLS certificate cannot be
trusted by the real client.  The witness endpoint is therefore a cleartext
loopback endpoint confined to a private network namespace with no route off
the host and no resolver.  The sealed egress relay remains in front of the
namespace and still refuses every destination outside its manifest; it never
terminates TLS.  This is recorded in the witness policy so the limitation
travels with the evidence instead of being implied away.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from admissible.capsule.common import (
    fingerprint,
    require_exact_keys,
    require_sha256,
)
from admissible.capsule.model_authority import (
    CodexModelAuthority,
    ModelConfigurationError,
    require_exact_model,
    require_exact_reasoning_effort,
)


SERIALIZATION_WITNESS_SCHEMA_VERSION = (
    "admissible_codex_provider_free_serialization_witness_v1"
)

#: The exact non-secret fields the witness may record.
CAPTURED_FIELDS = (
    "request_path",
    "serialized_model",
    "serialized_reasoning_effort",
)

#: Material the witness must never record, in the witness's own vocabulary.
DENIED_CAPTURE = (
    "http_authorization",
    "prompt_text",
    "request_input_items",
    "request_instructions",
    "response_body",
    "unrelated_http_headers",
    "synthetic_token_contents",
)

#: The responses path the pinned 0.145.0 client posts model turns to.
WITNESS_REQUEST_PATH_SUFFIX = "/responses"


class SerializationWitnessError(ValueError):
    """The pinned client did not serialize the bound model configuration."""


def witness_capture_policy() -> dict[str, Any]:
    """The closed, fingerprinted description of what the witness observes."""

    return {
        "schema_version": SERIALIZATION_WITNESS_SCHEMA_VERSION,
        "captured_fields": list(CAPTURED_FIELDS),
        "denied_capture": list(DENIED_CAPTURE),
        "request_path_suffix": WITNESS_REQUEST_PATH_SUFFIX,
        "executable": "content_attested_pinned_codex_0_145_0_only",
        "authentication": "synthetic_only",
        "namespace": "private_routeless_loopback",
        "endpoint": "local_synthetic_chatgpt_compatible_responses_endpoint",
        "public_dns_or_endpoint": False,
        "real_model_or_provider_execution": False,
        "endpoint_tls_terminated": False,
        "endpoint_tls_unavailable_reason": (
            "pinned_codex_0_145_0_has_no_supported_additional_certificate_authority"
        ),
        "proves": "client_request_serialization_only",
        "does_not_prove": [
            "provider_entitlement",
            "final_provider_routing",
            "real_service_selected_model",
        ],
    }


def serialization_witness_identity() -> str:
    """Identity of the provider-free serialization witness policy."""

    return fingerprint(witness_capture_policy())


class SerializationWitnessRecord:
    """One captured non-secret request assertion."""

    __slots__ = ("_body", "_fingerprint")

    def __init__(self, body: Mapping[str, Any], record_fingerprint: str):
        object.__setattr__(self, "_body", dict(body))
        object.__setattr__(self, "_fingerprint", record_fingerprint)

    def __setattr__(self, name: str, value: Any) -> None:  # pragma: no cover
        raise AttributeError("SerializationWitnessRecord is immutable")

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, SerializationWitnessRecord)
            and other.record_fingerprint == self.record_fingerprint
        )

    def __hash__(self) -> int:
        return hash(self.record_fingerprint)

    @classmethod
    def create(
        cls,
        *,
        request_path: str,
        serialized_model: str,
        serialized_reasoning_effort: str,
    ) -> "SerializationWitnessRecord":
        if not isinstance(request_path, str) or not request_path.startswith("/"):
            raise SerializationWitnessError("witness request path is not a URL path")
        if len(request_path) > 256 or "?" in request_path:
            raise SerializationWitnessError("witness request path is out of bounds")
        body = {
            "schema_version": SERIALIZATION_WITNESS_SCHEMA_VERSION,
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
                "witness_policy_identity",
                "request_path",
                "serialized_model",
                "serialized_reasoning_effort",
            },
            "serialization witness record",
        )
        if self._body["schema_version"] != SERIALIZATION_WITNESS_SCHEMA_VERSION:
            raise SerializationWitnessError("unsupported serialization witness schema")
        if self._body["witness_policy_identity"] != serialization_witness_identity():
            raise SerializationWitnessError("serialization witness policy changed")
        for label, value in (
            ("witness serialized model", self._body["serialized_model"]),
            (
                "witness serialized reasoning effort",
                self._body["serialized_reasoning_effort"],
            ),
        ):
            if not isinstance(value, str) or not value or len(value) > 128:
                raise SerializationWitnessError(f"{label} is not exact text")
        require_sha256(self._fingerprint, "serialization witness record fingerprint")
        if fingerprint(self._body) != self._fingerprint:
            raise SerializationWitnessError("serialization witness record fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body, "record_fingerprint": self._fingerprint}


def extract_witness_record(
    *,
    request_path: str,
    request_body: Mapping[str, Any],
) -> SerializationWitnessRecord:
    """Read only ``model`` and ``reasoning.effort`` out of a captured request.

    Every other member of ``request_body`` is ignored and never copied into
    the record, so prompt text, instructions and tool definitions cannot leak
    into evidence.
    """

    if not isinstance(request_body, Mapping):
        raise SerializationWitnessError("captured request body is not an object")
    model = request_body.get("model")
    if not isinstance(model, str) or not model:
        raise SerializationWitnessError(
            "pinned client serialized no explicit model on its request"
        )
    reasoning = request_body.get("reasoning")
    if not isinstance(reasoning, Mapping):
        raise SerializationWitnessError(
            "pinned client serialized no reasoning object on its request"
        )
    effort = reasoning.get("effort")
    if not isinstance(effort, str) or not effort:
        raise SerializationWitnessError(
            "pinned client serialized no explicit reasoning effort on its request"
        )
    return SerializationWitnessRecord.create(
        request_path=request_path,
        serialized_model=model,
        serialized_reasoning_effort=effort,
    )


def evaluate_serialization_witness(
    records: Sequence[SerializationWitnessRecord],
    authority: CodexModelAuthority,
) -> dict[str, Any]:
    """Refuse unless every captured request carried the exact bound values."""

    authority.validated()
    if not records:
        raise SerializationWitnessError(
            "no provider-free request was serialized by the pinned client"
        )
    for record in records:
        record.validated()
        if not record.request_path.endswith(WITNESS_REQUEST_PATH_SUFFIX):
            raise SerializationWitnessError(
                "witness observed a request outside the responses endpoint"
            )
        try:
            model = require_exact_model(
                record.serialized_model, "serialized model"
            )
            effort = require_exact_reasoning_effort(
                record.serialized_reasoning_effort, "serialized reasoning effort"
            )
        except ModelConfigurationError as error:
            raise SerializationWitnessError(str(error)) from error
        if model != authority.configured_model:
            raise SerializationWitnessError(
                "serialized model differs from the bound model authority"
            )
        if effort != authority.configured_reasoning_effort:
            raise SerializationWitnessError(
                "serialized reasoning effort differs from the bound model authority"
            )
    return {
        "witness_policy_identity": serialization_witness_identity(),
        "model_authority_fingerprint": authority.authority_fingerprint,
        "configured_model": authority.configured_model,
        "configured_reasoning_effort": authority.configured_reasoning_effort,
        "provider_free_serialized_model": authority.configured_model,
        "provider_free_serialized_reasoning_effort": (
            authority.configured_reasoning_effort
        ),
        "observed_requests": len(records),
        "record_fingerprints": [record.record_fingerprint for record in records],
        "real_service_selected_model": "CANARY_TIME_OBSERVATION_ONLY",
    }
