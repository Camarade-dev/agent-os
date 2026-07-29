"""Canonical immutable model/reasoning-effort authority for pinned Codex.

The failed ChatGPT Codex canary preflight established that the production
surface carried no explicit model or reasoning effort through Codex argv, the
ephemeral ``CODEX_HOME`` configuration, ``thread/start``, ``turn/start`` or the
execution authority, and therefore terminated with
``CHATGPT_CODEX_CANARY_MODEL_UNRESOLVED``.

This module supplies the missing binding.  It is deliberately narrow: it owns
the model/effort configuration channel and nothing else.  The OS boundary,
brokers, egress, controller, capsule, verification and finalizer are untouched.

Channel determination (pinned ``codex-cli 0.145.0`` only)
--------------------------------------------------------

The exact channel was determined empirically from the content-pinned 0.145.0
executable, its generated app-server JSON Schemas, its ``--strict-config``
oracle and its provider-free request serialization against a loopback synthetic
endpoint.  Nothing here is inferred from another Codex version.

* ``v2/ThreadStartParams.json`` declares ``model`` (``string | null``),
  ``allowProviderModelFallback`` (``boolean``) and ``config`` (a free-form
  configuration overlay).  It declares **no** reasoning-effort property, so the
  effort is carried in the ``config`` overlay as ``model_reasoning_effort``.
* ``v2/TurnStartParams.json`` declares ``model`` (``string | null``) and
  ``effort`` (``ReasoningEffort``: "a non-empty reasoning effort value
  advertised by the model").
* ``v2/ThreadStartResponse.json`` returns the *effective* ``model`` and
  ``reasoningEffort`` for the started thread, which is what makes the binding
  checkable before any effect runs.
* An ephemeral ``CODEX_HOME/config.toml`` carrying top-level ``model`` and
  ``model_reasoning_effort`` is recognized by ``--strict-config`` and *is*
  authoritative for the app server when the request fields are absent.  With
  both removed from every layer, 0.145.0 falls back to its own mutable client
  default model, which is exactly the failure the canary must prevent.

The admissible channel is therefore both layers at once: canonical ephemeral
configuration bytes generated in the authentication broker and byte-bound into
the authority, plus explicit ``thread/start`` and ``turn/start`` request fields
that re-assert the same two values.  ``allowProviderModelFallback`` is
explicitly ``false``, no ``-c``/``--config`` override is ever passed on argv,
and the empty mount namespace plus the ephemeral home prevent any user or
project configuration from being discovered.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Mapping

from admissible.capsule.codex_protocol import (
    CODEX_APP_SERVER_PROTOCOL_VERSION,
    protocol_schema_identity,
)
from admissible.capsule.common import (
    fingerprint,
    require_exact_keys,
    require_sha256,
    sha256_bytes,
)
from admissible.capsule.execution_authority import validate_component_identity_metadata


MODEL_AUTHORITY_SCHEMA_VERSION = "admissible_codex_model_authority_v1"
MODEL_CONFIGURATION_SCHEMA_VERSION = "admissible_codex_model_configuration_v1"

#: The exact canary binding required by the repair.
CANARY_CONFIGURED_MODEL = "gpt-5.3-codex"
CANARY_CONFIGURED_REASONING_EFFORT = "low"

#: The exact channel proven from pinned Codex 0.145.0 (see module docstring).
MODEL_CONFIGURATION_CHANNEL = (
    "codex_0_145_0_app_server_thread_start_model_and_config_effort_"
    "with_turn_start_reassertion_v1"
)

#: Closed reasoning-effort vocabulary this authority may express.  ``xhigh``
#: and ``ultra`` are deliberately outside it, as is any provider-selected or
#: automatic value.
SUPPORTED_REASONING_EFFORTS = ("low", "medium", "high")

#: Values that may never appear as a configured model or effort, whatever the
#: mission.  ``auto`` and the empty/omitted value are the two shapes that would
#: let the provider or a mutable client default choose at runtime.
PROHIBITED_CONFIGURATION_VALUES = ("", "auto", "default", "none", "null")

_MODEL_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_EFFORT_TOKEN = re.compile(r"^[a-z][a-z-]{0,31}$")

#: Configuration keys the ephemeral ``CODEX_HOME`` file is allowed to carry.
#: The file is non-secret by construction; authentication contents never pass
#: through it.
_EPHEMERAL_CONFIG_FILENAME = "config.toml"


class ModelConfigurationError(ValueError):
    """A model/effort binding is missing, ambiguous or substituted."""


def require_exact_model(value: Any, label: str = "configured model") -> str:
    """Refuse omitted, empty, ``auto``, mis-cased and free-form model values."""

    if not isinstance(value, str):
        raise ModelConfigurationError(f"{label} must be an explicit string")
    if value.strip() != value or _MODEL_TOKEN.fullmatch(value) is None:
        raise ModelConfigurationError(
            f"{label} must be an exact lowercase model identifier"
        )
    if value in PROHIBITED_CONFIGURATION_VALUES:
        raise ModelConfigurationError(
            f"{label} must not delegate model selection to the client or provider"
        )
    return value


def require_exact_reasoning_effort(
    value: Any,
    label: str = "configured reasoning effort",
) -> str:
    """Refuse omitted, empty, ``auto``, mis-cased and out-of-vocabulary effort."""

    if not isinstance(value, str):
        raise ModelConfigurationError(f"{label} must be an explicit string")
    if value.strip() != value or _EFFORT_TOKEN.fullmatch(value) is None:
        raise ModelConfigurationError(
            f"{label} must be an exact lowercase reasoning-effort token"
        )
    if value in PROHIBITED_CONFIGURATION_VALUES:
        raise ModelConfigurationError(
            f"{label} must not delegate reasoning effort to the client or provider"
        )
    if value not in SUPPORTED_REASONING_EFFORTS:
        raise ModelConfigurationError(
            f"{label} is outside the admissible reasoning-effort vocabulary"
        )
    return value


def configuration_prohibitions() -> dict[str, Any]:
    """The explicit, fingerprinted prohibition record carried by the authority."""

    return {
        "auto_model_refused": True,
        "auto_reasoning_effort_refused": True,
        "omitted_model_refused": True,
        "omitted_reasoning_effort_refused": True,
        "mutable_client_default_refused": True,
        "provider_model_fallback_refused": True,
        "runtime_provider_selected_model_without_request_binding_refused": True,
        "prohibited_values": list(PROHIBITED_CONFIGURATION_VALUES),
        "reasoning_effort_vocabulary": list(SUPPORTED_REASONING_EFFORTS),
    }


def ephemeral_config_bytes(*, model: str, reasoning_effort: str) -> bytes:
    """Canonical non-secret ``CODEX_HOME/config.toml`` bytes for one session.

    Generated deterministically so the broker, the launcher and the authority
    all agree on the same bytes.  It carries no authentication material and no
    host pathname.  ``model``/``model_reasoning_effort`` are authoritative for
    pinned 0.145.0 whenever the request fields are absent, so writing them here
    is what denies the mutable client default; the remaining keys deny native
    analytics and web search.
    """

    require_exact_model(model)
    require_exact_reasoning_effort(reasoning_effort)
    lines = (
        "# Admissible capsule ephemeral Codex configuration (non-secret).",
        "# Generated canonically by the authentication broker; byte-bound into",
        "# the backend execution authority.  No authentication contents here.",
        f'model = "{model}"',
        f'model_reasoning_effort = "{reasoning_effort}"',
        "",
        "[analytics]",
        "enabled = false",
        "",
        "[features]",
        "web_search = false",
        "",
    )
    return "\n".join(lines).encode("utf-8")


def thread_start_model_params(*, model: str, reasoning_effort: str) -> dict[str, Any]:
    """Exact ``thread/start`` request fields that bind model and effort."""

    require_exact_model(model)
    require_exact_reasoning_effort(reasoning_effort)
    return {
        "model": model,
        "allowProviderModelFallback": False,
        "config": {
            "model": model,
            "model_reasoning_effort": reasoning_effort,
        },
    }


def turn_start_model_params(*, model: str, reasoning_effort: str) -> dict[str, Any]:
    """Exact ``turn/start`` request fields that re-assert model and effort."""

    require_exact_model(model)
    require_exact_reasoning_effort(reasoning_effort)
    return {"model": model, "effort": reasoning_effort}


def _configuration_body(*, model: str, reasoning_effort: str) -> dict[str, Any]:
    config = ephemeral_config_bytes(model=model, reasoning_effort=reasoning_effort)
    return {
        "schema_version": MODEL_CONFIGURATION_SCHEMA_VERSION,
        "configured_model": model,
        "configured_reasoning_effort": reasoning_effort,
        "configuration_channel": MODEL_CONFIGURATION_CHANNEL,
        "thread_start_fields": thread_start_model_params(
            model=model, reasoning_effort=reasoning_effort
        ),
        "turn_start_fields": turn_start_model_params(
            model=model, reasoning_effort=reasoning_effort
        ),
        "ephemeral_config_filename": _EPHEMERAL_CONFIG_FILENAME,
        "ephemeral_config_base64": base64.b64encode(config).decode("ascii"),
        "ephemeral_config_sha256": sha256_bytes(config),
        "ephemeral_config_size": len(config),
        "prohibitions": configuration_prohibitions(),
    }


class CodexModelAuthority:
    """Canonical immutable model authority bound into one backend execution.

    Every field is derived; no caller-asserted string alone is accepted as an
    attestation.  The pinned executable identity, the app-server protocol
    identity and the provider-free serialization-witness identity are all
    bound, so changing either the model or the effort changes the complete
    authority fingerprint.
    """

    __slots__ = ("_body", "_fingerprint")

    def __init__(self, body: Mapping[str, Any], authority_fingerprint: str):
        object.__setattr__(self, "_body", dict(body))
        object.__setattr__(self, "_fingerprint", authority_fingerprint)

    def __setattr__(self, name: str, value: Any) -> None:  # pragma: no cover
        raise AttributeError("CodexModelAuthority is immutable")

    def __delattr__(self, name: str) -> None:  # pragma: no cover
        raise AttributeError("CodexModelAuthority is immutable")

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, CodexModelAuthority)
            and other.authority_fingerprint == self.authority_fingerprint
        )

    def __hash__(self) -> int:
        return hash(self.authority_fingerprint)

    @classmethod
    def create(
        cls,
        *,
        configured_model: str,
        configured_reasoning_effort: str,
        codex_executable_identity: Mapping[str, Any],
        serialization_witness_identity: str,
    ) -> "CodexModelAuthority":
        model = require_exact_model(configured_model)
        effort = require_exact_reasoning_effort(configured_reasoning_effort)
        configuration = _configuration_body(model=model, reasoning_effort=effort)
        identity = validate_component_identity_metadata(
            codex_executable_identity,
            "model authority Codex executable",
        )
        require_sha256(
            serialization_witness_identity,
            "provider-free serialization witness identity",
        )
        body = {
            "schema_version": MODEL_AUTHORITY_SCHEMA_VERSION,
            "configuration": configuration,
            "configuration_fingerprint": fingerprint(configuration),
            "codex_executable_identity": dict(identity),
            "app_server_protocol_version": CODEX_APP_SERVER_PROTOCOL_VERSION,
            "protocol_schema_identity": protocol_schema_identity(),
            "serialization_witness_identity": serialization_witness_identity,
        }
        return cls(body, fingerprint(body)).validated()

    # -- accessors -------------------------------------------------------

    @property
    def authority_fingerprint(self) -> str:
        return self._fingerprint

    @property
    def configuration(self) -> Mapping[str, Any]:
        return dict(self._body["configuration"])

    @property
    def configuration_fingerprint(self) -> str:
        return self._body["configuration_fingerprint"]

    @property
    def configured_model(self) -> str:
        return self._body["configuration"]["configured_model"]

    @property
    def configured_reasoning_effort(self) -> str:
        return self._body["configuration"]["configured_reasoning_effort"]

    @property
    def configuration_channel(self) -> str:
        return self._body["configuration"]["configuration_channel"]

    @property
    def thread_start_fields(self) -> dict[str, Any]:
        return {
            key: (dict(value) if isinstance(value, dict) else value)
            for key, value in self._body["configuration"]["thread_start_fields"].items()
        }

    @property
    def turn_start_fields(self) -> dict[str, Any]:
        return dict(self._body["configuration"]["turn_start_fields"])

    @property
    def ephemeral_config_bytes(self) -> bytes:
        return base64.b64decode(
            self._body["configuration"]["ephemeral_config_base64"], validate=True
        )

    @property
    def ephemeral_config_sha256(self) -> str:
        return self._body["configuration"]["ephemeral_config_sha256"]

    @property
    def codex_executable_identity(self) -> Mapping[str, Any]:
        return dict(self._body["codex_executable_identity"])

    @property
    def serialization_witness_identity(self) -> str:
        return self._body["serialization_witness_identity"]

    # -- validation ------------------------------------------------------

    def validated(self) -> "CodexModelAuthority":
        body = self._body
        require_exact_keys(
            body,
            {
                "schema_version",
                "configuration",
                "configuration_fingerprint",
                "codex_executable_identity",
                "app_server_protocol_version",
                "protocol_schema_identity",
                "serialization_witness_identity",
            },
            "Codex model authority",
        )
        if body["schema_version"] != MODEL_AUTHORITY_SCHEMA_VERSION:
            raise ModelConfigurationError("unsupported Codex model authority schema")
        configuration = body["configuration"]
        require_exact_keys(
            configuration,
            {
                "schema_version",
                "configured_model",
                "configured_reasoning_effort",
                "configuration_channel",
                "thread_start_fields",
                "turn_start_fields",
                "ephemeral_config_filename",
                "ephemeral_config_base64",
                "ephemeral_config_sha256",
                "ephemeral_config_size",
                "prohibitions",
            },
            "Codex model configuration",
        )
        if configuration["schema_version"] != MODEL_CONFIGURATION_SCHEMA_VERSION:
            raise ModelConfigurationError("unsupported Codex model configuration schema")
        model = require_exact_model(configuration["configured_model"])
        effort = require_exact_reasoning_effort(
            configuration["configured_reasoning_effort"]
        )
        if configuration["configuration_channel"] != MODEL_CONFIGURATION_CHANNEL:
            raise ModelConfigurationError("model configuration channel substitution refused")
        if configuration != _configuration_body(model=model, reasoning_effort=effort):
            raise ModelConfigurationError(
                "model configuration is not the canonical derivation of its values"
            )
        if body["configuration_fingerprint"] != fingerprint(configuration):
            raise ModelConfigurationError("model configuration fingerprint mismatch")
        validate_component_identity_metadata(
            body["codex_executable_identity"],
            "model authority Codex executable",
        )
        if body["app_server_protocol_version"] != CODEX_APP_SERVER_PROTOCOL_VERSION:
            raise ModelConfigurationError("model authority protocol version mismatch")
        if body["protocol_schema_identity"] != protocol_schema_identity():
            raise ModelConfigurationError("model authority protocol schema identity mismatch")
        require_sha256(
            body["serialization_witness_identity"],
            "provider-free serialization witness identity",
        )
        require_sha256(self._fingerprint, "Codex model authority fingerprint")
        if fingerprint(body) != self._fingerprint:
            raise ModelConfigurationError("Codex model authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            **{
                key: (dict(value) if isinstance(value, dict) else value)
                for key, value in self._body.items()
            },
            "authority_fingerprint": self._fingerprint,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CodexModelAuthority":
        if not isinstance(value, Mapping):
            raise ModelConfigurationError("Codex model authority must be an object")
        data = dict(value)
        try:
            authority_fingerprint = data.pop("authority_fingerprint")
        except KeyError as error:
            raise ModelConfigurationError(
                "Codex model authority has no fingerprint"
            ) from error
        require_sha256(authority_fingerprint, "Codex model authority fingerprint")
        return cls(data, authority_fingerprint).validated()


def canary_model_authority(
    *,
    codex_executable_identity: Mapping[str, Any],
    serialization_witness_identity: str,
) -> CodexModelAuthority:
    """The exact ``gpt-5.3-codex`` / ``low`` binding required by the canary."""

    return CodexModelAuthority.create(
        configured_model=CANARY_CONFIGURED_MODEL,
        configured_reasoning_effort=CANARY_CONFIGURED_REASONING_EFFORT,
        codex_executable_identity=codex_executable_identity,
        serialization_witness_identity=serialization_witness_identity,
    )


def validate_effective_thread_configuration(
    thread_result: Mapping[str, Any],
    authority: CodexModelAuthority,
) -> dict[str, str]:
    """Validate ``ThreadStartResponse`` effective model/effort before effects.

    This is *configured* evidence: the pinned app server reports the model and
    reasoning effort it will request.  It is not, and must not be read as,
    proof of entitlement or of final provider routing.
    """

    authority.validated()
    if not isinstance(thread_result, Mapping):
        raise ModelConfigurationError("thread/start response is not an object")
    if "model" not in thread_result:
        raise ModelConfigurationError(
            "thread/start response omitted the effective model"
        )
    if "reasoningEffort" not in thread_result:
        raise ModelConfigurationError(
            "thread/start response omitted the effective reasoning effort"
        )
    effective_model = thread_result["model"]
    effective_effort = thread_result["reasoningEffort"]
    if not isinstance(effective_model, str) or not isinstance(effective_effort, str):
        raise ModelConfigurationError(
            "thread/start effective model configuration is not exact text"
        )
    if effective_model != authority.configured_model:
        raise ModelConfigurationError(
            "thread/start effective model differs from the bound model authority"
        )
    if effective_effort != authority.configured_reasoning_effort:
        raise ModelConfigurationError(
            "thread/start effective reasoning effort differs from the bound authority"
        )
    return {
        "configured_model": authority.configured_model,
        "configured_reasoning_effort": authority.configured_reasoning_effort,
        "app_server_effective_model": effective_model,
        "app_server_effective_reasoning_effort": effective_effort,
        "model_authority_fingerprint": authority.authority_fingerprint,
        "real_service_selected_model": "CANARY_TIME_OBSERVATION_ONLY",
    }


def validate_launch_configuration_bytes(
    observed: bytes,
    authority: CodexModelAuthority,
) -> str:
    """Re-attest the effective ephemeral configuration before starting Codex."""

    authority.validated()
    if not isinstance(observed, (bytes, bytearray)):
        raise ModelConfigurationError("effective Codex configuration must be bytes")
    observed = bytes(observed)
    if observed != authority.ephemeral_config_bytes:
        raise ModelConfigurationError(
            "effective Codex configuration differs from the bound model authority"
        )
    digest = sha256_bytes(observed)
    if digest != authority.ephemeral_config_sha256:
        raise ModelConfigurationError("effective Codex configuration identity mismatch")
    return digest
