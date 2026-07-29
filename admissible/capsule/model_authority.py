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


MODEL_AUTHORITY_SCHEMA_VERSION = "admissible_codex_model_authority_v2"
MODEL_CONFIGURATION_SCHEMA_VERSION = "admissible_codex_model_configuration_v1"
MODEL_BINDING_POLICY_SCHEMA_VERSION = "admissible_codex_model_binding_policy_v1"
CANARY_MODEL_BINDING_POLICY_KIND = "chatgpt_codex_canary_gpt_5_3_low_v1"
ISOLATED_MODEL_BINDING_POLICY_KIND = "isolated_untrusted_model_binding_v1"

#: The exact canary binding required by the repair.
CANARY_CONFIGURED_MODEL = "gpt-5.3-codex"
CANARY_CONFIGURED_REASONING_EFFORT = "low"
CANARY_ALLOW_PROVIDER_MODEL_FALLBACK = False
CANARY_PINNED_CODEX_VERSION = "0.145.0"
CANARY_PINNED_CODEX_SHA256 = (
    "a2a05dafaa1acb002a45eaec0a462de5b13694fcfcd7bc43305f14781ce7be14"
)
CANARY_PROTOCOL_SCHEMA_IDENTITY = (
    "cec0eb5631a013b3be09670f9aa05193b43cf47b9ad7443d6266fff8b7fe960f"
)

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


class ModelBindingPolicy:
    """Canonical mission/run authorization for one exact Codex model tuple.

    Constructing a policy does not prove serialization.  A launch additionally
    requires a durable verified witness receipt for the same complete policy.
    This separation permits future missions to seal a different tuple without
    turning a runtime model argument into authority.
    """

    __slots__ = ("_body", "_fingerprint")

    def __init__(self, body: Mapping[str, Any], policy_fingerprint: str):
        object.__setattr__(self, "_body", dict(body))
        object.__setattr__(self, "_fingerprint", policy_fingerprint)

    def __setattr__(self, name: str, value: Any) -> None:  # pragma: no cover
        raise AttributeError("ModelBindingPolicy is immutable")

    @classmethod
    def create(
        cls,
        *,
        policy_kind: str,
        configured_model: str,
        configured_reasoning_effort: str,
        allow_provider_model_fallback: bool,
        codex_executable_identity: Mapping[str, Any],
        codex_version: str = CANARY_PINNED_CODEX_VERSION,
    ) -> "ModelBindingPolicy":
        from admissible.capsule.common import require_bool, require_identifier
        from admissible.capsule.serialization_witness import (
            serialization_witness_identity,
            trusted_witness_verifier_identity,
        )

        require_identifier(policy_kind, "model-binding policy kind")
        model = require_exact_model(configured_model)
        effort = require_exact_reasoning_effort(configured_reasoning_effort)
        if require_bool(
            allow_provider_model_fallback,
            "model-binding provider fallback",
        ):
            raise ModelConfigurationError(
                "sealed model-binding policies must refuse provider fallback"
            )
        if codex_version != CANARY_PINNED_CODEX_VERSION:
            raise ModelConfigurationError(
                "this policy implementation supports only pinned Codex 0.145.0"
            )
        executable = validate_component_identity_metadata(
            codex_executable_identity,
            "model-binding policy Codex executable",
        )
        configuration = _configuration_body(
            model=model,
            reasoning_effort=effort,
        )
        body = {
            "schema_version": MODEL_BINDING_POLICY_SCHEMA_VERSION,
            "policy_kind": policy_kind,
            "configured_model": model,
            "configured_reasoning_effort": effort,
            "allow_provider_model_fallback": False,
            "codex_version": codex_version,
            "codex_executable_identity": dict(executable),
            "protocol_schema_identity": protocol_schema_identity(),
            "canonical_configuration_fingerprint": fingerprint(configuration),
            "serialization_witness_policy_identity": (
                serialization_witness_identity()
            ),
            "trusted_witness_verifier_identity": (
                trusted_witness_verifier_identity()
            ),
        }
        return cls(body, fingerprint(body)).validated()

    @property
    def policy_fingerprint(self) -> str:
        return self._fingerprint

    @property
    def configured_model(self) -> str:
        return self._body["configured_model"]

    @property
    def configured_reasoning_effort(self) -> str:
        return self._body["configured_reasoning_effort"]

    @property
    def allow_provider_model_fallback(self) -> bool:
        return self._body["allow_provider_model_fallback"]

    @property
    def codex_executable_identity(self) -> Mapping[str, Any]:
        return dict(self._body["codex_executable_identity"])

    @property
    def protocol_schema_identity(self) -> str:
        return self._body["protocol_schema_identity"]

    @property
    def configuration_fingerprint(self) -> str:
        return self._body["canonical_configuration_fingerprint"]

    @property
    def witness_policy_identity(self) -> str:
        return self._body["serialization_witness_policy_identity"]

    @property
    def ephemeral_config_bytes(self) -> bytes:
        return ephemeral_config_bytes(
            model=self.configured_model,
            reasoning_effort=self.configured_reasoning_effort,
        )

    @property
    def thread_start_fields(self) -> dict[str, Any]:
        return thread_start_model_params(
            model=self.configured_model,
            reasoning_effort=self.configured_reasoning_effort,
        )

    @property
    def turn_start_fields(self) -> dict[str, Any]:
        return turn_start_model_params(
            model=self.configured_model,
            reasoning_effort=self.configured_reasoning_effort,
        )

    def validated(self) -> "ModelBindingPolicy":
        from admissible.capsule.common import require_bool, require_identifier
        from admissible.capsule.serialization_witness import (
            serialization_witness_identity,
            trusted_witness_verifier_identity,
        )

        require_exact_keys(
            self._body,
            {
                "schema_version",
                "policy_kind",
                "configured_model",
                "configured_reasoning_effort",
                "allow_provider_model_fallback",
                "codex_version",
                "codex_executable_identity",
                "protocol_schema_identity",
                "canonical_configuration_fingerprint",
                "serialization_witness_policy_identity",
                "trusted_witness_verifier_identity",
            },
            "model-binding policy",
        )
        if self._body["schema_version"] != MODEL_BINDING_POLICY_SCHEMA_VERSION:
            raise ModelConfigurationError("unsupported model-binding policy schema")
        require_identifier(self._body["policy_kind"], "model-binding policy kind")
        model = require_exact_model(self.configured_model)
        effort = require_exact_reasoning_effort(
            self.configured_reasoning_effort
        )
        if require_bool(
            self.allow_provider_model_fallback,
            "model-binding provider fallback",
        ):
            raise ModelConfigurationError(
                "model-binding policy permits provider fallback"
            )
        if self._body["codex_version"] != CANARY_PINNED_CODEX_VERSION:
            raise ModelConfigurationError("model-binding Codex version changed")
        validate_component_identity_metadata(
            self._body["codex_executable_identity"],
            "model-binding policy Codex executable",
        )
        if self.protocol_schema_identity != protocol_schema_identity():
            raise ModelConfigurationError(
                "model-binding protocol schema identity changed"
            )
        configuration = _configuration_body(
            model=model,
            reasoning_effort=effort,
        )
        if self.configuration_fingerprint != fingerprint(configuration):
            raise ModelConfigurationError(
                "model-binding canonical configuration changed"
            )
        if (
            self.witness_policy_identity != serialization_witness_identity()
            or self._body["trusted_witness_verifier_identity"]
            != trusted_witness_verifier_identity()
        ):
            raise ModelConfigurationError(
                "model-binding witness policy or verifier changed"
            )
        require_sha256(self._fingerprint, "model-binding policy fingerprint")
        if fingerprint(self._body) != self._fingerprint:
            raise ModelConfigurationError("model-binding policy fingerprint mismatch")
        return self

    def validated_canary(self) -> "ModelBindingPolicy":
        self.validated()
        executable = self.codex_executable_identity
        if (
            self._body["policy_kind"] != CANARY_MODEL_BINDING_POLICY_KIND
            or self.configured_model != CANARY_CONFIGURED_MODEL
            or self.configured_reasoning_effort
            != CANARY_CONFIGURED_REASONING_EFFORT
            or self.allow_provider_model_fallback is not False
            or executable.get("sha256") != CANARY_PINNED_CODEX_SHA256
            or self.protocol_schema_identity != CANARY_PROTOCOL_SCHEMA_IDENTITY
        ):
            raise ModelConfigurationError(
                "model-binding policy is not the closed canary authorization"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body, "policy_fingerprint": self._fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelBindingPolicy":
        if not isinstance(value, Mapping):
            raise ModelConfigurationError("model-binding policy must be an object")
        body = dict(value)
        try:
            policy_fingerprint = body.pop("policy_fingerprint")
        except KeyError as error:
            raise ModelConfigurationError(
                "model-binding policy has no fingerprint"
            ) from error
        return cls(body, policy_fingerprint).validated()


def canary_model_binding_policy(
    *,
    codex_executable_identity: Mapping[str, Any],
) -> ModelBindingPolicy:
    """Return the one closed model policy authorized for this canary."""

    return ModelBindingPolicy.create(
        policy_kind=CANARY_MODEL_BINDING_POLICY_KIND,
        configured_model=CANARY_CONFIGURED_MODEL,
        configured_reasoning_effort=CANARY_CONFIGURED_REASONING_EFFORT,
        allow_provider_model_fallback=False,
        codex_executable_identity=codex_executable_identity,
    ).validated_canary()


class CodexModelAuthority:
    """Immutable configuration authority, trusted only with a live receipt.

    ``create`` intentionally produces an isolated, non-launchable authority
    for protocol/configuration analysis.  Only ``from_verified_receipt`` sets
    the in-memory verified provenance bit, and serialized dictionaries never
    recreate that bit.  A backend must reload the receipt from its trusted
    store before accepting a deserialized authority.
    """

    __slots__ = ("_body", "_fingerprint", "_receipt_revalidated")

    def __init__(
        self,
        body: Mapping[str, Any],
        authority_fingerprint: str,
        *,
        receipt_revalidated: bool = False,
    ):
        object.__setattr__(self, "_body", dict(body))
        object.__setattr__(self, "_fingerprint", authority_fingerprint)
        object.__setattr__(
            self,
            "_receipt_revalidated",
            receipt_revalidated is True,
        )

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
        serialization_witness_identity: str | None = None,
    ) -> "CodexModelAuthority":
        """Create a valid-in-isolation authority that cannot authorize launch."""

        if serialization_witness_identity is not None:
            from admissible.capsule.serialization_witness import (
                serialization_witness_identity as expected_witness_policy,
            )

            if serialization_witness_identity != expected_witness_policy():
                raise ModelConfigurationError(
                    "arbitrary serialization witness identity is not authority"
                )
        model = require_exact_model(configured_model)
        effort = require_exact_reasoning_effort(configured_reasoning_effort)
        configuration = _configuration_body(model=model, reasoning_effort=effort)
        identity = validate_component_identity_metadata(
            codex_executable_identity,
            "model authority Codex executable",
        )
        policy = ModelBindingPolicy.create(
            policy_kind=ISOLATED_MODEL_BINDING_POLICY_KIND,
            configured_model=model,
            configured_reasoning_effort=effort,
            allow_provider_model_fallback=False,
            codex_executable_identity=identity,
        )
        body = {
            "schema_version": MODEL_AUTHORITY_SCHEMA_VERSION,
            "trust_state": "ISOLATED_UNAUTHORIZED",
            "configuration": configuration,
            "configuration_fingerprint": fingerprint(configuration),
            "codex_executable_identity": dict(identity),
            "app_server_protocol_version": CODEX_APP_SERVER_PROTOCOL_VERSION,
            "protocol_schema_identity": protocol_schema_identity(),
            "model_binding_policy": policy.to_dict(),
            "model_binding_policy_fingerprint": policy.policy_fingerprint,
            "verified_witness_receipt_identity": None,
            "verified_witness_run_identity": None,
        }
        return cls(body, fingerprint(body)).validated()

    @classmethod
    def from_verified_receipt(
        cls,
        *,
        policy: ModelBindingPolicy,
        receipt: Any,
        trusted_witness_store: Any,
    ) -> "CodexModelAuthority":
        """Derive the only launchable authority after reopening durable evidence."""

        from admissible.capsule.serialization_witness import (
            TrustedSerializationWitnessStore,
            VerifiedSerializationWitnessReceipt,
        )

        if not isinstance(receipt, VerifiedSerializationWitnessReceipt):
            raise ModelConfigurationError(
                "model authority requires an opaque verified witness receipt"
            )
        if not isinstance(trusted_witness_store, TrustedSerializationWitnessStore):
            raise ModelConfigurationError(
                "model authority requires the trusted witness store"
            )
        policy.validated()
        durable_receipt = trusted_witness_store.load_verified_receipt(
            receipt_identity=receipt.receipt_identity,
            witness_run_identity=receipt.witness_run_identity,
            expected_policy=policy,
            expected_executable_identity=policy.codex_executable_identity,
        )
        if durable_receipt.to_dict() != receipt.to_dict():
            raise ModelConfigurationError(
                "opaque receipt differs from revalidated durable evidence"
            )
        receipt = durable_receipt
        if (
            receipt.model_binding_policy_fingerprint != policy.policy_fingerprint
            or receipt.configured_model != policy.configured_model
            or receipt.configured_reasoning_effort
            != policy.configured_reasoning_effort
            or dict(receipt.executable_identity)
            != dict(policy.codex_executable_identity)
        ):
            raise ModelConfigurationError(
                "verified witness receipt belongs to another model policy"
            )
        configuration = _configuration_body(
            model=policy.configured_model,
            reasoning_effort=policy.configured_reasoning_effort,
        )
        body = {
            "schema_version": MODEL_AUTHORITY_SCHEMA_VERSION,
            "trust_state": "VERIFIED_DURABLE_WITNESS",
            "configuration": configuration,
            "configuration_fingerprint": fingerprint(configuration),
            "codex_executable_identity": dict(policy.codex_executable_identity),
            "app_server_protocol_version": CODEX_APP_SERVER_PROTOCOL_VERSION,
            "protocol_schema_identity": protocol_schema_identity(),
            "model_binding_policy": policy.to_dict(),
            "model_binding_policy_fingerprint": policy.policy_fingerprint,
            "verified_witness_receipt_identity": receipt.receipt_identity,
            "verified_witness_run_identity": receipt.witness_run_identity,
        }
        return cls(
            body,
            fingerprint(body),
            receipt_revalidated=True,
        ).validated().require_verified_receipt()

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
        """Compatibility accessor returning only the observation policy ID."""

        return ModelBindingPolicy.from_dict(
            self._body["model_binding_policy"]
        ).witness_policy_identity

    @property
    def model_binding_policy(self) -> ModelBindingPolicy:
        return ModelBindingPolicy.from_dict(self._body["model_binding_policy"])

    @property
    def model_binding_policy_fingerprint(self) -> str:
        return self._body["model_binding_policy_fingerprint"]

    @property
    def verified_witness_receipt_identity(self) -> str | None:
        return self._body["verified_witness_receipt_identity"]

    @property
    def verified_witness_run_identity(self) -> str | None:
        return self._body["verified_witness_run_identity"]

    @property
    def receipt_revalidated(self) -> bool:
        return self._receipt_revalidated

    def require_verified_receipt(self) -> "CodexModelAuthority":
        if (
            self._body["trust_state"] != "VERIFIED_DURABLE_WITNESS"
            or not self._receipt_revalidated
            or self.verified_witness_receipt_identity is None
            or self.verified_witness_run_identity is None
        ):
            raise ModelConfigurationError(
                "model authority has no revalidated durable witness receipt"
            )
        return self

    # -- validation ------------------------------------------------------

    def validated(self) -> "CodexModelAuthority":
        body = self._body
        require_exact_keys(
            body,
            {
                "schema_version",
                "trust_state",
                "configuration",
                "configuration_fingerprint",
                "codex_executable_identity",
                "app_server_protocol_version",
                "protocol_schema_identity",
                "model_binding_policy",
                "model_binding_policy_fingerprint",
                "verified_witness_receipt_identity",
                "verified_witness_run_identity",
            },
            "Codex model authority",
        )
        if body["schema_version"] != MODEL_AUTHORITY_SCHEMA_VERSION:
            raise ModelConfigurationError("unsupported Codex model authority schema")
        if body["trust_state"] not in {
            "ISOLATED_UNAUTHORIZED",
            "VERIFIED_DURABLE_WITNESS",
        }:
            raise ModelConfigurationError("unknown model authority trust state")
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
        policy = ModelBindingPolicy.from_dict(body["model_binding_policy"])
        require_sha256(
            body["model_binding_policy_fingerprint"],
            "model-binding policy fingerprint",
        )
        if (
            policy.policy_fingerprint
            != body["model_binding_policy_fingerprint"]
            or policy.configured_model != model
            or policy.configured_reasoning_effort != effort
            or dict(policy.codex_executable_identity)
            != dict(body["codex_executable_identity"])
            or policy.configuration_fingerprint
            != body["configuration_fingerprint"]
        ):
            raise ModelConfigurationError(
                "model authority differs from its sealed model policy"
            )
        if body["trust_state"] == "ISOLATED_UNAUTHORIZED":
            if (
                body["verified_witness_receipt_identity"] is not None
                or body["verified_witness_run_identity"] is not None
            ):
                raise ModelConfigurationError(
                    "isolated model authority asserted witness evidence"
                )
        else:
            require_sha256(
                body["verified_witness_receipt_identity"],
                "verified witness receipt identity",
            )
            from admissible.capsule.common import require_identifier

            require_identifier(
                body["verified_witness_run_identity"],
                "verified witness run identity",
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
        # Serialized bytes are only structurally valid.  Trust is recovered
        # solely by reopening the referenced receipt/evidence through the
        # externally anchored witness store.
        return cls(
            data,
            authority_fingerprint,
            receipt_revalidated=False,
        ).validated()


def canary_model_authority(
    *,
    model_binding_policy: ModelBindingPolicy,
    verified_witness_receipt: Any,
    trusted_witness_store: Any,
) -> CodexModelAuthority:
    """Derive the exact canary authority from durable verified evidence."""

    model_binding_policy.validated_canary()
    return CodexModelAuthority.from_verified_receipt(
        policy=model_binding_policy,
        receipt=verified_witness_receipt,
        trusted_witness_store=trusted_witness_store,
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
