"""The fixed, non-caller-selectable owner-authority layout and state machine.

Every production path in this module is a module constant.  Nothing in the
production path accepts a root, a socket, a key or a state directory from a
caller: :func:`production_layout` takes no arguments, and the backend never
sees a path parameter at all.  That is the whole point of the boundary --- the
previous self-rooted design failed its audit precisely because an ordinary
caller could choose where the "authority" lived.

A second, explicitly named synthetic layout exists for the provider-free
privilege witness.  It is a *different classification* (``SYNTHETIC_...``), it
can never be produced by :func:`production_layout`, and every production
acceptance point refuses it by classification, not by naming convention.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.common import require_identifier

#: Classification of a layout.  Production acceptance points compare against
#: :data:`PRODUCTION_LAYOUT` exactly; nothing else is production.
PRODUCTION_LAYOUT = "ADMISSIBLE_OWNER_AUTHORITY_PRODUCTION_LAYOUT_V1"
SYNTHETIC_LAYOUT = "ADMISSIBLE_OWNER_AUTHORITY_SYNTHETIC_NON_PRODUCTION_LAYOUT_V1"

#: Immutable configuration, owned by root, published by the privileged
#: installer.  The public verification key and the installation record live
#: here and nowhere else.
PRODUCTION_CONFIGURATION_ROOT = Path("/etc/admissible-owner-authority-v1")

#: Durable authorization state, owned by root, mode 0700.  The private signing
#: key and every pending/consumed authorization record live here.  An ordinary
#: launcher cannot traverse this directory at all.
PRODUCTION_STATE_ROOT = Path("/var/lib/admissible-owner-authority-v1")

#: Runtime broker socket directory.
PRODUCTION_RUNTIME_ROOT = Path("/run/admissible-owner-authority-v1")

INSTALLATION_RECORD_NAME = "installation-v1.json"
PUBLIC_KEY_NAME = "owner-authority-signing-key.v1.pub.pem"
PRIVATE_KEY_NAME = "owner-authority-signing-key.v1.pem"
BROKER_SOCKET_NAME = "broker.sock"
PRIVATE_SUBDIRECTORY = "private"
AUTHORIZATIONS_SUBDIRECTORY = "authorizations"

#: Schema of the root-owned installation record published by the installer.
INSTALLATION_RECORD_SCHEMA_VERSION = (
    "admissible_owner_authority_installation_record_v1"
)

#: Schema of the root-owned pending-authorization record written only by the
#: privileged provisioner.  No public library function creates one.
PENDING_AUTHORIZATION_SCHEMA_VERSION = (
    "admissible_owner_authority_pending_authorization_v1"
)

#: Schema of the broker-signed production receipt.
SIGNED_RECEIPT_SCHEMA_VERSION = (
    "admissible_owner_authority_signed_authorization_receipt_v1"
)

#: The closed broker protocol.  A client speaking any other protocol identity
#: is refused before its request body is examined.
BROKER_PROTOCOL_VERSION = "admissible_owner_authority_broker_protocol_v1"

#: The externally rooted owner digest construction.  It is deliberately a
#: different construction from the legacy self-rooted one, and it additionally
#: binds the root-generated authorization record identity, so a digest computed
#: under the legacy construction --- or before provisioning chose the record
#: identity --- can never satisfy this one.
EXTERNAL_OWNER_DIGEST_CONSTRUCTION = (
    "admissible_external_owner_authority_phrase_nul_payload_nul_record_sha256_v3"
)

#: The Ed25519 signature construction over the canonical receipt payload.
RECEIPT_SIGNATURE_CONSTRUCTION = (
    "admissible_owner_authority_ed25519_over_canonical_receipt_payload_v1"
)

# ---------------------------------------------------------------------------
# The durable one-time state machine (section H)
# ---------------------------------------------------------------------------

#: The provisioner wrote a pending authorization; no phrase has been seen.
PROVISIONED_PENDING = "PROVISIONED_PENDING"

#: The broker matched the owner phrase against the retained digest.  This state
#: is durable but is *not* launchable: no receipt exists yet.
PHRASE_VERIFIED = "PHRASE_VERIFIED"

#: The commit point.  This record is durably fsynced *before* any signature is
#: produced, so a receipt can never exist without a durable consumption.
CONSUMED_LAUNCH_COMMITTED = "CONSUMED_LAUNCH_COMMITTED"

#: The broker signed and returned exactly one receipt for this authorization.
RECEIPT_ISSUED = "RECEIPT_ISSUED"

#: Terminal audit append.  It never restores launchability.
LAUNCH_RESULT_RECORDED = "LAUNCH_RESULT_RECORDED"

#: States in the order they may occur.  Every transition is forward-only.
AUTHORIZATION_STATES = (
    PROVISIONED_PENDING,
    PHRASE_VERIFIED,
    CONSUMED_LAUNCH_COMMITTED,
    RECEIPT_ISSUED,
    LAUNCH_RESULT_RECORDED,
)

#: The only state from which ``VERIFY_AND_CONSUME`` may proceed.  Every other
#: state --- including the two states that follow consumption --- refuses.  A
#: crash therefore never restores launchability: recovery observes a state at
#: or after :data:`CONSUMED_LAUNCH_COMMITTED` and refuses.
LAUNCHABLE_STATE = PROVISIONED_PENDING

#: States at or after the commit point.
COMMITTED_STATES = frozenset(
    {CONSUMED_LAUNCH_COMMITTED, RECEIPT_ISSUED, LAUNCH_RESULT_RECORDED}
)


class OwnerAuthorityError(ValueError):
    """A classified refusal anywhere on the external owner-authority path."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_REFUSED",
    ):
        self.classification = require_identifier(
            classification, "owner authority failure classification"
        )
        super().__init__(f"{self.classification}: {detail}")


@dataclass(frozen=True)
class OwnerAuthorityLayout:
    """Where the owner authority lives.  Production instances are constants.

    The production instance is returned by :func:`production_layout`, which
    takes no arguments.  A caller cannot influence a single path on it.
    """

    classification: str
    configuration_root: Path
    state_root: Path
    runtime_root: Path

    @property
    def is_production(self) -> bool:
        return self.classification == PRODUCTION_LAYOUT

    @property
    def installation_record_path(self) -> Path:
        return self.configuration_root / INSTALLATION_RECORD_NAME

    @property
    def public_key_path(self) -> Path:
        return self.configuration_root / PUBLIC_KEY_NAME

    @property
    def private_directory(self) -> Path:
        return self.state_root / PRIVATE_SUBDIRECTORY

    @property
    def private_key_path(self) -> Path:
        return self.private_directory / PRIVATE_KEY_NAME

    @property
    def authorizations_root(self) -> Path:
        return self.state_root / AUTHORIZATIONS_SUBDIRECTORY

    @property
    def broker_socket_path(self) -> Path:
        return self.runtime_root / BROKER_SOCKET_NAME

    def validated(self) -> "OwnerAuthorityLayout":
        if self.classification not in {PRODUCTION_LAYOUT, SYNTHETIC_LAYOUT}:
            raise OwnerAuthorityError(
                "unknown owner-authority layout classification",
                classification="OWNER_AUTHORITY_LAYOUT_REFUSED",
            )
        for label, path in (
            ("configuration root", self.configuration_root),
            ("state root", self.state_root),
            ("runtime root", self.runtime_root),
        ):
            if (
                not isinstance(path, Path)
                or not path.is_absolute()
                or ".." in path.parts
            ):
                raise OwnerAuthorityError(
                    f"owner-authority {label} must be absolute without aliases",
                    classification="OWNER_AUTHORITY_LAYOUT_REFUSED",
                )
        if self.is_production and (
            self.configuration_root != PRODUCTION_CONFIGURATION_ROOT
            or self.state_root != PRODUCTION_STATE_ROOT
            or self.runtime_root != PRODUCTION_RUNTIME_ROOT
        ):
            raise OwnerAuthorityError(
                "the production owner-authority layout is fixed and may not be "
                "redirected",
                classification="OWNER_AUTHORITY_LAYOUT_REFUSED",
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "configuration_root": str(self.configuration_root),
            "state_root": str(self.state_root),
            "runtime_root": str(self.runtime_root),
            "installation_record_path": str(self.installation_record_path),
            "public_key_path": str(self.public_key_path),
            "broker_socket_path": str(self.broker_socket_path),
        }


_PRODUCTION_LAYOUT = OwnerAuthorityLayout(
    classification=PRODUCTION_LAYOUT,
    configuration_root=PRODUCTION_CONFIGURATION_ROOT,
    state_root=PRODUCTION_STATE_ROOT,
    runtime_root=PRODUCTION_RUNTIME_ROOT,
)


def production_layout() -> OwnerAuthorityLayout:
    """The one production layout.  It takes no arguments, by construction."""

    return _PRODUCTION_LAYOUT


def synthetic_non_production_layout(root: Path) -> OwnerAuthorityLayout:
    """A disposable synthetic layout for the provider-free privilege witness.

    The classification says what it is.  No production acceptance point accepts
    it, and :func:`production_layout` can never return one.
    """

    if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
        raise OwnerAuthorityError(
            "synthetic owner-authority root must be absolute without aliases",
            classification="OWNER_AUTHORITY_LAYOUT_REFUSED",
        )
    return OwnerAuthorityLayout(
        classification=SYNTHETIC_LAYOUT,
        configuration_root=root / "etc",
        state_root=root / "var-lib",
        runtime_root=root / "run",
    ).validated()


def require_production_layout(
    layout: OwnerAuthorityLayout, label: str
) -> OwnerAuthorityLayout:
    """Refuse anything but the fixed production layout."""

    if not isinstance(layout, OwnerAuthorityLayout) or not layout.is_production:
        raise OwnerAuthorityError(
            f"{label} requires the fixed production owner-authority layout",
            classification="OWNER_AUTHORITY_NON_PRODUCTION_LAYOUT_REFUSED",
        )
    return layout.validated()


def describe_state_machine() -> Mapping[str, Any]:
    """The documented one-time state machine, for schema and doc checks."""

    return {
        "schema_version": "admissible_owner_authority_state_machine_v1",
        "states": list(AUTHORIZATION_STATES),
        "launchable_state": LAUNCHABLE_STATE,
        "committed_states": sorted(COMMITTED_STATES),
        "commit_rule": (
            "CONSUMPTION_IS_DURABLE_BEFORE_ANY_SIGNATURE_IS_PRODUCED"
        ),
        "transitions": [
            {"from": PROVISIONED_PENDING, "to": PHRASE_VERIFIED},
            {"from": PHRASE_VERIFIED, "to": CONSUMED_LAUNCH_COMMITTED},
            {"from": CONSUMED_LAUNCH_COMMITTED, "to": RECEIPT_ISSUED},
            {"from": RECEIPT_ISSUED, "to": LAUNCH_RESULT_RECORDED},
        ],
        "launchable_after_commit": False,
    }
