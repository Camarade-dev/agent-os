"""The privileged runtime owner-authority broker and its unprivileged client.

The broker is the only process that ever touches the private signing key.  Its
protocol is closed: four operations, each with an exact request shape.  There
is deliberately **no** provisioning operation --- a running broker cannot create
an authorization, cannot choose an expected digest, cannot change a payload,
cannot select a state root or a key, cannot sign caller-supplied bytes, cannot
reset a consumed authorization and cannot authorize a retry or a repair.  Those
are all privileged provisioner or installer actions, and the provisioner has no
RPC surface at all.

The client takes an attested installation, never a path.  Its socket, its key
and its state all come from the root-owned installation record; there is no
constructor parameter through which a backend could point it elsewhere.
"""

from __future__ import annotations

import os
import socket
import stat
import struct
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.common import (
    canonical_bytes,
    fingerprint,
    require_exact_keys,
    require_identifier,
    require_sha256,
    strict_json_loads,
)
from admissible.capsule.owner_authority.installation import (
    OwnerAuthorityInstallation,
)
from admissible.capsule.owner_authority.layout import (
    BROKER_PROTOCOL_VERSION,
    CONSUMED_LAUNCH_COMMITTED,
    LAUNCH_RESULT_RECORDED,
    OwnerAuthorityError,
    PHRASE_VERIFIED,
    PROVISIONED_PENDING,
    RECEIPT_ISSUED,
)
from admissible.capsule.owner_authority.records import (
    SignedOwnerAuthorizationReceipt,
    authorization_consumption_identity,
    build_receipt_payload,
    external_owner_authorization_digest,
    require_authorization_record_id,
)
from admissible.capsule.owner_authority.signing import sign_message
from admissible.capsule.owner_authority.state import (
    AUTHORIZATION_ABSENT,
    AuthorizationStateDirectory,
    consumption_body,
)

#: The closed operation vocabulary.  Anything else is refused before the
#: request body is interpreted.
ATTEST_INSTALLATION = "ATTEST_INSTALLATION"
AUTHORIZATION_STATUS = "AUTHORIZATION_STATUS"
VERIFY_AND_CONSUME = "VERIFY_AND_CONSUME"
RECORD_LAUNCH_RESULT = "RECORD_LAUNCH_RESULT"

BROKER_OPERATIONS = frozenset(
    {
        ATTEST_INSTALLATION,
        AUTHORIZATION_STATUS,
        VERIFY_AND_CONSUME,
        RECORD_LAUNCH_RESULT,
    }
)

#: Operations the broker must never grow.  Named so a schema test can assert
#: their continued absence rather than trusting review.
FORBIDDEN_BROKER_OPERATIONS = frozenset(
    {
        "PROVISION_AUTHORIZATION",
        "CREATE_AUTHORIZATION",
        "SET_EXPECTED_DIGEST",
        "CHANGE_PAYLOAD",
        "SELECT_STATE_ROOT",
        "SELECT_SIGNING_KEY",
        "SIGN_MESSAGE",
        "RESET_CONSUMED_AUTHORIZATION",
        "AUTHORIZE_RETRY",
        "AUTHORIZE_REPAIR",
    }
)

_MAX_FRAME_BYTES = 256 * 1024
_MAX_PHRASE_BYTES = 4096
_MIN_PHRASE_BYTES = 8
_SOCKET_BACKLOG = 8


class OwnerAuthorityBrokerError(OwnerAuthorityError):
    """A refusal on the broker protocol."""

    def __init__(
        self,
        detail: str,
        *,
        classification: str = "OWNER_AUTHORITY_BROKER_REFUSED",
    ):
        super().__init__(detail, classification=classification)


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------


def _send_frame(connection: socket.socket, value: Mapping[str, Any]) -> None:
    body = canonical_bytes(dict(value))
    if len(body) > _MAX_FRAME_BYTES:
        raise OwnerAuthorityBrokerError("broker frame exceeds its byte bound")
    connection.sendall(struct.pack("!I", len(body)) + body)


def _receive_exactly(connection: socket.socket, count: int) -> bytes:
    collected = b""
    while len(collected) < count:
        block = connection.recv(count - len(collected))
        if not block:
            raise OwnerAuthorityBrokerError(
                "the broker connection closed mid-frame",
                classification="OWNER_AUTHORITY_BROKER_UNAVAILABLE",
            )
        collected += block
    return collected


def _receive_frame(connection: socket.socket) -> dict[str, Any]:
    (length,) = struct.unpack("!I", _receive_exactly(connection, 4))
    if not 0 < length <= _MAX_FRAME_BYTES:
        raise OwnerAuthorityBrokerError("broker frame exceeds its byte bound")
    body = _receive_exactly(connection, length)
    value = strict_json_loads(body, label="broker frame")
    if not isinstance(value, Mapping):
        raise OwnerAuthorityBrokerError("broker frame is not an object")
    return dict(value)


def peer_credentials(connection: socket.socket) -> dict[str, int]:
    """Kernel-attested credentials of the connected peer."""

    raw = connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    pid, uid, gid = struct.unpack("3i", raw)
    return {"pid": pid, "uid": uid, "gid": gid}


# ---------------------------------------------------------------------------
# The privileged broker
# ---------------------------------------------------------------------------


class OwnerAuthorityBroker:
    """The privileged broker.  It must run as the installer identity.

    It refuses to start unless it is genuinely running as uid 0 within the
    identity space of the installation it serves, because otherwise it could
    not hold a key an ordinary launcher cannot read.
    """

    def __init__(self, installation: OwnerAuthorityInstallation):
        self.installation = installation.validated()
        self.layout = self.installation.layout
        if os.geteuid() != 0:
            raise OwnerAuthorityBrokerError(
                "the owner-authority broker requires the privileged installer "
                "identity",
                classification="OWNER_AUTHORITY_BROKER_NOT_PRIVILEGED",
            )
        self._socket: socket.socket | None = None
        self._stop_requested = False

    # -- lifecycle --------------------------------------------------------

    def bind(self) -> Path:
        """Bind the fixed broker socket with root-owned, launcher-reachable mode."""

        path = self.layout.broker_socket_path
        if path.exists():
            raise OwnerAuthorityBrokerError(
                "the owner-authority broker socket already exists",
                classification="OWNER_AUTHORITY_BROKER_SOCKET_PRESENT",
            )
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chmod(path.parent, 0o755)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        previous_umask = os.umask(0o177)
        try:
            server.bind(str(path))
        finally:
            os.umask(previous_umask)
        # Root owns the socket; the authorized launcher group may connect, and
        # every connection is still checked against SO_PEERCRED.
        os.chown(path, 0, self.installation.record["authorized_launcher_gid"])
        os.chmod(path, 0o660)
        server.listen(_SOCKET_BACKLOG)
        self._socket = server
        return path

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        path = self.layout.broker_socket_path
        if path.exists() and path.is_socket():
            path.unlink()

    def request_stop(self) -> None:
        """Request a clean shutdown of :meth:`serve_forever`."""

        self._stop_requested = True
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    @property
    def stop_requested(self) -> bool:
        return self._stop_requested

    def serve_one(self, *, timeout: float = 30.0) -> str:
        """Accept and serve exactly one connection.  Returns the operation."""

        if self._socket is None:
            raise OwnerAuthorityBrokerError("the broker socket is not bound")
        self._socket.settimeout(timeout)
        connection, _ = self._socket.accept()
        try:
            connection.settimeout(timeout)
            return self._serve_connection(connection)
        finally:
            connection.close()

    def serve_forever(self, *, connection_limit: int | None = None) -> None:
        """Serve until stopped or the listening socket fails fatally."""

        served = 0
        while connection_limit is None or served < connection_limit:
            if self._stop_requested:
                return
            if self._socket is None:
                return
            try:
                self.serve_one()
            except (OwnerAuthorityError, TimeoutError, socket.timeout):
                # A refused request or an idle period must never stop the broker.
                continue
            except OSError:
                if self._stop_requested:
                    return
                raise
            served += 1

    # -- request handling -------------------------------------------------

    def _serve_connection(self, connection: socket.socket) -> str:
        operation = "UNKNOWN"
        try:
            credentials = peer_credentials(connection)
            if credentials["uid"] != self.installation.authorized_launcher_uid:
                raise OwnerAuthorityBrokerError(
                    "the connecting peer is not the authorized launcher "
                    "identity",
                    classification="OWNER_AUTHORITY_PEER_CREDENTIAL_REFUSED",
                )
            request = _receive_frame(connection)
            if request.get("protocol") != BROKER_PROTOCOL_VERSION:
                raise OwnerAuthorityBrokerError(
                    "the client speaks another broker protocol",
                    classification="OWNER_AUTHORITY_BROKER_PROTOCOL_REFUSED",
                )
            operation = request.get("operation", "UNKNOWN")
            if operation not in BROKER_OPERATIONS:
                raise OwnerAuthorityBrokerError(
                    f"the broker does not implement {operation!r}",
                    classification="OWNER_AUTHORITY_BROKER_OPERATION_REFUSED",
                )
            result = self._dispatch(operation, request, credentials)
            _send_frame(
                connection,
                {
                    "protocol": BROKER_PROTOCOL_VERSION,
                    "status": "OK",
                    "operation": operation,
                    "result": result,
                },
            )
        except OwnerAuthorityError as error:
            _send_frame(
                connection,
                {
                    "protocol": BROKER_PROTOCOL_VERSION,
                    "status": "REFUSED",
                    "operation": operation,
                    "classification": error.classification,
                    "detail": str(error),
                },
            )
        except Exception as error:  # noqa: BLE001 - the broker always answers
            # A privileged broker must never leave a peer hanging on a closed
            # connection, and must never die because one request was malformed.
            # Anything unclassified becomes a generic refusal, with no detail
            # beyond the exception type.
            _send_frame(
                connection,
                {
                    "protocol": BROKER_PROTOCOL_VERSION,
                    "status": "REFUSED",
                    "operation": operation,
                    "classification": "OWNER_AUTHORITY_BROKER_REQUEST_REFUSED",
                    "detail": type(error).__name__,
                },
            )
        return operation

    def _dispatch(
        self,
        operation: str,
        request: Mapping[str, Any],
        credentials: Mapping[str, int],
    ) -> dict[str, Any]:
        if operation == ATTEST_INSTALLATION:
            require_exact_keys(
                dict(request), {"protocol", "operation"}, "attestation request"
            )
            return dict(self.installation.validated().to_dict())
        if operation == AUTHORIZATION_STATUS:
            require_exact_keys(
                dict(request),
                {"protocol", "operation", "authorization_record_id"},
                "status request",
            )
            return self._status(request["authorization_record_id"])
        if operation == VERIFY_AND_CONSUME:
            require_exact_keys(
                dict(request),
                {
                    "protocol",
                    "operation",
                    "authorization_record_id",
                    "owner_payload_fingerprint",
                    "owner_phrase",
                },
                "verify-and-consume request",
            )
            return self._verify_and_consume(request, credentials)
        if operation == RECORD_LAUNCH_RESULT:
            require_exact_keys(
                dict(request),
                {
                    "protocol",
                    "operation",
                    "authorization_record_id",
                    "receipt_identity",
                    "outcome",
                },
                "launch result request",
            )
            return self._record_launch_result(request, credentials)
        raise OwnerAuthorityBrokerError(  # pragma: no cover - closed vocabulary
            f"unreachable broker operation {operation!r}"
        )

    def _directory(self, record_id: Any) -> AuthorizationStateDirectory:
        return AuthorizationStateDirectory(
            self.layout,
            require_authorization_record_id(record_id, "authorization record id"),
        )

    def _status(self, record_id: Any) -> dict[str, Any]:
        return self._directory(record_id).status()

    def _verify_and_consume(
        self,
        request: Mapping[str, Any],
        credentials: Mapping[str, int],
    ) -> dict[str, Any]:
        directory = self._directory(request["authorization_record_id"])
        payload_fingerprint = require_sha256(
            request["owner_payload_fingerprint"],
            "requested owner payload fingerprint",
        )
        phrase = request["owner_phrase"]
        if not isinstance(phrase, str):
            raise OwnerAuthorityBrokerError("the owner phrase must be text")
        encoded_length = len(phrase.encode("utf-8"))
        if not _MIN_PHRASE_BYTES <= encoded_length <= _MAX_PHRASE_BYTES:
            raise OwnerAuthorityBrokerError(
                "the owner phrase is outside its byte bounds",
                classification="OWNER_AUTHORITY_PHRASE_REFUSED",
            )
        # The lock lives inside the record directory, so absence must be
        # answered before any attempt to take it.
        if directory.current_state() == AUTHORIZATION_ABSENT:
            raise OwnerAuthorityBrokerError(
                "no authorization is provisioned under that identity",
                classification="OWNER_AUTHORITY_AUTHORIZATION_ABSENT",
            )
        with directory.lock():
            state = directory.current_state()
            if state != PROVISIONED_PENDING:
                raise OwnerAuthorityBrokerError(
                    "this authorization is no longer launchable: " + state,
                    classification="OWNER_AUTHORITY_ALREADY_CONSUMED",
                )
            record = directory.pending_record()
            if record["installation_identity"] != (
                self.installation.installation_identity
            ):
                raise OwnerAuthorityBrokerError(
                    "this authorization was provisioned under another "
                    "installation",
                    classification="OWNER_AUTHORITY_FOREIGN_INSTALLATION",
                )
            if record["owner_payload_fingerprint"] != payload_fingerprint:
                raise OwnerAuthorityBrokerError(
                    "the requested payload is not the provisioned payload",
                    classification="OWNER_AUTHORITY_PAYLOAD_REFUSED",
                )
            observed_digest = external_owner_authorization_digest(
                phrase=phrase,
                payload_bytes=canonical_bytes(dict(record["owner_payload"])),
                authorization_record_id=record["authorization_record_id"],
            )
            del phrase
            if not _constant_time_equal(
                observed_digest, record["expected_owner_authorization_digest"]
            ):
                raise OwnerAuthorityBrokerError(
                    "the owner phrase does not authorize this payload",
                    classification="OWNER_AUTHORITY_PHRASE_REFUSED",
                )
            sequence = [PROVISIONED_PENDING]

            directory.record_phrase_verified(
                {
                    "schema_version": (
                        "admissible_owner_authority_phrase_verified_v1"
                    ),
                    "state": PHRASE_VERIFIED,
                    "authorization_record_id": record["authorization_record_id"],
                    "owner_payload_fingerprint": payload_fingerprint,
                    "peer_uid": credentials["uid"],
                }
            )
            sequence.append(PHRASE_VERIFIED)

            consumption_identity = authorization_consumption_identity(
                authorization_record_id=record["authorization_record_id"],
                owner_payload_fingerprint=payload_fingerprint,
                installation_identity=self.installation.installation_identity,
            )
            commit = consumption_body(
                record_id=record["authorization_record_id"],
                consumption_identity=consumption_identity,
                owner_payload_fingerprint=payload_fingerprint,
                installation_identity=self.installation.installation_identity,
                peer_uid=credentials["uid"],
            )
            # The commit point.  Everything after this line happens only once,
            # and no crash after it can return this record to PROVISIONED_PENDING.
            marker_identity = directory.commit_consumption(commit)
            sequence.append(CONSUMED_LAUNCH_COMMITTED)

            receipt_payload = build_receipt_payload(
                installation=self.installation,
                pending=record,
                consumption_identity=consumption_identity,
                consumption_record_identity=commit["commit_identity"],
                terminal_evidence={
                    "schema_version": (
                        "admissible_owner_authority_broker_terminal_evidence_v1"
                    ),
                    "commit_rule": (
                        "CONSUMPTION_IS_DURABLE_BEFORE_ANY_SIGNATURE_IS_PRODUCED"
                    ),
                    "observed_state_sequence": list(sequence),
                    "consumption_marker_identity": marker_identity,
                    "cryptographic_executable_identity": dict(
                        self.installation.reattest_cryptographic_executable()
                    ),
                    "broker_protocol": BROKER_PROTOCOL_VERSION,
                    "peer_uid": credentials["uid"],
                },
            )
            signature = sign_message(
                executable=self.installation.cryptographic_executable_identity,
                private_key_path=self.layout.private_key_path,
                message=canonical_bytes(receipt_payload),
            )
            receipt = SignedOwnerAuthorizationReceipt.create(
                payload=receipt_payload, signature=signature
            )
            directory.record_receipt(
                {
                    "schema_version": "admissible_owner_authority_receipt_issued_v1",
                    "state": RECEIPT_ISSUED,
                    "authorization_record_id": record["authorization_record_id"],
                    "receipt_identity": receipt.receipt_identity,
                    "authorization_consumption_identity": consumption_identity,
                    "peer_uid": credentials["uid"],
                }
            )
        return {"signed_receipt": receipt.to_dict()}

    def _record_launch_result(
        self,
        request: Mapping[str, Any],
        credentials: Mapping[str, int],
    ) -> dict[str, Any]:
        directory = self._directory(request["authorization_record_id"])
        receipt_identity = require_sha256(
            request["receipt_identity"], "recorded receipt identity"
        )
        outcome = require_identifier(request["outcome"], "launch outcome")
        if directory.current_state() == AUTHORIZATION_ABSENT:
            raise OwnerAuthorityBrokerError(
                "no authorization is provisioned under that identity",
                classification="OWNER_AUTHORITY_AUTHORIZATION_ABSENT",
            )
        with directory.lock():
            state = directory.current_state()
            if state != RECEIPT_ISSUED:
                raise OwnerAuthorityBrokerError(
                    "no issued receipt is awaiting a launch result: " + state,
                    classification="OWNER_AUTHORITY_STATE_NOT_ELIGIBLE",
                )
            issued = directory.marker("receipt.json")
            if issued["receipt_identity"] != receipt_identity:
                raise OwnerAuthorityBrokerError(
                    "that receipt was not the one issued for this "
                    "authorization",
                    classification="OWNER_AUTHORITY_RECEIPT_SUBSTITUTED",
                )
            body = {
                "schema_version": "admissible_owner_authority_launch_result_v1",
                "state": LAUNCH_RESULT_RECORDED,
                "authorization_record_id": directory.record_id,
                "receipt_identity": receipt_identity,
                "outcome": outcome,
                "peer_uid": credentials["uid"],
            }
            directory.record_launch_result(body)
        return {"state": LAUNCH_RESULT_RECORDED, "outcome": outcome}


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


# ---------------------------------------------------------------------------
# The unprivileged client
# ---------------------------------------------------------------------------


class OwnerAuthorityBrokerClient:
    """Talks to the broker named by an attested installation, and only that one.

    There is no socket-path parameter.  A rogue broker listening elsewhere is
    unreachable through this client, and a rogue broker that somehow occupied
    the fixed path still cannot produce a receipt that verifies against the
    installed public key.
    """

    def __init__(self, installation: OwnerAuthorityInstallation):
        self.installation = installation.validated()
        self.socket_path = self.installation.layout.broker_socket_path

    def _connect(self, timeout: float) -> socket.socket:
        try:
            info = os.stat(self.socket_path)
        except OSError as error:
            raise OwnerAuthorityBrokerError(
                "the owner-authority broker socket is not present at its "
                "fixed path",
                classification="OWNER_AUTHORITY_BROKER_UNAVAILABLE",
            ) from error
        if not stat.S_ISSOCK(info.st_mode):
            raise OwnerAuthorityBrokerError(
                "the fixed broker path is not a socket",
                classification="OWNER_AUTHORITY_BROKER_SOCKET_REFUSED",
            )
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o007:
            raise OwnerAuthorityBrokerError(
                "the broker socket is not root-owned and restricted",
                classification="OWNER_AUTHORITY_BROKER_SOCKET_REFUSED",
            )
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(timeout)
        try:
            connection.connect(str(self.socket_path))
        except OSError as error:
            connection.close()
            raise OwnerAuthorityBrokerError(
                "the owner-authority broker is not accepting connections",
                classification="OWNER_AUTHORITY_BROKER_UNAVAILABLE",
            ) from error
        return connection

    def _call(
        self, request: Mapping[str, Any], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        connection = self._connect(timeout)
        try:
            _send_frame(
                connection,
                {"protocol": BROKER_PROTOCOL_VERSION, **dict(request)},
            )
            response = _receive_frame(connection)
        finally:
            connection.close()
        if response.get("protocol") != BROKER_PROTOCOL_VERSION:
            raise OwnerAuthorityBrokerError(
                "the broker answered with another protocol",
                classification="OWNER_AUTHORITY_BROKER_PROTOCOL_REFUSED",
            )
        if response.get("status") != "OK":
            raise OwnerAuthorityBrokerError(
                str(response.get("detail", "the broker refused the request")),
                classification=require_identifier(
                    response.get("classification", "OWNER_AUTHORITY_BROKER_REFUSED"),
                    "broker refusal classification",
                ),
            )
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise OwnerAuthorityBrokerError("the broker answer has no result")
        return dict(result)

    # -- the four allowed operations --------------------------------------

    def attest_installation(self) -> dict[str, Any]:
        """Ask the broker what installation it serves, and check it is ours."""

        attested = self._call({"operation": ATTEST_INSTALLATION})
        expected = dict(self.installation.to_dict())
        if attested != expected:
            raise OwnerAuthorityBrokerError(
                "the broker serves another installation than the one attested "
                "at the fixed root-owned path",
                classification="OWNER_AUTHORITY_BROKER_IMPERSONATION_REFUSED",
            )
        return attested

    def authorization_status(self, authorization_record_id: str) -> dict[str, Any]:
        return self._call(
            {
                "operation": AUTHORIZATION_STATUS,
                "authorization_record_id": require_authorization_record_id(
                    authorization_record_id, "authorization record id"
                ),
            }
        )

    def verify_and_consume(
        self,
        *,
        authorization_record_id: str,
        owner_payload_fingerprint: str,
        owner_phrase: str,
    ) -> SignedOwnerAuthorizationReceipt:
        """Verify the phrase and atomically consume, in one broker transaction."""

        result = self._call(
            {
                "operation": VERIFY_AND_CONSUME,
                "authorization_record_id": require_authorization_record_id(
                    authorization_record_id, "authorization record id"
                ),
                "owner_payload_fingerprint": require_sha256(
                    owner_payload_fingerprint, "owner payload fingerprint"
                ),
                "owner_phrase": owner_phrase,
            }
        )
        receipt = SignedOwnerAuthorizationReceipt.from_dict(
            result.get("signed_receipt")
        )
        # Verify before the caller ever sees it: a broker that returned an
        # unsigned or foreign-signed receipt is refused here.
        from admissible.capsule.owner_authority.records import verify_signed_receipt

        verify_signed_receipt(receipt=receipt, installation=self.installation)
        return receipt

    def record_launch_result(
        self,
        *,
        authorization_record_id: str,
        receipt_identity: str,
        outcome: str,
    ) -> dict[str, Any]:
        return self._call(
            {
                "operation": RECORD_LAUNCH_RESULT,
                "authorization_record_id": require_authorization_record_id(
                    authorization_record_id, "authorization record id"
                ),
                "receipt_identity": require_sha256(
                    receipt_identity, "receipt identity"
                ),
                "outcome": require_identifier(outcome, "launch outcome"),
            }
        )


def broker_protocol_schema() -> Mapping[str, Any]:
    """The closed protocol, for schema tests and documentation."""

    body = {
        "schema_version": "admissible_owner_authority_broker_protocol_schema_v1",
        "protocol": BROKER_PROTOCOL_VERSION,
        "operations": sorted(BROKER_OPERATIONS),
        "forbidden_operations": sorted(FORBIDDEN_BROKER_OPERATIONS),
        "peer_credential_check": "SO_PEERCRED_UID_EQUALS_AUTHORIZED_LAUNCHER",
        "socket_owner_uid": 0,
        "socket_mode": 0o660,
        "provisioning_rpc": False,
        "caller_selectable_paths": False,
        "signs_caller_supplied_messages": False,
        "max_frame_bytes": _MAX_FRAME_BYTES,
    }
    return {**body, "schema_identity": fingerprint(body)}
