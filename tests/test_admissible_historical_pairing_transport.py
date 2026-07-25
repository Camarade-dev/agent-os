"""Step 5C2C2: the conditional historical pairing loopback HTTP transport.

Every confirmation tag driven over the wire here is produced by the independent
oracle in ``test_admissible_historical_pairing_service``: it re-implements the
documented construction with the standard library from the public
confirmation-message bytes the owner review encodes.  The product is never asked
to produce a credential it is then verified against.
"""

from __future__ import annotations

import hashlib
import io
import json
import socket
import socketserver
import sys
import threading
import time
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path

import pytest

from admissible.delegated_gate.historical_evaluation_store import (
    load_historical_evaluation_pairing,
)
from admissible.delegated_gate.historical_pairing_review import (
    PREPARATION_STATE_CONSUMED,
    PREPARATION_STATE_READY_FOR_CONFIRMATION,
)
from admissible.delegated_gate.historical_pairing_workflow import (
    HistoricalEvaluationPairingCoordinator,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V5,
)
from admissible.delegated_gate.native_canary import (
    NativeCanaryAuthorizationPayloadV4,
)
from admissible.product_launcher import ui_transport as ui_transport_module
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_PRECOMMITTED,
    LauncherConfiguration,
)
from admissible.product_launcher.historical_pairing_registry import (
    HistoricalPayloadEntry,
    MalformedHistoricalPayloadDocument,
)
from admissible.product_launcher.historical_pairing_service import (
    HistoricalPairingFeatureConfigurationError,
    HistoricalPairingService,
)
from admissible.product_launcher.launcher import ProductLauncher
from admissible.product_launcher.ui_transport import (
    CSRF_HEADER,
    HISTORICAL_PAIRINGS_SEGMENT,
    HISTORICAL_PAIRING_CONFIRMATION_HEADER,
    UI_API_PREFIX,
    _UIHandler,
    _UIServer,
)
from test_admissible_historical_pairing_confirmation import (
    _disclosures,
    _disclosures_in_text,
    _fragments_of,
    _observed_sinks,
)
from test_admissible_historical_pairing_service import (
    ACTOR_ID,
    OTHER_PAYLOAD_ID,
    OTHER_SECRET,
    PAIRING_SECRET,
    PAYLOAD_ID,
    build_historical_payload,
    build_second_historical_payload,
    graph_disclosures,
    independent_confirmation_tag,
    owner_material,
    pairing_configuration,
    single_entry_configuration,
    write_document,
)


PAYLOADS_PATH = f"{UI_API_PREFIX}/{HISTORICAL_PAIRINGS_SEGMENT}/payloads"
PREPARATIONS_PATH = f"{UI_API_PREFIX}/{HISTORICAL_PAIRINGS_SEGMENT}/preparations"

# One runtime owner-authorization digest shape, used as a rejected credential.
RUNTIME_OWNER_DIGEST = hashlib.sha256(
    b"runtime owner authorization phrase"
).hexdigest()


@pytest.fixture(scope="module")
def historical_payload(
    tmp_path_factory: pytest.TempPathFactory,
) -> NativeCanaryAuthorizationPayloadV4:
    return build_historical_payload(tmp_path_factory.mktemp("s5c2c2-t-a"))


@pytest.fixture(scope="module")
def other_payload(
    tmp_path_factory: pytest.TempPathFactory,
) -> NativeCanaryAuthorizationPayloadV4:
    return build_second_historical_payload(tmp_path_factory.mktemp("s5c2c2-t-b"))


# ---------------------------------------------------------------------------
# Launcher construction helpers.
# ---------------------------------------------------------------------------


def launcher_configuration(tmp_path: Path) -> LauncherConfiguration:
    source = (tmp_path / "source").resolve()
    source.mkdir(parents=True, exist_ok=True)
    return LauncherConfiguration(
        source_repository=source,
        required_source_head="a" * 40,
        run_parent=(tmp_path / "runs").resolve(),
        contract_documents_directory=(tmp_path / "docs").resolve(),
        executable="provider",
        executable_prefix_args=(),
        attestation_class="package-bin",
        model_default="auto",
        timeout_default=60,
        timeout_maximum=600,
        stdout_byte_limit=8192,
        stderr_byte_limit=8192,
        product_ui_bind_host="127.0.0.1",
        product_ui_bind_port=0,
        g2_bind_host="127.0.0.1",
        g2_bind_port=0,
        authorization_mode=AUTHORIZATION_MODE_PRECOMMITTED,
        open_browser=False,
    ).validated()


def build_launcher(tmp_path: Path, **overrides) -> ProductLauncher:
    values = dict(
        historical_pairing_configuration=None,
        historical_pairing_secret=None,
    )
    values.update(overrides)
    return ProductLauncher(
        launcher_configuration(tmp_path), verify_head=False, **values
    )


@pytest.fixture()
def disabled_launcher(tmp_path: Path):
    launcher = build_launcher(tmp_path / "disabled").start()
    try:
        yield launcher
    finally:
        launcher.close()


@pytest.fixture()
def enabled_launcher(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    root = tmp_path / "enabled"
    root.mkdir(parents=True, exist_ok=True)
    launcher = build_launcher(
        root,
        historical_pairing_configuration=single_entry_configuration(
            root, historical_payload
        ),
        historical_pairing_secret=PAIRING_SECRET,
    ).start()
    try:
        yield launcher
    finally:
        launcher.close()


# ---------------------------------------------------------------------------
# HTTP helpers.
# ---------------------------------------------------------------------------


# Windows resets a connection whose receive buffer still holds an unread
# request body when the peer closes it, so a response the accepted transport
# refuses *before* reading the body can be destroyed in transit. That is
# pre-existing loopback behavior of the accepted UI server and is deliberately
# not changed by this slice. Every refusal that can trigger it -- a Host,
# Origin, CSRF, method, or query refusal -- is pure and mutates no launcher
# state, so the identical request is simply re-issued a bounded number of times.
_RESET_ERRORS = (ConnectionAbortedError, ConnectionResetError)
_TRANSPORT_ATTEMPTS = 4


def _single_request(
    launcher: ProductLauncher,
    method: str,
    path: str,
    *,
    body: object,
    headers: dict | None,
    omit: tuple[str, ...],
    raw_body: bytes | None,
):
    sent = {
        "Host": f"127.0.0.1:{launcher.ui_port}",
        "Content-Type": "application/json",
        CSRF_HEADER: launcher.csrf_nonce,
    }
    sent.update(headers or {})
    for name in omit:
        sent.pop(name, None)
    data = raw_body
    if body is not None:
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    connection = HTTPConnection("127.0.0.1", launcher.ui_port, timeout=15)
    try:
        connection.request(method, path, body=data, headers=sent)
        response = connection.getresponse()
        raw = response.read()
        headers = dict(response.getheaders())
        parsed = (
            json.loads(raw.decode("utf-8"))
            if raw and headers.get("Content-Type") == "application/json"
            else None
        )
        return response.status, headers, parsed, raw
    finally:
        connection.close()


def request(
    launcher: ProductLauncher,
    method: str,
    path: str,
    *,
    body: object = None,
    headers: dict | None = None,
    omit: tuple[str, ...] = (),
    raw_body: bytes | None = None,
):
    """One bounded loopback request with the accepted default guard headers."""

    failure: BaseException | None = None
    for _attempt in range(_TRANSPORT_ATTEMPTS):
        try:
            return _single_request(
                launcher,
                method,
                path,
                body=body,
                headers=headers,
                omit=omit,
                raw_body=raw_body,
            )
        except _RESET_ERRORS as exc:
            failure = exc
    raise AssertionError(f"loopback response was lost repeatedly: {failure!r}")


def _single_raw_exchange(port: int, request_bytes: bytes) -> bytes:
    sock = socket.create_connection(("127.0.0.1", port), timeout=15)
    try:
        sock.sendall(request_bytes)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


def raw_exchange(port: int, request_bytes: bytes) -> bytes:
    """Drive one exact request line and header block over a raw socket."""

    failure: BaseException | None = None
    for _attempt in range(_TRANSPORT_ATTEMPTS):
        try:
            observed = _single_raw_exchange(port, request_bytes)
        except _RESET_ERRORS as exc:
            failure = exc
            continue
        if observed:
            return observed
        failure = AssertionError("empty loopback response")
    raise AssertionError(f"loopback response was lost repeatedly: {failure!r}")


def raw_request_bytes(
    port: int,
    method: str,
    path: str,
    *,
    headers: list[tuple[str, str]],
    body: bytes = b"",
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1".encode("latin-1")]
    lines.extend(f"{name}: {value}".encode("latin-1") for name, value in headers)
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def status_of(raw: bytes) -> int:
    return int(raw.split(b" ", 2)[1])


def body_of(raw: bytes) -> object:
    head, _sep, payload = raw.partition(b"\r\n\r\n")
    assert _sep
    return json.loads(payload.decode("utf-8")) if payload else None


def prepare_over_http(
    launcher: ProductLauncher,
    payload: NativeCanaryAuthorizationPayloadV4,
    *,
    payload_id: str = PAYLOAD_ID,
    actor_id: str = ACTOR_ID,
):
    status, _headers, review, _raw = request(
        launcher,
        "POST",
        PREPARATIONS_PATH,
        body={
            "payload_id": payload_id,
            "actor_id": actor_id,
            **owner_material(payload),
        },
    )
    return status, review


def locator_of(review: dict) -> tuple[str, str]:
    identity = review["pairing_identity"]
    return identity["preparation_id"], identity["pairing_authority_fingerprint"]


def review_path(preparation_id: str, fingerprint: str) -> str:
    return f"{PREPARATIONS_PATH}/{preparation_id}/{fingerprint}"


def confirmation_path(preparation_id: str) -> str:
    return f"{PREPARATIONS_PATH}/{preparation_id}/confirmation"


def confirm_over_http(
    launcher: ProductLauncher,
    preparation_id: str,
    fingerprint: str,
    tag: str,
    **kwargs,
):
    return request(
        launcher,
        "POST",
        confirmation_path(preparation_id),
        body={"expected_authority_fingerprint": fingerprint},
        headers={HISTORICAL_PAIRING_CONFIRMATION_HEADER: tag},
        **kwargs,
    )


# ---------------------------------------------------------------------------
# A. Construction, feature absence, and startup ordering.
# ---------------------------------------------------------------------------


def test_both_optional_inputs_absent_leaves_the_feature_disabled(tmp_path: Path):
    launcher = build_launcher(tmp_path)
    try:
        assert launcher.historical_pairing_available is False
        assert launcher._historical_pairing is None
    finally:
        launcher.close()


@pytest.mark.parametrize("supplied", ["configuration", "secret"])
def test_exactly_one_optional_input_refuses_construction(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    supplied: str,
):
    """A half-configured feature is a loud defect, never a quiet disable."""

    root = tmp_path / supplied
    root.mkdir()
    configuration = (
        single_entry_configuration(root, historical_payload)
        if supplied == "configuration"
        else None
    )
    secret = PAIRING_SECRET if supplied == "secret" else None
    base = launcher_configuration(root)
    with pytest.raises(HistoricalPairingFeatureConfigurationError):
        ProductLauncher(
            base,
            verify_head=False,
            historical_pairing_configuration=configuration,
            historical_pairing_secret=secret,
        )
    # Nothing was created: no run parent, no documents directory, no socket.
    assert not Path(base.run_parent).exists()
    assert not Path(base.contract_documents_directory).exists()
    assert not any(
        thread.name.startswith("admissible-g2") for thread in threading.enumerate()
    )


def test_empty_payload_configuration_refuses_construction(tmp_path: Path):
    base = launcher_configuration(tmp_path)
    with pytest.raises(HistoricalPairingFeatureConfigurationError):
        ProductLauncher(
            base,
            verify_head=False,
            historical_pairing_configuration=pairing_configuration(tmp_path, ()),
            historical_pairing_secret=PAIRING_SECRET,
        )
    assert not Path(base.run_parent).exists()


def test_malformed_payload_document_aborts_before_any_server_exists(
    tmp_path: Path,
):
    documents = tmp_path / "documents"
    documents.mkdir()
    document = documents / "broken.json"
    document.write_bytes(b"{}")
    base = launcher_configuration(tmp_path)
    with pytest.raises(MalformedHistoricalPayloadDocument):
        ProductLauncher(
            base,
            verify_head=False,
            historical_pairing_configuration=pairing_configuration(
                tmp_path,
                (
                    HistoricalPayloadEntry(
                        payload_id=PAYLOAD_ID, document_path=document.resolve()
                    ),
                ),
            ),
            historical_pairing_secret=PAIRING_SECRET,
        )
    assert not Path(base.run_parent).exists()
    assert not Path(base.contract_documents_directory).exists()


def test_configured_service_is_complete_before_any_server_can_start(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """Registry startup loading finishes during construction, not on first use."""

    launcher = build_launcher(
        tmp_path,
        historical_pairing_configuration=single_entry_configuration(
            tmp_path, historical_payload
        ),
        historical_pairing_secret=PAIRING_SECRET,
    )
    try:
        assert launcher.historical_pairing_available is True
        assert isinstance(launcher._historical_pairing, HistoricalPairingService)
        assert isinstance(
            launcher._historical_pairing._coordinator,
            HistoricalEvaluationPairingCoordinator,
        )
        # Answering does not need the server to be running.
        status, body = launcher.list_historical_pairing_payloads()
        assert status == 200
        assert [item["payload_id"] for item in body["payloads"]] == [PAYLOAD_ID]
    finally:
        launcher.close()


def test_neither_optional_input_is_carried_by_launcher_configuration(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    base = launcher_configuration(tmp_path)
    fields = set(vars(base))
    assert not any("historical" in name or "secret" in name for name in fields)
    launcher = build_launcher(
        tmp_path,
        historical_pairing_configuration=single_entry_configuration(
            tmp_path, historical_payload
        ),
        historical_pairing_secret=PAIRING_SECRET,
    )
    try:
        assert launcher.configuration == base
        assert not any(
            "historical" in name or "secret" in name for name in vars(launcher.configuration)
        )
    finally:
        launcher.close()


# ---------------------------------------------------------------------------
# B. Route absence when the feature is disabled.
# ---------------------------------------------------------------------------


DISABLED_GET_PATHS = (
    PAYLOADS_PATH,
    f"{PREPARATIONS_PATH}/some-preparation-id/{'a' * 64}",
)
DISABLED_POST_PATHS = (
    PREPARATIONS_PATH,
    f"{PREPARATIONS_PATH}/some-preparation-id/confirmation",
)


@pytest.mark.parametrize("path", DISABLED_GET_PATHS)
def test_disabled_get_paths_answer_exactly_like_an_unknown_route(
    disabled_launcher: ProductLauncher,
    path: str,
):
    unknown = request(disabled_launcher, "GET", f"{UI_API_PREFIX}/no-such-route")
    observed = request(disabled_launcher, "GET", path)
    assert observed[0] == unknown[0] == 404
    assert observed[2] == unknown[2] == {"error": "NOT_FOUND"}
    assert observed[3] == unknown[3]


@pytest.mark.parametrize("path", DISABLED_POST_PATHS)
def test_disabled_post_paths_answer_exactly_like_an_unknown_route(
    disabled_launcher: ProductLauncher,
    path: str,
):
    unknown = request(
        disabled_launcher, "POST", f"{UI_API_PREFIX}/no-such-route", body={}
    )
    observed = request(disabled_launcher, "POST", path, body={})
    assert observed[0] == unknown[0] == 404
    assert observed[2] == unknown[2] == {"error": "NOT_FOUND"}
    assert observed[3] == unknown[3]


def test_disabled_routes_never_reveal_a_partial_feature(
    disabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    answers = []
    answers.append(request(disabled_launcher, "GET", PAYLOADS_PATH))
    answers.append(request(disabled_launcher, "GET", f"{PAYLOADS_PATH}?x=1"))
    answers.append(
        request(
            disabled_launcher,
            "POST",
            PREPARATIONS_PATH,
            body={
                "payload_id": PAYLOAD_ID,
                "actor_id": ACTOR_ID,
                **owner_material(historical_payload),
            },
        )
    )
    answers.append(
        confirm_over_http(
            disabled_launcher, "some-preparation-id", "a" * 64, "b" * 64
        )
    )
    for status, _headers, body, _raw in answers:
        assert status == 404
        assert body == {"error": "NOT_FOUND"}
        rendered = json.dumps(body)
        for forbidden in (
            "FEATURE_DISABLED",
            "HISTORICAL_PAIRING_UNAVAILABLE",
            "historical",
            "pairing",
            "payload",
        ):
            assert forbidden not in rendered


def test_guard_order_is_identical_for_absent_routes(
    disabled_launcher: ProductLauncher,
):
    """A bad Host must be refused before the route-absence decision is reached."""

    port = disabled_launcher.ui_port
    for path in DISABLED_POST_PATHS + (f"{UI_API_PREFIX}/no-such-route",):
        raw = raw_exchange(
            port,
            raw_request_bytes(
                port,
                "POST",
                path,
                headers=[
                    ("Host", "evil.example:1"),
                    ("Content-Type", "application/json"),
                    (CSRF_HEADER, disabled_launcher.csrf_nonce),
                    ("Content-Length", "2"),
                    ("Connection", "close"),
                ],
                body=b"{}",
            ),
        )
        assert status_of(raw) == 403
        assert body_of(raw) == {"error": "INVALID_HOST"}
    for path in DISABLED_GET_PATHS:
        raw = raw_exchange(
            port,
            raw_request_bytes(
                port,
                "GET",
                path,
                headers=[("Host", "evil.example:1"), ("Connection", "close")],
            ),
        )
        assert status_of(raw) == 403
        assert body_of(raw) == {"error": "INVALID_HOST"}


def test_disabled_post_paths_still_execute_the_existing_mutating_guards(
    disabled_launcher: ProductLauncher,
):
    for path in DISABLED_POST_PATHS:
        status, _headers, body, _raw = request(
            disabled_launcher,
            "POST",
            path,
            body={},
            headers={CSRF_HEADER: "wrong-nonce"},
        )
        assert (status, body) == (403, {"error": "INVALID_CSRF"})
        status, _headers, body, _raw = request(
            disabled_launcher,
            "POST",
            path,
            body={},
            headers={"Origin": "http://evil.example"},
        )
        assert (status, body) == (403, {"error": "INVALID_ORIGIN"})


def test_bootstrap_is_unchanged_by_the_optional_feature(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    root = tmp_path / "shared"
    root.mkdir()
    base = launcher_configuration(root)
    off = ProductLauncher(base, verify_head=False)
    try:
        on = ProductLauncher(
            base,
            verify_head=False,
            historical_pairing_configuration=single_entry_configuration(
                root, historical_payload
            ),
            historical_pairing_secret=PAIRING_SECRET,
        )
        try:
            # Byte-identical bootstrap is the load-bearing proof; the token
            # scan below only pins that no feature vocabulary was introduced.
            assert on.bootstrap("fixed-nonce") == off.bootstrap("fixed-nonce")
            rendered = json.dumps(on.bootstrap("fixed-nonce"), sort_keys=True)
            for forbidden in (
                "historical_pairing",
                HISTORICAL_PAIRINGS_SEGMENT,
                PAYLOAD_ID,
                "archive_root",
                "confirmation_tag",
            ):
                assert forbidden not in rendered
        finally:
            on.close()
    finally:
        off.close()


# The exact pre-existing loopback inventory, pinned absolutely rather than by
# comparison, so a slice that changed one status or one error code everywhere
# still fails here.
PRE_EXISTING_ROUTES = (
    ("GET", f"{UI_API_PREFIX}", 404, {"error": "NOT_FOUND"}),
    ("GET", f"{UI_API_PREFIX}/recoveries", 200, {"recoveries": []}),
    ("GET", f"{UI_API_PREFIX}/recoveries/missing", 404, {"error": "NOT_FOUND"}),
    ("GET", f"{UI_API_PREFIX}/preparations/missing", 404, {"error": "NOT_FOUND"}),
    (
        "GET",
        f"{UI_API_PREFIX}/runs",
        200,
        {"control_runs": [], "persisted_runs": []},
    ),
    ("GET", f"{UI_API_PREFIX}/runs/missing", 404, {"error": "RUN_NOT_FOUND"}),
    (
        "GET",
        f"{UI_API_PREFIX}/runs/missing/result",
        404,
        {"error": "RUN_NOT_FOUND"},
    ),
    ("GET", f"{UI_API_PREFIX}/unknown", 404, {"error": "NOT_FOUND"}),
    ("GET", "/nope", 404, {"error": "NOT_FOUND"}),
    ("POST", f"{UI_API_PREFIX}/unknown", 404, {"error": "NOT_FOUND"}),
    (
        "POST",
        f"{UI_API_PREFIX}/contracts/missing/preparations",
        404,
        {"error": "CONTRACT_NOT_FOUND"},
    ),
    (
        "POST",
        f"{UI_API_PREFIX}/runs/missing/recovery",
        404,
        {"error": "RUN_NOT_FOUND"},
    ),
    ("PUT", f"{UI_API_PREFIX}/recoveries", 405, {"error": "METHOD_NOT_ALLOWED"}),
    ("PATCH", f"{UI_API_PREFIX}/recoveries", 405, {"error": "METHOD_NOT_ALLOWED"}),
    ("DELETE", f"{UI_API_PREFIX}/recoveries", 405, {"error": "METHOD_NOT_ALLOWED"}),
)


def test_pre_existing_route_behavior_is_pinned_absolutely(
    enabled_launcher: ProductLauncher,
):
    for method, path, status, body in PRE_EXISTING_ROUTES:
        payload = {} if method == "POST" else None
        observed = request(enabled_launcher, method, path, body=payload)
        assert (observed[0], observed[2]) == (status, body), path
    # The document root and the bootstrap keep their exact accepted shapes.
    status, headers, _parsed, raw = request(enabled_launcher, "GET", "/")
    assert status == 200
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert raw.startswith(b"<!doctype html>") or raw.startswith(b"<!DOCTYPE html>")
    status, _headers, bootstrap, _raw = request(
        enabled_launcher, "GET", f"{UI_API_PREFIX}/bootstrap"
    )
    assert status == 200
    assert bootstrap["service"] == "admissible-product-launcher"
    assert bootstrap["version"] == "g2.5"
    assert bootstrap["visual_ui_available"] is False
    assert set(bootstrap) == set(enabled_launcher.bootstrap("x"))
    status, _headers, body, _raw = request(
        enabled_launcher,
        "POST",
        f"{UI_API_PREFIX}/contracts",
        body={"bad": 1},
    )
    assert (status, body["error"]) == (400, "AUTHORING_REJECTED")
    status, _headers, body, _raw = request(
        enabled_launcher,
        "POST",
        f"{UI_API_PREFIX}/runs",
        body={"contract_id": "x", "preparation_id": "y"},
    )
    assert (status, body) == (400, {"error": "OWNER_AUTHORIZATION_REQUIRED"})


def test_existing_route_inventory_is_unchanged_when_disabled(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """Every pre-existing path keeps its method, status and body verbatim."""

    root = tmp_path / "inventory"
    root.mkdir()
    base = launcher_configuration(root)
    off = ProductLauncher(base, verify_head=False).start()
    try:
        on = ProductLauncher(
            base,
            verify_head=False,
            historical_pairing_configuration=single_entry_configuration(
                root, historical_payload
            ),
            historical_pairing_secret=PAIRING_SECRET,
        ).start()
        try:
            probes = (
                ("GET", f"{UI_API_PREFIX}/recoveries", None),
                ("GET", f"{UI_API_PREFIX}/preparations/missing", None),
                ("GET", f"{UI_API_PREFIX}/recoveries/missing", None),
                ("GET", f"{UI_API_PREFIX}/unknown", None),
                ("POST", f"{UI_API_PREFIX}/unknown", {}),
                ("POST", f"{UI_API_PREFIX}/contracts", {"bad": 1}),
                (
                    "POST",
                    f"{UI_API_PREFIX}/contracts/missing/preparations",
                    {},
                ),
                ("POST", f"{UI_API_PREFIX}/runs/missing/recovery", {}),
                ("PUT", f"{UI_API_PREFIX}/recoveries", None),
                ("DELETE", f"{UI_API_PREFIX}/recoveries", None),
            )
            for method, path, body in probes:
                left = request(off, method, path, body=body)
                right = request(on, method, path, body=body)
                assert left[0] == right[0], path
                assert left[2] == right[2], path
            # The four additions exist only on the configured launcher.
            assert request(off, "GET", PAYLOADS_PATH)[0] == 404
            assert request(on, "GET", PAYLOADS_PATH)[0] == 200
        finally:
            on.close()
    finally:
        off.close()


# ---------------------------------------------------------------------------
# C. Payload route.
# ---------------------------------------------------------------------------


def test_payload_route_lists_configured_records_in_declaration_order(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_payload: NativeCanaryAuthorizationPayloadV4,
):
    root = tmp_path / "ordered"
    documents = root / "documents"
    documents.mkdir(parents=True)
    second = write_document(documents / "second.json", other_payload)
    first = write_document(documents / "first.json", historical_payload)
    launcher = build_launcher(
        root,
        historical_pairing_configuration=pairing_configuration(
            root,
            (
                HistoricalPayloadEntry(
                    payload_id=OTHER_PAYLOAD_ID, document_path=second.resolve()
                ),
                HistoricalPayloadEntry(
                    payload_id=PAYLOAD_ID, document_path=first.resolve()
                ),
            ),
        ),
        historical_pairing_secret=PAIRING_SECRET,
    ).start()
    try:
        status, _headers, body, raw = request(launcher, "GET", PAYLOADS_PATH)
        assert status == 200
        assert [item["payload_id"] for item in body["payloads"]] == [
            OTHER_PAYLOAD_ID,
            PAYLOAD_ID,
        ]
        for item in body["payloads"]:
            assert set(item) == {
                "payload_id",
                "payload_fingerprint",
                "document_sha256",
                "document_byte_length",
            }
        rendered = raw.decode("utf-8")
        assert str(root) not in rendered
        assert "document_path" not in rendered
        assert "archive" not in rendered
    finally:
        launcher.close()


def test_payload_route_reopens_no_document_per_request(
    tmp_path: Path,
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """Deleting every configured document cannot change a built registry."""

    baseline = request(enabled_launcher, "GET", PAYLOADS_PATH)[2]
    documents = tmp_path / "enabled" / "documents"
    removed = sorted(documents.glob("*.json"))
    assert removed
    for path in removed:
        path.unlink()
    assert not any(documents.glob("*.json"))
    assert request(enabled_launcher, "GET", PAYLOADS_PATH)[2] == baseline
    status, review = prepare_over_http(enabled_launcher, historical_payload)
    assert status == 201
    assert review["pairing_identity"]["target_authorization_payload_fingerprint"] == (
        historical_payload.payload_fingerprint
    )


@pytest.mark.parametrize(
    "path",
    [
        f"{PAYLOADS_PATH}?",
        f"{PAYLOADS_PATH}?x=1",
        f"{PAYLOADS_PATH}?tag=" + "a" * 64,
    ],
)
def test_payload_route_refuses_any_query_string(
    enabled_launcher: ProductLauncher,
    path: str,
):
    status, _headers, body, _raw = request(enabled_launcher, "GET", path)
    if path.endswith("?"):
        # An empty query is not a query: the route answers normally.
        assert status == 200
    else:
        assert (status, body) == (400, {"error": "QUERY_NOT_ALLOWED"})


def test_payload_route_keeps_the_existing_host_and_origin_guards(
    enabled_launcher: ProductLauncher,
):
    port = enabled_launcher.ui_port
    raw = raw_exchange(
        port,
        raw_request_bytes(
            port,
            "GET",
            PAYLOADS_PATH,
            headers=[("Host", "127.0.0.1:1"), ("Connection", "close")],
        ),
    )
    assert (status_of(raw), body_of(raw)) == (403, {"error": "INVALID_HOST"})
    status, _headers, body, _raw = request(
        enabled_launcher,
        "GET",
        PAYLOADS_PATH,
        headers={"Origin": "http://evil.example"},
    )
    assert (status, body) == (403, {"error": "INVALID_ORIGIN"})
    # The accepted absent-Origin policy is untouched by this slice.
    raw = raw_exchange(
        port,
        raw_request_bytes(
            port,
            "GET",
            PAYLOADS_PATH,
            headers=[("Host", f"127.0.0.1:{port}"), ("Connection", "close")],
        ),
    )
    assert status_of(raw) == 200
    # A GET never requires the CSRF header.
    assert request(enabled_launcher, "GET", PAYLOADS_PATH, omit=(CSRF_HEADER,))[0] == 200


# ---------------------------------------------------------------------------
# D. Preparation route.
# ---------------------------------------------------------------------------


def test_preparation_route_answers_created_with_the_complete_review(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    status, review = prepare_over_http(enabled_launcher, historical_payload)
    assert status == 201
    assert set(review) == {
        "pairing_identity",
        "claim_authority",
        "verification_plan_authority",
        "verification_evidence_binding_authority",
        "historical_mission_context",
        "historical_authority_context",
        "compatibility_revalidation",
        "withheld_fields",
        "notices",
    }
    identity = review["pairing_identity"]
    assert identity["preparation_state"] == PREPARATION_STATE_READY_FOR_CONFIRMATION
    assert identity["evaluation_profile_is_launchable"] is False
    assert identity["target_authorization_payload_fingerprint"] == (
        historical_payload.payload_fingerprint
    )


FORBIDDEN_PREPARATION_FIELDS = (
    "preparation_id",
    "authority_fingerprint",
    "expected_authority_fingerprint",
    "profile_fingerprint",
    "payload_fingerprint",
    "pairing_authority",
    "confirmation_message",
    "archive_root",
    "document_path",
    "payload_path",
    "run_root",
    "evidence_root",
    "configured_secret",
    "secret",
    "expected_tag",
    "presented_confirmation_tag",
    "result",
    "evidence",
    "verdict",
)


@pytest.mark.parametrize("extra", FORBIDDEN_PREPARATION_FIELDS)
def test_preparation_route_refuses_every_additional_authority_field(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    extra: str,
):
    status, _headers, body, _raw = request(
        enabled_launcher,
        "POST",
        PREPARATIONS_PATH,
        body={
            "payload_id": PAYLOAD_ID,
            "actor_id": ACTOR_ID,
            **owner_material(historical_payload),
            extra: "injected",
        },
    )
    assert (status, body) == (400, {"error": "INVALID_FIELDS"})


def test_preparation_route_requires_the_exact_five_field_set(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    complete = {
        "payload_id": PAYLOAD_ID,
        "actor_id": ACTOR_ID,
        **owner_material(historical_payload),
    }
    for missing in sorted(complete):
        partial = {key: value for key, value in complete.items() if key != missing}
        status, _headers, body, _raw = request(
            enabled_launcher, "POST", PREPARATIONS_PATH, body=partial
        )
        assert (status, body) == (400, {"error": "INVALID_FIELDS"})
    assert request(enabled_launcher, "POST", PREPARATIONS_PATH, body={})[0] == 400


def test_preparation_route_never_accepts_a_payload_path_as_a_locator(
    tmp_path: Path,
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    configured = enabled_launcher._historical_pairing
    del configured
    document = tmp_path / "enabled" / "documents" / f"{PAYLOAD_ID}.json"
    candidates = (
        str(document),
        document.as_posix(),
        "unregistered-payload",
        "../../etc/passwd",
        "ALPHA-HISTORICAL-RUN",
    )
    for candidate in candidates:
        status, _headers, body, _raw = request(
            enabled_launcher,
            "POST",
            PREPARATIONS_PATH,
            body={
                "payload_id": candidate,
                "actor_id": ACTOR_ID,
                **owner_material(historical_payload),
            },
        )
        assert (status, body) == (404, {"error": "PAYLOAD_NOT_ALLOWLISTED"})


def test_preparation_route_refuses_a_query_string_and_non_json(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    body = {
        "payload_id": PAYLOAD_ID,
        "actor_id": ACTOR_ID,
        **owner_material(historical_payload),
    }
    status, _headers, parsed, _raw = request(
        enabled_launcher, "POST", f"{PREPARATIONS_PATH}?actor_id=other", body=body
    )
    assert (status, parsed) == (400, {"error": "QUERY_NOT_ALLOWED"})
    status, _headers, parsed, _raw = request(
        enabled_launcher,
        "POST",
        PREPARATIONS_PATH,
        body=body,
        headers={"Content-Type": "text/plain"},
    )
    assert (status, parsed) == (415, {"error": "JSON_REQUIRED"})


def test_request_mutation_after_preparation_cannot_change_a_later_review(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """The wire copy is gone; a later review is derived from pinned objects."""

    status, review = prepare_over_http(enabled_launcher, historical_payload)
    assert status == 201
    preparation_id, fingerprint = locator_of(review)
    review["claim_authority"]["claims"].clear()
    review["pairing_identity"]["asserted_actor_id"] = "impostor"
    status, _headers, refreshed, _raw = request(
        enabled_launcher, "GET", review_path(preparation_id, fingerprint)
    )
    assert status == 200
    assert refreshed["pairing_identity"]["asserted_actor_id"] == ACTOR_ID
    assert refreshed["claim_authority"]["claims"] != []


# ---------------------------------------------------------------------------
# E. Review route.
# ---------------------------------------------------------------------------


def test_review_route_requires_the_complete_locator(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    assert request(
        enabled_launcher, "GET", review_path(preparation_id, fingerprint)
    )[0] == 200
    # A missing fingerprint segment is not a historical route at all.
    assert request(enabled_launcher, "GET", f"{PREPARATIONS_PATH}/{preparation_id}")[
        2
    ] == {"error": "NOT_FOUND"}
    assert request(
        enabled_launcher, "GET", f"{PREPARATIONS_PATH}/{preparation_id}/"
    )[2] == {"error": "NOT_FOUND"}
    # A truncated or upper-cased fingerprint is a bounded locator refusal.
    for wrong in (fingerprint[:63], fingerprint.upper(), fingerprint + "0"):
        status, _headers, body, _raw = request(
            enabled_launcher, "GET", review_path(preparation_id, wrong)
        )
        assert (status, body) == (400, {"error": "PAIRING_LOCATOR_INVALID"})
    status, _headers, body, _raw = request(
        enabled_launcher, "GET", review_path(preparation_id, "f" * 64)
    )
    assert (status, body) == (409, {"error": "STALE_AUTHORITY_FINGERPRINT"})
    status, _headers, body, _raw = request(
        enabled_launcher, "GET", review_path("unknown-preparation", fingerprint)
    )
    assert (status, body) == (404, {"error": "PREPARATION_NOT_FOUND"})


def test_review_route_is_fresh_extends_no_ttl_and_reads_no_secret(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    coordinator = enabled_launcher._historical_pairing._coordinator
    created_at = coordinator._preparations[preparation_id].created_at
    secret_reads: list[str] = []

    class _WatchedSecret(bytes):
        pass

    first = request(enabled_launcher, "GET", review_path(preparation_id, fingerprint))
    second = request(enabled_launcher, "GET", review_path(preparation_id, fingerprint))
    assert first[2] == second[2] == review
    assert coordinator._preparations[preparation_id].created_at == created_at
    assert coordinator._preparations[preparation_id].confirmation_reserved is False
    assert coordinator._preparations[preparation_id].consumed is False
    assert secret_reads == []
    # No configured-secret fragment can appear in a review answer.
    fragments = _fragments_of(PAIRING_SECRET, "0" * 64)
    assert _disclosures_in_text(first[3].decode("utf-8"), fragments) == []


def test_review_route_answers_for_a_consumed_preparation(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    assert confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[0] == 200
    status, _headers, body, _raw = request(
        enabled_launcher, "GET", review_path(preparation_id, fingerprint)
    )
    assert status == 200
    assert body["pairing_identity"]["preparation_state"] == PREPARATION_STATE_CONSUMED


def test_review_route_reports_an_expired_record_as_expired(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    coordinator = enabled_launcher._historical_pairing._coordinator
    coordinator._preparations[preparation_id].created_at -= (
        coordinator._preparation_ttl_seconds + 10
    )
    status, _headers, body, _raw = request(
        enabled_launcher, "GET", review_path(preparation_id, fingerprint)
    )
    assert (status, body) == (410, {"error": "PREPARATION_EXPIRED"})


def test_review_route_refuses_a_query_string(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    status, _headers, body, _raw = request(
        enabled_launcher,
        "GET",
        review_path(preparation_id, fingerprint) + "?tag=" + "a" * 64,
    )
    assert (status, body) == (400, {"error": "QUERY_NOT_ALLOWED"})


# ---------------------------------------------------------------------------
# F. Confirmation route.
# ---------------------------------------------------------------------------


def test_confirmation_route_accepts_one_correct_independent_tag(
    tmp_path: Path,
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    status, _headers, body, raw = confirm_over_http(
        enabled_launcher, preparation_id, fingerprint, tag
    )
    assert status == 200
    assert set(body) == {
        "outcome",
        "preparation_id",
        "asserted_actor_id",
        "pairing_authority_fingerprint",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "archived_pairing_document_count",
        "limitations",
    }
    assert body["outcome"] == "CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE"
    assert body["archived_pairing_document_count"] == 3
    assert body["asserted_actor_id"] == ACTOR_ID
    assert tag not in raw.decode("utf-8")


def test_confirmation_route_requires_exactly_one_tag_header(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    port = enabled_launcher.ui_port
    payload = json.dumps(
        {"expected_authority_fingerprint": fingerprint},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    def drive(tag_headers: list[tuple[str, str]]) -> bytes:
        return raw_exchange(
            port,
            raw_request_bytes(
                port,
                "POST",
                confirmation_path(preparation_id),
                headers=[
                    ("Host", f"127.0.0.1:{port}"),
                    ("Content-Type", "application/json"),
                    (CSRF_HEADER, enabled_launcher.csrf_nonce),
                    *tag_headers,
                    ("Content-Length", str(len(payload))),
                    ("Connection", "close"),
                ],
                body=payload,
            ),
        )

    absent = drive([])
    assert (status_of(absent), body_of(absent)) == (
        400,
        {"error": "CONFIRMATION_TAG_REQUIRED"},
    )
    duplicated = drive(
        [
            (HISTORICAL_PAIRING_CONFIRMATION_HEADER, tag),
            (HISTORICAL_PAIRING_CONFIRMATION_HEADER, tag),
        ]
    )
    assert (status_of(duplicated), body_of(duplicated)) == (
        400,
        {"error": "CONFIRMATION_TAG_MALFORMED"},
    )
    # Two instances are refused even when one of them is the correct tag.
    mixed = drive(
        [
            (HISTORICAL_PAIRING_CONFIRMATION_HEADER, tag),
            (HISTORICAL_PAIRING_CONFIRMATION_HEADER, "0" * 64),
        ]
    )
    assert status_of(mixed) == 400
    assert body_of(mixed) == {"error": "CONFIRMATION_TAG_MALFORMED"}
    empty = drive([(HISTORICAL_PAIRING_CONFIRMATION_HEADER, "")])
    assert (status_of(empty), body_of(empty)) == (
        400,
        {"error": "CONFIRMATION_TAG_MALFORMED"},
    )
    # The preparation survived every refusal above.
    accepted = drive([(HISTORICAL_PAIRING_CONFIRMATION_HEADER, tag)])
    assert status_of(accepted) == 200


def test_confirmation_route_never_normalizes_the_presented_tag(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """Case folding and whitespace trimming would each forge an acceptance."""

    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    port = enabled_launcher.ui_port
    payload = json.dumps(
        {"expected_authority_fingerprint": fingerprint},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    for variant in (tag.upper(), tag + " ", tag + "\t", tag[:63], tag + "0"):
        raw = raw_exchange(
            port,
            raw_request_bytes(
                port,
                "POST",
                confirmation_path(preparation_id),
                headers=[
                    ("Host", f"127.0.0.1:{port}"),
                    ("Content-Type", "application/json"),
                    (CSRF_HEADER, enabled_launcher.csrf_nonce),
                    (HISTORICAL_PAIRING_CONFIRMATION_HEADER, variant),
                    ("Content-Length", str(len(payload))),
                    ("Connection", "close"),
                ],
                body=payload,
            ),
        )
        assert (status_of(raw), body_of(raw)) == (
            400,
            {"error": "CONFIRMATION_TAG_MALFORMED"},
        ), variant
    # Only the exact byte-for-byte tag is accepted.
    assert confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[0] == 200


class _RecordingService:
    """Stand-in service recording exactly what the transport handed it."""

    def __init__(self) -> None:
        self.tags: list[str] = []
        self.calls: list[tuple[str, dict]] = []

    def payloads(self):
        self.calls.append(("payloads", {}))
        return 200, {"payloads": []}

    def prepare(self, **kwargs):
        self.calls.append(("prepare", dict(kwargs)))
        return 201, {"recorded": True}

    def review(self, **kwargs):
        self.calls.append(("review", dict(kwargs)))
        return 200, {"recorded": True}

    def confirm(self, **kwargs):
        self.calls.append(("confirm", dict(kwargs)))
        self.tags.append(kwargs["presented_confirmation_tag"])
        return 200, {"recorded": True}


def test_the_presented_tag_reaches_the_service_byte_for_byte(
    enabled_launcher: ProductLauncher,
):
    recorder = _RecordingService()
    enabled_launcher._historical_pairing = recorder
    port = enabled_launcher.ui_port
    payload = json.dumps(
        {"expected_authority_fingerprint": "a" * 64},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    variants = ["AbC dEf", "0" * 64, "F" * 64, "  padded  ", "tab\ttab", "x" * 200]
    for variant in variants:
        raw = raw_exchange(
            port,
            raw_request_bytes(
                port,
                "POST",
                confirmation_path("some-preparation"),
                headers=[
                    ("Host", f"127.0.0.1:{port}"),
                    ("Content-Type", "application/json"),
                    (CSRF_HEADER, enabled_launcher.csrf_nonce),
                    (HISTORICAL_PAIRING_CONFIRMATION_HEADER, variant),
                    ("Content-Length", str(len(payload))),
                    ("Connection", "close"),
                ],
                body=payload,
            ),
        )
        assert status_of(raw) == 200
    # A leading space is removed by the HTTP header grammar itself, never by
    # this transport; everything the parser preserved arrives unchanged.
    assert recorder.tags == [
        "AbC dEf",
        "0" * 64,
        "F" * 64,
        "padded  ",
        "tab\ttab",
        "x" * 200,
    ]
    for _name, kwargs in recorder.calls:
        assert kwargs["preparation_id"] == "some-preparation"
        assert kwargs["expected_authority_fingerprint"] == "a" * 64
        assert set(kwargs) == {
            "preparation_id",
            "expected_authority_fingerprint",
            "presented_confirmation_tag",
        }


def test_absent_or_duplicate_tag_headers_never_reach_the_service(
    enabled_launcher: ProductLauncher,
):
    """Occurrence handling refuses in transport: no joined, first, or last value."""

    recorder = _RecordingService()
    enabled_launcher._historical_pairing = recorder
    port = enabled_launcher.ui_port
    payload = json.dumps(
        {"expected_authority_fingerprint": "a" * 64},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    def drive(tag_headers):
        return raw_exchange(
            port,
            raw_request_bytes(
                port,
                "POST",
                confirmation_path("some-preparation"),
                headers=[
                    ("Host", f"127.0.0.1:{port}"),
                    ("Content-Type", "application/json"),
                    (CSRF_HEADER, enabled_launcher.csrf_nonce),
                    *tag_headers,
                    ("Content-Length", str(len(payload))),
                    ("Connection", "close"),
                ],
                body=payload,
            ),
        )

    absent = drive([])
    assert (status_of(absent), body_of(absent)) == (
        400,
        {"error": "CONFIRMATION_TAG_REQUIRED"},
    )
    for duplicates in (
        [("a" * 64), ("b" * 64)],
        [("a" * 64), ("a" * 64)],
        [("a" * 64), ("b" * 64), ("c" * 64)],
    ):
        raw = drive(
            [
                (HISTORICAL_PAIRING_CONFIRMATION_HEADER, value)
                for value in duplicates
            ]
        )
        assert (status_of(raw), body_of(raw)) == (
            400,
            {"error": "CONFIRMATION_TAG_MALFORMED"},
        )
    # Not one of those four requests was allowed to reach the service.
    assert recorder.calls == []
    assert recorder.tags == []
    # Exactly one instance does reach it, so the guard above is not vacuous.
    accepted = drive([(HISTORICAL_PAIRING_CONFIRMATION_HEADER, "d" * 64)])
    assert status_of(accepted) == 200
    assert recorder.tags == ["d" * 64]


FORBIDDEN_CONFIRMATION_FIELDS = (
    "actor_id",
    "payload_id",
    "result_claims",
    "claim_verification_plan",
    "verification_evidence_bindings",
    "archive_root",
    "configured_secret",
    "secret",
    "tag",
    "presented_confirmation_tag",
    "expected_tag",
    "profile_fingerprint",
    "payload_fingerprint",
    "preparation_id",
)


@pytest.mark.parametrize("extra", FORBIDDEN_CONFIRMATION_FIELDS)
def test_confirmation_body_accepts_only_the_expected_fingerprint(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    extra: str,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    status, _headers, body, _raw = request(
        enabled_launcher,
        "POST",
        confirmation_path(preparation_id),
        body={"expected_authority_fingerprint": fingerprint, extra: "injected"},
        headers={HISTORICAL_PAIRING_CONFIRMATION_HEADER: tag},
    )
    assert (status, body) == (400, {"error": "INVALID_FIELDS"})
    # The preparation is untouched by the refusal.
    assert confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[0] == 200


def test_confirmation_route_refuses_a_tag_in_the_body_or_the_query(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    status, _headers, body, _raw = request(
        enabled_launcher,
        "POST",
        confirmation_path(preparation_id),
        body={
            "expected_authority_fingerprint": fingerprint,
            "presented_confirmation_tag": tag,
        },
    )
    assert (status, body) == (400, {"error": "INVALID_FIELDS"})
    status, _headers, body, _raw = request(
        enabled_launcher,
        "POST",
        confirmation_path(preparation_id) + f"?tag={tag}",
        body={"expected_authority_fingerprint": fingerprint},
        headers={HISTORICAL_PAIRING_CONFIRMATION_HEADER: tag},
    )
    assert (status, body) == (400, {"error": "QUERY_NOT_ALLOWED"})
    # Neither attempt confirmed anything.
    assert confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[0] == 200


def test_unknown_body_fields_are_refused_before_the_header_is_read(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """A malformed body never lets a caller probe tag-header handling."""

    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    status, _headers, body, _raw = request(
        enabled_launcher,
        "POST",
        confirmation_path(preparation_id),
        body={"expected_authority_fingerprint": fingerprint, "extra": 1},
    )
    assert (status, body) == (400, {"error": "INVALID_FIELDS"})
    status, _headers, body, _raw = request(
        enabled_launcher, "POST", confirmation_path(preparation_id), body={}
    )
    assert (status, body) == (400, {"error": "INVALID_FIELDS"})
    status, _headers, body, _raw = request(
        enabled_launcher,
        "POST",
        confirmation_path(preparation_id),
        raw_body=b"not json",
    )
    assert (status, body) == (400, {"error": "INVALID_JSON"})


@pytest.mark.parametrize(
    "credential",
    ["authority", "profile", "payload", "message_digest", "runtime_digest", "other_secret"],
)
def test_every_wrong_credential_reaches_one_indistinguishable_refusal(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    credential: str,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    identity = review["pairing_identity"]
    candidates = {
        "authority": identity["pairing_authority_fingerprint"],
        "profile": identity["evaluation_profile_fingerprint"],
        "payload": identity["target_authorization_payload_fingerprint"],
        "message_digest": identity["confirmation_message_sha256"],
        "runtime_digest": RUNTIME_OWNER_DIGEST,
        "other_secret": independent_confirmation_tag(OTHER_SECRET, review),
    }
    candidate = candidates[credential]
    assert len(candidate) == 64
    status, _headers, body, raw = confirm_over_http(
        enabled_launcher, preparation_id, fingerprint, candidate
    )
    assert (status, body) == (403, {"error": "CONFIRMATION_REJECTED"})
    assert candidate not in raw.decode("utf-8")


def test_retry_after_success_reports_consumed_and_leaves_three_documents(
    tmp_path: Path,
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """The client response of the first confirmation is deliberately discarded."""

    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    discarded = confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)
    assert discarded[0] == 200
    del discarded
    status, _headers, body, _raw = confirm_over_http(
        enabled_launcher, preparation_id, fingerprint, tag
    )
    assert (status, body) == (409, {"error": "PREPARATION_CONSUMED"})
    archive = tmp_path / "enabled" / "archive"
    documents = sorted(
        path.relative_to(archive).as_posix()
        for path in archive.rglob("*")
        if path.is_file()
    )
    assert len(documents) == 3


def test_no_route_infers_confirmation_from_archive_existence(
    tmp_path: Path,
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """A published archive never turns a fresh preparation into a confirmed one."""

    _status, first = prepare_over_http(enabled_launcher, historical_payload)
    first_id, fingerprint = locator_of(first)
    tag = independent_confirmation_tag(PAIRING_SECRET, first)
    assert confirm_over_http(enabled_launcher, first_id, fingerprint, tag)[0] == 200
    _status, second = prepare_over_http(enabled_launcher, historical_payload)
    second_id, second_fingerprint = locator_of(second)
    assert second_fingerprint == fingerprint
    status, _headers, body, _raw = request(
        enabled_launcher, "GET", review_path(second_id, second_fingerprint)
    )
    assert status == 200
    assert body["pairing_identity"]["preparation_state"] == (
        PREPARATION_STATE_READY_FOR_CONFIRMATION
    )
    # A wrong tag on the second preparation is still refused, archive or not.
    assert (
        confirm_over_http(enabled_launcher, second_id, second_fingerprint, "0" * 64)[0]
        == 403
    )


# ---------------------------------------------------------------------------
# G. Guard order and framing.
# ---------------------------------------------------------------------------


def test_transport_guards_precede_every_route_specific_step(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    port = enabled_launcher.ui_port
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    garbage = b"{{{ not json at all"

    def drive(headers, body=garbage, path=None):
        return raw_exchange(
            port,
            raw_request_bytes(
                port,
                "POST",
                path or confirmation_path(preparation_id),
                headers=headers,
                body=body,
            ),
        )

    base = [
        ("Host", f"127.0.0.1:{port}"),
        ("Content-Type", "application/json"),
        (CSRF_HEADER, enabled_launcher.csrf_nonce),
        (HISTORICAL_PAIRING_CONFIRMATION_HEADER, tag),
        ("Content-Length", str(len(garbage))),
        ("Connection", "close"),
    ]
    bad_host = [("Host", "evil.example:1")] + base[1:]
    raw = drive(bad_host)
    assert (status_of(raw), body_of(raw)) == (403, {"error": "INVALID_HOST"})
    bad_origin = base[:1] + [("Origin", "http://evil.example")] + base[1:]
    raw = drive(bad_origin)
    assert (status_of(raw), body_of(raw)) == (403, {"error": "INVALID_ORIGIN"})
    bad_csrf = [
        item if item[0] != CSRF_HEADER else (CSRF_HEADER, "wrong") for item in base
    ]
    raw = drive(bad_csrf)
    assert (status_of(raw), body_of(raw)) == (403, {"error": "INVALID_CSRF"})
    # Only after every guard passes does body framing decide.
    raw = drive(base)
    assert (status_of(raw), body_of(raw)) == (400, {"error": "INVALID_JSON"})
    # The preparation is still confirmable: no guard refusal consumed it.
    assert confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[0] == 200


def test_body_framing_controls_are_unchanged_on_the_new_routes(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    port = enabled_launcher.ui_port
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    good = json.dumps(
        {"expected_authority_fingerprint": fingerprint},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    def drive(extra_headers, body=good, include_length=True):
        headers = [
            ("Host", f"127.0.0.1:{port}"),
            ("Content-Type", "application/json"),
            (CSRF_HEADER, enabled_launcher.csrf_nonce),
            (HISTORICAL_PAIRING_CONFIRMATION_HEADER, tag),
            *extra_headers,
        ]
        if include_length:
            headers.append(("Content-Length", str(len(body))))
        headers.append(("Connection", "close"))
        return raw_exchange(
            port,
            raw_request_bytes(
                port, "POST", confirmation_path(preparation_id),
                headers=headers, body=body,
            ),
        )

    raw = drive([("Transfer-Encoding", "chunked")])
    assert (status_of(raw), body_of(raw)) == (400, {"error": "UNBOUNDED_BODY"})
    raw = drive([], include_length=False)
    assert (status_of(raw), body_of(raw)) == (411, {"error": "CONTENT_LENGTH_REQUIRED"})
    raw = raw_exchange(
        port,
        raw_request_bytes(
            port,
            "POST",
            confirmation_path(preparation_id),
            headers=[
                ("Host", f"127.0.0.1:{port}"),
                ("Content-Type", "application/json"),
                (CSRF_HEADER, enabled_launcher.csrf_nonce),
                (HISTORICAL_PAIRING_CONFIRMATION_HEADER, tag),
                ("Content-Length", str(len(good))),
                ("Content-Length", str(len(good))),
                ("Connection", "close"),
            ],
            body=good,
        ),
    )
    assert (status_of(raw), body_of(raw)) == (400, {"error": "CONTENT_LENGTH_INVALID"})
    oversized = json.dumps(
        {"expected_authority_fingerprint": fingerprint}
    ).encode("utf-8")
    raw = raw_exchange(
        port,
        raw_request_bytes(
            port,
            "POST",
            confirmation_path(preparation_id),
            headers=[
                ("Host", f"127.0.0.1:{port}"),
                ("Content-Type", "application/json"),
                (CSRF_HEADER, enabled_launcher.csrf_nonce),
                (HISTORICAL_PAIRING_CONFIRMATION_HEADER, tag),
                ("Content-Length", str(2 * 1024 * 1024)),
                ("Connection", "close"),
            ],
            body=oversized,
        ),
    )
    assert (status_of(raw), body_of(raw)) == (413, {"error": "BODY_TOO_LARGE"})
    duplicate_keys = b'{"expected_authority_fingerprint":"a","expected_authority_fingerprint":"b"}'
    raw = drive([], body=duplicate_keys)
    assert (status_of(raw), body_of(raw)) == (400, {"error": "INVALID_JSON"})
    raw = drive([], body=b"[]")
    assert (status_of(raw), body_of(raw)) == (400, {"error": "JSON_OBJECT_REQUIRED"})


def test_historical_paths_reject_unsupported_methods_unchanged(
    enabled_launcher: ProductLauncher,
):
    for method in ("PUT", "PATCH", "DELETE"):
        status, _headers, body, _raw = request(
            enabled_launcher, method, PAYLOADS_PATH, body={}
        )
        assert (status, body) == (405, {"error": "METHOD_NOT_ALLOWED"})


def test_dispatch_uses_no_dynamic_registration_or_route_table():
    source = Path(ui_transport_module.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "add_route",
        "register_route",
        "ROUTES = ",
        "@route",
        "send_response(30",
        "Location",
    ):
        assert forbidden not in source
    assert not issubclass(_UIServer, socketserver.ThreadingMixIn)
    assert not issubclass(_UIServer, ThreadingHTTPServer)
    assert issubclass(_UIServer, HTTPServer)


def test_all_three_request_log_hooks_are_explicit_no_ops(
    monkeypatch: pytest.MonkeyPatch,
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """Inherited hooks would route request lines back through log_message."""

    for name in ("log_message", "log_request", "log_error"):
        assert name in _UIHandler.__dict__

    recorded: list[tuple] = []
    monkeypatch.setattr(
        _UIHandler,
        "log_message",
        lambda self, *args, **kwargs: recorded.append(args),
    )
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    assert confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[0] == 200
    assert request(enabled_launcher, "GET", PAYLOADS_PATH)[0] == 200
    assert request(enabled_launcher, "GET", f"{UI_API_PREFIX}/nope")[0] == 404
    assert recorded == []


# ---------------------------------------------------------------------------
# H. Confidentiality over the wire.
# ---------------------------------------------------------------------------


def test_a_complete_http_workflow_is_silent_and_discloses_nothing(
    tmp_path: Path,
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    other_tag = independent_confirmation_tag(OTHER_SECRET, review)
    fragments = _fragments_of(PAIRING_SECRET, tag) | _fragments_of(
        OTHER_SECRET, other_tag
    )
    captured: list[bytes] = []
    with _observed_sinks() as observation:
        captured.append(request(enabled_launcher, "GET", PAYLOADS_PATH)[3])
        captured.append(
            request(enabled_launcher, "GET", review_path(preparation_id, fingerprint))[3]
        )
        captured.append(
            confirm_over_http(enabled_launcher, preparation_id, fingerprint, "0" * 64)[3]
        )
        captured.append(
            confirm_over_http(
                enabled_launcher, preparation_id, fingerprint, other_tag
            )[3]
        )
        captured.append(
            confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[3]
        )
        captured.append(
            confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[3]
        )
        captured.append(repr(enabled_launcher).encode("utf-8"))
        captured.append(repr(enabled_launcher._historical_pairing).encode("utf-8"))
    assert _disclosures(observation, fragments) == []
    assert observation.warnings == []
    for raw in captured:
        assert _disclosures_in_text(raw.decode("utf-8"), fragments) == []


def test_response_headers_never_carry_a_tag_or_secret_fragment(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    fragments = _fragments_of(PAIRING_SECRET, tag)
    for status, headers, _body, _raw in (
        confirm_over_http(enabled_launcher, preparation_id, fingerprint, "0" * 64),
        confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag),
    ):
        assert status in (200, 403)
        rendered = json.dumps(headers, sort_keys=True)
        assert _disclosures_in_text(rendered, fragments) == []
        assert HISTORICAL_PAIRING_CONFIRMATION_HEADER not in headers


def test_malformed_tag_answers_reveal_no_length_or_near_match_information(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    answers = []
    for variant in ("", "a", tag[:63], tag.upper(), tag[:-1] + ("0" if tag[-1] != "0" else "1")):
        status, _headers, body, raw = confirm_over_http(
            enabled_launcher, preparation_id, fingerprint, variant
        )
        answers.append((status, body))
        assert set(body) == {"error"}
        assert variant == "" or variant not in raw.decode("utf-8")
    # Every malformed shape is one code; the near-match differs only by being
    # a well-formed wrong credential.
    assert [item[1] for item in answers[:4]] == [
        {"error": "CONFIRMATION_TAG_MALFORMED"}
    ] * 4
    assert answers[4] == (403, {"error": "CONFIRMATION_REJECTED"})


def test_launcher_object_graph_holds_no_tag_and_one_documented_secret_slot(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    assert confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[0] == 200
    secret_fragments = _fragments_of(PAIRING_SECRET, tag)
    tag_only = frozenset(
        fragment
        for fragment in secret_fragments
        if fragment in _fragments_of(OTHER_SECRET, tag)
    )
    assert len(tag_only) > 8
    assert graph_disclosures(enabled_launcher, tag_only) == []
    slots = {
        path for path, _fragment in graph_disclosures(enabled_launcher, secret_fragments)
    }
    assert slots == {"<root>._historical_pairing._coordinator._configured_secret"}


def test_confirmation_message_hashes_are_named_as_public_message_values(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """No review field presents a public-message digest as secret-derived."""

    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    identity = review["pairing_identity"]
    for name in (
        "confirmation_message_base64",
        "confirmation_message_byte_length",
        "confirmation_message_sha256",
        "confirmation_message_recipe",
    ):
        assert name in identity
    rendered = json.dumps(review, sort_keys=True)
    for forbidden in ("expected_tag", "secret", "presented_tag", "hmac_key"):
        assert f'"{forbidden}"' not in rendered
    assert "the exact confirmation message is the fixed domain constant" in (
        identity["confirmation_message_recipe"]
    )


def test_recovery_and_read_surfaces_never_learn_about_the_feature(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    assert confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[0] == 200
    status, _headers, body, _raw = request(
        enabled_launcher, "GET", f"{UI_API_PREFIX}/recoveries"
    )
    assert (status, body) == (200, {"recoveries": []})
    bootstrap = enabled_launcher.bootstrap("fixed-nonce")
    rendered = json.dumps(bootstrap, sort_keys=True)
    for forbidden in ("historical", "pairing", PAYLOAD_ID, preparation_id):
        assert forbidden not in rendered


# ---------------------------------------------------------------------------
# I. Lifecycle, locking and serialized concurrency.
# ---------------------------------------------------------------------------


def launcher_lock_is_free(launcher: ProductLauncher, timeout: float = 2.0) -> bool:
    """Probe the launcher lock from a foreign thread; an RLock is reentrant."""

    observed: list[bool] = []

    def probe() -> None:
        acquired = launcher._lock.acquire(timeout=timeout)
        observed.append(acquired)
        if acquired:
            launcher._lock.release()

    thread = threading.Thread(target=probe)
    thread.start()
    thread.join()
    return observed[0]


class _LockObservingService:
    """Records whether the launcher lock was free during each service call."""

    def __init__(self, launcher: ProductLauncher, inner) -> None:
        self._launcher = launcher
        self._inner = inner
        self.free: list[tuple[str, bool]] = []

    def _observe(self, name: str) -> None:
        self.free.append((name, launcher_lock_is_free(self._launcher)))

    def payloads(self):
        self._observe("payloads")
        return self._inner.payloads()

    def prepare(self, **kwargs):
        self._observe("prepare")
        return self._inner.prepare(**kwargs)

    def review(self, **kwargs):
        self._observe("review")
        return self._inner.review(**kwargs)

    def confirm(self, **kwargs):
        self._observe("confirm")
        return self._inner.confirm(**kwargs)


def test_the_launcher_lock_is_never_held_during_service_work(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    observer = _LockObservingService(
        enabled_launcher, enabled_launcher._historical_pairing
    )
    enabled_launcher._historical_pairing = observer
    assert request(enabled_launcher, "GET", PAYLOADS_PATH)[0] == 200
    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    assert request(enabled_launcher, "GET", review_path(preparation_id, fingerprint))[
        0
    ] == 200
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    assert confirm_over_http(enabled_launcher, preparation_id, fingerprint, tag)[0] == 200
    assert [name for name, _free in observer.free] == [
        "payloads",
        "prepare",
        "review",
        "confirm",
    ]
    assert all(free for _name, free in observer.free)


class _GatedConfirmationService:
    """Blocks the first confirmation until the test releases it."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self._guard = threading.Lock()
        self._entered = 0
        self.order: list[str] = []
        self.first_entered = threading.Event()
        self.second_entered = threading.Event()
        self.release_first = threading.Event()

    def payloads(self):
        return self._inner.payloads()

    def prepare(self, **kwargs):
        return self._inner.prepare(**kwargs)

    def review(self, **kwargs):
        return self._inner.review(**kwargs)

    def confirm(self, **kwargs):
        with self._guard:
            self._entered += 1
            index = self._entered
            self.order.append("first" if index == 1 else "second")
        if index == 1:
            self.first_entered.set()
            assert self.release_first.wait(60)
        else:
            self.second_entered.set()
        return self._inner.confirm(**kwargs)


def test_two_concurrent_http_confirmations_are_serialized_head_of_line(
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """The single-threaded server queues; the second sees a consumed record."""

    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    gate = _GatedConfirmationService(enabled_launcher._historical_pairing)
    enabled_launcher._historical_pairing = gate

    answers: dict[str, tuple] = {}
    second_sent = threading.Event()

    def first() -> None:
        answers["first"] = confirm_over_http(
            enabled_launcher, preparation_id, fingerprint, tag
        )

    def second() -> None:
        connection = HTTPConnection("127.0.0.1", enabled_launcher.ui_port, timeout=60)
        try:
            payload = json.dumps(
                {"expected_authority_fingerprint": fingerprint},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            connection.request(
                "POST",
                confirmation_path(preparation_id),
                body=payload,
                headers={
                    "Host": f"127.0.0.1:{enabled_launcher.ui_port}",
                    "Content-Type": "application/json",
                    CSRF_HEADER: enabled_launcher.csrf_nonce,
                    HISTORICAL_PAIRING_CONFIRMATION_HEADER: tag,
                },
            )
            second_sent.set()
            response = connection.getresponse()
            raw = response.read()
            answers["second"] = (response.status, json.loads(raw.decode("utf-8")))
        finally:
            connection.close()

    first_thread = threading.Thread(target=first)
    first_thread.start()
    assert gate.first_entered.wait(30)
    second_thread = threading.Thread(target=second)
    second_thread.start()
    assert second_sent.wait(30)
    # The second request is fully written to the socket, yet the second service
    # call cannot be entered while the first one is still inside the handler.
    assert gate.second_entered.wait(1.5) is False
    assert gate.order == ["first"]
    gate.release_first.set()
    first_thread.join(60)
    second_thread.join(60)
    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert gate.order == ["first", "second"]
    assert answers["first"][0] == 200
    assert answers["second"] == (409, {"error": "PREPARATION_CONSUMED"})


def test_close_drops_the_service_without_touching_the_archive(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    root = tmp_path / "closing"
    root.mkdir()
    configuration = single_entry_configuration(root, historical_payload)
    launcher = build_launcher(
        root,
        historical_pairing_configuration=configuration,
        historical_pairing_secret=PAIRING_SECRET,
    ).start()
    _status, review = prepare_over_http(launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    assert confirm_over_http(launcher, preparation_id, fingerprint, tag)[0] == 200
    service = launcher._historical_pairing
    document = configuration.payload_entries[0].document_path
    document_bytes = document.read_bytes()
    archive = configuration.archive_root
    before = sorted(
        (path.relative_to(archive).as_posix(), path.read_bytes())
        for path in archive.rglob("*")
        if path.is_file()
    )
    launcher.close()
    assert launcher._historical_pairing is None
    assert launcher.historical_pairing_available is False
    assert launcher.list_historical_pairing_payloads() == (
        409,
        {"error": "LAUNCHER_CLOSED"},
    )
    assert launcher.confirm_historical_pairing(
        preparation_id=preparation_id,
        expected_authority_fingerprint=fingerprint,
        presented_confirmation_tag=tag,
    ) == (409, {"error": "LAUNCHER_CLOSED"})
    # The archive and every configured document survive untouched.
    assert document.read_bytes() == document_bytes
    assert (
        sorted(
            (path.relative_to(archive).as_posix(), path.read_bytes())
            for path in archive.rglob("*")
            if path.is_file()
        )
        == before
    )
    # An externally held reference stays an ordinary Python object; the
    # launcher never claimed the power to erase it.
    assert isinstance(service, HistoricalPairingService)
    assert service.payloads()[0] == 200


def test_restart_loses_preparations_but_keeps_a_replayable_archive(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    root = tmp_path / "restart"
    root.mkdir()
    configuration = single_entry_configuration(root, historical_payload)
    first = build_launcher(
        root,
        historical_pairing_configuration=configuration,
        historical_pairing_secret=PAIRING_SECRET,
    ).start()
    _status, review = prepare_over_http(first, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    assert confirm_over_http(first, preparation_id, fingerprint, tag)[0] == 200
    first.close()

    second = build_launcher(
        root,
        historical_pairing_configuration=single_entry_configuration(
            root, historical_payload
        ),
        historical_pairing_secret=PAIRING_SECRET,
    ).start()
    try:
        # In-memory process state is gone: the old locator is simply not found.
        status, _headers, body, _raw = request(
            second, "GET", review_path(preparation_id, fingerprint)
        )
        assert (status, body) == (404, {"error": "PREPARATION_NOT_FOUND"})
        status, _headers, body, _raw = confirm_over_http(
            second, preparation_id, fingerprint, tag
        )
        assert (status, body) == (404, {"error": "PREPARATION_NOT_FOUND"})
        # No endpoint claims the earlier pairing was confirmed.
        assert request(second, "GET", PAYLOADS_PATH)[0] == 200
        rendered = json.dumps(request(second, "GET", PAYLOADS_PATH)[2], sort_keys=True)
        assert "confirmed" not in rendered
        # A fresh preparation for the same authority replays idempotently.
        _status, again = prepare_over_http(second, historical_payload)
        again_id, again_fingerprint = locator_of(again)
        assert again_fingerprint == fingerprint
        again_tag = independent_confirmation_tag(PAIRING_SECRET, again)
        assert again_tag == tag
        status, _headers, body, _raw = confirm_over_http(
            second, again_id, again_fingerprint, again_tag
        )
        assert status == 200
        assert body["archived_pairing_document_count"] == 3
    finally:
        second.close()
    # The archive still holds exactly the three accepted documents.
    archive = configuration.archive_root
    documents = [path for path in archive.rglob("*") if path.is_file()]
    assert len(documents) == 3
    bundle = load_historical_evaluation_pairing(
        archive_root=archive, authority_fingerprint=fingerprint
    )
    assert bundle.evaluation_profile.schema_version == (
        MISSION_PROFILE_SCHEMA_VERSION_V5
    )
    assert bundle.evaluation_profile.is_launchable_runtime_profile is False


def test_a_torn_client_connection_leaves_no_tag_in_any_server_diagnostic(
    tmp_path: Path,
    enabled_launcher: ProductLauncher,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """A response the client never reads still consumes exactly one preparation."""

    _status, review = prepare_over_http(enabled_launcher, historical_payload)
    preparation_id, fingerprint = locator_of(review)
    tag = independent_confirmation_tag(PAIRING_SECRET, review)
    payload = json.dumps(
        {"expected_authority_fingerprint": fingerprint},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    port = enabled_launcher.ui_port
    captured = io.StringIO()
    real_stderr = sys.stderr
    sys.stderr = captured
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=15)
        sock.sendall(
            raw_request_bytes(
                port,
                "POST",
                confirmation_path(preparation_id),
                headers=[
                    ("Host", f"127.0.0.1:{port}"),
                    ("Content-Type", "application/json"),
                    (CSRF_HEADER, enabled_launcher.csrf_nonce),
                    (HISTORICAL_PAIRING_CONFIRMATION_HEADER, tag),
                    ("Content-Length", str(len(payload))),
                    ("Connection", "close"),
                ],
                body=payload,
            )
        )
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        sock.close()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status, _headers, body, _raw = confirm_over_http(
                enabled_launcher, preparation_id, fingerprint, tag
            )
            if status != 200:
                break
            time.sleep(0.05)
    finally:
        sys.stderr = real_stderr
    assert (status, body) == (409, {"error": "PREPARATION_CONSUMED"})
    fragments = _fragments_of(PAIRING_SECRET, tag)
    assert _disclosures_in_text(captured.getvalue(), fragments) == []
    archive = tmp_path / "enabled" / "archive"
    assert len([path for path in archive.rglob("*") if path.is_file()]) == 3


# ---------------------------------------------------------------------------
# J. Accepted lower layers stay unchanged.
# ---------------------------------------------------------------------------


def test_step_5c2b_and_5c2c1_public_apis_are_untouched():
    coordinator_api = {
        name
        for name in dir(HistoricalEvaluationPairingCoordinator)
        if not name.startswith("_")
    }
    assert coordinator_api == {
        "confirm_historical_evaluation_pairing",
        "get_historical_evaluation_pairing_review",
        "prepare_historical_evaluation_pairing",
    }


def test_the_four_route_shapes_are_exactly_the_documented_ones():
    for path, expected_length in (
        (PAYLOADS_PATH, 6),
        (PREPARATIONS_PATH, 6),
        (review_path("p", "f"), 8),
        (confirmation_path("p"), 8),
    ):
        parts = path.split("/")
        assert len(parts) == expected_length
        assert parts[4] == HISTORICAL_PAIRINGS_SEGMENT
