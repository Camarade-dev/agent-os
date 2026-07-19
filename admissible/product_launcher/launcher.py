"""One launcher process owning G2, UI transport, authoring, and preflight."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import secrets
import threading
import webbrowser
from typing import Any, Callable, Mapping

from admissible.product_launcher.authoring import AuthoringError, author_runtime_contract
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_INTERACTIVE,
    AUTHORIZATION_MODE_PRECOMMITTED,
    LauncherConfiguration,
    verify_required_source_head,
)
from admissible.product_launcher.preflight import (
    STATE_FAILED,
    STATE_QUEUED,
    STATE_READY,
    STATE_RUNNING,
    AuthorizationPreparation,
    PreparationStore,
    apply_ready_payload,
    compute_interactive_digest,
    consume_ready_preflight,
    require_precommitted_digest,
)
from admissible.product_launcher.preflight_runner import ProductionPreflightApplication
from admissible.product_launcher.ui_transport import (
    DIGEST_HEADER,
    OWNER_HEADER,
    SERVICE_NAME,
    SERVICE_VERSION,
    create_ui_loopback_server,
    proxy_http,
)
from admissible.product_service import create_loopback_server, create_product_control_plane


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class AuthoredContractRecord:
    contract_id: str
    document_path: str
    profile_fingerprint: str
    contract_summary: dict[str, object]
    generated_ids: dict[str, str]
    run_id: str
    session_id: str
    model: str
    timeout_seconds: int
    stdout_byte_limit: int
    stderr_byte_limit: int


class ProductLauncher:
    """Owns control plane, G2 loopback, UI loopback, and ephemeral state."""

    def __init__(
        self,
        configuration: LauncherConfiguration,
        *,
        control_plane: object | None = None,
        g2_server: object | None = None,
        ui_server: object | None = None,
        preflight_application: Callable[..., tuple[int, bytes]] | None = None,
        id_generator: Callable[[], str] | None = None,
        browser_opener: Callable[[str], object] | None = None,
        verify_head: bool = True,
        clock: Callable[[], str] = _now,
    ):
        self.configuration = configuration.validated()
        if verify_head:
            verify_required_source_head(self.configuration)
        self.authorization_mode = self.configuration.authorization_mode
        self._id_generator = id_generator or (lambda: secrets.token_hex(16))
        self._clock = clock
        self._browser_opener = browser_opener or webbrowser.open
        self._preflight_application = (
            preflight_application
            if preflight_application is not None
            else ProductionPreflightApplication()
        )
        self._lock = threading.RLock()
        self._closed = False
        self._browser_opened = False
        self._contracts: dict[str, AuthoredContractRecord] = {}
        self._preparations = PreparationStore(
            max_preparations=self.configuration.max_preparations,
            ttl_seconds=self.configuration.preparation_ttl_seconds,
            clock=clock,
        )
        self._preflight_worker = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="admissible-g2-5-preflight",
        )
        self._active_preflight: str | None = None
        Path(self.configuration.contract_documents_directory).mkdir(parents=True, exist_ok=True)
        Path(self.configuration.run_parent).mkdir(parents=True, exist_ok=True)
        if control_plane is None:
            control_plane = create_product_control_plane(
                run_parent=self.configuration.run_parent,
                source_repository=self.configuration.source_repository,
                required_source_head=self.configuration.required_source_head,
                executable=self.configuration.executable,
                executable_prefix_args=self.configuration.executable_prefix_args,
                attestation_class=self.configuration.attestation_class,
                id_generator=self._id_generator,
            )
        self._control_plane = control_plane
        if g2_server is None:
            g2_server = create_loopback_server(
                control_plane,
                host=self.configuration.g2_bind_host,
                port=self.configuration.g2_bind_port,
            )
        self._g2_server = g2_server
        self._g2_token = g2_server.control_token
        if ui_server is None:
            ui_server = create_ui_loopback_server(
                self,
                host=self.configuration.product_ui_bind_host,
                port=self.configuration.product_ui_bind_port,
            )
        else:
            # Injected servers still need the launcher bound for handlers.
            if hasattr(ui_server, "_server") and hasattr(ui_server._server, "context"):
                ui_server._server.context.launcher = self
        self._ui_server = ui_server
        self._csrf_nonce = ui_server.csrf_nonce
        if hmac_tokens_collide(self._g2_token, self._csrf_nonce):
            raise RuntimeError("G2 token and UI CSRF nonce must be distinct")

    @property
    def g2_port(self) -> int:
        return self._g2_server.port

    @property
    def ui_port(self) -> int:
        return self._ui_server.port

    @property
    def csrf_nonce(self) -> str:
        return self._csrf_nonce

    def start(self) -> "ProductLauncher":
        with self._lock:
            if self._closed:
                raise RuntimeError("launcher closed")
            self._g2_server.start()
            self._ui_server.start()
            if self.configuration.open_browser and not self._browser_opened:
                self._browser_opener(f"http://127.0.0.1:{self._ui_server.port}/")
                self._browser_opened = True
        return self

    def serve_forever(self) -> None:
        stopper = threading.Event()
        try:
            stopper.wait()
        except KeyboardInterrupt:
            return

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._ui_server.stop()
        finally:
            try:
                self._preflight_worker.shutdown(wait=True, cancel_futures=False)
            finally:
                terminator = getattr(self._preflight_application, "terminate_active", None)
                if callable(terminator):
                    try:
                        terminator()
                    except Exception:
                        pass
                try:
                    self._g2_server.stop()
                finally:
                    self._preparations.clear()
                    self._contracts.clear()
                    self._g2_token = ""
                    self._csrf_nonce = ""

    def bootstrap(self, csrf_nonce: str) -> dict[str, object]:
        return {
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "repository_display_path": str(self.configuration.source_repository),
            "required_source_head": self.configuration.required_source_head,
            "authorization_mode": self.authorization_mode,
            "g2_ready": not self._closed,
            "g2_api_version": "v1",
            "csrf_nonce": csrf_nonce,
            "supported_authoring_template_ids": list(self.configuration.template_ids),
            "visual_ui_available": False,
        }

    def author_and_validate(self, inputs: Mapping[str, Any]) -> tuple[int, dict[str, object]]:
        with self._lock:
            if self._closed:
                return 409, {"error": "LAUNCHER_CLOSED"}
            if len(self._contracts) >= self.configuration.max_authored_contracts:
                return 429, {"error": "CONTRACT_CAPACITY"}
        try:
            authored = author_runtime_contract(
                inputs,
                launcher_configuration=self.configuration,
                documents_directory=self.configuration.contract_documents_directory,
                id_generator=self._id_generator,
            )
        except AuthoringError as exc:
            return 400, {"error": "AUTHORING_REJECTED", **exc.to_dict()}
        status, body = self.proxy_g2(
            "POST",
            "/api/v1/contracts/validate",
            body={"profile_document": authored.document_path},
        )
        if status != 200:
            return status, body
        contract_id = body.get("contract_id")
        if not isinstance(contract_id, str):
            return 502, {"error": "G2_VALIDATE_INVALID"}
        record = AuthoredContractRecord(
            contract_id=contract_id,
            document_path=authored.document_path,
            profile_fingerprint=authored.profile_fingerprint,
            contract_summary=authored.contract_summary,
            generated_ids=authored.generated_ids,
            run_id=authored.generated_ids["run_id"],
            session_id=authored.generated_ids["session_id"],
            model=str(getattr(authored.profile, "model")),
            timeout_seconds=int(getattr(authored.profile, "timeout_seconds")),
            stdout_byte_limit=int(getattr(authored.profile, "stdout_byte_limit")),
            stderr_byte_limit=int(getattr(authored.profile, "stderr_byte_limit")),
        )
        with self._lock:
            self._contracts[contract_id] = record
        return 200, {
            "contract_id": contract_id,
            "profile_fingerprint": authored.profile_fingerprint,
            "contract_summary": authored.contract_summary,
            "generated_ids": authored.generated_ids,
            "execution_started": False,
            "authorization_mode": self.authorization_mode,
        }

    def enqueue_preparation(self, contract_id: str) -> tuple[int, dict[str, object]]:
        with self._lock:
            if self._closed:
                return 409, {"error": "LAUNCHER_CLOSED"}
            record = self._contracts.get(contract_id)
            if record is None:
                return 404, {"error": "CONTRACT_NOT_FOUND"}
            if self._active_preflight is not None:
                return 409, {"error": "PREFLIGHT_BUSY"}
            preparation_id = self._id_generator()
            preparation = AuthorizationPreparation(
                preparation_id=preparation_id,
                contract_id=contract_id,
                authorization_mode=self.authorization_mode,
                state=STATE_QUEUED,
                created_at=self._clock(),
            )
            try:
                self._preparations.create(preparation)
            except RuntimeError:
                return 429, {"error": "PREPARATION_CAPACITY"}
            self._active_preflight = preparation_id
            self._preflight_worker.submit(self._run_preflight, preparation_id, record)
        return 202, {"preparation_id": preparation_id, "state": STATE_QUEUED}

    def _run_preflight(self, preparation_id: str, record: AuthoredContractRecord) -> None:
        preparation = self._preparations.get(preparation_id)
        if preparation is None:
            with self._lock:
                if self._active_preflight == preparation_id:
                    self._active_preflight = None
            return
        preparation.state = STATE_RUNNING
        self._preparations.update(preparation)
        future_run_root = Path(self.configuration.run_parent) / record.run_id
        try:
            code, stdout = self._preflight_application(
                profile_document=record.document_path,
                source_repository=self.configuration.source_repository,
                required_source_head=self.configuration.required_source_head,
                run_root=future_run_root,
                run_id=record.run_id,
                session_id=record.session_id,
                executable=self.configuration.executable,
                executable_prefix_args=self.configuration.executable_prefix_args,
                model=record.model,
                timeout_seconds=self.configuration.preflight_timeout_seconds,
                stdout_byte_limit=self.configuration.preflight_stdout_byte_limit,
                stderr_byte_limit=self.configuration.preflight_stderr_byte_limit,
                attestation_class=self.configuration.attestation_class,
            )
            state, payload, blocked = consume_ready_preflight(return_code=code, stdout=stdout)
            if state == STATE_READY and payload is not None:
                apply_ready_payload(preparation, payload)
            else:
                preparation.state = state
                preparation.blocked_summary = blocked
                preparation.error_type = None if blocked is None else str(blocked.get("error_type"))
                preparation.canonical_payload_bytes = None
            self._preparations.update(preparation)
        except Exception as exc:
            preparation.state = STATE_FAILED
            preparation.error_type = type(exc).__name__
            preparation.canonical_payload_bytes = None
            self._preparations.update(preparation)
        finally:
            with self._lock:
                if self._active_preflight == preparation_id:
                    self._active_preflight = None

    def preparation_status(self, preparation_id: str) -> dict[str, object]:
        preparation = self._preparations.get(preparation_id)
        if preparation is None:
            raise KeyError(preparation_id)
        return preparation.to_status_dict()

    def launch_run(
        self,
        *,
        contract_id: str,
        preparation_id: str,
        owner_authorization: str | None,
        owner_authorization_digest: str | None,
    ) -> tuple[int, dict[str, object]]:
        phrase = owner_authorization
        digest = owner_authorization_digest
        forwarded_digest = ""
        try:
            with self._lock:
                if self._closed:
                    return 409, {"error": "LAUNCHER_CLOSED"}
                record = self._contracts.get(contract_id)
                preparation = self._preparations.get(preparation_id)
                if record is None:
                    return 404, {"error": "CONTRACT_NOT_FOUND"}
                if preparation is None:
                    return 404, {"error": "PREPARATION_NOT_FOUND"}
                if preparation.contract_id != contract_id:
                    return 409, {"error": "PREPARATION_CONTRACT_MISMATCH"}
                if preparation.consumed:
                    return 409, {"error": "PREPARATION_CONSUMED"}
                if preparation.state != STATE_READY or preparation.canonical_payload_bytes is None:
                    return 409, {"error": "PREPARATION_NOT_READY"}
                if not isinstance(phrase, str) or phrase == "":
                    return 400, {"error": "OWNER_AUTHORIZATION_REQUIRED"}
                mode = self.authorization_mode
                if mode == AUTHORIZATION_MODE_PRECOMMITTED:
                    if digest is None:
                        return 400, {"error": "OWNER_AUTHORIZATION_DIGEST_INVALID"}
                    try:
                        forwarded_digest = require_precommitted_digest(digest)
                    except ValueError:
                        return 400, {"error": "OWNER_AUTHORIZATION_DIGEST_INVALID"}
                elif mode == AUTHORIZATION_MODE_INTERACTIVE:
                    if digest is not None:
                        return 400, {"error": "DIGEST_NOT_ACCEPTED_IN_INTERACTIVE_MODE"}
                    forwarded_digest = compute_interactive_digest(
                        phrase=phrase,
                        canonical_payload=preparation.canonical_payload_bytes,
                    )
                else:
                    return 500, {"error": "UNSUPPORTED_AUTHORIZATION_MODE"}
            headers = {
                OWNER_HEADER: phrase,
                DIGEST_HEADER: forwarded_digest,
            }
            status, body = self.proxy_g2(
                "POST",
                "/api/v1/runs",
                body={"contract_id": contract_id},
                extra_headers=headers,
            )
            if status == 202:
                self._preparations.mark_consumed(preparation_id)
            return status, body
        finally:
            phrase = ""
            digest = ""
            forwarded_digest = ""

    def proxy_g2(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        return proxy_http(
            host=self._g2_server.host,
            port=self._g2_server.port,
            method=method,
            path=path,
            token=self._g2_token,
            body=body,
            extra_headers=extra_headers,
        )


def hmac_tokens_collide(left: str, right: str) -> bool:
    if left == right:
        return True
    return False


def create_product_launcher(configuration: LauncherConfiguration, **kwargs: object) -> ProductLauncher:
    return ProductLauncher(configuration, **kwargs)


__all__ = ["AuthoredContractRecord", "ProductLauncher", "create_product_launcher"]
