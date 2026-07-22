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

from admissible.product_launcher.authoring import (
    AuthoringError,
    GOLDEN_EXACT_CONTRACT_FIELDS,
    author_runtime_contract,
)
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_INTERACTIVE,
    AUTHORIZATION_MODE_PRECOMMITTED,
    GOLDEN_TEMPLATE_ID,
    LauncherConfiguration,
    verify_required_source_head,
)
from admissible.product_launcher.preflight import (
    INTERACTIVE_AUTHORIZATION_NOTICE,
    OWNER_AUTHORIZATION_ENCODING,
    PRECOMMITTED_AUTHORIZATION_NOTICE,
    STATE_BLOCKED,
    STATE_EXPIRED,
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
from admissible.product_launcher.recovery import (
    CLASSIFICATION_REAUTHORIZATION_REQUIRED,
    OWNER_DECISION_AUTHORIZED_RERUN,
    RECOVERY_REASON_BACKEND_DRIFT,
    RECOVERY_STATE_AWAITING_OWNER_AUTHORIZATION,
    RECOVERY_STATE_CHILD_RUN_CREATED,
    RECOVERY_STATE_COMPLETED,
    RECOVERY_STATE_PREPARING,
    RecoveryPersistenceError,
    RecoveryRecord,
    RecoveryStore,
    TERMINAL_CONTROL_STATES,
    classify_recovery,
    emit_recovery_record,
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
    is_launchable_runtime_profile: bool


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
        # Governed backend-drift rerun state. All of it is launcher-resident:
        # pending recoveries survive browser refresh through GET routes but are
        # not claimed to survive launcher restart. The durable write-once
        # recovery record is emitted only at CHILD_RUN_CREATED.
        self._recoveries = RecoveryStore()
        self._launched_runs: dict[str, str] = {}
        self._recovery_creation_lock = threading.Lock()
        self._recoveries_directory = (
            Path(self.configuration.contract_documents_directory) / "recoveries"
        )
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
                    self._recoveries.clear()
                    self._launched_runs.clear()
                    self._g2_token = ""
                    self._csrf_nonce = ""

    def bootstrap(self, csrf_nonce: str) -> dict[str, object]:
        notice = (
            INTERACTIVE_AUTHORIZATION_NOTICE
            if self.authorization_mode == AUTHORIZATION_MODE_INTERACTIVE
            else PRECOMMITTED_AUTHORIZATION_NOTICE
        )
        return {
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "repository_display_path": str(self.configuration.source_repository),
            "required_source_head": self.configuration.required_source_head,
            "authorization_mode": self.authorization_mode,
            "authorization_semantics_notice": notice,
            "owner_authorization_encoding": OWNER_AUTHORIZATION_ENCODING,
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
        launchable = bool(getattr(authored.profile, "is_launchable_runtime_profile", False))
        if launchable:
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
        else:
            # V3 is reviewable here only. It never crosses the runtime document
            # loader, which intentionally remains V2-only.
            contract_id = f"draft-{self._id_generator()}"
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
            is_launchable_runtime_profile=launchable,
        )
        with self._lock:
            self._contracts[contract_id] = record
        response = {
            "contract_id": contract_id,
            "profile_fingerprint": authored.profile_fingerprint,
            "contract_summary": authored.contract_summary,
            "generated_ids": authored.generated_ids,
            "execution_started": False,
            "authorization_mode": self.authorization_mode,
        }
        if not launchable:
            response["runtime_launchable"] = False
        return 200, response

    def enqueue_preparation(self, contract_id: str) -> tuple[int, dict[str, object]]:
        with self._lock:
            if self._closed:
                return 409, {"error": "LAUNCHER_CLOSED"}
            record = self._contracts.get(contract_id)
            if record is None:
                return 404, {"error": "CONTRACT_NOT_FOUND"}
            if not record.is_launchable_runtime_profile:
                return 409, {"error": "CLAIM_AWARE_V3_NOT_LAUNCHABLE"}
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
                authority_timeout_seconds=record.timeout_seconds,
                authority_stdout_byte_limit=record.stdout_byte_limit,
                authority_stderr_byte_limit=record.stderr_byte_limit,
                process_timeout_seconds=self.configuration.preflight_timeout_seconds,
                process_stdout_capture_limit=self.configuration.preflight_stdout_byte_limit,
                process_stderr_capture_limit=self.configuration.preflight_stderr_byte_limit,
                attestation_class=self.configuration.attestation_class,
            )
            state, payload, blocked = consume_ready_preflight(return_code=code, stdout=stdout)
            if state == STATE_READY and payload is not None:
                apply_ready_payload(preparation, payload)
            else:
                preparation.state = state
                # Only a true BLOCKED result carries a blocked summary; protocol
                # mismatches and failures must never be described as BLOCKED.
                preparation.blocked_summary = blocked if state == STATE_BLOCKED else None
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

    def create_recovery(self, parent_control_run_id: str) -> tuple[int, dict[str, object]]:
        """Create (or idempotently return) the governed rerun for one refused parent.

        Server-side truth decides eligibility: the parent control state and the
        authoritative result are re-fetched through the launcher-to-G2 proxy on
        every creation attempt. The browser is never trusted to classify.
        """

        if not isinstance(parent_control_run_id, str) or not parent_control_run_id:
            return 404, {"error": "RUN_NOT_FOUND"}
        # One creation at a time: a concurrent duplicate waits and then receives
        # the identical existing recovery instead of creating a second one.
        with self._recovery_creation_lock:
            with self._lock:
                if self._closed:
                    return 409, {"error": "LAUNCHER_CLOSED"}
            existing = self._recoveries.get_by_parent(parent_control_run_id)
            if existing is not None:
                return 200, self._recovery_view(existing)
            if self._recoveries.is_recovery_child(parent_control_run_id):
                # Maximum recovery depth is one child rerun; a recovery child
                # can never become a recovery parent through this slice.
                return 409, {"error": "RECOVERY_DEPTH_EXCEEDED"}
            status, state_body = self.proxy_g2(
                "GET", f"/api/v1/runs/{parent_control_run_id}"
            )
            if status == 404:
                return 404, {"error": "RUN_NOT_FOUND"}
            if status != 200:
                return 502, {"error": "RECOVERY_PARENT_STATE_UNAVAILABLE"}
            control_state = state_body.get("control_state")
            if control_state not in TERMINAL_CONTROL_STATES:
                return 409, {"error": "RECOVERY_PARENT_NOT_TERMINAL"}
            result_status, result_body = self.proxy_g2(
                "GET", f"/api/v1/runs/{parent_control_run_id}/result"
            )
            if result_status == 409:
                return 409, {"error": "RECOVERY_PARENT_NOT_TERMINAL"}
            if result_status != 200:
                # Includes 410 NO_AUTHORITATIVE_RESULT: without an authoritative
                # result there is no supported recovery class.
                return 409, {"error": "RECOVERY_PARENT_RESULT_UNAVAILABLE"}
            classification = classify_recovery(
                result_body,
                control_state=control_state,
                parent_is_recovery_child=False,
            )
            if classification != CLASSIFICATION_REAUTHORIZATION_REQUIRED:
                return 409, {"error": "RECOVERY_NOT_ELIGIBLE"}
            with self._lock:
                parent_contract_id = self._launched_runs.get(parent_control_run_id)
                parent_record = (
                    self._contracts.get(parent_contract_id) if parent_contract_id else None
                )
            if parent_record is None:
                # The functional template identity comes from the launcher-owned
                # parent contract record; a run launched by another launcher
                # process cannot be imported into this slice.
                return 409, {"error": "RECOVERY_PARENT_CONTRACT_UNKNOWN"}
            template_id = parent_record.contract_summary.get("template_id")
            if template_id != GOLDEN_TEMPLATE_ID:
                return 409, {"error": "RECOVERY_TEMPLATE_UNSUPPORTED"}
            # Fresh child contract: the launcher-owned golden exact fields plus
            # only the allowed owner variables retained from the parent record.
            # No parent contract, preparation, phrase, digest, fingerprint, run
            # or session identity is ever reused.
            child_inputs: dict[str, Any] = {
                field_name: (list(value) if isinstance(value, tuple) else value)
                for field_name, value in GOLDEN_EXACT_CONTRACT_FIELDS.items()
            }
            child_inputs["template_id"] = template_id
            child_inputs["model"] = parent_record.model
            child_inputs["timeout_seconds"] = parent_record.timeout_seconds
            authored_status, authored = self.author_and_validate(child_inputs)
            if authored_status != 200:
                return authored_status, authored
            child_contract_id = authored.get("contract_id")
            if not isinstance(child_contract_id, str) or not child_contract_id:
                return 502, {"error": "G2_VALIDATE_INVALID"}
            # Enforced freshness, never assumed: every child identity must
            # differ from the parent record (contract, fingerprint, and each
            # generated profile/run/session/gate/mission/document ID).
            child_generated = authored.get("generated_ids")
            child_fingerprint = authored.get("profile_fingerprint")
            parent_identity = {parent_record.contract_id, parent_record.profile_fingerprint}
            parent_identity.update(parent_record.generated_ids.values())
            child_identity = {child_contract_id}
            if isinstance(child_fingerprint, str):
                child_identity.add(child_fingerprint)
            if isinstance(child_generated, Mapping):
                child_identity.update(
                    value for value in child_generated.values() if isinstance(value, str)
                )
            if not isinstance(child_generated, Mapping) or parent_identity & child_identity:
                return 409, {"error": "RECOVERY_CHILD_IDENTITY_NOT_FRESH"}
            prep_status, prep = self.enqueue_preparation(child_contract_id)
            if prep_status != 202:
                # No recovery exists yet (e.g. PREFLIGHT_BUSY); the owner may
                # retry, which authors another fresh child contract.
                return prep_status, prep
            authorization = result_body.get("authorization")
            parent_backend_identity = (
                authorization.get("backend_identity")
                if isinstance(authorization, Mapping)
                else None
            )
            session_id = state_body.get("authoritative_session_id")
            record = self._recoveries.create(
                RecoveryRecord(
                    recovery_id=self._id_generator(),
                    parent_control_run_id=parent_control_run_id,
                    parent_session_id=session_id if isinstance(session_id, str) else None,
                    refusal_reason=RECOVERY_REASON_BACKEND_DRIFT,
                    classification=classification,
                    preparation_id=str(prep.get("preparation_id")),
                    created_at=self._clock(),
                    child_contract_id=child_contract_id,
                    parent_backend_identity=(
                        parent_backend_identity
                        if isinstance(parent_backend_identity, str)
                        else None
                    ),
                )
            )
            return 201, self._recovery_view(record)

    def recovery_status(self, recovery_key: str) -> dict[str, object]:
        record = self._recoveries.get(recovery_key)
        if record is None:
            record = self._recoveries.get_by_parent(recovery_key)
        if record is None:
            raise KeyError(recovery_key)
        return self._recovery_view(record)

    def list_recoveries(self) -> dict[str, object]:
        return {
            "recoveries": [self._recovery_view(record) for record in self._recoveries.values()]
        }

    def _recovery_view(self, record: RecoveryRecord) -> dict[str, object]:
        """Secret-safe browser view of one recovery with its truthful state.

        The state is computed from the existing preparation lifecycle and the
        live child control state; preparation BLOCKED/FAILED/EXPIRED terminates
        the recovery through the existing preparation error surface.
        """

        preparation = self._preparations.get(record.preparation_id)
        child_control_state: str | None = None
        if record.child_control_run_id:
            status, body = self.proxy_g2(
                "GET", f"/api/v1/runs/{record.child_control_run_id}"
            )
            if status == 200:
                raw_state = body.get("control_state")
                child_control_state = raw_state if isinstance(raw_state, str) else None
            state = (
                RECOVERY_STATE_COMPLETED
                if child_control_state in TERMINAL_CONTROL_STATES
                else RECOVERY_STATE_CHILD_RUN_CREATED
            )
        elif preparation is None:
            state = STATE_EXPIRED
        elif preparation.state in (STATE_QUEUED, STATE_RUNNING):
            state = RECOVERY_STATE_PREPARING
        elif preparation.state == STATE_READY:
            state = RECOVERY_STATE_AWAITING_OWNER_AUTHORIZATION
        else:
            state = preparation.state
        view: dict[str, object] = record.to_durable_json()
        view["state"] = state
        view["child_contract_id"] = record.child_contract_id
        view["child_control_state"] = child_control_state
        view["parent_backend_identity"] = record.parent_backend_identity
        view["durable_record_written"] = record.durable_record_written
        view["durable_record_error"] = record.durable_record_error
        view["authorization_mode"] = self.authorization_mode
        view["preparation"] = (
            preparation.to_status_dict() if preparation is not None else None
        )
        return view

    def _emit_durable_recovery(self, record: RecoveryRecord) -> None:
        """Write the one durable recovery record; never disturb the 202 launch."""

        try:
            emit_recovery_record(record, directory=self._recoveries_directory)
        except RecoveryPersistenceError as exc:
            record.durable_record_error = exc.error_code
        else:
            record.durable_record_written = True
            record.durable_record_error = None

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
        canonical_payload = None
        preparation = None
        reserved = False
        try:
            # Reservation phase: resolve, verify binding and READY state, and
            # take the one-shot launch reservation atomically under the lock.
            with self._lock:
                if self._closed:
                    return 409, {"error": "LAUNCHER_CLOSED"}
                record = self._contracts.get(contract_id)
                preparation = self._preparations.get(preparation_id)
                if record is None:
                    return 404, {"error": "CONTRACT_NOT_FOUND"}
                if not record.is_launchable_runtime_profile:
                    return 409, {"error": "CLAIM_AWARE_V3_NOT_LAUNCHABLE"}
                if preparation is None:
                    return 404, {"error": "PREPARATION_NOT_FOUND"}
                if preparation.contract_id != contract_id:
                    return 409, {"error": "PREPARATION_CONTRACT_MISMATCH"}
                if preparation.consumed:
                    return 409, {"error": "PREPARATION_CONSUMED"}
                if preparation.state != STATE_READY or preparation.canonical_payload_bytes is None:
                    return 409, {"error": "PREPARATION_NOT_READY"}
                if preparation.launch_reserved:
                    return 409, {"error": "PREPARATION_IN_USE"}
                preparation.launch_reserved = True
                reserved = True
                canonical_payload = preparation.canonical_payload_bytes
            # The lock is released before phrase validation and the potentially
            # blocking G2 request; the reservation alone serializes this launch.
            if not isinstance(phrase, str) or phrase == "":
                return 400, {"error": "OWNER_AUTHORIZATION_REQUIRED"}
            try:
                phrase.encode(OWNER_AUTHORIZATION_ENCODING, "strict")
            except UnicodeEncodeError:
                # The shared G2 header boundary cannot carry this phrase
                # losslessly; fail before any digest calculation or G2 call.
                return 400, {"error": "OWNER_AUTHORIZATION_ENCODING_UNSUPPORTED"}
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
                    canonical_payload=canonical_payload,
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
                # Exactly one accepted G2 launch consumes the preparation.
                control_run_id = body.get("control_run_id")
                bound_recovery = None
                with self._lock:
                    self._preparations.mark_consumed(preparation_id)
                    if isinstance(control_run_id, str) and control_run_id:
                        # Launcher-resident association only; the parent run
                        # root and evidence are never touched.
                        self._launched_runs[control_run_id] = contract_id
                        recovery = self._recoveries.get_by_child_contract(contract_id)
                        if recovery is not None and recovery.child_control_run_id is None:
                            recovery.child_control_run_id = control_run_id
                            recovery.owner_decision = OWNER_DECISION_AUTHORIZED_RERUN
                            recovery.authorized_at = self._clock()
                            bound_recovery = recovery
                if bound_recovery is not None:
                    self._emit_durable_recovery(bound_recovery)
            return status, body
        finally:
            if reserved:
                # Unconditional release: a non-202 response, local validation
                # error, or proxy exception must never strand the reservation.
                with self._lock:
                    preparation.launch_reserved = False
            phrase = ""
            digest = ""
            forwarded_digest = ""
            canonical_payload = None

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
