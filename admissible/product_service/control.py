"""Single-worker orchestration over the audited G1 and G4A seams.

V1 keeps contracts/control IDs in memory; completed evidence is rediscovered
through G4A after restart. It adds no durable control database.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import secrets, threading
from typing import Callable, Mapping
from admissible.delegated_gate.mission_profile import load_native_mission_profile_document
from admissible.product_launcher import ProductionChildApplication
from admissible.product_read_model import discover_runs, load_run_detail, load_run_summary, render_result_json
from admissible.product_read_model.truth_provider import create_g1_reconstruction_provider
from .models import ControlRun, ControlState, TerminalEvidence, ValidatedContract

class ControlPlaneError(RuntimeError): pass
class UnknownContract(ControlPlaneError): pass
class ContractConsumed(ControlPlaneError): pass
class ActiveRunConflict(ControlPlaneError): pass
class UnknownControlRun(ControlPlaneError): pass
class ResultNotReady(ControlPlaneError): pass
class NoAuthoritativeResult(ControlPlaneError):
    def __init__(self,payload:Mapping[str,object]): self.payload=dict(payload)
_TRANSPORT_SCHEMA_VERSION="admissible_product_service_transport_v1"
_RESULT_TRANSPORT_REDACTIONS=("diagnostics","run_root")
def _now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def _id(): return secrets.token_hex(16)
def _terminal_evidence(root:Path)->TerminalEvidence:
    if not root.is_dir(): return TerminalEvidence.RUN_ROOT_ABSENT
    if not (root/"evidence").is_dir(): return TerminalEvidence.RUN_ROOT_WITHOUT_EVIDENCE_DIRECTORY
    return TerminalEvidence.EVIDENCE_ROOT_PRESENT

def _transport_summary(source: Mapping[str,object])->tuple[dict[str,object],list[str]]:
    transported=dict(source); redactions=[]
    if "run_root" in transported:
        transported.pop("run_root"); redactions.append("run_root")
    return transported,redactions

class ProductControlPlane:
    def __init__(self, *, run_parent: str|Path, source_repository: str|Path,
                 required_source_head: str, executable: str,
                 executable_prefix_args: tuple[str,...]=(), attestation_class: str="package-bin",
                 application: Callable[...,int]|None=None,
                 profile_validator: Callable[[str|Path],object]=load_native_mission_profile_document,
                 truth_provider: object|None=None,
                 detail_loader: Callable[...,object]=load_run_detail,
                 summary_loader: Callable[...,object]=load_run_summary,
                 run_discovery: Callable[...,object]=discover_runs,
                 result_renderer: Callable[[object],Mapping[str,object]]=render_result_json,
                 clock: Callable[[],str]=_now, id_generator: Callable[[],str]=_id):
        self.run_parent=Path(run_parent).resolve(); self.source_repository=Path(source_repository).resolve()
        self.required_source_head=required_source_head; self.executable=executable
        self.executable_prefix_args=tuple(executable_prefix_args); self.attestation_class=attestation_class
        self._application=application if application is not None else ProductionChildApplication(); self._profile_validator=profile_validator
        self._truth_provider=truth_provider if truth_provider is not None else create_g1_reconstruction_provider()
        self._detail_loader=detail_loader; self._summary_loader=summary_loader
        self._run_discovery=run_discovery; self._result_renderer=result_renderer
        self._clock=clock; self._id_generator=id_generator
        self._contracts: dict[str,ValidatedContract]={}; self._runs: dict[str,ControlRun]={}
        self._lock=threading.RLock(); self._worker=ThreadPoolExecutor(max_workers=1,thread_name_prefix="admissible-g2-worker"); self._closed=False; self._futures=[]

    def validate_contract(self, profile_document: str)->dict[str,object]:
        path=Path(profile_document)
        if not path.is_absolute(): raise ValueError("profile document must be absolute")
        profile=self._profile_validator(path); cid=self._id_generator()
        record=ValidatedContract(cid,profile,str(path),self._clock())
        with self._lock:
            if self._closed: raise RuntimeError("closed")
            self._contracts[cid]=record
        return {"contract_id":cid,"control_state":"VALIDATED","execution_started":False,
                "profile_fingerprint":profile.profile_fingerprint,
                "contract_summary":{"schema_version":profile.schema_version,"profile_id":profile.profile_id,
                "run_id":profile.run_id,"session_id":profile.session_id,"gate_id":profile.gate_id,
                "mission_id":profile.mission_id,"workspace_source_kind":profile.effective_workspace_source.kind.value,
                "verification_mode":profile.verification_mode.value}}

    def start_run(self, contract_id: str, owner_authorization: str, owner_authorization_digest: str)->ControlRun:
        with self._lock:
            contract=self._contracts.get(contract_id)
            if contract is None: raise UnknownContract()
            if contract.consumed: raise ContractConsumed()
            if any(r.control_state in {ControlState.QUEUED,ControlState.STARTING,ControlState.RUNNING} for r in self._runs.values()): raise ActiveRunConflict()
            p=contract.profile; rid=self._id_generator(); root=self.run_parent/p.run_id
            run=ControlRun(rid,contract_id,ControlState.QUEUED,p.session_id,str(root),self._clock())
            self._contracts[contract_id]=contract.consumed_copy(); self._runs[rid]=run
            future=self._worker.submit(self._invoke,rid,p,root,contract.profile_document,owner_authorization,owner_authorization_digest)
            self._futures.append(future); return run

    def _transition(self,rid: str,state: ControlState,**changes: object):
        with self._lock:
            cur=self._runs[rid]; allowed={ControlState.QUEUED:{ControlState.STARTING,ControlState.START_FAILED},ControlState.STARTING:{ControlState.RUNNING,ControlState.START_FAILED},ControlState.RUNNING:{ControlState.TERMINAL,ControlState.START_FAILED}}
            if state not in allowed.get(cur.control_state,set()): raise RuntimeError("illegal transition")
            self._runs[rid]=cur.transition(state,**changes)

    def _invoke(self,rid:str,p:object,root:Path,profile_document:str,owner_authorization:str,owner_authorization_digest:str):
        try:
            self._transition(rid,ControlState.STARTING,started_at=self._clock()); self._transition(rid,ControlState.RUNNING)
            return_code=self._application(source_repository=self.source_repository,required_source_head=self.required_source_head,
                run_root=root,run_id=p.run_id,session_id=p.session_id,executable=self.executable,profile_document=profile_document,
                executable_prefix_args=self.executable_prefix_args,model=p.model,timeout_seconds=p.timeout_seconds,
                stdout_byte_limit=p.stdout_byte_limit,stderr_byte_limit=p.stderr_byte_limit,
                attestation_class=self.attestation_class,owner_authorization=owner_authorization,
                owner_authorization_digest=owner_authorization_digest)
            if isinstance(return_code,bool) or not isinstance(return_code,int): raise TypeError("application return must be an integer")
        except Exception as exc:
            self._transition(rid,ControlState.START_FAILED,ended_at=self._clock(),start_error_type=type(exc).__name__,terminal_evidence=_terminal_evidence(root))
        except BaseException as exc:
            self._transition(rid,ControlState.START_FAILED,ended_at=self._clock(),start_error_type=type(exc).__name__,terminal_evidence=_terminal_evidence(root)); raise
        else:self._transition(rid,ControlState.TERMINAL,ended_at=self._clock(),application_return_code=return_code,terminal_evidence=_terminal_evidence(root))
        finally:owner_authorization=""; owner_authorization_digest=""

    def _snapshot(self,rid: str)->ControlRun:
        with self._lock:
            if rid not in self._runs: raise UnknownControlRun()
            return self._runs[rid]
    def status(self,rid: str)->dict[str,object]:
        r=self._snapshot(rid); summary=None; summary_redactions=[]
        if r.run_root and Path(r.run_root).is_dir():
            try:
                source_summary=self._summary_loader(r.run_root,truth_provider=self._truth_provider).to_json()
                summary,summary_redactions=_transport_summary(source_summary)
            except Exception: summary=None
        response={"control_state":r.control_state.value,"control_run_id":r.control_run_id,
                "authoritative_session_id":r.authoritative_session_id,"started_at":r.started_at,"ended_at":r.ended_at,
                "start_error_type":r.start_error_type,"application_return_code":r.application_return_code,
                "terminal_evidence":r.terminal_evidence.value if r.terminal_evidence else None,"product_summary":summary}
        if summary_redactions: response["product_summary_transport_redactions"]=summary_redactions
        return response
    def result(self,rid: str)->dict[str,object]:
        r=self._snapshot(rid)
        if r.control_state not in {ControlState.TERMINAL,ControlState.START_FAILED}: raise ResultNotReady()
        if r.terminal_evidence is TerminalEvidence.RUN_ROOT_ABSENT:
            raise NoAuthoritativeResult({"error":"NO_AUTHORITATIVE_RESULT","control_state":r.control_state.value,
                "application_return_code":r.application_return_code,"terminal_evidence":r.terminal_evidence.value,
                "start_error_type":r.start_error_type})
        payload=dict(self._result_renderer(self._detail_loader(r.run_root,truth_provider=self._truth_provider)))
        for field in _RESULT_TRANSPORT_REDACTIONS: payload.pop(field,None)
        payload["transport_schema_version"]=_TRANSPORT_SCHEMA_VERSION
        payload["transport_redactions"]=list(_RESULT_TRANSPORT_REDACTIONS)
        return payload
    def list_runs(self)->dict[str,object]:
        with self._lock: controls=[self.status(rid) for rid in sorted(self._runs)]
        persisted=[]
        for run in self._run_discovery(self.run_parent).runs:
            try:
                source_item=self._summary_loader(run.run_root,truth_provider=self._truth_provider).to_json()
                item,item_redactions=_transport_summary(source_item)
            except Exception as exc: item={"run_id":run.run_id,"presentation_status":"UNAVAILABLE","error_type":type(exc).__name__}
            else:
                if item_redactions: item["transport_redactions"]=item_redactions
            persisted.append(item)
        persisted.sort(key=lambda x:str(x.get("run_id") or "")); return {"control_runs":controls,"persisted_runs":persisted}
    def close(self):
        with self._lock:
            if self._closed:return
            self._closed=True
        terminator=getattr(self._application,"terminate_active",None)
        if callable(terminator): terminator()
        self._worker.shutdown(wait=True,cancel_futures=False)
def create_product_control_plane(**kwargs: object)->ProductControlPlane: return ProductControlPlane(**kwargs)
