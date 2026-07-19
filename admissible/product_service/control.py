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
from admissible.delegated_gate.native_canary import run_native_mission_application
from admissible.product_read_model import discover_runs, load_run_detail, load_run_summary, render_result_json
from admissible.product_read_model.truth_provider import create_g1_reconstruction_provider
from .models import ControlRun, ControlState, ValidatedContract

class ControlPlaneError(RuntimeError): pass
class UnknownContract(ControlPlaneError): pass
class ContractConsumed(ControlPlaneError): pass
class ActiveRunConflict(ControlPlaneError): pass
class UnknownControlRun(ControlPlaneError): pass
class ResultNotReady(ControlPlaneError): pass
def _now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def _id(): return secrets.token_hex(16)

class ProductControlPlane:
    def __init__(self, *, run_parent: str|Path, source_repository: str|Path,
                 required_source_head: str, executable: str,
                 executable_prefix_args: tuple[str,...]=(), attestation_class: str="package-bin",
                 application: Callable[...,int]=run_native_mission_application,
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
        self._application=application; self._profile_validator=profile_validator
        self._truth_provider=truth_provider if truth_provider is not None else create_g1_reconstruction_provider()
        self._detail_loader=detail_loader; self._summary_loader=summary_loader
        self._run_discovery=run_discovery; self._result_renderer=result_renderer
        self._clock=clock; self._id_generator=id_generator
        self._contracts: dict[str,ValidatedContract]={}; self._runs: dict[str,ControlRun]={}
        self._lock=threading.RLock(); self._worker=ThreadPoolExecutor(max_workers=1,thread_name_prefix="admissible-g2-worker"); self._closed=False

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

    def start_run(self, contract_id: str, owner_authorization: str)->ControlRun:
        with self._lock:
            contract=self._contracts.get(contract_id)
            if contract is None: raise UnknownContract()
            if contract.consumed: raise ContractConsumed()
            if any(r.control_state in {ControlState.QUEUED,ControlState.STARTING,ControlState.RUNNING} for r in self._runs.values()): raise ActiveRunConflict()
            p=contract.profile; rid=self._id_generator(); root=self.run_parent/p.run_id
            run=ControlRun(rid,contract_id,ControlState.QUEUED,p.session_id,str(root),self._clock())
            self._contracts[contract_id]=contract.consumed_copy(); self._runs[rid]=run
            self._worker.submit(self._invoke,rid,p,root,owner_authorization); return run

    def _transition(self,rid: str,state: ControlState,**changes: object):
        with self._lock:
            cur=self._runs[rid]; allowed={ControlState.QUEUED:{ControlState.STARTING},ControlState.STARTING:{ControlState.RUNNING,ControlState.START_FAILED},ControlState.RUNNING:{ControlState.TERMINAL,ControlState.START_FAILED}}
            if state not in allowed.get(cur.control_state,set()): raise RuntimeError("illegal transition")
            self._runs[rid]=cur.transition(state,**changes)

    def _invoke(self,rid: str,p: object,root: Path,owner_authorization: str):
        try:
            self._transition(rid,ControlState.STARTING,started_at=self._clock()); self._transition(rid,ControlState.RUNNING)
            self._application(source_repository=self.source_repository,required_source_head=self.required_source_head,
                run_root=root,run_id=p.run_id,session_id=p.session_id,executable=self.executable,profile=p,
                executable_prefix_args=self.executable_prefix_args,model=p.model,timeout_seconds=p.timeout_seconds,
                stdout_byte_limit=p.stdout_byte_limit,stderr_byte_limit=p.stderr_byte_limit,
                attestation_class=self.attestation_class,owner_authorization=owner_authorization)
        except Exception as exc:
            self._transition(rid,ControlState.START_FAILED,ended_at=self._clock(),start_error_type=type(exc).__name__)
        else: self._transition(rid,ControlState.TERMINAL,ended_at=self._clock())
        finally: owner_authorization=""

    def _snapshot(self,rid: str)->ControlRun:
        with self._lock:
            if rid not in self._runs: raise UnknownControlRun()
            return self._runs[rid]
    def status(self,rid: str)->dict[str,object]:
        r=self._snapshot(rid); summary=None
        if r.run_root and Path(r.run_root).is_dir():
            try: summary=self._summary_loader(r.run_root,truth_provider=self._truth_provider).to_json(); summary.pop("run_root",None)
            except Exception: summary=None
        return {"control_state":r.control_state.value,"control_run_id":r.control_run_id,
                "authoritative_session_id":r.authoritative_session_id,"started_at":r.started_at,"ended_at":r.ended_at,
                "start_error_type":r.start_error_type,"product_summary":summary}
    def result(self,rid: str)->dict[str,object]:
        r=self._snapshot(rid)
        if r.control_state not in {ControlState.TERMINAL,ControlState.START_FAILED} or not r.run_root or not Path(r.run_root).is_dir(): raise ResultNotReady()
        payload=dict(self._result_renderer(self._detail_loader(r.run_root,truth_provider=self._truth_provider)))
        payload.pop("run_root",None); payload.pop("diagnostics",None); return payload
    def list_runs(self)->dict[str,object]:
        with self._lock: controls=[self.status(rid) for rid in sorted(self._runs)]
        persisted=[]
        for run in self._run_discovery(self.run_parent).runs:
            try: item=self._summary_loader(run.run_root,truth_provider=self._truth_provider).to_json()
            except Exception as exc: item={"run_id":run.run_id,"presentation_status":"UNAVAILABLE","error_type":type(exc).__name__}
            item.pop("run_root",None); persisted.append(item)
        persisted.sort(key=lambda x:str(x.get("run_id") or "")); return {"control_runs":controls,"persisted_runs":persisted}
    def close(self):
        with self._lock:
            if self._closed:return
            self._closed=True
        self._worker.shutdown(wait=True,cancel_futures=False)
def create_product_control_plane(**kwargs: object)->ProductControlPlane: return ProductControlPlane(**kwargs)
