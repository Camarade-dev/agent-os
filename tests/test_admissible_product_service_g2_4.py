from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
import os, sys, threading, time
import pytest
from admissible.product_launcher.child_runner import ProductionChildApplication
from admissible.product_service.control import ControlPlaneClosed, NoAuthoritativeResult, ProductControlPlane, ResultNotReady, WorkerSubmissionFailed

DIGEST="a"*64
def _pid_alive(pid):
    if os.name!="nt":
        try: os.kill(pid,0); return True
        except OSError: return False
    import ctypes
    handle=ctypes.windll.kernel32.OpenProcess(0x00100000,False,pid)
    if not handle:return False
    try:return ctypes.windll.kernel32.WaitForSingleObject(handle,0)==0x102
    finally:ctypes.windll.kernel32.CloseHandle(handle)
@dataclass(frozen=True)
class Profile:
    schema_version:str="v2"; profile_id:str="p"; run_id:str="run"; session_id:str="session"; gate_id:str="g"; mission_id:str="m"
    profile_fingerprint:str="b"*64; model:str="model"; timeout_seconds:int=5; stdout_byte_limit:int=1000; stderr_byte_limit:int=1000
    effective_workspace_source:object=field(default_factory=lambda:SimpleNamespace(kind=SimpleNamespace(value="EXISTING_LOCAL_GIT_REPOSITORY")))
    verification_mode:object=field(default_factory=lambda:SimpleNamespace(value="OBSERVED_ONLY"))
def make_plane(tmp_path,app,**kw):
    values=dict(run_parent=tmp_path/"runs",source_repository=tmp_path/"source",required_source_head="c"*40,executable="provider",
                application=app,profile_validator=lambda _p:Profile(),truth_provider=object(),id_generator=iter(["contract","control"]).__next__)
    values.update(kw); return ProductControlPlane(**values)
def terminal(plane,rid):
    for _ in range(300):
        state=plane.status(rid)["control_state"]
        if state in {"TERMINAL","START_FAILED"}: return state
        time.sleep(.005)
    raise AssertionError(state)

@pytest.mark.parametrize(("code","shape"),[(0,"absent"),(1,"partial"),(2,"evidence")])
def test_exact_return_and_structural_terminal_evidence(tmp_path,code,shape):
    def app(**kw):
        root=Path(kw["run_root"])
        if shape!="absent": root.mkdir(parents=True)
        if shape=="evidence": (root/"evidence").mkdir()
        return code
    p=make_plane(tmp_path,app); c=p.validate_contract(str((tmp_path/"profile.json").resolve()))
    r=p.start_run(c["contract_id"],"owner",DIGEST); assert terminal(p,r.control_run_id)=="TERMINAL"
    status=p.status(r.control_run_id)
    expected={"absent":"RUN_ROOT_ABSENT","partial":"RUN_ROOT_WITHOUT_EVIDENCE_DIRECTORY","evidence":"EVIDENCE_ROOT_PRESENT"}[shape]
    assert status["application_return_code"]==code and status["terminal_evidence"]==expected
    assert "product_verdict" not in status
    p.close()

@pytest.mark.parametrize("fault",[RuntimeError,SystemExit,KeyboardInterrupt,GeneratorExit])
def test_faults_are_terminal_and_baseexceptions_propagate(tmp_path,fault):
    def app(**_kw): raise fault("secret text")
    p=make_plane(tmp_path,app); c=p.validate_contract(str((tmp_path/"p").resolve())); r=p.start_run(c["contract_id"],"owner",DIGEST)
    assert terminal(p,r.control_run_id)=="START_FAILED"; status=p.status(r.control_run_id)
    assert status["start_error_type"]==fault.__name__ and status["terminal_evidence"]=="RUN_ROOT_ABSENT"
    assert "secret text" not in repr(status)
    if not issubclass(fault,Exception):
        with pytest.raises(fault): p._futures[-1].result()
    p.close()

def test_result_routing_absent_partial_and_reader_fault(tmp_path):
    release=[]
    def absent(**_kw): return 2
    p=make_plane(tmp_path,absent); c=p.validate_contract(str((tmp_path/"p").resolve())); r=p.start_run(c["contract_id"],"x",DIGEST)
    try: p.result(r.control_run_id)
    except ResultNotReady: pass
    terminal(p,r.control_run_id)
    with pytest.raises(NoAuthoritativeResult) as caught: p.result(r.control_run_id)
    assert caught.value.payload=={"error":"NO_AUTHORITATIVE_RESULT","control_state":"TERMINAL","application_return_code":2,"terminal_evidence":"RUN_ROOT_ABSENT","start_error_type":None}
    p.close()
    def partial(**kw): Path(kw["run_root"]).mkdir(parents=True); return 0
    p=make_plane(tmp_path/"partial",partial,detail_loader=lambda *_a,**_k:"detail",result_renderer=lambda _:{"presentation_status":"INCOMPLETE"})
    c=p.validate_contract(str((tmp_path/"q").resolve())); r=p.start_run(c["contract_id"],"x",DIGEST); terminal(p,r.control_run_id)
    assert p.result(r.control_run_id)["presentation_status"]=="INCOMPLETE"; p._detail_loader=lambda *_a,**_k:(_ for _ in ()).throw(OSError())
    with pytest.raises(OSError):p.result(r.control_run_id)
    p.close()

def test_start_after_close_is_typed_and_non_mutating(tmp_path):
    calls=[]; p=make_plane(tmp_path,lambda **kw:calls.append(kw)); c=p.validate_contract(str((tmp_path/"p").resolve()))
    p.close()
    with pytest.raises(ControlPlaneClosed): p.start_run(c["contract_id"],"owner",DIGEST)
    assert not p._runs and not p._contracts[c["contract_id"]].consumed and not calls and not p._futures

def test_submit_failure_terminalizes_record_with_type_only(tmp_path):
    p=make_plane(tmp_path,lambda **_kw:0); c=p.validate_contract(str((tmp_path/"p").resolve()))
    p._worker.shutdown(wait=True)
    class BrokenExecutor:
        def submit(self,*_a,**_kw): raise OSError("secret output")
        def shutdown(self,**_kw): pass
    p._worker=BrokenExecutor()
    with pytest.raises(WorkerSubmissionFailed): p.start_run(c["contract_id"],"owner",DIGEST)
    status=p.status("control")
    assert status["control_state"]=="START_FAILED" and status["start_error_type"]=="OSError"
    assert status["application_return_code"] is None and "secret output" not in repr(status)
    p.close()

def test_close_start_race_thirty_rounds_has_no_zombie_or_losing_consumption(tmp_path):
    for round_no in range(30):
        calls=[]; p=make_plane(tmp_path/str(round_no),lambda **kw:calls.append(kw))
        c=p.validate_contract(str((tmp_path/f"p-{round_no}").resolve())); barrier=threading.Barrier(3); outcomes=[]
        def start():
            barrier.wait()
            try: outcomes.append(("run",p.start_run(c["contract_id"],"owner",DIGEST).control_run_id))
            except ControlPlaneClosed: outcomes.append(("closed",None))
        def close(): barrier.wait(); p.close(); outcomes.append(("close",None))
        starter=threading.Thread(target=start); closer=threading.Thread(target=close)
        starter.start(); closer.start(); barrier.wait(); starter.join(2); closer.join(2)
        assert not starter.is_alive() and not closer.is_alive()
        p.close(); states=[r.control_state.value for r in p._runs.values()]
        assert all(state in {"TERMINAL","START_FAILED"} for state in states)
        if any(kind=="closed" for kind,_ in outcomes):
            assert not p._runs and not p._contracts[c["contract_id"]].consumed and not calls
        else: assert len(p._runs)==1 and p._contracts[c["contract_id"]].consumed and len(calls)<=1

def test_real_close_cancellation_is_start_failed_without_return_code(tmp_path):
    ready=tmp_path/"child-ready.json"
    child_code=("import json,os,subprocess,sys,time;c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
                "json.dump([os.getpid(),c.pid],open(sys.argv[1],'w'));time.sleep(30)")
    app=ProductionChildApplication(child_argv=(sys.executable,"-c",child_code,str(ready)))
    p=make_plane(tmp_path,app); c=p.validate_contract(str((tmp_path/"p").resolve()))
    run=p.start_run(c["contract_id"],"owner",DIGEST)
    for _ in range(200):
        if app._active is not None and app._active.pid and ready.is_file(): break
        time.sleep(.01)
    assert app._active is not None and app._active.pid and ready.is_file()
    observed_pids=__import__("json").loads(ready.read_text()); assert len(observed_pids)==2 and all(_pid_alive(pid) for pid in observed_pids)
    started=time.monotonic(); p.close(); duration=time.monotonic()-started; p.close()
    status=p.status(run.control_run_id)
    assert duration<7 and status["control_state"]=="START_FAILED"
    assert status["start_error_type"]=="ChildProcessCancelled" and status["application_return_code"] is None
    assert not any(_pid_alive(pid) for pid in observed_pids)
