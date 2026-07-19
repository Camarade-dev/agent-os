from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
import time
import pytest
from admissible.product_service.control import NoAuthoritativeResult, ProductControlPlane, ResultNotReady

DIGEST="a"*64
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
