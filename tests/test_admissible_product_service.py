from __future__ import annotations
from dataclasses import dataclass, field
from http.client import HTTPConnection
import json, sys, threading, time
from pathlib import Path
from types import SimpleNamespace
import pytest
from admissible.product_service import create_loopback_server, create_product_control_plane
from admissible.product_service.control import ActiveRunConflict, ContractConsumed, ProductControlPlane, ResultNotReady
from admissible.product_service.models import ControlState
from admissible.delegated_gate.mission_profile import load_native_mission_profile_document
from admissible.delegated_gate.native_canary import run_native_mission_application
from admissible.product_read_model import discover_runs, load_run_detail, load_run_summary, render_result_json

@dataclass(frozen=True)
class Profile:
    schema_version:str="v2"; profile_id:str="profile"; run_id:str="run-1"; session_id:str="session-1"
    gate_id:str="gate"; mission_id:str="mission"; profile_fingerprint:str="a"*64; model:str="model"
    timeout_seconds:int=10; stdout_byte_limit:int=1000; stderr_byte_limit:int=1000
    effective_workspace_source:object=field(default_factory=lambda:SimpleNamespace(kind=SimpleNamespace(value="EXISTING_LOCAL_GIT_REPOSITORY")))
    verification_mode:object=field(default_factory=lambda:SimpleNamespace(value="OBSERVED_ONLY"))

def plane(tmp_path, **kw):
    values=dict(run_parent=tmp_path/"runs",source_repository=tmp_path/"source",required_source_head="b"*40,
                executable="provider",profile_validator=lambda _p:Profile(),truth_provider=object(),id_generator=iter(["contract","control"]).__next__)
    values.update(kw); return create_product_control_plane(**values)
def wait_state(p,rid,state):
    for _ in range(200):
        got=p.status(rid)["control_state"]
        if got==state:return
        time.sleep(.005)
    raise AssertionError(got)
def request(server,method,path,body=None,headers=None):
    conn=HTTPConnection(server.host,server.port,timeout=3); data=body
    if isinstance(body,dict): data=json.dumps(body).encode()
    conn.request(method,path,body=data,headers=headers or {}); response=conn.getresponse(); raw=response.read(); conn.close()
    return response.status,response.getheaders(),json.loads(raw)
def auth(server,**extra):
    return {"X-Admissible-Control-Token":server.control_token,"Content-Type":"application/json",
            "Host":f"127.0.0.1:{server.port}",**extra}

def test_construction_injection_and_import_safety(tmp_path):
    before={t.name for t in threading.enumerate()}; called=[]
    p=plane(tmp_path,profile_validator=lambda path:(called.append(path),Profile())[1])
    assert {t.name for t in threading.enumerate()}==before
    result=p.validate_contract(str((tmp_path/"profile.json").resolve()))
    assert called and result["execution_started"] is False and result["profile_fingerprint"]=="a"*64
    p.close()

def test_production_defaults_are_canonical_g1_g4a_seams():
    defaults=ProductControlPlane.__init__.__kwdefaults__
    assert defaults["application"] is run_native_mission_application
    assert defaults["profile_validator"] is load_native_mission_profile_document
    assert defaults["detail_loader"] is load_run_detail and defaults["summary_loader"] is load_run_summary
    assert defaults["run_discovery"] is discover_runs and defaults["result_renderer"] is render_result_json

@pytest.mark.parametrize("host",["0.0.0.0","::","localhost","192.168.1.2"])
def test_non_loopback_rejected(tmp_path,host):
    p=plane(tmp_path)
    with pytest.raises(ValueError): create_loopback_server(p,host=host)
    p.close()
def test_loopback_and_port_zero_accepted(tmp_path):
    p=plane(tmp_path); s=create_loopback_server(p,host="127.0.0.1",port=0)
    assert s.host=="127.0.0.1" and s.port>0 and len(s.control_token.encode())>=32; s.stop()

def test_health_and_control_token(tmp_path):
    p=plane(tmp_path); s=create_loopback_server(p).start()
    try:
        status,headers,body=request(s,"GET","/api/v1/health")
        assert (status,body)==(200,{"service":"admissible-product-control-plane","status":"READY","api_version":"v1"})
        assert request(s,"GET","/api/v1/runs")[0]==401
        assert request(s,"GET","/api/v1/runs",headers={"X-Admissible-Control-Token":"wrong"})[0]==401
        status,headers,body=request(s,"GET","/api/v1/runs",headers={"X-Admissible-Control-Token":s.control_token})
        assert status==200 and not any(k.lower()=="access-control-allow-origin" for k,_ in headers)
        assert s.control_token not in json.dumps(body)
    finally:s.stop()

def test_host_origin_and_json_safety(tmp_path):
    p=plane(tmp_path); s=create_loopback_server(p).start(); url="/api/v1/contracts/validate"; valid={"profile_document":str((tmp_path/"p.json").resolve())}
    try:
        assert request(s,"POST",url,valid,auth(s))[0]==200
        assert request(s,"POST",url,valid,auth(s,Origin=f"http://127.0.0.1:{s.port}"))[0]==200
        assert request(s,"POST",url,valid,auth(s,Origin="https://foreign.invalid"))[0]==403
        assert request(s,"POST",url,valid,{**auth(s),"Host":"localhost"})[0]==403
        assert request(s,"POST",url,b"{}",{**auth(s),"Content-Type":"text/plain"})[0]==415
        assert request(s,"POST",url,b'{"profile_document":"a","profile_document":"b"}',auth(s))[0]==400
        assert request(s,"POST",url,b"{",auth(s))[0]==400
        assert request(s,"POST",url,[],auth(s))[0]==400
        assert request(s,"POST",url,{**valid,"extra":1},auth(s))[0]==400
        assert request(s,"POST",url,b"x"*(1024*1024+1),auth(s))[0]==413
    finally:s.stop()

def test_validation_never_executes_and_rejects_authorization_json(tmp_path):
    calls=[]; p=plane(tmp_path,application=lambda **kw:calls.append(kw))
    response=p.validate_contract(str((tmp_path/"p.json").resolve()))
    assert response["control_state"]=="VALIDATED" and not calls and not (tmp_path/"runs").exists()
    s=create_loopback_server(p).start()
    try:
        body={"profile_document":str((tmp_path/"p.json").resolve()),"owner_authorization":"secret"}
        assert request(s,"POST","/api/v1/contracts/validate",body,auth(s))[0]==400
    finally:s.stop()

def test_transient_authorization_and_terminal_not_succeeded(tmp_path):
    seen=[]
    def app(**kw): seen.append(kw["owner_authorization"]); Path(kw["run_root"]).mkdir(parents=True)
    p=plane(tmp_path,application=app); c=p.validate_contract(str((tmp_path/"p.json").resolve()))
    run=p.start_run(c["contract_id"],"phrase-top-secret"); wait_state(p,run.control_run_id,"TERMINAL")
    assert seen==["phrase-top-secret"] and p.status(run.control_run_id)["control_state"]=="TERMINAL"
    assert "phrase-top-secret" not in repr(p._contracts) and "phrase-top-secret" not in repr(p._runs)
    p.close()

def test_single_active_run_and_exactly_one_invocation(tmp_path):
    entered=threading.Event(); release=threading.Event(); calls=[]
    def app(**kw): calls.append(kw); entered.set(); release.wait(2)
    ids=iter(["c1","r1","c2","r2"]); p=plane(tmp_path,application=app,id_generator=ids.__next__)
    c1=p.validate_contract(str((tmp_path/"1").resolve())); c2=p.validate_contract(str((tmp_path/"2").resolve()))
    first=p.start_run(c1["contract_id"],"one"); assert entered.wait(1)
    with pytest.raises(ActiveRunConflict): p.start_run(c2["contract_id"],"two")
    assert len(calls)==1; release.set(); wait_state(p,first.control_run_id,"TERMINAL"); p.close()

def test_http_start_is_202_and_second_active_is_409(tmp_path):
    entered=threading.Event(); release=threading.Event()
    def app(**_kw): entered.set(); release.wait(2)
    ids=iter(["c1","c2","r1"]); p=plane(tmp_path,application=app,id_generator=ids.__next__)
    c1=p.validate_contract(str((tmp_path/"1").resolve())); c2=p.validate_contract(str((tmp_path/"2").resolve()))
    s=create_loopback_server(p).start()
    try:
        headers=auth(s,**{"X-Admissible-Owner-Authorization":"secret"})
        status,_,body=request(s,"POST","/api/v1/runs",{"contract_id":c1["contract_id"]},headers)
        assert status==202 and body["control_state"] in {"QUEUED","STARTING"} and "product_verdict" not in body
        assert entered.wait(1)
        assert request(s,"POST","/api/v1/runs",{"contract_id":c2["contract_id"]},headers)[0]==409
    finally: release.set(); s.stop()

def test_exception_is_start_failed_type_only(tmp_path):
    def app(**_kw): raise RuntimeError("phrase and provider output")
    p=plane(tmp_path,application=app); c=p.validate_contract(str((tmp_path/"p").resolve())); r=p.start_run(c["contract_id"],"phrase")
    wait_state(p,r.control_run_id,"START_FAILED"); status=p.status(r.control_run_id)
    assert status["start_error_type"]=="RuntimeError" and "phrase" not in json.dumps(status); p.close()

def test_result_uses_detail_and_renderer_and_is_not_ready_early(tmp_path):
    release=threading.Event(); calls=[]
    def app(**kw): Path(kw["run_root"]).mkdir(parents=True); release.wait(2)
    class Summary:
        def to_json(self): return {"run_id":"run-1","run_root":"secret","product_verdict":"UNKNOWN"}
    def detail(root,**kw): calls.append(("detail",root,kw)); return "DETAIL"
    def render(value): calls.append(("render",value)); return {"run_root":"secret","diagnostics":["secret"],"result_admission_state":{"verdict":"INCONSISTENT","source":"AUTHORITATIVE_RECONSTRUCTION"}}
    p=plane(tmp_path,application=app,detail_loader=detail,summary_loader=lambda *a,**k:Summary(),result_renderer=render)
    c=p.validate_contract(str((tmp_path/"p").resolve())); r=p.start_run(c["contract_id"],"x")
    with pytest.raises(ResultNotReady): p.result(r.control_run_id)
    release.set(); wait_state(p,r.control_run_id,"TERMINAL"); result=p.result(r.control_run_id)
    assert result=={"result_admission_state":{"verdict":"INCONSISTENT","source":"AUTHORITATIVE_RECONSTRUCTION"},
                    "transport_schema_version":"admissible_product_service_transport_v1",
                    "transport_redactions":["diagnostics","run_root"]}
    assert [x[0] for x in calls]==["detail","render"]; p.close()

def test_transport_redaction_contract_preserves_g4a_semantics_and_source_mappings(tmp_path):
    source_result={
        "schema_version":"admissible_product_read_model_result_v1",
        "run_root":"C:/private/run", "diagnostics":{"private":"detail"},
        "result_admission_state":{"verdict":"CONSISTENT","source":"AUTHORITATIVE_RECONSTRUCTION"},
        "product_verdict":"PASS", "source_status":"AVAILABLE", "truth_status":"RECONSTRUCTED",
        "consistency_status":"CONSISTENT", "persisted_claims":{"claim":"value"},
        "presentation_status":"AVAILABLE", "future_g4a_field":{"nested":[1,"two"]},
    }
    source_summary={"schema_version":"summary-v1","run_id":"run-1","run_root":"C:/private/run",
                    "product_verdict":"PASS","presentation_status":"AVAILABLE","future_summary_field":17}
    original_result={**source_result,"diagnostics":{"private":"detail"},"result_admission_state":dict(source_result["result_admission_state"]),
                     "persisted_claims":dict(source_result["persisted_claims"]),"future_g4a_field":{"nested":[1,"two"]}}
    original_summary=dict(source_summary)
    release=threading.Event()
    def app(**kw): Path(kw["run_root"]).mkdir(parents=True); release.wait(2)
    class Summary:
        def to_json(self): return source_summary
    p=plane(tmp_path,application=app,summary_loader=lambda *_a,**_k:Summary(),
            detail_loader=lambda *_a,**_k:object(),result_renderer=lambda _detail:source_result)
    c=p.validate_contract(str((tmp_path/"p").resolve())); r=p.start_run(c["contract_id"],"x")
    release.set(); wait_state(p,r.control_run_id,"TERMINAL")
    assert p.result(r.control_run_id)=={
        "schema_version":"admissible_product_read_model_result_v1",
        "result_admission_state":{"verdict":"CONSISTENT","source":"AUTHORITATIVE_RECONSTRUCTION"},
        "product_verdict":"PASS", "source_status":"AVAILABLE", "truth_status":"RECONSTRUCTED",
        "consistency_status":"CONSISTENT", "persisted_claims":{"claim":"value"},
        "presentation_status":"AVAILABLE", "future_g4a_field":{"nested":[1,"two"]},
        "transport_schema_version":"admissible_product_service_transport_v1",
        "transport_redactions":["diagnostics","run_root"],
    }
    assert p.status(r.control_run_id)["product_summary"]=={
        "schema_version":"summary-v1","run_id":"run-1","product_verdict":"PASS",
        "presentation_status":"AVAILABLE","future_summary_field":17}
    assert p.status(r.control_run_id)["product_summary_transport_redactions"]==["run_root"]
    assert source_result==original_result and source_summary==original_summary
    p.close()

def test_status_and_list_summary_redactions_are_adjacent_and_conditional(tmp_path):
    redacted={"run_id":"redacted","run_root":"hidden","product_verdict":"PASS","future":True}
    plain={"run_id":"plain","product_verdict":"UNKNOWN","future":False}
    originals={"redacted":dict(redacted),"plain":dict(plain)}
    class Summary:
        def __init__(self,source): self.source=source
        def to_json(self): return self.source
    runs=(SimpleNamespace(run_id="plain",run_root="plain"),SimpleNamespace(run_id="redacted",run_root="redacted"))
    p=plane(tmp_path,run_discovery=lambda _p:SimpleNamespace(runs=runs),
            summary_loader=lambda root,**_k:Summary(redacted if root=="redacted" else plain))
    assert p.list_runs()["persisted_runs"]==[
        {"run_id":"plain","product_verdict":"UNKNOWN","future":False},
        {"run_id":"redacted","product_verdict":"PASS","future":True,"transport_redactions":["run_root"]},
    ]
    assert redacted==originals["redacted"] and plain==originals["plain"]
    p.close()

def test_status_has_no_summary_redaction_marker_without_product_summary(tmp_path):
    p=plane(tmp_path,application=lambda **_kw:None); c=p.validate_contract(str((tmp_path/"p").resolve()))
    run=p.start_run(c["contract_id"],"x"); wait_state(p,run.control_run_id,"TERMINAL")
    status=p.status(run.control_run_id)
    assert status["product_summary"] is None and "product_summary_transport_redactions" not in status
    p.close()

def test_simultaneous_distinct_contract_starts_are_atomic(tmp_path):
    original_switch_interval=sys.getswitchinterval()
    try:
        sys.setswitchinterval(1e-6)
        for round_number in range(20):
            contender_count=8; barrier=threading.Barrier(contender_count)
            entered=threading.Event(); release=threading.Event(); counter_lock=threading.Lock(); invocation_count=0
            def app(**_kw):
                nonlocal invocation_count
                with counter_lock: invocation_count+=1
                entered.set(); release.wait(5)
            ids=iter([f"contract-{round_number}-{i}" for i in range(contender_count)]+[f"control-{round_number}-{i}" for i in range(contender_count)])
            p=plane(tmp_path/f"round-{round_number}",application=app,id_generator=ids.__next__)
            contracts=[p.validate_contract(str((tmp_path/f"round-{round_number}"/f"profile-{i}").resolve()))["contract_id"] for i in range(contender_count)]
            outcomes=[]; outcome_lock=threading.Lock()
            def contend(contract_id):
                barrier.wait()
                try: outcome=("success",p.start_run(contract_id,"owner-authorization"))
                except ActiveRunConflict as exc: outcome=("conflict",exc)
                except ContractConsumed as exc: outcome=("consumed",exc)
                with outcome_lock: outcomes.append((contract_id,outcome))
            threads=[threading.Thread(target=contend,args=(cid,),name=f"g2-contender-{round_number}-{i}") for i,cid in enumerate(contracts)]
            try:
                for thread in threads: thread.start()
                for thread in threads: thread.join(3)
                assert all(not thread.is_alive() for thread in threads)
                successes=[outcome for _,outcome in outcomes if outcome[0]=="success"]
                conflicts=[outcome for _,outcome in outcomes if outcome[0]=="conflict"]
                consumed=[outcome for _,outcome in outcomes if outcome[0]=="consumed"]
                assert len(successes)==1 and len(conflicts)==7 and len(consumed)==0 and entered.wait(1)
                assert invocation_count==1 and len(p._runs)==1
                assert sum(contract.consumed for contract in p._contracts.values())==1
                winning_contract=successes[0][1].contract_id
                assert sum(not p._contracts[cid].consumed for cid in contracts if cid!=winning_contract)==7
                release.set(); wait_state(p,successes[0][1].control_run_id,"TERMINAL")
                assert p.status(successes[0][1].control_run_id)["control_state"]=="TERMINAL"
            finally:
                release.set()
                for thread in threads: thread.join(1)
                p.close()
            assert all(not thread.is_alive() for thread in threads)
            assert not any(thread.is_alive() and thread.name.startswith("admissible-g2-worker") for thread in threading.enumerate())
    finally:
        sys.setswitchinterval(original_switch_interval)

def test_discovery_is_deterministic_and_malformed_sibling_survives(tmp_path):
    class S:
        def __init__(self,rid): self.rid=rid
        def to_json(self):
            if self.rid=="bad": raise ValueError("bad")
            return {"run_id":self.rid,"run_root":"hidden"}
    runs=(SimpleNamespace(run_id="z",run_root="z"),SimpleNamespace(run_id="bad",run_root="bad"),SimpleNamespace(run_id="a",run_root="a"))
    p=plane(tmp_path,run_discovery=lambda _p:SimpleNamespace(runs=runs),summary_loader=lambda root,**_k:S(root))
    got=p.list_runs()["persisted_runs"]
    assert [x["run_id"] for x in got]==["a","bad","z"] and all("run_root" not in x for x in got)
    assert got[0]["transport_redactions"]==["run_root"] and "transport_redactions" not in got[1] and got[2]["transport_redactions"]==["run_root"]
    p.close()

def test_server_shutdown_releases_port_and_threads(tmp_path):
    before={t.ident for t in threading.enumerate()}; p=plane(tmp_path); s=create_loopback_server(p); port=s.port; s.start(); s.stop()
    assert all(t.ident in before or not t.is_alive() for t in threading.enumerate() if t.name.startswith("admissible-g2"))
    p2=plane(tmp_path); s2=create_loopback_server(p2,port=port); s2.stop()
