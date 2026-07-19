from __future__ import annotations
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
import base64, json, os, subprocess, sys, threading, time
import pytest
from admissible.delegated_gate.native_canary import OWNER_AUTHORIZATION_DIGEST_ENV
from admissible.managed_process import TERMINATION_CANCELLED, TERMINATION_CLEANUP_FAILED, TERMINATION_COMPLETED, TERMINATION_HARD_TIMEOUT
from admissible.product_launcher.child_runner import ChildProcessCancelled, ChildProcessCleanupFailed, ChildProcessTimedOut, ChildWrapperFault, MAX_PHRASE_BYTES, PreexistingDigestConflict, ProductionChildApplication, WRAPPER_ARGUMENT_ERROR, WRAPPER_DIGEST_ERROR, WRAPPER_INTERNAL_ERROR, WRAPPER_STDIN_ERROR, child_main

DIGEST="f"*64
ARGS=["--source-repository","source","--required-source-head","a"*40,"--run-root","run","--run-id","rid","--session-id","sid","--executable","provider","--profile-document","profile.json","--attestation-class","package-bin"]
def _pid_alive(pid):
    if os.name!="nt":
        try: os.kill(pid,0); return True
        except OSError: return False
    import ctypes
    handle=ctypes.windll.kernel32.OpenProcess(0x00100000,False,pid)
    if not handle:return False
    try:return ctypes.windll.kernel32.WaitForSingleObject(handle,0)==0x102
    finally:ctypes.windll.kernel32.CloseHandle(handle)
class FakeProcess:
    instances=[]
    def __init__(self,argv,**kw): self.argv=argv; self.kw=kw; self.writes=[]; self.closed=0; self.terminated=0; self.instances.append(self)
    def start(self):pass
    def send_stdin(self,value):self.writes.append(value)
    def close_stdin(self):self.closed+=1
    def wait(self,timeout):return 2
    def poll(self):return 2
    def finish(self,reason=TERMINATION_COMPLETED,**_kw):return SimpleNamespace(cleanup_proven=True,exit_code=2,termination_reason=reason)
    def terminate(self,reason=TERMINATION_CANCELLED,**_kw):self.terminated+=1; return SimpleNamespace(cleanup_proven=True,exit_code=2,termination_reason=reason)

def test_phrase_and_digest_have_single_scoped_transports(monkeypatch,tmp_path):
    monkeypatch.delenv(OWNER_AUTHORIZATION_DIGEST_ENV,raising=False); before=dict(os.environ)
    phrase="  Unicode é\nembedded\n"
    app=ProductionChildApplication(process_factory=FakeProcess)
    code=app(owner_authorization=phrase,owner_authorization_digest=DIGEST,profile_document=tmp_path/"p.json",source_repository=tmp_path,
        required_source_head="a"*40,run_root=tmp_path/"run",run_id="rid",session_id="sid",executable="provider",timeout_seconds=2)
    proc=FakeProcess.instances[-1]; assert code==2 and proc.writes==[phrase] and proc.closed==1
    assert phrase not in proc.argv and phrase not in proc.kw["env"].values() and DIGEST not in proc.argv and DIGEST not in proc.writes
    assert proc.kw["env"][OWNER_AUTHORIZATION_DIGEST_ENV]==DIGEST and dict(os.environ)==before
    assert proc.kw["env"]["PYTHONDONTWRITEBYTECODE"]=="1"
    assert proc.argv[:3]==[sys.executable,"-m","admissible.product_launcher.child_runner"]

def test_parent_digest_match_and_conflict(monkeypatch,tmp_path):
    monkeypatch.setenv(OWNER_AUTHORIZATION_DIGEST_ENV,DIGEST); before=os.environ[OWNER_AUTHORIZATION_DIGEST_ENV]
    app=ProductionChildApplication(process_factory=FakeProcess)
    common=dict(owner_authorization="x",profile_document=tmp_path/"p",source_repository=tmp_path,required_source_head="a"*40,
                run_root=tmp_path/"r",run_id="r",session_id="s",executable="p",timeout_seconds=1)
    assert app(owner_authorization_digest=DIGEST,**common)==2 and os.environ[OWNER_AUTHORIZATION_DIGEST_ENV]==before
    with pytest.raises(PreexistingDigestConflict):app(owner_authorization_digest="e"*64,**common)
    assert os.environ[OWNER_AUTHORIZATION_DIGEST_ENV]==before

def test_child_wrapper_exact_input_and_bounded_fault_codes():
    seen={}
    def application(**kw):seen.update(kw); return 1
    phrase=" x\nü "; assert child_main(ARGS,application=application,stdin=BytesIO(phrase.encode()),environ={OWNER_AUTHORIZATION_DIGEST_ENV:DIGEST})==1
    assert seen["owner_authorization"]==phrase
    assert child_main(ARGS,stdin=BytesIO(b"x"),environ={})==WRAPPER_DIGEST_ERROR
    assert child_main(ARGS,stdin=BytesIO(b"\xff"),environ={OWNER_AUTHORIZATION_DIGEST_ENV:DIGEST})==WRAPPER_STDIN_ERROR
    assert child_main(ARGS,stdin=BytesIO(b"x"*(MAX_PHRASE_BYTES+1)),environ={OWNER_AUTHORIZATION_DIGEST_ENV:DIGEST})==WRAPPER_STDIN_ERROR
    assert child_main(ARGS,application=lambda **_kw:(_ for _ in ()).throw(RuntimeError("secret")),stdin=BytesIO(b"secret"),environ={OWNER_AUTHORIZATION_DIGEST_ENV:DIGEST})==WRAPPER_INTERNAL_ERROR

def test_active_child_termination_is_bounded_and_repeated_close_safe(monkeypatch,tmp_path):
    monkeypatch.delenv(OWNER_AUTHORIZATION_DIGEST_ENV,raising=False)
    class Blocking(FakeProcess):
        entered=threading.Event(); stopped=threading.Event()
        def wait(self,timeout): self.entered.set(); self.stopped.wait(timeout); return 2 if self.stopped.is_set() else None
        def poll(self): return 2 if self.stopped.is_set() else None
        reason=TERMINATION_COMPLETED
        def finish(self,**_kw): return SimpleNamespace(cleanup_proven=True,exit_code=2,termination_reason=self.reason)
        def terminate(self,reason=TERMINATION_CANCELLED,**_kw): self.terminated+=1; self.reason=reason; self.stopped.set(); return SimpleNamespace(cleanup_proven=True,exit_code=1,termination_reason=reason)
    app=ProductionChildApplication(process_factory=Blocking); outcome=[]
    kwargs=dict(owner_authorization="x",owner_authorization_digest=DIGEST,profile_document=tmp_path/"p",source_repository=tmp_path,
                required_source_head="a"*40,run_root=tmp_path/"r",run_id="r",session_id="s",executable="p",timeout_seconds=10)
    def invoke():
        try: outcome.append(app(**kwargs))
        except Exception as exc: outcome.append(type(exc))
    thread=threading.Thread(target=invoke); thread.start(); assert Blocking.entered.wait(1)
    started=time.monotonic(); app.terminate_active(); app.terminate_active(); thread.join(1)
    assert not thread.is_alive() and time.monotonic()-started<1 and outcome==[ChildProcessCancelled]

@pytest.mark.parametrize(("reason","cleanup","code","expected"),[
    (TERMINATION_COMPLETED,True,0,0),(TERMINATION_COMPLETED,True,1,1),(TERMINATION_COMPLETED,True,2,2),
    (TERMINATION_HARD_TIMEOUT,True,1,ChildProcessTimedOut),(TERMINATION_CANCELLED,True,1,ChildProcessCancelled),
    (TERMINATION_CLEANUP_FAILED,False,1,ChildProcessCleanupFailed),(TERMINATION_COMPLETED,True,64,ChildWrapperFault),
    (TERMINATION_COMPLETED,True,9,ChildWrapperFault),
])
def test_termination_reason_dominates_exit_code(tmp_path,reason,cleanup,code,expected):
    class Classified(FakeProcess):
        def wait(self,timeout): return None if reason==TERMINATION_HARD_TIMEOUT else code
        def poll(self): return None if reason==TERMINATION_HARD_TIMEOUT else code
        def finish(self,**_kw): return SimpleNamespace(cleanup_proven=cleanup,exit_code=code,termination_reason=reason)
        def terminate(self,**_kw): return SimpleNamespace(cleanup_proven=cleanup,exit_code=code,termination_reason=reason)
    app=ProductionChildApplication(process_factory=Classified)
    kw=dict(owner_authorization="x",owner_authorization_digest=DIGEST,profile_document=tmp_path/"p",source_repository=tmp_path,
            required_source_head="a"*40,run_root=tmp_path/"r",run_id="r",session_id="s",executable="p",timeout_seconds=1)
    if isinstance(expected,int): assert app(**kw)==expected
    else:
        with pytest.raises(expected): app(**kw)

def test_real_module_entry_wrapper_matrix_has_bounded_empty_output(tmp_path):
    base=[sys.executable,"-m","admissible.product_launcher.child_runner"]
    env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"}
    cases=[(base,b"",env,WRAPPER_ARGUMENT_ERROR),(base+ARGS,b"x",env,WRAPPER_DIGEST_ERROR),
           (base+ARGS,b"\xff",{**env,OWNER_AUTHORIZATION_DIGEST_ENV:DIGEST},WRAPPER_STDIN_ERROR),
           (base+ARGS,b"x"*(MAX_PHRASE_BYTES+1),{**env,OWNER_AUTHORIZATION_DIGEST_ENV:DIGEST},WRAPPER_STDIN_ERROR),
           (base+ARGS,b"secret-marker",{**env,OWNER_AUTHORIZATION_DIGEST_ENV:DIGEST},WRAPPER_INTERNAL_ERROR)]
    for argv,stdin,child_env,expected in cases:
        completed=subprocess.run(argv,input=stdin,capture_output=True,env=child_env,cwd=Path(__file__).parents[1],timeout=5)
        assert completed.returncode==expected and len(completed.stdout)+len(completed.stderr)<4096
        assert b"secret-marker" not in completed.stdout+completed.stderr and DIGEST.encode() not in completed.stdout+completed.stderr

def test_real_managed_process_stdin_environment_and_timeout(tmp_path,monkeypatch):
    monkeypatch.delenv(OWNER_AUTHORIZATION_DIGEST_ENV,raising=False); before=dict(os.environ)
    output=tmp_path/"transport.json"; phrase=" spaces\tCRLF\r\nUnicode é 😀 "
    code=("import base64,json,os,sys; data=sys.stdin.buffer.read(); "
          f"json.dump({{'data':base64.b64encode(data).decode(),'digest':os.environ.get({OWNER_AUTHORIZATION_DIGEST_ENV!r}),"
          "'argv':sys.argv,'env_has_phrase':any(data.decode('utf-8')==v for v in os.environ.values()),"
          "'dontwrite':os.environ.get('PYTHONDONTWRITEBYTECODE')},open(sys.argv[1],'w'))")
    app=ProductionChildApplication(child_argv=(sys.executable,"-c",code,str(output)))
    kw=dict(owner_authorization=phrase,owner_authorization_digest=DIGEST,profile_document=tmp_path/"p",source_repository=tmp_path,
            required_source_head="a"*40,run_root=tmp_path/"r",run_id="r",session_id="s",executable="p",timeout_seconds=3)
    assert app(**kw)==0; observed=json.loads(output.read_text())
    assert base64.b64decode(observed["data"])==phrase.encode() and observed["digest"]==DIGEST
    assert phrase not in observed["argv"] and not observed["env_has_phrase"] and observed["dontwrite"]=="1" and dict(os.environ)==before
    pids=tmp_path/"timeout-pids.json"
    sleeper_code=("import json,os,subprocess,sys,time; c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
                  "json.dump([os.getpid(),c.pid],open(sys.argv[1],'w'));time.sleep(30)")
    sleeper=ProductionChildApplication(child_argv=(sys.executable,"-c",sleeper_code,str(pids)))
    with pytest.raises(ChildProcessTimedOut): sleeper(**{**kw,"owner_authorization":"timeout","timeout_seconds":1})
    observed_pids=json.loads(pids.read_text()); assert len(observed_pids)==2 and all(pid>0 for pid in observed_pids)
    assert not any(_pid_alive(pid) for pid in observed_pids)
    time.sleep(.5)
