from __future__ import annotations
from io import BytesIO
from types import SimpleNamespace
import os, sys, threading, time
import pytest
from admissible.delegated_gate.native_canary import OWNER_AUTHORIZATION_DIGEST_ENV
from admissible.product_launcher.child_runner import MAX_PHRASE_BYTES, PreexistingDigestConflict, ProductionChildApplication, WRAPPER_DIGEST_ERROR, WRAPPER_INTERNAL_ERROR, WRAPPER_STDIN_ERROR, child_main

DIGEST="f"*64
ARGS=["--source-repository","source","--required-source-head","a"*40,"--run-root","run","--run-id","rid","--session-id","sid","--executable","provider","--profile-document","profile.json","--attestation-class","package-bin"]
class FakeProcess:
    instances=[]
    def __init__(self,argv,**kw): self.argv=argv; self.kw=kw; self.writes=[]; self.closed=0; self.terminated=0; self.instances.append(self)
    def start(self):pass
    def send_stdin(self,value):self.writes.append(value)
    def close_stdin(self):self.closed+=1
    def wait(self,timeout):return 2
    def poll(self):return 2
    def finish(self,**_kw):return SimpleNamespace(cleanup_proven=True,exit_code=2)
    def terminate(self,**_kw):self.terminated+=1; return SimpleNamespace(cleanup_proven=True,exit_code=2)

def test_phrase_and_digest_have_single_scoped_transports(monkeypatch,tmp_path):
    monkeypatch.delenv(OWNER_AUTHORIZATION_DIGEST_ENV,raising=False); before=dict(os.environ)
    phrase="  Unicode é\nembedded\n"
    app=ProductionChildApplication(process_factory=FakeProcess)
    code=app(owner_authorization=phrase,owner_authorization_digest=DIGEST,profile_document=tmp_path/"p.json",source_repository=tmp_path,
        required_source_head="a"*40,run_root=tmp_path/"run",run_id="rid",session_id="sid",executable="provider",timeout_seconds=2)
    proc=FakeProcess.instances[-1]; assert code==2 and proc.writes==[phrase] and proc.closed==1
    assert phrase not in proc.argv and phrase not in proc.kw["env"].values() and DIGEST not in proc.argv and DIGEST not in proc.writes
    assert proc.kw["env"][OWNER_AUTHORIZATION_DIGEST_ENV]==DIGEST and dict(os.environ)==before
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
        def terminate(self,**_kw): self.terminated+=1; self.stopped.set(); return SimpleNamespace(cleanup_proven=True,exit_code=2)
    app=ProductionChildApplication(process_factory=Blocking); outcome=[]
    kwargs=dict(owner_authorization="x",owner_authorization_digest=DIGEST,profile_document=tmp_path/"p",source_repository=tmp_path,
                required_source_head="a"*40,run_root=tmp_path/"r",run_id="r",session_id="s",executable="p",timeout_seconds=10)
    thread=threading.Thread(target=lambda:outcome.append(app(**kwargs))); thread.start(); assert Blocking.entered.wait(1)
    started=time.monotonic(); app.terminate_active(); app.terminate_active(); thread.join(1)
    assert not thread.is_alive() and time.monotonic()-started<1 and outcome==[2]
