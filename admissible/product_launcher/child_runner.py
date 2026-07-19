"""Child-scoped transport for G1 owner authorization."""
from __future__ import annotations
import argparse, os, re, sys, threading
from pathlib import Path
from typing import Callable, Mapping
from admissible.delegated_gate.native_canary import OWNER_AUTHORIZATION_DIGEST_ENV, run_native_mission_application
from admissible.delegated_gate.native_executor import DEFAULT_ENVIRONMENT_ALLOWLIST
from admissible.managed_process import ManagedProcess, TERMINATION_CANCELLED, TERMINATION_COMPLETED, TERMINATION_HARD_TIMEOUT

MAX_PHRASE_BYTES=64*1024
WRAPPER_ARGUMENT_ERROR=64; WRAPPER_DIGEST_ERROR=65; WRAPPER_STDIN_ERROR=66; WRAPPER_INTERNAL_ERROR=67
_DIGEST=re.compile(r"[0-9a-f]{64}\Z")
class PreexistingDigestConflict(RuntimeError): pass
class ChildWrapperFault(RuntimeError): pass
class ChildProcessCleanupFailed(RuntimeError): pass
def _canonical_digest(value: object)->bool: return isinstance(value,str) and _DIGEST.fullmatch(value) is not None
def _curated_environment(parent: Mapping[str,str],digest: str)->dict[str,str]:
    allowed={name.upper() for name in DEFAULT_ENVIRONMENT_ALLOWLIST}
    child={key:value for key,value in parent.items() if key.upper() in allowed}
    child[OWNER_AUTHORIZATION_DIGEST_ENV]=digest
    return child

class ProductionChildApplication:
    """Canonical launch kwargs plus explicit owner_authorization_digest."""
    def __init__(self,*,process_factory: Callable[...,ManagedProcess]=ManagedProcess):
        self._process_factory=process_factory; self._lock=threading.RLock(); self._active:ManagedProcess|None=None; self._closing=False
    def __call__(self,*,owner_authorization:str,owner_authorization_digest:str,profile_document:str|Path,
                 source_repository:str|Path,required_source_head:str,run_root:str|Path,run_id:str,session_id:str,
                 executable:str,executable_prefix_args:tuple[str,...]=(),model:str|None=None,
                 timeout_seconds:int|None=None,stdout_byte_limit:int|None=None,stderr_byte_limit:int|None=None,
                 attestation_class:str="package-bin",**_unused:object)->int:
        if not _canonical_digest(owner_authorization_digest): raise ValueError("invalid owner authorization digest")
        parent_value=os.environ.get(OWNER_AUTHORIZATION_DIGEST_ENV)
        if parent_value is not None and parent_value!=owner_authorization_digest: raise PreexistingDigestConflict()
        argv=[sys.executable,"-m","admissible.product_launcher.child_runner","--source-repository",str(source_repository),
              "--required-source-head",required_source_head,"--run-root",str(run_root),"--run-id",run_id,
              "--session-id",session_id,"--executable",executable,"--profile-document",str(profile_document),
              "--attestation-class",attestation_class]
        for value in executable_prefix_args: argv.extend(("--executable-prefix-arg",value))
        for flag,value in (("--model",model),("--timeout-seconds",timeout_seconds),("--stdout-byte-limit",stdout_byte_limit),("--stderr-byte-limit",stderr_byte_limit)):
            if value is not None: argv.extend((flag,str(value)))
        environment=_curated_environment(os.environ,owner_authorization_digest)
        proc=self._process_factory(argv,cwd=str(Path(__file__).resolve().parents[2]),env=environment,want_stdin=True,
                                   max_capture_bytes=max(int(stdout_byte_limit or 0),int(stderr_byte_limit or 0),1024))
        try:
            with self._lock:
                if self._closing: raise RuntimeError("launcher closed")
                proc.start(); self._active=proc
            proc.send_stdin(owner_authorization); proc.close_stdin(); code=proc.wait(timeout=float(timeout_seconds or 1))
            result=proc.terminate(reason=TERMINATION_HARD_TIMEOUT) if code is None and proc.poll() is None else proc.finish(reason=TERMINATION_COMPLETED)
            if not result.cleanup_proven: raise ChildProcessCleanupFailed()
            actual=result.exit_code if result.exit_code is not None else code
            if actual in {64,65,66,67} or actual not in {0,1,2}: raise ChildWrapperFault()
            return int(actual)
        finally:
            with self._lock:
                if self._active is proc:self._active=None
            owner_authorization=""; owner_authorization_digest=""
    def terminate_active(self)->None:
        with self._lock: self._closing=True; proc=self._active
        if proc is not None and not proc.terminate(reason=TERMINATION_CANCELLED).cleanup_proven: raise ChildProcessCleanupFailed()

def _parser()->argparse.ArgumentParser:
    parser=argparse.ArgumentParser(add_help=False)
    for name in ("source-repository","required-source-head","run-root","run-id","session-id","executable","profile-document","attestation-class"): parser.add_argument("--"+name,required=True)
    parser.add_argument("--executable-prefix-arg",action="append",default=[]); parser.add_argument("--model")
    for name in ("timeout-seconds","stdout-byte-limit","stderr-byte-limit"): parser.add_argument("--"+name,type=int)
    return parser
def child_main(argv:list[str]|None=None,*,application:Callable[...,int]=run_native_mission_application,stdin:object|None=None,environ:Mapping[str,str]|None=None)->int:
    try: args=_parser().parse_args(argv)
    except SystemExit:return WRAPPER_ARGUMENT_ERROR
    environment=os.environ if environ is None else environ; digest=environment.get(OWNER_AUTHORIZATION_DIGEST_ENV)
    if not _canonical_digest(digest):return WRAPPER_DIGEST_ERROR
    stream=sys.stdin.buffer if stdin is None else stdin; phrase=""
    try:
        raw=stream.read(MAX_PHRASE_BYTES+1)
        if not isinstance(raw,bytes) or len(raw)>MAX_PHRASE_BYTES:return WRAPPER_STDIN_ERROR
        try:phrase=raw.decode("utf-8","strict")
        except UnicodeDecodeError:return WRAPPER_STDIN_ERROR
        try:return int(application(source_repository=args.source_repository,required_source_head=args.required_source_head,
            run_root=args.run_root,run_id=args.run_id,session_id=args.session_id,executable=args.executable,
            profile_document=args.profile_document,executable_prefix_args=tuple(args.executable_prefix_arg),model=args.model,
            timeout_seconds=args.timeout_seconds,stdout_byte_limit=args.stdout_byte_limit,stderr_byte_limit=args.stderr_byte_limit,
            attestation_class=args.attestation_class,owner_authorization=phrase))
        except Exception:return WRAPPER_INTERNAL_ERROR
    finally:phrase=""; digest=""
if __name__=="__main__":sys.exit(child_main())
__all__=["ChildProcessCleanupFailed","ChildWrapperFault","PreexistingDigestConflict","ProductionChildApplication","child_main"]
