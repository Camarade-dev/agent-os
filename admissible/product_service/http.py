"""Bounded authenticated JSON HTTP transport, exact IPv4 loopback only."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler, HTTPServer
import hmac,json,secrets,threading
from typing import Any,Callable
from urllib.parse import urlsplit
from .control import ActiveRunConflict,ContractConsumed,ProductControlPlane,ResultNotReady,UnknownContract,UnknownControlRun
API_PREFIX="/api/v1"; TOKEN_HEADER="X-Admissible-Control-Token"; OWNER_HEADER="X-Admissible-Owner-Authorization"; MAX_REQUEST_BYTES=1024*1024
def _pairs(pairs: list[tuple[str,Any]]):
    out={}
    for k,v in pairs:
        if k in out: raise ValueError("duplicate")
        out[k]=v
    return out
class _Server(HTTPServer):
    allow_reuse_address=True
    def __init__(self,address,plane,token): self.control_plane=plane; self.control_token=token; super().__init__(address,_Handler)
class _Handler(BaseHTTPRequestHandler):
    server:_Server; protocol_version="HTTP/1.1"
    def log_message(self,*_args): pass
    def _send(self,status,payload):
        body=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
        self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body)))
        self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(body)
    def _error(self,status,code): self._send(status,{"error":code})
    def _auth(self):
        supplied=self.headers.get(TOKEN_HEADER)
        if supplied is None or not hmac.compare_digest(supplied,self.server.control_token): self._error(401,"UNAUTHORIZED"); return False
        return True
    def _origin(self):
        host=f"127.0.0.1:{self.server.server_port}"
        if self.headers.get("Host")!=host: self._error(403,"INVALID_HOST"); return False
        origin=self.headers.get("Origin")
        if origin is not None and origin!=f"http://{host}": self._error(403,"INVALID_ORIGIN"); return False
        return True
    def _json(self,fields):
        if self.headers.get("Content-Type")!="application/json": self._error(415,"JSON_REQUIRED"); return None
        if self.headers.get("Transfer-Encoding") is not None: self._error(400,"UNBOUNDED_BODY"); return None
        raw=self.headers.get("Content-Length")
        try: length=int(raw) if raw is not None else -1
        except ValueError: length=-1
        if length<0: self._error(411,"CONTENT_LENGTH_REQUIRED"); return None
        if length>MAX_REQUEST_BYTES: self._error(413,"BODY_TOO_LARGE"); return None
        try: obj=json.loads(self.rfile.read(length).decode("utf-8"),object_pairs_hook=_pairs)
        except (UnicodeDecodeError,json.JSONDecodeError,ValueError): self._error(400,"INVALID_JSON"); return None
        if not isinstance(obj,dict): self._error(400,"JSON_OBJECT_REQUIRED"); return None
        if set(obj)!=fields: self._error(400,"INVALID_FIELDS"); return None
        return obj
    def do_GET(self):
        path=urlsplit(self.path).path
        if path==API_PREFIX+"/health": self._send(200,{"service":"admissible-product-control-plane","status":"READY","api_version":"v1"}); return
        if not path.startswith(API_PREFIX+"/"): self._error(404,"NOT_FOUND"); return
        if not self._auth(): return
        parts=path.split("/")
        try:
            if path==API_PREFIX+"/runs": self._send(200,self.server.control_plane.list_runs()); return
            if len(parts)==5 and parts[4]: self._send(200,self.server.control_plane.status(parts[4])); return
            if len(parts)==6 and parts[4] and parts[5]=="result": self._send(200,self.server.control_plane.result(parts[4])); return
        except UnknownControlRun: self._error(404,"RUN_NOT_FOUND"); return
        except ResultNotReady: self._error(409,"RESULT_NOT_READY"); return
        except Exception: self._error(500,"READ_UNAVAILABLE"); return
        self._error(404,"NOT_FOUND")
    def do_POST(self):
        path=urlsplit(self.path).path
        if not path.startswith(API_PREFIX+"/"): self._error(404,"NOT_FOUND"); return
        if not self._auth() or not self._origin(): return
        if path==API_PREFIX+"/contracts/validate":
            body=self._json({"profile_document"})
            if body is None:return
            if not isinstance(body["profile_document"],str): self._error(400,"INVALID_PROFILE_DOCUMENT"); return
            try: response=self.server.control_plane.validate_contract(body["profile_document"])
            except Exception: self._error(422,"CONTRACT_INVALID"); return
            self._send(200,response); return
        if path==API_PREFIX+"/runs":
            body=self._json({"contract_id"})
            if body is None:return
            if not isinstance(body["contract_id"],str): self._error(400,"INVALID_CONTRACT_ID"); return
            phrase=self.headers.get(OWNER_HEADER)
            if not phrase: self._error(400,"OWNER_AUTHORIZATION_REQUIRED"); return
            try: run=self.server.control_plane.start_run(body["contract_id"],phrase)
            except UnknownContract: self._error(404,"CONTRACT_NOT_FOUND"); return
            except (ContractConsumed,ActiveRunConflict): self._error(409,"RUN_CONFLICT"); return
            except Exception: self._error(500,"START_UNAVAILABLE"); return
            finally: phrase=""
            self._send(202,{"control_run_id":run.control_run_id,"control_state":run.control_state.value}); return
        self._error(404,"NOT_FOUND")
    def do_PUT(self): self._error(405,"METHOD_NOT_ALLOWED")
    def do_PATCH(self): self._error(405,"METHOD_NOT_ALLOWED")
    def do_DELETE(self): self._error(405,"METHOD_NOT_ALLOWED")
class LoopbackServer:
    def __init__(self,server): self._server=server; self._thread=None
    @property
    def host(self): return "127.0.0.1"
    @property
    def port(self): return self._server.server_port
    @property
    def control_token(self): return self._server.control_token
    def start(self):
        if self._thread is not None: raise RuntimeError("already started")
        self._thread=threading.Thread(target=self._server.serve_forever,name="admissible-g2-http"); self._thread.start(); return self
    def stop(self):
        if self._thread is not None: self._server.shutdown(); self._thread.join(); self._thread=None
        self._server.server_close(); self._server.control_plane.close()
    def __enter__(self): return self.start()
    def __exit__(self,*_args): self.stop()
def create_loopback_server(control_plane:ProductControlPlane,*,host="127.0.0.1",port=0,token_generator:Callable[[int],str]=secrets.token_urlsafe):
    if host!="127.0.0.1": raise ValueError("only exact IPv4 loopback is permitted")
    if isinstance(port,bool) or not isinstance(port,int) or not 0<=port<=65535: raise ValueError("invalid port")
    token=token_generator(32)
    if not isinstance(token,str) or len(token.encode())<32: raise ValueError("token too short")
    return LoopbackServer(_Server((host,port),control_plane,token))
