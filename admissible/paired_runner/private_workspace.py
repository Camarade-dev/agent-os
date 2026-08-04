"""Private per-effect execution view and trusted transactional export.

A live writable bind of the authorized host workspace cannot satisfy the
governing invariant that the effect process never observes a host-backed IPC
endpoint.  A host-visible temporary directory is also insufficient: a same-UID
host process that discovers its path can plant a FIFO there while the effect
runs.

Every effect therefore materialises its writable view onto a tmpfs that exists
only inside a private user+mount namespace helper (``PRIVATE_MOUNTNS_TMPFS``),
retained solely by an open directory descriptor.  After process-domain
quiescence a trusted controller computes a closed change set and exports it
through a durable, race-safe transactional protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
import array
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import time
from typing import Any, Callable, ClassVar, Iterator

from .canonical import Fingerprint, fingerprint, canonical_bytes
from .cgroup_launch import gate_child_before_exec, release_gate
from .observation import (
    M2_PREFIX,
    M2_SCHEMA_VERSION,
    ObservationError,
    _decode_fp,
    _decode_strings,
    _encode_fp,
    _encode_strings,
    _M2Record,
    _require_int,
    _require_text,
    m2_schema_descriptor,
)


SCHEMA_SOURCE_SNAPSHOT_IDENTITY = f"{M2_PREFIX}.source_snapshot_identity"
SCHEMA_PRIVATE_EXECUTION_VIEW_IDENTITY = f"{M2_PREFIX}.private_execution_view_identity"
SCHEMA_PROPOSED_EXPORT_CHANGE_SET = f"{M2_PREFIX}.proposed_export_change_set"
SCHEMA_EXPORT_RESERVATION = f"{M2_PREFIX}.export_reservation"
SCHEMA_EXPORT_RECEIPT = f"{M2_PREFIX}.export_receipt"
SCHEMA_EXPORT_RECONCILIATION = f"{M2_PREFIX}.export_reconciliation"
SCHEMA_TRANSACTIONAL_EXPORT_RESERVATION = f"{M2_PREFIX}.transactional_export_reservation"

EXPORT_OPERATIONS = (
    "CREATE_REGULAR_FILE",
    "UPDATE_REGULAR_FILE",
    "DELETE_REGULAR_FILE",
    "CREATE_DIRECTORY",
    "DELETE_DIRECTORY",
    "CREATE_SYMLINK",
    "UPDATE_SYMLINK",
    "DELETE_SYMLINK",
)

EXPORT_STATES = (
    "RESERVED",
    "APPLIED",
    "REFUSED_SOURCE_MUTATED",
    "REFUSED_UNSUPPORTED_INODE",
    "REFUSED_PARTIAL",
    "REFUSED_CRASH_CLASSIFIABLE",
    "REFUSED_CONCURRENT_MUTATION",
    "REFUSED_AMBIGUOUS",
    "REFUSED_REPLAY",
)

EXPORT_PROTOCOL_VERSION = 1
MAX_EXPORT_ENTRIES = 100_000
MAX_MATERIALIZE_BYTES = 2 * 1024 * 1024 * 1024
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o755
PRIVATE_FILE_MODE = 0o644
MATERIALIZATION_KIND = "PRIVATE_MOUNTNS_TMPFS"
DEFAULT_PRIVATE_TMPFS_SIZE = "2g"

_CLONE_NEWNS = getattr(os, "CLONE_NEWNS", 0x00020000)
_CLONE_NEWUSER = getattr(os, "CLONE_NEWUSER", 0x10000000)
_MS_NOSUID = 2
_MS_NODEV = 4
_MS_REC = 16384
_MS_PRIVATE = 1 << 18


class PrivateWorkspaceError(RuntimeError):
    """The private view or trusted export cannot proceed."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}:{detail}" if detail else code)
        self.code = code
        self.detail = detail


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def _send_framed(sock: socket.socket, payload: dict[str, Any], fds: tuple[int, ...] = ()) -> None:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    header = struct.pack("!I", len(raw))
    # Length header travels alone so SCM_RIGHTS always accompanies the JSON body.
    sock.sendall(header)
    if fds:
        sock.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", list(fds)))])
    else:
        sock.sendall(raw)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        piece = sock.recv(size - len(chunks))
        if not piece:
            raise PrivateWorkspaceError("private_mountns_helper_closed", "short_read")
        chunks.extend(piece)
    return bytes(chunks)


def _recv_framed(sock: socket.socket) -> tuple[dict[str, Any], list[int]]:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length > 1 << 20:
        raise PrivateWorkspaceError("private_mountns_frame_too_large", str(length))
    raw, ancillary, _flags, _address = sock.recvmsg(length, socket.CMSG_SPACE(256))
    if len(raw) < length:
        raw += _recv_exact(sock, length - len(raw))
    fds: list[int] = []
    for level, typ, data in ancillary or ():
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            values = array.array("i")
            values.frombytes(data[: len(data) - (len(data) % values.itemsize)])
            fds.extend(int(value) for value in values)
    return json.loads(raw.decode("utf-8")), fds


def _helper_main(sock: socket.socket, *, size: str) -> None:  # pragma: no cover - child process
    """Mount-namespace helper: private tmpfs + gated launcher spawn service."""

    try:
        try:
            os.unshare(_CLONE_NEWUSER | _CLONE_NEWNS)
        except OSError as error:
            sock.sendall(f"UNSHARE:{error.errno}".encode())
            os._exit(2)
        # Signal the parent to write uid/gid maps (unprivileged userns rule:
        # the mapping writer must be outside the new user namespace).
        sock.sendall(b"READY")
        if sock.recv(4) != b"MAPS":
            os._exit(3)
        libc = _libc()
        libc.mount(b"none", b"/", None, _MS_REC | _MS_PRIVATE, None)
        staging = f"/tmp/.admissible-private-view-{os.getpid()}"
        os.makedirs(staging, mode=PRIVATE_DIR_MODE, exist_ok=True)
        options = f"mode=0755,size={size}".encode()
        if libc.mount(b"tmpfs", staging.encode(), b"tmpfs", _MS_NOSUID | _MS_NODEV, options) != 0:
            sock.sendall(f"MNT:{ctypes.get_errno()}".encode())
            os._exit(4)
        handle = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        sock.sendmsg(
            [b"OKFD" + staging.encode("utf-8")],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [handle]))],
        )
        os.close(handle)
        children: dict[int, dict[str, Any]] = {}
        reaped: dict[int, int] = {}
        while True:
            request, received_fds = _recv_framed(sock)
            op = request.get("op")
            if op == "exit":
                for meta in list(children.values()):
                    try:
                        os.kill(meta["pid"], signal.SIGKILL)
                    except OSError:
                        pass
                    try:
                        os.waitpid(meta["pid"], 0)
                    except OSError:
                        pass
                _send_framed(sock, {"ok": True})
                os._exit(0)
            if op == "spawn":
                argv = [str(item) for item in request["argv"]]
                parent_fds = [int(item) for item in request["parent_fds"]]
                if len(parent_fds) != len(received_fds):
                    _send_framed(sock, {"ok": False, "error": "fd_count_mismatch"})
                    for handle_fd in received_fds:
                        os.close(handle_fd)
                    continue
                remap = {old: new for old, new in zip(parent_fds, received_fds)}
                rewritten: list[str] = []
                for item in argv:
                    if item.isdigit() and int(item) in remap:
                        rewritten.append(str(remap[int(item)]))
                    elif item.startswith("/proc/self/fd/"):
                        old = int(item.rsplit("/", 1)[1])
                        rewritten.append(f"/proc/self/fd/{remap.get(old, old)}")
                    else:
                        rewritten.append(item)
                for index, item in enumerate(rewritten):
                    if item == "--bind-fd" and index + 2 < len(rewritten):
                        rewritten[index] = "--bind"
                        rewritten[index + 1] = staging
                        break
                await_release = bool(request.get("await_release"))
                gate_r, gate_w = os.pipe()
                stdout_r, stdout_w = os.pipe()
                stderr_r, stderr_w = os.pipe()
                pid = os.fork()
                if pid == 0:
                    try:
                        os.close(gate_w)
                        os.close(stdout_r)
                        os.close(stderr_r)
                        os.dup2(stdout_w, 1)
                        os.dup2(stderr_w, 2)
                        os.close(stdout_w)
                        os.close(stderr_w)
                        # stdin from /dev/null
                        null = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                        os.dup2(null, 0)
                        os.close(null)
                        keep = set(received_fds) | {0, 1, 2, gate_r}
                        for fd in range(3, 256):
                            if fd not in keep:
                                try:
                                    os.close(fd)
                                except OSError:
                                    pass
                        if await_release:
                            gate_child_before_exec(gate_r)
                        else:
                            os.close(gate_r)
                        os.execv(rewritten[0], rewritten)
                    except BaseException:
                        os._exit(127)
                os.close(gate_r)
                os.close(stdout_w)
                os.close(stderr_w)
                for handle_fd in received_fds:
                    try:
                        os.close(handle_fd)
                    except OSError:
                        pass
                children[pid] = {"pid": pid, "gate_w": gate_w if await_release else -1}
                if not await_release:
                    try:
                        os.close(gate_w)
                    except OSError:
                        pass
                _send_framed(sock, {"ok": True, "pid": pid, "await_release": await_release}, (stdout_r, stderr_r))
                os.close(stdout_r)
                os.close(stderr_r)
                continue
            if op == "release":
                meta = children.get(int(request["pid"]))
                if meta is None:
                    _send_framed(sock, {"ok": False, "error": "unknown_pid"})
                    continue
                gate_w = meta.get("gate_w", -1)
                if gate_w >= 0:
                    try:
                        release_gate(gate_w)
                    except OSError as error:
                        _send_framed(sock, {"ok": False, "error": str(error.errno)})
                        continue
                    meta["gate_w"] = -1
                _send_framed(sock, {"ok": True})
                continue
            if op == "poll":
                pid = int(request["pid"])
                if pid in reaped:
                    _send_framed(sock, {"ok": True, "returncode": reaped[pid]})
                    continue
                meta = children.get(pid)
                if meta is None:
                    _send_framed(sock, {"ok": False, "error": "unknown_pid"})
                    continue
                result = os.waitpid(meta["pid"], os.WNOHANG)
                if result[0] == 0:
                    _send_framed(sock, {"ok": True, "returncode": None})
                else:
                    code = result[1]
                    if os.WIFEXITED(code):
                        rc = os.WEXITSTATUS(code)
                    elif os.WIFSIGNALED(code):
                        rc = -os.WTERMSIG(code)
                    else:
                        rc = code
                    children.pop(meta["pid"], None)
                    reaped[pid] = rc
                    _send_framed(sock, {"ok": True, "returncode": rc})
                continue
            if op == "wait":
                pid = int(request["pid"])
                if pid in reaped:
                    _send_framed(sock, {"ok": True, "returncode": reaped[pid]})
                    continue
                meta = children.get(pid)
                if meta is None:
                    _send_framed(sock, {"ok": False, "error": "unknown_pid"})
                    continue
                timeout = request.get("timeout_seconds")
                deadline = None if timeout is None else time.monotonic() + float(timeout)
                while True:
                    result = os.waitpid(meta["pid"], os.WNOHANG)
                    if result[0] != 0:
                        code = result[1]
                        if os.WIFEXITED(code):
                            rc = os.WEXITSTATUS(code)
                        elif os.WIFSIGNALED(code):
                            rc = -os.WTERMSIG(code)
                        else:
                            rc = code
                        children.pop(meta["pid"], None)
                        reaped[pid] = rc
                        _send_framed(sock, {"ok": True, "returncode": rc})
                        break
                    if deadline is not None and time.monotonic() >= deadline:
                        _send_framed(sock, {"ok": False, "error": "timeout"})
                        break
                    time.sleep(0.01)
                continue
            if op == "kill":
                pid = int(request["pid"])
                if pid in reaped:
                    _send_framed(sock, {"ok": True})
                    continue
                meta = children.get(pid)
                if meta is None:
                    _send_framed(sock, {"ok": False, "error": "unknown_pid"})
                    continue
                try:
                    os.kill(meta["pid"], int(request.get("signal", signal.SIGKILL)))
                    _send_framed(sock, {"ok": True})
                except OSError as error:
                    _send_framed(sock, {"ok": False, "error": str(error.errno)})
                continue
            _send_framed(sock, {"ok": False, "error": f"unknown_op:{op}"})
    except BaseException as error:
        try:
            import traceback as _tb

            sock.sendall(
                ("ERR:" + "".join(_tb.format_exception(type(error), error, error.__traceback__))).encode(
                    "utf-8", "replace"
                )[:1500]
            )
        except OSError:
            pass
        os._exit(1)


@dataclass
class SpawnedLauncher:
    """Launcher process started inside the private mount namespace."""

    pid: int
    stdout_fd: int
    stderr_fd: int
    _helper: "PrivateMountHelper"
    _awaiting_release: bool = False

    def release(self) -> None:
        if self._awaiting_release:
            self._helper.release(self.pid)
            self._awaiting_release = False

    def poll(self) -> int | None:
        return self._helper.poll(self.pid)

    def wait(self, timeout: float | None = None) -> int:
        return self._helper.wait(self.pid, timeout=timeout)

    def kill(self, sig: int = signal.SIGKILL) -> None:
        self._helper.kill(self.pid, sig)

    def send_signal(self, sig: int) -> None:
        self._helper.kill(self.pid, sig)


class PrivateMountHelper:
    """Long-lived user+mount namespace holding the private tmpfs and spawn service."""

    def __init__(self, pid: int, conn: socket.socket, view_fd: int, staging_path: str) -> None:
        self.pid = pid
        self.conn = conn
        self.view_fd = view_fd
        self.staging_path = staging_path
        self._closed = False

    @classmethod
    def start(cls, *, size: str = DEFAULT_PRIVATE_TMPFS_SIZE) -> "PrivateMountHelper":
        if not hasattr(os, "unshare"):
            raise PrivateWorkspaceError("private_mountns_unavailable", "os.unshare is absent")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            parent.close()
            _helper_main(child, size=size)
            os._exit(0)
        child.close()
        try:
            ready = parent.recv(5)
            if ready != b"READY":
                raise PrivateWorkspaceError(
                    "private_mountns_tmpfs_failed",
                    ready.decode("utf-8", "replace"),
                )
            uid = os.getuid()
            gid = os.getgid()
            Path(f"/proc/{pid}/setgroups").write_text("deny\n", encoding="ascii")
            Path(f"/proc/{pid}/uid_map").write_text(f"{uid} {uid} 1\n", encoding="ascii")
            Path(f"/proc/{pid}/gid_map").write_text(f"{gid} {gid} 1\n", encoding="ascii")
            parent.sendall(b"MAPS")
            msg, anc, _flags, _addr = parent.recvmsg(4096, socket.CMSG_SPACE(4))
            if not msg.startswith(b"OKFD"):
                detail = msg.decode("utf-8", "replace")
                raise PrivateWorkspaceError("private_mountns_tmpfs_failed", detail)
            staging = msg[4:].decode("utf-8")
            fds: list[int] = []
            for level, typ, data in anc:
                if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                    fds.extend(array.array("i", data).tolist())
            if not fds:
                raise PrivateWorkspaceError("private_mountns_tmpfs_failed", "missing-fd")
            return cls(pid, parent, fds[0], staging)
        except BaseException:
            parent.close()
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
            raise

    def spawn(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        pass_fds: tuple[int, ...] = (),
        await_release: bool = False,
    ) -> SpawnedLauncher:
        if self._closed:
            raise PrivateWorkspaceError("private_mountns_helper_closed", "spawn")
        _send_framed(
            self.conn,
            {
                "op": "spawn",
                "argv": list(argv),
                "parent_fds": list(pass_fds),
                "await_release": bool(await_release),
            },
            pass_fds,
        )
        reply, fds = _recv_framed(self.conn)
        if not reply.get("ok"):
            raise PrivateWorkspaceError("private_mountns_spawn_failed", str(reply.get("error")))
        if len(fds) < 2:
            raise PrivateWorkspaceError("private_mountns_spawn_failed", "missing_stdio_fds")
        return SpawnedLauncher(
            pid=int(reply["pid"]),
            stdout_fd=fds[0],
            stderr_fd=fds[1],
            _helper=self,
            _awaiting_release=bool(reply.get("await_release")),
        )

    def release(self, pid: int) -> None:
        _send_framed(self.conn, {"op": "release", "pid": pid})
        reply, _fds = _recv_framed(self.conn)
        if not reply.get("ok"):
            raise PrivateWorkspaceError("private_mountns_release_failed", str(reply.get("error")))

    def poll(self, pid: int) -> int | None:
        _send_framed(self.conn, {"op": "poll", "pid": pid})
        reply, _fds = _recv_framed(self.conn)
        if not reply.get("ok"):
            raise PrivateWorkspaceError("private_mountns_poll_failed", str(reply.get("error")))
        return reply.get("returncode")

    def wait(self, pid: int, timeout: float | None = None) -> int:
        payload: dict[str, Any] = {"op": "wait", "pid": pid}
        if timeout is not None:
            payload["timeout_seconds"] = float(timeout)
        _send_framed(self.conn, payload)
        reply, _fds = _recv_framed(self.conn)
        if not reply.get("ok"):
            if reply.get("error") == "timeout":
                raise TimeoutError("launcher wait timed out")
            raise PrivateWorkspaceError("private_mountns_wait_failed", str(reply.get("error")))
        return int(reply["returncode"])

    def kill(self, pid: int, sig: int = signal.SIGKILL) -> None:
        _send_framed(self.conn, {"op": "kill", "pid": pid, "signal": int(sig)})
        reply, _fds = _recv_framed(self.conn)
        if not reply.get("ok"):
            raise PrivateWorkspaceError("private_mountns_kill_failed", str(reply.get("error")))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            _send_framed(self.conn, {"op": "exit"})
            try:
                _recv_framed(self.conn)
            except Exception:
                pass
        except Exception:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            self.conn.close()
        except OSError:
            pass
        try:
            os.close(self.view_fd)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass


def host_can_pathname_reach(view_fd: int) -> bool:
    """Return True if a same-UID host pathname opens the same inode as view_fd."""

    try:
        info = os.fstat(view_fd)
    except OSError:
        return False
    try:
        path = os.readlink(f"/proc/self/fd/{view_fd}")
    except OSError:
        return False
    if not path or path.startswith("anon_inode:"):
        return False
    try:
        candidate = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        other = os.fstat(candidate)
        # Same path string can name an empty host directory while view_fd names
        # the private tmpfs.  Compare device/inode.
        return other.st_dev == info.st_dev and other.st_ino == info.st_ino
    finally:
        os.close(candidate)


def _entry_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular_file"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISBLK(mode):
        return "block_device"
    if stat.S_ISCHR(mode):
        return "character_device"
    return "other"


def _is_ipc_or_special(kind: str) -> bool:
    return kind in {"socket", "fifo", "block_device", "character_device", "other"}


def _symlink_is_exportable(target: str) -> bool:
    if not target or "\x00" in target:
        return False
    if target.startswith("/") or target.startswith("\\"):
        return False
    parts = Path(target).parts
    return ".." not in parts


def _walk_tree(root_fd: int) -> Iterator[tuple[str, os.stat_result]]:
    stack: list[tuple[int, str]] = [(root_fd, ".")]
    owned: list[int] = []
    try:
        while stack:
            dir_fd, prefix = stack.pop()
            with os.scandir(dir_fd) as entries:
                for entry in entries:
                    relative = entry.name if prefix == "." else f"{prefix}/{entry.name}"
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        raise PrivateWorkspaceError("tree_walk_failed", f"{relative}:{error.errno}") from error
                    yield relative, info
                    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
                        owned.append(child)
                        stack.append((child, relative))
    finally:
        for handle in owned:
            try:
                os.close(handle)
            except OSError:
                pass


def _hash_regular_at(dir_fd: int, name: str) -> tuple[str, int]:
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(handle, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MATERIALIZE_BYTES:
                raise PrivateWorkspaceError("materialize_byte_limit", name)
            digest.update(chunk)
        return digest.hexdigest(), total
    finally:
        os.close(handle)


def _open_parent(root_fd: int, relative: str) -> tuple[int, str]:
    if relative in {"", "."}:
        return os.dup(root_fd), "."
    parts = relative.split("/")
    leaf = parts[-1]
    dir_fd = root_fd
    owned: list[int] = []
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            owned.append(nxt)
            dir_fd = nxt
        result = os.dup(dir_fd)
        return result, leaf
    finally:
        for handle in owned:
            try:
                os.close(handle)
            except OSError:
                pass


def snapshot_tree_identity(root_fd: int) -> tuple[str, int, int, tuple[str, ...]]:
    digest = hashlib.sha256()
    entries = 0
    total_bytes = 0
    specials: list[str] = []
    for relative, info in sorted(_walk_tree(root_fd), key=lambda item: item[0]):
        entries += 1
        if entries > MAX_EXPORT_ENTRIES:
            raise PrivateWorkspaceError("tree_entry_limit", str(entries))
        kind = _entry_kind(info.st_mode)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(kind.encode("utf-8"))
        digest.update(b"\x00")
        if kind == "regular_file":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                sha, size = _hash_regular_at(parent_fd, leaf)
            finally:
                os.close(parent_fd)
            total_bytes += size
            digest.update(sha.encode("ascii"))
            digest.update(b"\x00")
            digest.update(str(size).encode("ascii"))
        elif kind == "symlink":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                target = os.readlink(leaf, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            digest.update(target.encode("utf-8", "surrogateescape"))
        elif kind == "directory":
            digest.update(b"dir")
        else:
            specials.append(f"{kind}:{relative}")
            digest.update(b"special")
        digest.update(b"\n")
    return digest.hexdigest(), entries, total_bytes, tuple(specials)


@dataclass(frozen=True)
class SourceSnapshotIdentity(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_SOURCE_SNAPSHOT_IDENTITY
    LABEL: ClassVar[str] = "source snapshot identity"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "source_root",
        "device",
        "inode",
        "tree_sha256",
        "entry_count",
        "total_regular_file_bytes",
        "special_inode_count",
    )

    source_root: str
    device: int
    inode: int
    tree_sha256: str
    entry_count: int
    total_regular_file_bytes: int
    special_inode_count: int
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "SourceSnapshotIdentity":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.source_root, "source_root", max_bytes=4096)
        _require_text(self.tree_sha256, "tree_sha256", max_bytes=64)
        if len(self.tree_sha256) != 64:
            raise ObservationError("tree_sha256 must be a sha256 hex digest")
        for name in ("device", "inode", "entry_count", "total_regular_file_bytes", "special_inode_count"):
            _require_int(getattr(self, name), name)


@dataclass(frozen=True)
class PrivateExecutionViewIdentity(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_PRIVATE_EXECUTION_VIEW_IDENTITY
    LABEL: ClassVar[str] = "private execution view identity"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "view_root",
        "device",
        "inode",
        "source_snapshot_fingerprint",
        "tree_sha256",
        "entry_count",
        "materialization_kind",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _decode_fp,
    }

    view_root: str
    device: int
    inode: int
    source_snapshot_fingerprint: Fingerprint
    tree_sha256: str
    entry_count: int
    materialization_kind: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "PrivateExecutionViewIdentity":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.view_root, "view_root", max_bytes=4096)
        _require_text(self.tree_sha256, "tree_sha256", max_bytes=64)
        _require_text(self.materialization_kind, "materialization_kind", max_bytes=64)
        self.source_snapshot_fingerprint.validated()
        for name in ("device", "inode", "entry_count"):
            _require_int(getattr(self, name), name)


@dataclass(frozen=True)
class ProposedExportChangeSet(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_PROPOSED_EXPORT_CHANGE_SET
    LABEL: ClassVar[str] = "proposed export change set"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "change_count",
        "operations",
        "paths",
        "change_set_sha256",
        "unsupported_inode_count",
        "unsupported_inodes",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "operations": _encode_strings,
        "paths": _encode_strings,
        "unsupported_inodes": _encode_strings,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "operations": _decode_strings,
        "paths": _decode_strings,
        "unsupported_inodes": _decode_strings,
    }

    change_count: int
    operations: tuple[str, ...]
    paths: tuple[str, ...]
    change_set_sha256: str
    unsupported_inode_count: int
    unsupported_inodes: tuple[str, ...]
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ProposedExportChangeSet":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_int(self.change_count, "change_count")
        _require_int(self.unsupported_inode_count, "unsupported_inode_count")
        _require_text(self.change_set_sha256, "change_set_sha256", max_bytes=64)
        _encode_strings(self.operations)
        _encode_strings(self.paths)
        _encode_strings(self.unsupported_inodes)
        if self.change_count != len(self.operations) or self.change_count != len(self.paths):
            raise ObservationError("change set counts do not agree")
        if self.unsupported_inode_count != len(self.unsupported_inodes):
            raise ObservationError("unsupported inode counts do not agree")
        for operation in self.operations:
            if operation not in EXPORT_OPERATIONS:
                raise ObservationError(f"unsupported export operation {operation}")


@dataclass(frozen=True)
class ExportReservation(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_EXPORT_RESERVATION
    LABEL: ClassVar[str] = "export reservation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "reservation_id",
        "source_snapshot_fingerprint",
        "private_view_fingerprint",
        "change_set_fingerprint",
        "state",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _encode_fp,
        "private_view_fingerprint": _encode_fp,
        "change_set_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _decode_fp,
        "private_view_fingerprint": _decode_fp,
        "change_set_fingerprint": _decode_fp,
    }

    reservation_id: str
    source_snapshot_fingerprint: Fingerprint
    private_view_fingerprint: Fingerprint
    change_set_fingerprint: Fingerprint
    state: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ExportReservation":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.reservation_id, "reservation_id", max_bytes=256)
        _require_text(self.state, "state", max_bytes=64)
        if self.state not in EXPORT_STATES:
            raise ObservationError(f"invalid export state {self.state}")
        self.source_snapshot_fingerprint.validated()
        self.private_view_fingerprint.validated()
        self.change_set_fingerprint.validated()


@dataclass(frozen=True)
class ExportReceipt(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_EXPORT_RECEIPT
    LABEL: ClassVar[str] = "export receipt"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "reservation_id",
        "applied_count",
        "state",
        "refusal_code",
        "change_set_fingerprint",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "change_set_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "change_set_fingerprint": _decode_fp,
    }

    reservation_id: str
    applied_count: int
    state: str
    refusal_code: str
    change_set_fingerprint: Fingerprint
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ExportReceipt":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.reservation_id, "reservation_id", max_bytes=256)
        _require_text(self.state, "state", max_bytes=64)
        _require_text(self.refusal_code, "refusal_code", max_bytes=256)
        _require_int(self.applied_count, "applied_count")
        if self.state not in EXPORT_STATES:
            raise ObservationError(f"invalid export state {self.state}")
        self.change_set_fingerprint.validated()


@dataclass(frozen=True)
class ExportReconciliation(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_EXPORT_RECONCILIATION
    LABEL: ClassVar[str] = "export reconciliation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "reservation_id",
        "verified",
        "state",
        "source_mutated",
        "private_ipc_exported",
        "partial_export",
        "note",
    )

    reservation_id: str
    verified: bool
    state: str
    source_mutated: bool
    private_ipc_exported: bool
    partial_export: bool
    note: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ExportReconciliation":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.reservation_id, "reservation_id", max_bytes=256)
        _require_text(self.state, "state", max_bytes=64)
        _require_text(self.note, "note", max_bytes=2048)
        if self.state not in EXPORT_STATES:
            raise ObservationError(f"invalid export state {self.state}")
        for name in ("verified", "source_mutated", "private_ipc_exported", "partial_export"):
            if not isinstance(getattr(self, name), bool):
                raise ObservationError(f"{name} must be a boolean")


M2_PRIVATE_WORKSPACE_SCHEMAS = {
    record_type.SCHEMA_ID: m2_schema_descriptor(
        record_type.SCHEMA_ID,
        record_type.__name__,
        ("schema_id", "schema_version") + record_type.FIELDS + ("record_fingerprint",),
    )
    for record_type in (
        SourceSnapshotIdentity,
        PrivateExecutionViewIdentity,
        ProposedExportChangeSet,
        ExportReservation,
        ExportReceipt,
        ExportReconciliation,
    )
}
for _descriptor in M2_PRIVATE_WORKSPACE_SCHEMAS.values():
    object.__setattr__(_descriptor, "owning_module", "admissible.paired_runner.private_workspace")


def _materialize_copy_to_fd(source_fd: int, dest_fd: int) -> None:
    for relative, info in _walk_tree(source_fd):
        kind = _entry_kind(info.st_mode)
        if _is_ipc_or_special(kind):
            raise PrivateWorkspaceError("source_contains_special_inode", f"{kind}:{relative}")
        if kind == "directory":
            parent_fd, leaf = _open_parent(dest_fd, relative)
            try:
                os.mkdir(leaf, PRIVATE_DIR_MODE, dir_fd=parent_fd)
            except FileExistsError:
                pass
            finally:
                os.close(parent_fd)
        elif kind == "regular_file":
            src_parent, src_leaf = _open_parent(source_fd, relative)
            try:
                src_handle = os.open(src_leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=src_parent)
            finally:
                os.close(src_parent)
            try:
                dst_parent, dst_leaf = _open_parent(dest_fd, relative)
                try:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
                    dst_handle = os.open(dst_leaf, flags, PRIVATE_FILE_MODE, dir_fd=dst_parent)
                    try:
                        while True:
                            chunk = os.read(src_handle, 1 << 20)
                            if not chunk:
                                break
                            offset = 0
                            while offset < len(chunk):
                                offset += os.write(dst_handle, chunk[offset:])
                        os.fchmod(dst_handle, PRIVATE_FILE_MODE)
                    finally:
                        os.close(dst_handle)
                finally:
                    os.close(dst_parent)
            finally:
                os.close(src_handle)
        elif kind == "symlink":
            src_parent, src_leaf = _open_parent(source_fd, relative)
            try:
                target = os.readlink(src_leaf, dir_fd=src_parent)
            finally:
                os.close(src_parent)
            if not _symlink_is_exportable(target):
                raise PrivateWorkspaceError("source_symlink_not_exportable", relative)
            dst_parent, dst_leaf = _open_parent(dest_fd, relative)
            try:
                os.symlink(target, dst_leaf, dir_fd=dst_parent)
            finally:
                os.close(dst_parent)
        else:
            raise PrivateWorkspaceError("source_contains_special_inode", f"{kind}:{relative}")


@dataclass
class PrivateExecutionView:
    """One private per-effect filesystem view retained by descriptor only."""

    helper: PrivateMountHelper
    source_snapshot: SourceSnapshotIdentity
    view_identity: PrivateExecutionViewIdentity
    _closed: bool = False

    @property
    def view_fd(self) -> int:
        return self.helper.view_fd

    @property
    def view_root(self) -> Path:
        """Helper-internal staging path.  Not a host-reachable mutation target."""

        return Path(self.helper.staging_path)

    @classmethod
    def materialize(cls, source_root: Path, source_fd: int) -> "PrivateExecutionView":
        """Copy the authorized source into a private mount-namespace tmpfs."""

        info = os.fstat(source_fd)
        tree_sha, entry_count, total_bytes, specials = snapshot_tree_identity(source_fd)
        if specials:
            raise PrivateWorkspaceError("source_contains_special_inode", specials[0])
        snapshot = SourceSnapshotIdentity.create(
            source_root=str(Path(os.path.realpath(source_root))),
            device=info.st_dev,
            inode=info.st_ino,
            tree_sha256=tree_sha,
            entry_count=entry_count,
            total_regular_file_bytes=total_bytes,
            special_inode_count=0,
        )
        helper = PrivateMountHelper.start()
        try:
            _materialize_copy_to_fd(source_fd, helper.view_fd)
            view_info = os.fstat(helper.view_fd)
            view_sha, view_entries, _, view_specials = snapshot_tree_identity(helper.view_fd)
            if view_specials:
                raise PrivateWorkspaceError("private_view_contains_special_inode", view_specials[0])
            if view_sha != tree_sha:
                raise PrivateWorkspaceError("private_view_digest_mismatch", f"{view_sha}!={tree_sha}")
            if host_can_pathname_reach(helper.view_fd):
                raise PrivateWorkspaceError("private_view_host_pathname_reachable", helper.staging_path)
            identity = PrivateExecutionViewIdentity.create(
                view_root=helper.staging_path,
                device=view_info.st_dev,
                inode=view_info.st_ino,
                source_snapshot_fingerprint=snapshot.record_fingerprint,
                tree_sha256=view_sha,
                entry_count=view_entries,
                materialization_kind=MATERIALIZATION_KIND,
            )
            return cls(helper=helper, source_snapshot=snapshot, view_identity=identity)
        except BaseException:
            helper.close()
            raise

    def write_file(self, relative: str, data: bytes) -> None:
        parent_fd, leaf = _open_parent(self.view_fd, relative)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            handle = os.open(leaf, flags, PRIVATE_FILE_MODE, dir_fd=parent_fd)
            try:
                offset = 0
                while offset < len(data):
                    offset += os.write(handle, data[offset:])
            finally:
                os.close(handle)
        finally:
            os.close(parent_fd)

    def mkfifo(self, relative: str) -> None:
        parent_fd, leaf = _open_parent(self.view_fd, relative)
        try:
            os.mkfifo(leaf, 0o600, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)

    def host_pathname_reachable(self) -> bool:
        return host_can_pathname_reach(self.view_fd)

    def spawn_launcher(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        pass_fds: tuple[int, ...] = (),
        await_release: bool = False,
    ) -> SpawnedLauncher:
        return self.helper.spawn(argv, pass_fds=pass_fds, await_release=await_release)

    def source_mutated(self, source_fd: int) -> bool:
        tree_sha, _, _, _ = snapshot_tree_identity(source_fd)
        return tree_sha != self.source_snapshot.tree_sha256

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.helper.close()


def _tree_map(root_fd: int) -> dict[str, tuple[str, str | None]]:
    mapping: dict[str, tuple[str, str | None]] = {}
    for relative, info in _walk_tree(root_fd):
        kind = _entry_kind(info.st_mode)
        if kind == "regular_file":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                sha, _ = _hash_regular_at(parent_fd, leaf)
            finally:
                os.close(parent_fd)
            mapping[relative] = (kind, sha)
        elif kind == "symlink":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                target = os.readlink(leaf, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            mapping[relative] = (kind, target)
        elif kind == "directory":
            mapping[relative] = (kind, None)
        else:
            mapping[relative] = (kind, None)
    return mapping


def compute_change_set(*, baseline_fd: int, private_fd: int) -> ProposedExportChangeSet:
    before = _tree_map(baseline_fd)
    after = _tree_map(private_fd)
    operations: list[str] = []
    paths: list[str] = []
    unsupported: list[str] = []

    for relative, (kind, _) in sorted(before.items()):
        if relative in after:
            continue
        if kind == "regular_file":
            operations.append("DELETE_REGULAR_FILE")
        elif kind == "directory":
            operations.append("DELETE_DIRECTORY")
        elif kind == "symlink":
            operations.append("DELETE_SYMLINK")
        else:
            unsupported.append(f"{kind}:{relative}")
            continue
        paths.append(relative)

    for relative, (kind, payload) in sorted(after.items()):
        if _is_ipc_or_special(kind):
            unsupported.append(f"{kind}:{relative}")
            continue
        previous = before.get(relative)
        if previous is None:
            if kind == "regular_file":
                operations.append("CREATE_REGULAR_FILE")
            elif kind == "directory":
                operations.append("CREATE_DIRECTORY")
            elif kind == "symlink":
                if payload is None or not _symlink_is_exportable(payload):
                    unsupported.append(f"symlink:{relative}")
                    continue
                operations.append("CREATE_SYMLINK")
            else:
                unsupported.append(f"{kind}:{relative}")
                continue
            paths.append(relative)
            continue
        prev_kind, prev_payload = previous
        if prev_kind == kind and prev_payload == payload:
            continue
        if kind == "regular_file" and prev_kind == "regular_file":
            operations.append("UPDATE_REGULAR_FILE")
            paths.append(relative)
        elif kind == "symlink" and prev_kind == "symlink":
            if payload is None or not _symlink_is_exportable(payload):
                unsupported.append(f"symlink:{relative}")
                continue
            operations.append("UPDATE_SYMLINK")
            paths.append(relative)
        else:
            unsupported.append(f"type_change:{relative}:{prev_kind}->{kind}")

    digest = hashlib.sha256()
    for operation, path in zip(operations, paths):
        digest.update(operation.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.encode("utf-8"))
        digest.update(b"\n")
    return ProposedExportChangeSet.create(
        change_count=len(operations),
        operations=tuple(operations),
        paths=tuple(paths),
        change_set_sha256=digest.hexdigest(),
        unsupported_inode_count=len(unsupported),
        unsupported_inodes=tuple(unsupported),
    )


def _complete_write(handle: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(handle, data[offset:])
        if written <= 0:
            raise PrivateWorkspaceError("short_write", str(offset))
        offset += written


def _fsync_dir(path: Path) -> None:
    handle = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def _durable_publish_json(directory: Path, name: str, payload: dict[str, Any]) -> Path:
    """No-replace durable publish: temp write, fsync file, linkat EXCL, fsync dir."""

    directory.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    final = directory / name
    if final.exists():
        raise PrivateWorkspaceError("durable_replace_forbidden", name)
    temporary = directory / f".tmp-{os.getpid()}-{name}"
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, FILE_MODE)
    try:
        _complete_write(handle, raw)
        os.fsync(handle)
    finally:
        os.close(handle)
    try:
        os.link(temporary, final)
    except FileExistsError as error:
        raise PrivateWorkspaceError("durable_replace_forbidden", name) from error
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass
    _fsync_dir(directory)
    return final


def _durable_replace_json(directory: Path, name: str, payload: dict[str, Any]) -> Path:
    """Replaceable progress document: write temp, fsync, rename, fsync dir."""

    directory.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temporary = directory / f".tmp-{os.getpid()}-{name}"
    final = directory / name
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, FILE_MODE)
    try:
        _complete_write(handle, raw)
        os.fsync(handle)
    finally:
        os.close(handle)
    os.replace(temporary, final)
    _fsync_dir(directory)
    return final


def _path_state(root_fd: int, relative: str) -> dict[str, Any]:
    try:
        parent_fd, leaf = _open_parent(root_fd, relative)
    except OSError:
        return {"kind": "absent"}
    try:
        try:
            info = os.lstat(leaf, dir_fd=parent_fd)
        except FileNotFoundError:
            return {"kind": "absent"}
        kind = _entry_kind(info.st_mode)
        if kind == "regular_file":
            sha, size = _hash_regular_at(parent_fd, leaf)
            return {"kind": kind, "sha256": sha, "size": size}
        if kind == "symlink":
            return {"kind": kind, "target": os.readlink(leaf, dir_fd=parent_fd)}
        return {"kind": kind}
    finally:
        os.close(parent_fd)


def _build_operation_plan(
    *,
    source_fd: int,
    private_fd: int,
    change_set: ProposedExportChangeSet,
) -> list[dict[str, Any]]:
    before = _tree_map(source_fd)
    after = _tree_map(private_fd)
    plan: list[dict[str, Any]] = []
    paired = list(zip(change_set.operations, change_set.paths))
    deletes = [(op, path) for op, path in paired if op.startswith("DELETE_")]
    others = [(op, path) for op, path in paired if not op.startswith("DELETE_")]
    deletes.sort(key=lambda item: item[1].count("/"), reverse=True)
    others.sort(key=lambda item: item[1].count("/"))
    for index, (operation, relative) in enumerate(deletes + others):
        pre = _path_state(source_fd, relative)
        if operation.startswith("DELETE"):
            post = {"kind": "absent"}
        elif operation in {"CREATE_REGULAR_FILE", "UPDATE_REGULAR_FILE"}:
            payload = after.get(relative)
            post = {"kind": "regular_file", "sha256": None if payload is None else payload[1]}
        elif operation in {"CREATE_SYMLINK", "UPDATE_SYMLINK"}:
            payload = after.get(relative)
            post = {"kind": "symlink", "target": None if payload is None else payload[1]}
        elif operation == "CREATE_DIRECTORY":
            post = {"kind": "directory"}
        else:
            post = {"kind": "absent"}
        plan.append(
            {
                "index": index,
                "operation": operation,
                "path": relative,
                "expected_pre_state": pre,
                "intended_post_state": post,
            }
        )
    return plan


def _make_outcome(
    *,
    reservation_id: str,
    source_snapshot: SourceSnapshotIdentity,
    view_identity: PrivateExecutionViewIdentity,
    change_set: ProposedExportChangeSet,
    state: str,
    applied: int,
    refusal: str,
    source_mutated: bool,
    partial: bool,
    note: str,
) -> tuple[ExportReservation, ExportReceipt, ExportReconciliation]:
    # Typed reservation remains RESERVED at admit time; the receipt carries the
    # terminal state published after durable barriers.
    reservation = ExportReservation.create(
        reservation_id=reservation_id,
        source_snapshot_fingerprint=source_snapshot.record_fingerprint,
        private_view_fingerprint=view_identity.record_fingerprint,
        change_set_fingerprint=change_set.record_fingerprint,
        state="RESERVED",
    )
    receipt = ExportReceipt.create(
        reservation_id=reservation_id,
        applied_count=applied,
        state=state,
        refusal_code=refusal,
        change_set_fingerprint=change_set.record_fingerprint,
    )
    reconciliation = ExportReconciliation.create(
        reservation_id=reservation_id,
        verified=state == "APPLIED",
        state=state,
        source_mutated=source_mutated,
        private_ipc_exported=False,
        partial_export=partial,
        note=note,
    )
    return reservation, receipt, reconciliation


def apply_export(
    *,
    source_root_fd: int,
    private_fd: int,
    change_set: ProposedExportChangeSet,
    reservation_id: str,
    source_snapshot: SourceSnapshotIdentity,
    view_identity: PrivateExecutionViewIdentity,
    durable_root: Path | str,
    causal: dict[str, str] | None = None,
) -> tuple[ExportReservation, ExportReceipt, ExportReconciliation]:
    """Apply a validated change set through the durable transactional protocol."""

    durable = Path(durable_root)
    export_dir = durable / "export" / reservation_id
    causal = {
        "run_id": (causal or {}).get("run_id", "unknown"),
        "session_id": (causal or {}).get("session_id", "unknown"),
        "proposal_id": (causal or {}).get("proposal_id", "unknown"),
        "decision_id": (causal or {}).get("decision_id", "unknown"),
        "reservation_id": (causal or {}).get("reservation_id", reservation_id),
        "effect_id": (causal or {}).get("effect_id", reservation_id),
    }

    # Refuse automatic replay of an existing durable reservation.
    existing = recover_export(durable, reservation_id)
    if existing.get("state") not in {None, "ABSENT"}:
        state = "REFUSED_REPLAY" if existing.get("state") == "APPLIED" else "REFUSED_AMBIGUOUS"
        reservation, receipt, reconciliation = _make_outcome(
            reservation_id=reservation_id,
            source_snapshot=source_snapshot,
            view_identity=view_identity,
            change_set=change_set,
            state=state,
            applied=int(existing.get("applied_count") or 0),
            refusal="export_reservation_already_durable",
            source_mutated=False,
            partial=bool(existing.get("partial_export")),
            note="export refused: durable reservation already exists; automatic replay is forbidden",
        )
        return reservation, receipt, reconciliation

    if change_set.unsupported_inode_count:
        plan = []
    else:
        plan = _build_operation_plan(source_fd=source_root_fd, private_fd=private_fd, change_set=change_set)

    intended_final = snapshot_tree_identity(private_fd)[0]
    reservation_doc = {
        "schema_id": SCHEMA_TRANSACTIONAL_EXPORT_RESERVATION,
        "schema_version": M2_SCHEMA_VERSION,
        "export_protocol_version": EXPORT_PROTOCOL_VERSION,
        "reservation_id": reservation_id,
        "causal": causal,
        "source_snapshot": source_snapshot.to_dict(),
        "private_view": view_identity.to_dict(),
        "change_set": change_set.to_dict(),
        "operations": plan,
        "intended_final_tree_sha256": intended_final,
        "source_tree_sha256_at_reserve": source_snapshot.tree_sha256,
        "state": "RESERVED",
        "durability_barriers": [
            "1.write_temp_reservation",
            "2.fsync_reservation_file",
            "3.link_no_replace_into_export_dir",
            "4.fsync_export_dir",
            "5.per_op_revalidate_pre_state",
            "6.mutate",
            "7.fsync_mutated_file_or_parent",
            "8.append_journal_entry_fsync",
            "9.verify_final_tree",
            "10.publish_receipt_fsync",
            "11.publish_reconciliation_fsync",
        ],
    }

    # Durable reservation BEFORE any authorized-source mutation.
    _durable_publish_json(export_dir, "reservation.json", reservation_doc)
    _durable_replace_json(
        export_dir,
        "progress.json",
        {"reservation_id": reservation_id, "applied_count": 0, "next_index": 0, "entries": []},
    )

    typed_reservation = ExportReservation.create(
        reservation_id=reservation_id,
        source_snapshot_fingerprint=source_snapshot.record_fingerprint,
        private_view_fingerprint=view_identity.record_fingerprint,
        change_set_fingerprint=change_set.record_fingerprint,
        state="RESERVED",
    )

    if change_set.unsupported_inode_count:
        reservation, receipt, reconciliation = _make_outcome(
            reservation_id=reservation_id,
            source_snapshot=source_snapshot,
            view_identity=view_identity,
            change_set=change_set,
            state="REFUSED_UNSUPPORTED_INODE",
            applied=0,
            refusal="unsupported_inode_in_private_view",
            source_mutated=False,
            partial=False,
            note="export refused: private view contains an unsupported inode type",
        )
        _durable_publish_json(export_dir, "receipt.json", receipt.to_dict())
        _durable_publish_json(export_dir, "reconciliation.json", reconciliation.to_dict())
        return typed_reservation, receipt, reconciliation

    current_sha, _, _, _ = snapshot_tree_identity(source_root_fd)
    if current_sha != source_snapshot.tree_sha256:
        reservation, receipt, reconciliation = _make_outcome(
            reservation_id=reservation_id,
            source_snapshot=source_snapshot,
            view_identity=view_identity,
            change_set=change_set,
            state="REFUSED_SOURCE_MUTATED",
            applied=0,
            refusal="source_mutated_during_effect",
            source_mutated=True,
            partial=False,
            note="export refused: authorized source mutated between snapshot and export",
        )
        _durable_publish_json(export_dir, "receipt.json", receipt.to_dict())
        _durable_publish_json(export_dir, "reconciliation.json", reconciliation.to_dict())
        return typed_reservation, receipt, reconciliation

    applied = 0
    journal: list[dict[str, Any]] = []
    try:
        for item in plan:
            pre_now = _path_state(source_root_fd, item["path"])
            if pre_now != item["expected_pre_state"]:
                raise PrivateWorkspaceError(
                    "concurrent_source_mutation",
                    f"{item['path']}:{pre_now}!={item['expected_pre_state']}",
                )
            _apply_one(source_root_fd, private_fd, item["operation"], item["path"])
            # Durability barrier for the mutated parent directory.
            parent_fd, _leaf = _open_parent(source_root_fd, item["path"])
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            applied += 1
            journal.append({"index": item["index"], "path": item["path"], "operation": item["operation"], "status": "APPLIED"})
            _durable_replace_json(
                export_dir,
                "progress.json",
                {
                    "reservation_id": reservation_id,
                    "applied_count": applied,
                    "next_index": applied,
                    "entries": journal,
                },
            )
    except PrivateWorkspaceError as error:
        state = "REFUSED_CONCURRENT_MUTATION" if error.code == "concurrent_source_mutation" else (
            "REFUSED_PARTIAL" if applied else "REFUSED_CRASH_CLASSIFIABLE"
        )
        reservation, receipt, reconciliation = _make_outcome(
            reservation_id=reservation_id,
            source_snapshot=source_snapshot,
            view_identity=view_identity,
            change_set=change_set,
            state=state,
            applied=applied,
            refusal=error.code,
            source_mutated=error.code in {"concurrent_source_mutation", "source_mutated_during_effect"},
            partial=applied > 0,
            note=f"export failed after {applied} operations: {error.code}",
        )
        _durable_publish_json(export_dir, "receipt.json", receipt.to_dict())
        _durable_publish_json(export_dir, "reconciliation.json", reconciliation.to_dict())
        return typed_reservation, receipt, reconciliation

    final_sha, _, _, _ = snapshot_tree_identity(source_root_fd)
    if final_sha != intended_final:
        reservation, receipt, reconciliation = _make_outcome(
            reservation_id=reservation_id,
            source_snapshot=source_snapshot,
            view_identity=view_identity,
            change_set=change_set,
            state="REFUSED_PARTIAL",
            applied=applied,
            refusal="final_tree_identity_mismatch",
            source_mutated=False,
            partial=True,
            note="export refused: final full-tree identity did not match the intended post-state",
        )
        _durable_publish_json(export_dir, "receipt.json", receipt.to_dict())
        _durable_publish_json(export_dir, "reconciliation.json", reconciliation.to_dict())
        return typed_reservation, receipt, reconciliation

    # Ensure the source root directory itself is durable before success.
    os.fsync(source_root_fd)
    reservation, receipt, reconciliation = _make_outcome(
        reservation_id=reservation_id,
        source_snapshot=source_snapshot,
        view_identity=view_identity,
        change_set=change_set,
        state="APPLIED",
        applied=applied,
        refusal="none",
        source_mutated=False,
        partial=False,
        note="trusted transactional export applied only validated regular-file, directory, and symlink changes",
    )
    _durable_publish_json(export_dir, "receipt.json", receipt.to_dict())
    _durable_publish_json(export_dir, "reconciliation.json", reconciliation.to_dict())
    return typed_reservation, receipt, reconciliation


def recover_export(durable_root: Path | str, reservation_id: str) -> dict[str, Any]:
    """Classify an export from durable records and filesystem state alone."""

    export_dir = Path(durable_root) / "export" / reservation_id
    reservation_path = export_dir / "reservation.json"
    if not reservation_path.exists():
        return {"state": "ABSENT", "reservation_id": reservation_id, "classifiable": True}
    try:
        reservation = json.loads(reservation_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"state": "REFUSED_AMBIGUOUS", "reservation_id": reservation_id, "classifiable": True, "reason": "corrupt_reservation"}
    receipt_path = export_dir / "receipt.json"
    progress_path = export_dir / "progress.json"
    progress = {}
    if progress_path.exists():
        try:
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            progress = {"corrupt": True}
    if receipt_path.exists():
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {
                "state": "REFUSED_AMBIGUOUS",
                "reservation_id": reservation_id,
                "classifiable": True,
                "reason": "corrupt_receipt",
                "applied_count": progress.get("applied_count"),
            }
        return {
            "state": receipt.get("state"),
            "reservation_id": reservation_id,
            "classifiable": True,
            "applied_count": receipt.get("applied_count"),
            "refusal_code": receipt.get("refusal_code"),
            "partial_export": receipt.get("state") == "REFUSED_PARTIAL",
            "replay_forbidden": True,
            "reservation": reservation,
            "progress": progress,
        }
    applied = int(progress.get("applied_count") or 0)
    if applied == 0:
        return {
            "state": "REFUSED_CRASH_CLASSIFIABLE",
            "reservation_id": reservation_id,
            "classifiable": True,
            "applied_count": 0,
            "partial_export": False,
            "replay_forbidden": True,
            "reason": "reserved_without_receipt",
            "reservation": reservation,
            "progress": progress,
        }
    return {
        "state": "REFUSED_PARTIAL",
        "reservation_id": reservation_id,
        "classifiable": True,
        "applied_count": applied,
        "partial_export": True,
        "replay_forbidden": True,
        "reason": "partial_journal_without_receipt",
        "reservation": reservation,
        "progress": progress,
    }


def _apply_one(source_fd: int, private_fd: int, operation: str, relative: str) -> None:
    parent_fd, leaf = _open_parent(source_fd, relative)
    try:
        if operation in {"DELETE_REGULAR_FILE", "DELETE_SYMLINK"}:
            try:
                os.unlink(leaf, dir_fd=parent_fd)
            except OSError as error:
                raise PrivateWorkspaceError("export_delete_failed", f"{relative}:{error.errno}") from error
            return
        if operation == "DELETE_DIRECTORY":
            try:
                os.rmdir(leaf, dir_fd=parent_fd)
            except OSError as error:
                raise PrivateWorkspaceError("export_rmdir_failed", f"{relative}:{error.errno}") from error
            return
        if operation == "CREATE_DIRECTORY":
            try:
                os.mkdir(leaf, DIRECTORY_MODE, dir_fd=parent_fd)
            except FileExistsError:
                info = os.lstat(leaf, dir_fd=parent_fd)
                if not stat.S_ISDIR(info.st_mode):
                    raise PrivateWorkspaceError("export_mkdir_conflict", relative)
            except OSError as error:
                raise PrivateWorkspaceError("export_mkdir_failed", f"{relative}:{error.errno}") from error
            return
        if operation in {"CREATE_REGULAR_FILE", "UPDATE_REGULAR_FILE"}:
            _export_regular_file(source_fd, private_fd, relative, parent_fd, leaf, replace=operation.startswith("UPDATE"))
            return
        if operation in {"CREATE_SYMLINK", "UPDATE_SYMLINK"}:
            priv_parent, priv_leaf = _open_parent(private_fd, relative)
            try:
                target = os.readlink(priv_leaf, dir_fd=priv_parent)
            finally:
                os.close(priv_parent)
            if not _symlink_is_exportable(target):
                raise PrivateWorkspaceError("export_symlink_not_exportable", relative)
            if operation.startswith("UPDATE"):
                try:
                    os.unlink(leaf, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            try:
                os.symlink(target, leaf, dir_fd=parent_fd)
            except OSError as error:
                raise PrivateWorkspaceError("export_symlink_failed", f"{relative}:{error.errno}") from error
            return
        raise PrivateWorkspaceError("export_unknown_operation", operation)
    finally:
        os.close(parent_fd)


def _export_regular_file(
    source_fd: int,
    private_fd: int,
    relative: str,
    parent_fd: int,
    leaf: str,
    *,
    replace: bool,
) -> None:
    priv_parent, priv_leaf = _open_parent(private_fd, relative)
    try:
        src = os.open(priv_leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=priv_parent)
    finally:
        os.close(priv_parent)
    try:
        info = os.fstat(src)
        if not stat.S_ISREG(info.st_mode):
            raise PrivateWorkspaceError("export_not_regular_file", relative)
        tmp_name = f".admissible-export-{os.getpid()}-{leaf}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        try:
            dst = os.open(tmp_name, flags, FILE_MODE, dir_fd=parent_fd)
        except OSError as error:
            raise PrivateWorkspaceError("export_temp_create_failed", f"{relative}:{error.errno}") from error
        try:
            while True:
                chunk = os.read(src, 1 << 20)
                if not chunk:
                    break
                offset = 0
                while offset < len(chunk):
                    offset += os.write(dst, chunk[offset:])
            os.fchmod(dst, FILE_MODE)
            os.fsync(dst)
        finally:
            os.close(dst)
        try:
            os.replace(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except OSError as error:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
            raise PrivateWorkspaceError("export_replace_failed", f"{relative}:{error.errno}") from error
    finally:
        os.close(src)


def private_ipc_host_visible(source_root: Path, private_view: PrivateExecutionView) -> tuple[str, ...]:
    source_fd = os.open(source_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _, _, _, source_specials = snapshot_tree_identity(source_fd)
    finally:
        os.close(source_fd)
    _, _, _, private_specials = snapshot_tree_identity(private_view.view_fd)
    source_set = set(source_specials)
    return tuple(item for item in private_specials if item in source_set)


__all__ = [
    "EXPORT_OPERATIONS",
    "EXPORT_PROTOCOL_VERSION",
    "EXPORT_STATES",
    "ExportReceipt",
    "ExportReconciliation",
    "ExportReservation",
    "MATERIALIZATION_KIND",
    "M2_PRIVATE_WORKSPACE_SCHEMAS",
    "PrivateExecutionView",
    "PrivateExecutionViewIdentity",
    "PrivateMountHelper",
    "PrivateWorkspaceError",
    "ProposedExportChangeSet",
    "SCHEMA_EXPORT_RECEIPT",
    "SCHEMA_EXPORT_RECONCILIATION",
    "SCHEMA_EXPORT_RESERVATION",
    "SCHEMA_PRIVATE_EXECUTION_VIEW_IDENTITY",
    "SCHEMA_PROPOSED_EXPORT_CHANGE_SET",
    "SCHEMA_SOURCE_SNAPSHOT_IDENTITY",
    "SCHEMA_TRANSACTIONAL_EXPORT_RESERVATION",
    "SourceSnapshotIdentity",
    "SpawnedLauncher",
    "apply_export",
    "compute_change_set",
    "host_can_pathname_reach",
    "private_ipc_host_visible",
    "recover_export",
    "snapshot_tree_identity",
]
