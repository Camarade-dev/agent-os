"""Entry point for the privileged owner-authority broker service.

The systemd unit starts exactly this module from the fixed root-owned
deployment artifact.  It attests the fixed production installation, safely
clears a stale socket that belongs to this installation, binds the fixed
socket, notifies readiness, and serves the closed protocol.

Stale-socket cleanup
--------------------

Before binding, :func:`_clear_stale_socket` may unlink only the exact stale
Unix socket that belongs to the attested installation authority.  It opens the
runtime directory without following symlinks, obtains the directory entry with
no-follow semantics, and refuses unless the entry is a Unix socket whose
uid/gid/mode match the installed broker authority, the installation record and
layout agree on the socket path, the socket is not live, and the same
device/inode/type/uid/gid/mode identity still exists immediately before
``unlinkat``.  An unexpected object --- including a world-writable ``0777``
socket --- is never deleted merely to recover availability.
"""

from __future__ import annotations

import errno
import os
import signal
import socket
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

from admissible.capsule.common import require_sha256, require_strict_int
from admissible.capsule.owner_authority.broker import OwnerAuthorityBroker
from admissible.capsule.owner_authority.installation import (
    attest_production_installation,
)
from admissible.capsule.owner_authority.layout import (
    BROKER_SOCKET_NAME,
    OwnerAuthorityError,
)

#: Root owns the broker socket; the authorized launcher group may connect.
EXPECTED_BROKER_SOCKET_OWNER_UID = 0
EXPECTED_BROKER_SOCKET_MODE = 0o660
EXPECTED_RUNTIME_DIRECTORY_OWNER_UID = 0
EXPECTED_RUNTIME_DIRECTORY_MODE = 0o755

_STALE_CONNECT_ERRNOS = frozenset(
    {
        errno.ECONNREFUSED,
        errno.ENOENT,
    }
)


def _sd_notify(message: str) -> bool:
    notify_socket = os.environ.get("NOTIFY_SOCKET")
    if not notify_socket:
        return False
    address = notify_socket
    if address.startswith("@"):
        address = "\0" + address[1:]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(address)
        sock.sendall(message.encode("utf-8"))
    finally:
        sock.close()
    return True


def _socket_error(
    detail: str, *, classification: str = "OWNER_AUTHORITY_SOCKET_REFUSED"
) -> OwnerAuthorityError:
    return OwnerAuthorityError(detail, classification=classification)


def _refuse_socket(
    detail: str, *, classification: str = "OWNER_AUTHORITY_SOCKET_REFUSED"
) -> None:
    raise _socket_error(detail, classification=classification)


def _socket_identity_tuple(info: os.stat_result) -> tuple[Any, ...]:
    return (
        "socket" if stat.S_ISSOCK(info.st_mode) else mode_type_name(info.st_mode),
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_uid),
        int(info.st_gid),
        int(stat.S_IMODE(info.st_mode)),
    )


def mode_type_name(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISCHR(mode):
        return "character"
    if stat.S_ISBLK(mode):
        return "block"
    return "other"


def expected_broker_socket_identity(
    installation: Any,
) -> tuple[int, int, int]:
    """Return ``(uid, gid, mode)`` required of an installed broker socket."""

    record = dict(installation.record)
    try:
        require_sha256(
            installation.installation_identity, "installation identity"
        )
    except ValueError as error:
        raise _socket_error(
            "stale-socket cleanup refused: missing or malformed installation "
            "identity",
        ) from error
    try:
        gid = require_strict_int(
            record["authorized_launcher_gid"],
            "authorized launcher gid",
            minimum=0,
            maximum=2**31 - 1,
        )
    except (KeyError, ValueError, TypeError) as error:
        raise _socket_error(
            "stale-socket cleanup refused: missing or malformed installation "
            "socket authority",
        ) from error
    return (
        EXPECTED_BROKER_SOCKET_OWNER_UID,
        gid,
        EXPECTED_BROKER_SOCKET_MODE,
    )


def require_expected_broker_socket_identity(
    info: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> tuple[Any, ...]:
    """Fail closed unless ``info`` is exactly the installed broker socket."""

    if stat.S_ISLNK(info.st_mode):
        _refuse_socket("broker socket path is a symlink")
    if not stat.S_ISSOCK(info.st_mode):
        _refuse_socket(
            "broker socket path exists and is not a Unix socket"
        )
    mode = stat.S_IMODE(info.st_mode)
    if int(info.st_uid) != int(expected_uid):
        _refuse_socket(
            "broker socket ownership does not match the installed authority"
        )
    if int(info.st_gid) != int(expected_gid):
        _refuse_socket(
            "broker socket group does not match the authorized launcher gid"
        )
    if mode != int(expected_mode):
        _refuse_socket(
            "broker socket mode does not match the installed authority"
        )
    return _socket_identity_tuple(info)


def require_stable_socket_identity(
    first: tuple[Any, ...],
    second: tuple[Any, ...],
) -> None:
    """Refuse when the socket identity changed between validation and unlink."""

    if first != second:
        _refuse_socket(
            "broker socket identity changed between validation and deletion"
        )


def _open_validated_runtime_directory(
    broker: OwnerAuthorityBroker,
) -> int | None:
    """Open the runtime directory with no-follow semantics, or ``None`` if absent."""

    layout = broker.installation.layout
    record = dict(broker.installation.record)
    runtime = Path(layout.runtime_root)
    socket_path = Path(layout.broker_socket_path)
    try:
        record_runtime = Path(record["runtime_root"])
        record_socket = Path(record["broker_socket_path"])
    except (KeyError, TypeError) as error:
        raise _socket_error(
            "stale-socket cleanup refused: missing or malformed installation "
            "socket path authority",
        ) from error
    if (
        runtime != record_runtime
        or socket_path != record_socket
        or socket_path.parent != runtime
        or socket_path.name != BROKER_SOCKET_NAME
    ):
        _refuse_socket(
            "broker socket path does not match the installed authority"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        dir_fd = os.open(os.fspath(runtime), flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise _socket_error(
            "runtime directory could not be opened without following symlinks",
        ) from error
    try:
        info = os.fstat(dir_fd)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            _refuse_socket(
                "runtime directory is not the expected root-owned directory"
            )
        mode = stat.S_IMODE(info.st_mode)
        if int(info.st_uid) != EXPECTED_RUNTIME_DIRECTORY_OWNER_UID:
            _refuse_socket(
                "runtime directory ownership does not match the installed "
                "authority"
            )
        if mode != EXPECTED_RUNTIME_DIRECTORY_MODE:
            _refuse_socket(
                "runtime directory mode does not match the installed authority"
            )
    except OwnerAuthorityError:
        os.close(dir_fd)
        raise
    except OSError as error:
        os.close(dir_fd)
        raise _socket_error(
            "runtime directory could not be validated",
        ) from error
    return dir_fd


def _probe_socket_is_live(*, dir_fd: int, name: str, absolute_path: Path) -> bool:
    """Return True if a live listener accepts connections; refuse ambiguities."""

    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.2)
        # Connect still addresses the fixed absolute path; identity was already
        # validated relative to dir_fd and is re-checked before unlinkat.
        probe.connect(os.fspath(absolute_path))
    except ConnectionRefusedError:
        return False
    except OSError as error:
        if error.errno in _STALE_CONNECT_ERRNOS:
            return False
        raise _socket_error(
            "broker socket connect probe was ambiguous; refusing deletion",
        ) from error
    finally:
        probe.close()
    return True


def _unlink_verified_stale_socket(
    *,
    dir_fd: int,
    name: str,
    expected_identity: tuple[Any, ...],
) -> None:
    """Delete ``name`` relative to ``dir_fd`` only if identity is unchanged."""

    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise _socket_error(
            "broker socket could not be re-validated before deletion",
        ) from error
    require_stable_socket_identity(expected_identity, _socket_identity_tuple(info))
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return
    except OSError as error:
        raise _socket_error(
            "broker socket could not be removed safely",
        ) from error


def _clear_stale_socket(broker: OwnerAuthorityBroker) -> None:
    """Remove only an exact stale socket belonging to this installation."""

    expected_uid, expected_gid, expected_mode = expected_broker_socket_identity(
        broker.installation
    )
    layout = broker.installation.layout
    socket_path = Path(layout.broker_socket_path)
    dir_fd = _open_validated_runtime_directory(broker)
    if dir_fd is None:
        return
    try:
        try:
            info = os.stat(
                BROKER_SOCKET_NAME, dir_fd=dir_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            return
        except OSError as error:
            raise _socket_error(
                "broker socket entry could not be examined",
            ) from error
        identity = require_expected_broker_socket_identity(
            info,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_mode=expected_mode,
        )
        if _probe_socket_is_live(
            dir_fd=dir_fd,
            name=BROKER_SOCKET_NAME,
            absolute_path=socket_path,
        ):
            raise OwnerAuthorityError(
                "a live broker already owns the installation socket",
                classification="OWNER_AUTHORITY_SOCKET_BUSY",
            )
        _unlink_verified_stale_socket(
            dir_fd=dir_fd,
            name=BROKER_SOCKET_NAME,
            expected_identity=identity,
        )
    finally:
        os.close(dir_fd)


def _announce_readiness(broker: OwnerAuthorityBroker) -> None:
    socket_path = Path(broker.installation.layout.broker_socket_path)
    info = os.lstat(socket_path)
    if not stat.S_ISSOCK(info.st_mode):
        raise OwnerAuthorityError(
            "readiness refused: broker socket is not bound",
            classification="OWNER_AUTHORITY_NOT_READY",
        )
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != EXPECTED_BROKER_SOCKET_OWNER_UID:
        raise OwnerAuthorityError(
            "readiness refused: broker socket is not root-owned",
            classification="OWNER_AUTHORITY_NOT_READY",
        )
    if mode != EXPECTED_BROKER_SOCKET_MODE:
        raise OwnerAuthorityError(
            f"readiness refused: unexpected broker socket mode {oct(mode)}",
            classification="OWNER_AUTHORITY_NOT_READY",
        )
    marker = socket_path.parent / "broker-ready"
    with open(marker, "w", encoding="utf-8") as handle:
        handle.write(
            f"ready installation_identity={broker.installation.installation_identity}\n"
        )
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(marker, 0o644)
    if not _sd_notify("READY=1"):
        # Bounded non-notify readiness: the marker file above is the equivalent
        # signal when NOTIFY_SOCKET is absent (tests / non-systemd hosts).
        pass


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        print(
            "refusing: the owner-authority broker takes no arguments",
            file=sys.stderr,
        )
        return 2
    broker: OwnerAuthorityBroker | None = None
    stopped_cleanly = False
    fatal_serve_error = False
    try:
        broker = OwnerAuthorityBroker(attest_production_installation())
        signal.signal(signal.SIGTERM, lambda *_args: broker.request_stop())
        signal.signal(signal.SIGINT, lambda *_args: broker.request_stop())
        _clear_stale_socket(broker)
        broker.bind()
        _announce_readiness(broker)
        try:
            broker.serve_forever()
        except OSError:
            fatal_serve_error = True
        else:
            stopped_cleanly = broker.stop_requested
    except OwnerAuthorityError as error:
        print(f"{error}", file=sys.stderr)
        return 1
    finally:
        if broker is not None:
            broker.close()
    if fatal_serve_error:
        return 1
    if stopped_cleanly:
        return 0
    # serve_forever returning without an explicit stop is unexpected.
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
