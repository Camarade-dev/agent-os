"""Entry point for the privileged owner-authority broker service.

The systemd unit starts exactly this module from the fixed root-owned
deployment artifact.  It attests the fixed production installation, safely
clears a stale socket that belongs to this installation, binds the fixed
socket, notifies readiness, and serves the closed protocol.

Stale-socket cleanup
--------------------

Before binding, :func:`_clear_stale_socket` ``lstat``s the fixed socket path.
If the path is absent, binding proceeds.  If it exists but is not a socket, or
is a symlink, startup refuses.  If it is a socket with no live listener, the
stale file is removed for this installation only.  If another process still
accepts connections on that path, startup refuses with ``OWNER_AUTHORITY_SOCKET_BUSY``.
"""

from __future__ import annotations

import os
import signal
import socket
import stat
import sys
from pathlib import Path
from typing import Sequence

from admissible.capsule.owner_authority.broker import OwnerAuthorityBroker
from admissible.capsule.owner_authority.installation import (
    attest_production_installation,
)
from admissible.capsule.owner_authority.layout import OwnerAuthorityError


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


def _clear_stale_socket(broker: OwnerAuthorityBroker) -> None:
    path = Path(broker.installation.layout.broker_socket_path)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise OwnerAuthorityError(
            f"broker socket path is a symlink: {path}",
            classification="OWNER_AUTHORITY_SOCKET_REFUSED",
        )
    if not stat.S_ISSOCK(info.st_mode):
        raise OwnerAuthorityError(
            f"broker socket path exists and is not a socket: {path}",
            classification="OWNER_AUTHORITY_SOCKET_REFUSED",
        )
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.2)
        probe.connect(os.fspath(path))
    except OSError:
        # No live listener owns this socket; safe to remove for this installation.
        os.unlink(path)
        return
    finally:
        probe.close()
    raise OwnerAuthorityError(
        "a live broker already owns the installation socket",
        classification="OWNER_AUTHORITY_SOCKET_BUSY",
    )


def _announce_readiness(broker: OwnerAuthorityBroker) -> None:
    socket_path = Path(broker.installation.layout.broker_socket_path)
    info = os.lstat(socket_path)
    if not stat.S_ISSOCK(info.st_mode):
        raise OwnerAuthorityError(
            "readiness refused: broker socket is not bound",
            classification="OWNER_AUTHORITY_NOT_READY",
        )
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != 0:
        raise OwnerAuthorityError(
            "readiness refused: broker socket is not root-owned",
            classification="OWNER_AUTHORITY_NOT_READY",
        )
    if mode & 0o077 != 0 and mode not in {0o660, 0o600}:
        # Allow the documented 0660 launcher-group mode.
        if mode != 0o660:
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
