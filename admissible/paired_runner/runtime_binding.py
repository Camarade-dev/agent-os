"""Descriptor-bound capsule runtime identity.

Hashing a pathname and later executing that pathname leaves a replacement
window.  This module opens the launcher, interpreter, and in-capsule init once,
verifies their bytes and inode identity against the recorded runtime manifest,
and exposes those descriptors for actual use through ``/proc/self/fd/N`` and
``bwrap --ro-bind-fd`` / ``--bind-fd``.  A same-owner replacement of any pathname
after the bind cannot change which inode is executed or mounted.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
from typing import Any

from .capsule_identity import CapsuleIdentityRefused, CapsuleRuntimeManifest, FileIdentity, _hash_file_identity
from .capsule_seccomp import describe as describe_seccomp
from .private_workspace import PrivateExecutionView


class RuntimeBindingRefused(RuntimeError):
    """A runtime input could not be bound to a verified descriptor."""


@dataclass
class BoundRuntime:
    """Open, verified descriptors for one capsule launch."""

    manifest: CapsuleRuntimeManifest
    launcher_fd: int
    interpreter_fd: int
    init_fd: int
    workspace_fd: int
    private_view: PrivateExecutionView
    launcher_proc_path: str
    interpreter_identity: FileIdentity
    init_identity: FileIdentity
    launcher_identity: FileIdentity
    _closed: bool = False
    #: M2-B43.  The private view's last closure evidence, including whether its
    #: helper was positively reaped and its ownership ended.
    private_view_cleanup: dict[str, Any] | None = None

    @classmethod
    def bind(
        cls,
        *,
        manifest: CapsuleRuntimeManifest,
        private_view: PrivateExecutionView,
        resolver: Any | None = None,
    ) -> "BoundRuntime":
        """Open and verify every runtime input, refusing any mismatch.

        ``resolver`` optionally re-resolves the launcher through ``PATH`` so a
        shadowing entry is detected even when the recorded absolute path still
        holds the original bytes.  The open itself is always against the
        verified inode that matches the manifest, never against the ambient
        ``PATH`` result alone.
        """

        if resolver is not None:
            current = resolver()
            if current is None or os.path.realpath(current) != manifest.mechanism_path:
                raise RuntimeBindingRefused(
                    f"the capsule mechanism now resolves to {current!r}, not {manifest.mechanism_path}"
                )

        launcher = _open_verified_regular(manifest.mechanism_path, "capsule mechanism", expected={
            "sha256": manifest.mechanism_sha256,
            "device": manifest.mechanism_device,
            "inode": manifest.mechanism_inode,
            "size_bytes": manifest.mechanism_size_bytes,
            "mode": manifest.mechanism_mode,
            "owner_uid": manifest.mechanism_owner_uid,
        })
        try:
            interpreter = _open_verified_regular(manifest.interpreter_path, "capsule interpreter", expected={
                "sha256": manifest.interpreter_sha256,
                "device": manifest.interpreter_device,
                "inode": manifest.interpreter_inode,
                "size_bytes": manifest.interpreter_size_bytes,
                "mode": manifest.interpreter_mode,
                "owner_uid": manifest.interpreter_owner_uid,
            })
            try:
                init = _open_verified_regular(manifest.capsule_init_path, "in-capsule init", expected={
                    "sha256": manifest.capsule_init_sha256,
                    "size_bytes": manifest.capsule_init_size_bytes,
                })
                try:
                    seccomp = describe_seccomp()
                    if seccomp["program_sha256"] != manifest.seccomp_program_sha256:
                        raise RuntimeBindingRefused("the seccomp program digest no longer matches the manifest")
                    from .capsule_identity import package_source_identity

                    source_digest, _ = package_source_identity()
                    if source_digest != manifest.package_source_sha256:
                        raise RuntimeBindingRefused("the package source identity no longer matches the manifest")
                    # Workspace FD is the private view; re-verify its inode.
                    view_info = os.fstat(private_view.view_fd)
                    if (
                        view_info.st_dev != private_view.view_identity.device
                        or view_info.st_ino != private_view.view_identity.inode
                    ):
                        raise RuntimeBindingRefused("the private execution view inode changed before launch")
                    workspace_fd = os.dup(private_view.view_fd)
                    launcher_identity = FileIdentity(
                        path=manifest.mechanism_path,
                        sha256=manifest.mechanism_sha256,
                        device=manifest.mechanism_device,
                        inode=manifest.mechanism_inode,
                        size_bytes=manifest.mechanism_size_bytes,
                        mode=manifest.mechanism_mode,
                        owner_uid=manifest.mechanism_owner_uid,
                        owner_gid=manifest.mechanism_owner_gid,
                    )
                    interpreter_identity = FileIdentity(
                        path=manifest.interpreter_path,
                        sha256=manifest.interpreter_sha256,
                        device=manifest.interpreter_device,
                        inode=manifest.interpreter_inode,
                        size_bytes=manifest.interpreter_size_bytes,
                        mode=manifest.interpreter_mode,
                        owner_uid=manifest.interpreter_owner_uid,
                        owner_gid=0,
                    )
                    init_identity = FileIdentity(
                        path=manifest.capsule_init_path,
                        sha256=manifest.capsule_init_sha256,
                        device=0,
                        inode=0,
                        size_bytes=manifest.capsule_init_size_bytes,
                        mode=0,
                        owner_uid=0,
                        owner_gid=0,
                    )
                    return cls(
                        manifest=manifest,
                        launcher_fd=launcher[0],
                        interpreter_fd=interpreter[0],
                        init_fd=init[0],
                        workspace_fd=workspace_fd,
                        private_view=private_view,
                        launcher_proc_path=f"/proc/self/fd/{launcher[0]}",
                        launcher_identity=launcher_identity,
                        interpreter_identity=interpreter_identity,
                        init_identity=init_identity,
                    )
                except BaseException:
                    os.close(init[0])
                    raise
            except BaseException:
                os.close(interpreter[0])
                raise
        except BaseException:
            os.close(launcher[0])
            raise

    @property
    def cleanup_complete(self) -> bool:
        """Whether the private view this runtime holds has finished cleaning up."""

        return self.private_view.cleanup_complete

    @property
    def cleanup_registry_id(self) -> str | None:
        """The process registry entry retaining this view's cleanup (M2-B48)."""

        return self.private_view.registry_id

    def close(self) -> dict[str, Any]:
        """Close the bound descriptors and the private view it holds.

        M2-B43.  The descriptors are closed exactly once; the private view's
        closure is attempted on every call while its cleanup is incomplete, and
        its evidence is returned rather than discarded, so a caller is never
        told a shutdown finished when a helper of this controller is still an
        unreaped child.

        M2-B48.  Returning the evidence was never sufficient on its own: the
        caller dropped it, and with it the only handle to the retry.  The
        evidence now names the process-level registry entry that retains that
        handle, so what this method returns is a fact the caller may propagate
        and not the last copy of it.
        """

        if not self._closed:
            self._closed = True
            for handle in (self.launcher_fd, self.interpreter_fd, self.init_fd, self.workspace_fd):
                try:
                    os.close(handle)
                except OSError:
                    pass
        self.private_view_cleanup = self.private_view.close()
        return dict(self.private_view_cleanup)


def _open_verified_regular(path: str, label: str, expected: dict[str, Any]) -> tuple[int, FileIdentity]:
    """Open a regular file and prove it matches the recorded identity."""

    try:
        identity = _hash_file_identity(path, label)
    except CapsuleIdentityRefused as error:
        raise RuntimeBindingRefused(str(error)) from error
    for key, value in expected.items():
        if getattr(identity, key) != value:
            raise RuntimeBindingRefused(f"the {label} {key} does not match the recorded runtime manifest")
    # Re-open and keep the descriptor.  Hashing already used one open; a
    # replacement between hash and this open is caught by comparing the new
    # fstat against the identity just derived.
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        handle = os.open(os.path.realpath(path), flags)
    except OSError as error:
        raise RuntimeBindingRefused(f"the {label} cannot be re-opened for binding: {error}") from error
    try:
        info = os.fstat(handle)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeBindingRefused(f"the {label} is not a regular file at bind time")
        if info.st_dev != identity.device or info.st_ino != identity.inode or info.st_size != identity.size_bytes:
            raise RuntimeBindingRefused(f"the {label} inode changed between verification and binding")
        return handle, identity
    except BaseException:
        os.close(handle)
        raise


__all__ = [
    "BoundRuntime",
    "RuntimeBindingRefused",
]
