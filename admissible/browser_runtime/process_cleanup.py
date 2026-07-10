"""Reliable process-tree launch/cleanup for the bounded browser runtime (PART B.9).

Windows: the child is assigned to a Job Object created with
``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` so closing the job handle terminates
the whole process tree, including any renderer/utility processes Chrome
spawns as children of the launched process.

POSIX: the child is launched in a new session (``start_new_session=True``)
so the whole process group can be terminated with one bounded signal.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from typing import Any


class ProcessTreeHandle:
    """Launches one subprocess with bounded, reliable tree cleanup."""

    def __init__(self, args: list[str]) -> None:
        self.args = list(args)
        self.process: subprocess.Popen | None = None
        self._job_handle = None
        self._platform = sys.platform

    def start(self) -> None:
        if self._platform.startswith("win"):
            self._start_windows()
        else:
            self._start_posix()

    def _start_windows(self) -> None:
        import ctypes

        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.process = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False, no user-controlled command
            self.args,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        try:
            self._job_handle = _create_kill_on_close_job(self.process.pid)
        except OSError:
            self._job_handle = None

    def _start_posix(self) -> None:
        self.process = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False, no user-controlled command
            self.args,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def terminate_tree(self, *, timeout: float = 5.0) -> dict[str, Any]:
        if self.process is None:
            return {"terminated": True, "method": "not_started"}
        if self._platform.startswith("win"):
            return self._terminate_windows(timeout=timeout)
        return self._terminate_posix(timeout=timeout)

    def _terminate_windows(self, *, timeout: float) -> dict[str, Any]:
        method = "job_object"
        if self._job_handle is not None:
            import ctypes

            ctypes.windll.kernel32.CloseHandle(self._job_handle)
            self._job_handle = None
        else:
            method = "direct_terminate"
            try:
                self.process.terminate()
            except OSError:
                pass
        exited = self._wait(timeout)
        if not exited:
            method = "force_kill"
            try:
                self.process.kill()
            except OSError:
                pass
            exited = self._wait(timeout)
        return {"terminated": bool(exited), "method": method, "returncode": self.process.returncode}

    def _terminate_posix(self, *, timeout: float) -> dict[str, Any]:
        pid = self.process.pid
        method = "sigterm_process_group"
        try:
            pgid = os.getpgid(pid)
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        exited = self._wait(timeout)
        if not exited:
            method = "sigkill_process_group"
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            exited = self._wait(timeout)
        return {"terminated": bool(exited), "method": method, "returncode": self.process.returncode}

    def _wait(self, timeout: float) -> bool:
        try:
            self.process.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    @property
    def pid(self) -> int | None:
        return self.process.pid if self.process else None


def _create_kill_on_close_job(pid: int):
    """Create a Windows Job Object with KILL_ON_JOB_CLOSE and assign ``pid``."""

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9
    PROCESS_ALL_ACCESS = 0x1F0FFF

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_void_p),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    job_handle = kernel32.CreateJobObjectW(None, None)
    if not job_handle:
        raise OSError("CreateJobObjectW failed")

    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    ok = kernel32.SetInformationJobObject(
        job_handle,
        JobObjectExtendedLimitInformation,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if not ok:
        kernel32.CloseHandle(job_handle)
        raise OSError("SetInformationJobObject failed")

    process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        kernel32.CloseHandle(job_handle)
        raise OSError("OpenProcess failed")
    try:
        ok = kernel32.AssignProcessToJobObject(job_handle, process_handle)
        if not ok:
            raise OSError("AssignProcessToJobObject failed")
    finally:
        kernel32.CloseHandle(process_handle)
    return job_handle
