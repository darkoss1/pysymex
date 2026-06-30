# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Platform-specific resource probes."""

from __future__ import annotations

import ctypes
import importlib
import sys
from ctypes import wintypes
from typing import Protocol, cast

from pysymex._internal.logging.root import get_logger

_logger = get_logger(__name__)


class _ProcessMemoryCountersEx(ctypes.Structure):
    """ctypes structure for the Windows PROCESS_MEMORY_COUNTERS_EX API."""

    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


if sys.platform == "win32":
    try:
        GetProcessMemoryInfo = ctypes.windll.psapi.GetProcessMemoryInfo
        GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
        GetCurrentProcess.restype = wintypes.HANDLE
        GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ProcessMemoryCountersEx),
            wintypes.DWORD,
        ]
        GetProcessMemoryInfo.restype = wintypes.BOOL
    except Exception:
        _logger.debug("Failed to configure Windows process memory probes", exc_info=True)
        GetProcessMemoryInfo = None
        GetCurrentProcess = None
else:
    GetProcessMemoryInfo = None
    GetCurrentProcess = None

if sys.platform != "win32":
    import resource
else:
    resource = None

_psutil_process: _PsutilProcess | None = None
_psutil_unavailable = False
_PAGE_SIZE_BYTES = 4096


class DebugLogger(Protocol):
    """Minimal logger contract needed by resource probes."""

    def debug(self, message: str, *args: object, exc_info: bool = False) -> None:
        """Log a debug diagnostic."""


class _MemoryInfo(Protocol):
    """Subset of psutil memory-info records used by this module."""

    rss: int | float


class _PsutilProcess(Protocol):
    """Subset of psutil.Process used by this module."""

    def memory_info(self) -> _MemoryInfo:
        """Return process memory information."""
        ...


def current_memory_usage_mb(logger: DebugLogger) -> float:
    """Get current process memory usage in MB."""
    try:
        if sys.platform != "win32":
            try:
                with open("/proc/self/statm", encoding="ascii") as f:
                    parts = f.read().strip().split()
                if len(parts) >= 2:
                    rss_pages = int(parts[1])
                    return (rss_pages * _PAGE_SIZE_BYTES) / (1024 * 1024)
            except (OSError, ValueError):
                logger.debug("Failed to read /proc/self/statm for memory usage", exc_info=True)

            if resource is not None:
                usage = resource.getrusage(resource.RUSAGE_SELF)
                return usage.ru_maxrss / 1024
        elif (
            sys.platform == "win32"
            and GetProcessMemoryInfo is not None
            and GetCurrentProcess is not None
        ):
            try:
                counters = _ProcessMemoryCountersEx()
                counters.cb = ctypes.sizeof(_ProcessMemoryCountersEx)
                handle = GetCurrentProcess()
                if GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                    return float(counters.WorkingSetSize) / (1024 * 1024)
            except Exception:
                logger.debug("Failed to query Windows process memory usage", exc_info=True)

        psutil_memory = _psutil_memory_usage_mb(logger)
        if psutil_memory > 0.0:
            return psutil_memory

        return 0.0
    except OSError:
        logger.debug("Failed to get peak memory usage", exc_info=True)
        return 0.0


def _psutil_memory_usage_mb(logger: DebugLogger) -> float:
    """Return RSS via a cached psutil.Process fallback when available."""
    global _psutil_process
    global _psutil_unavailable

    if _psutil_unavailable:
        return 0.0
    try:
        process = _psutil_process
        if process is None:
            psutil_mod = importlib.import_module("psutil")
            process = cast("_PsutilProcess", psutil_mod.Process())
            _psutil_process = process
        memory_info = process.memory_info()
        return float(memory_info.rss) / (1024 * 1024)
    except ImportError:
        _psutil_unavailable = True
        logger.debug("psutil unavailable for memory usage probe", exc_info=True)
        return 0.0
    except Exception:
        logger.debug("Failed to query psutil process memory usage", exc_info=True)
        return 0.0
