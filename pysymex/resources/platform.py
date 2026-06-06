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

import importlib
import sys
from typing import Protocol

from pysymex.logger import get_logger

_logger = get_logger(__name__)

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
        """ctypes structure representing the PROCESS_MEMORY_COUNTERS_EX Windows API structure.

        This structure is used to retrieve memory statistics for the current process on Windows platforms.

        Attributes:
            cb (wintypes.DWORD): The size of the structure, in bytes.
            PageFaultCount (wintypes.DWORD): The number of page faults.
            PeakWorkingSetSize (ctypes.c_size_t): The peak working set size, in bytes.
            WorkingSetSize (ctypes.c_size_t): The current working set size, in bytes.
            QuotaPeakPagedPoolUsage (ctypes.c_size_t): The peak paged pool usage, in bytes.
            QuotaPagedPoolUsage (ctypes.c_size_t): The current paged pool usage, in bytes.
            QuotaPeakNonPagedPoolUsage (ctypes.c_size_t): The peak non-paged pool usage, in bytes.
            QuotaNonPagedPoolUsage (ctypes.c_size_t): The current non-paged pool usage, in bytes.
            PagefileUsage (ctypes.c_size_t): The Commit Charge value in bytes for this process.
            PeakPagefileUsage (ctypes.c_size_t): The peak value in bytes of the Commit Charge during the lifetime of this process.
            PrivateUsage (ctypes.c_size_t): The private working set size, in bytes.
        """

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

    try:
        GetProcessMemoryInfo = ctypes.windll.psapi.GetProcessMemoryInfo
        GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
        GetCurrentProcess.restype = wintypes.HANDLE
        GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
            wintypes.DWORD,
        ]
        GetProcessMemoryInfo.restype = wintypes.BOOL
    except Exception:
        _logger.debug("Failed to configure Windows process memory probes", exc_info=True)
        GetProcessMemoryInfo = None
        GetCurrentProcess = None
else:
    PROCESS_MEMORY_COUNTERS_EX = None
    GetProcessMemoryInfo = None
    GetCurrentProcess = None

if sys.platform != "win32":
    import resource as sys_resource
else:
    sys_resource = None


class DebugLogger(Protocol):
    """Minimal logger contract needed by resource probes."""

    def debug(self, message: str, *args: object, exc_info: bool = False) -> None:
        """Log a debug diagnostic."""


def current_memory_usage_mb(logger: DebugLogger) -> float:
    """Get current process memory usage in MB."""
    try:
        try:
            psutil_mod = importlib.import_module("psutil")
            process = psutil_mod.Process()
            return process.memory_info().rss / (1024 * 1024)
        except ImportError:
            logger.debug("psutil unavailable for memory usage probe", exc_info=True)

        if sys.platform != "win32":
            try:
                with open("/proc/self/statm", "r", encoding="ascii") as f:
                    parts = f.read().strip().split()
                if len(parts) >= 2:
                    rss_pages = int(parts[1])
                    page_bytes = 4096
                    return (rss_pages * page_bytes) / (1024 * 1024)
            except (OSError, ValueError):
                logger.debug("Failed to read /proc/self/statm for memory usage", exc_info=True)

            if sys_resource is not None:
                usage = sys_resource.getrusage(sys_resource.RUSAGE_SELF)
                return usage.ru_maxrss / 1024
        elif GetProcessMemoryInfo is not None and GetCurrentProcess is not None:
            try:
                counters = PROCESS_MEMORY_COUNTERS_EX()
                counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
                handle = GetCurrentProcess()
                if GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                    return float(counters.WorkingSetSize) / (1024 * 1024)
            except Exception:
                logger.debug("Failed to query Windows process memory usage", exc_info=True)

        return 0.0
    except OSError:
        logger.debug("Failed to get peak memory usage", exc_info=True)
        return 0.0
