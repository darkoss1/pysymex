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

"""Data models for bytecode-level resource usage tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
import dis


class ResourceKind(Enum):
    """Classification of trackable resource types.

    Each member corresponds to a Python API that acquires an OS or
    library resource requiring explicit cleanup.
    """

    FILE_HANDLE = auto()
    NETWORK_SOCKET = auto()
    DATABASE_CONNECTION = auto()
    DATABASE_CURSOR = auto()
    LOCK = auto()
    SEMAPHORE = auto()
    THREAD = auto()
    PROCESS = auto()
    TEMP_FILE = auto()
    MEMORY_MAP = auto()
    ZIP_FILE = auto()
    TAR_FILE = auto()
    HTTP_CONNECTION = auto()
    SSL_CONTEXT = auto()
    TIMER = auto()
    GENERATOR = auto()
    CONTEXT_MANAGER = auto()


class ResourceState(Enum):
    """Lifecycle state of a tracked resource.

    ``MAYBE_CLOSED`` is used when a close call is only reachable on
    some paths.  ``ESCAPED`` means the resource was passed to code
    outside the analysed scope.
    """

    OPENED = auto()
    CLOSED = auto()
    MAYBE_CLOSED = auto()
    ESCAPED = auto()


@dataclass
class Resource:
    """Mutable model of a single tracked resource instance.

    Records where the resource was opened, its current lifecycle state,
    and whether it is guarded by a context manager.
    """

    kind: ResourceKind
    name: str
    open_line: int
    open_pc: int
    state: ResourceState = ResourceState.OPENED
    close_line: int | None = None
    in_context_manager: bool = False

    def is_leaked(self) -> bool:
        """Return ``True`` if opened but not closed and not guarded by ``with``."""
        return self.state == ResourceState.OPENED and not self.in_context_manager


@dataclass
class ResourceWarning:
    """A single resource-analysis finding.

    Carries the finding kind, source location, resource metadata,
    human-readable message, and severity level.
    """

    kind: str
    file: str
    line: int
    resource_kind: ResourceKind
    resource_name: str
    message: str
    severity: str = "warning"


@dataclass
class ObjectNode:
    """Node in the reference graph used for cycle detection.

    Tracks an object's name, source line, and the set of other
    object names it references.
    """

    name: str
    line: int
    references: set[str] = field(default_factory=set[str])


RESOURCE_OPENERS: dict[str, ResourceKind] = {
    "open": ResourceKind.FILE_HANDLE,
    "io.open": ResourceKind.FILE_HANDLE,
    "codecs.open": ResourceKind.FILE_HANDLE,
    "gzip.open": ResourceKind.FILE_HANDLE,
    "bz2.open": ResourceKind.FILE_HANDLE,
    "lzma.open": ResourceKind.FILE_HANDLE,
    "tempfile.NamedTemporaryFile": ResourceKind.TEMP_FILE,
    "tempfile.SpooledTemporaryFile": ResourceKind.TEMP_FILE,
    "tempfile.TemporaryFile": ResourceKind.TEMP_FILE,
    "socket.socket": ResourceKind.NETWORK_SOCKET,
    "socket.create_connection": ResourceKind.NETWORK_SOCKET,
    "urllib.request.urlopen": ResourceKind.HTTP_CONNECTION,
    "http.client.HTTPConnection": ResourceKind.HTTP_CONNECTION,
    "http.client.HTTPSConnection": ResourceKind.HTTP_CONNECTION,
    "sqlite3.connect": ResourceKind.DATABASE_CONNECTION,
    "psycopg2.connect": ResourceKind.DATABASE_CONNECTION,
    "mysql.connector.connect": ResourceKind.DATABASE_CONNECTION,
    "pymongo.MongoClient": ResourceKind.DATABASE_CONNECTION,
    "zipfile.ZipFile": ResourceKind.ZIP_FILE,
    "tarfile.open": ResourceKind.TAR_FILE,
    "threading.Thread": ResourceKind.THREAD,
    "multiprocessing.Process": ResourceKind.PROCESS,
    "subprocess.Popen": ResourceKind.PROCESS,
    "mmap.mmap": ResourceKind.MEMORY_MAP,
}

RESOURCE_CLOSERS: set[str] = {
    "close",
    "shutdown",
    "release",
    "terminate",
    "join",
    "kill",
    "disconnect",
    "__exit__",
}

FILE_OPEN_MODES: frozenset[str] = frozenset(
    {
        "r",
        "w",
        "a",
        "x",
        "rb",
        "wb",
        "ab",
        "xb",
        "r+",
        "w+",
        "a+",
        "rb+",
        "wb+",
        "ab+",
    }
)

COUNTED_RESOURCE_CALL_OPS: frozenset[str] = frozenset(
    {"CALL", "CALL_FUNCTION", "CALL_METHOD", "CALL_KW"}
)


def is_zero_arg_builtin_open(target_name: str, argc: int) -> bool:
    """Return True for exact builtin open() calls that CPython rejects before opening."""
    return argc == 0 and target_name.lower() in {"open", "builtins.open"}


def is_counted_resource_call(instr: dis.Instruction) -> bool:
    """Return True for resource call opcodes whose argument is an explicit argc."""
    return instr.opname in COUNTED_RESOURCE_CALL_OPS


def extract_call_argc(instr: dis.Instruction) -> int:
    """Extract a call argument count from a bytecode instruction."""
    if isinstance(instr.argval, int):
        return instr.argval
    if isinstance(instr.arg, int):
        return instr.arg
    return 0


__all__ = [
    "COUNTED_RESOURCE_CALL_OPS",
    "FILE_OPEN_MODES",
    "RESOURCE_CLOSERS",
    "RESOURCE_OPENERS",
    "extract_call_argc",
    "is_counted_resource_call",
    "is_zero_arg_builtin_open",
    "ObjectNode",
    "Resource",
    "ResourceKind",
    "ResourceState",
    "ResourceWarning",
]
