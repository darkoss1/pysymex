# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
Resource Leak and Memory Safety Analysis for pysymex.
This module detects:
- Unclosed file handles
- Unclosed network connections
- Unclosed database connections
- Context manager misuse
- Reference cycles
- Memory leaks from circular references
- Unreleased locks
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from types import CodeType

from pysymex._compat import get_starts_line
from pysymex.core.cache import get_instructions as _cached_get_instructions

logger = logging.getLogger(__name__)


class ResourceKind(Enum):
    """Types of resources that can leak."""

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
    SUBPROCESS = auto()
    TIMER = auto()
    GENERATOR = auto()
    CONTEXT_MANAGER = auto()


class ResourceState(Enum):
    """State of a resource."""

    OPENED = auto()
    CLOSED = auto()
    MAYBE_CLOSED = auto()
    ESCAPED = auto()


@dataclass
class Resource:
    """A tracked resource."""

    kind: ResourceKind
    name: str
    open_line: int
    open_pc: int
    state: ResourceState = ResourceState.OPENED
    close_line: int | None = None
    in_context_manager: bool = False

    def is_leaked(self) -> bool:
        """Check if resource is leaked."""
        return self.state == ResourceState.OPENED and not self.in_context_manager


@dataclass
class ResourceWarning:
    """Warning about resource usage."""

    kind: str
    file: str
    line: int
    resource_kind: ResourceKind
    resource_name: str
    message: str
    severity: str = "warning"


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
    "subprocess.Popen": ResourceKind.SUBPROCESS,
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


class ResourceLeakDetector:
    """
    Detects resource leaks by tracking open/close operations.
    """

    def __init__(self) -> None:
        self.resources: dict[str, Resource] = {}
        self.warnings: list[ResourceWarning] = []
        self.context_stack: list[str] = []

    def detect(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Detect resource leaks in function."""
        self.resources.clear()
        self.warnings.clear()
        self.context_stack.clear()
        reported_leaks: set[str] = set()
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno
        call_stack: list[str] = []
        pending_store: str | None = None
        for i, instr in enumerate(instructions):
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname in {"LOAD_GLOBAL", "LOAD_NAME"}:
                call_stack.append(str(arg))
            elif opname in {"LOAD_ATTR", "LOAD_METHOD"}:
                if str(arg) in RESOURCE_CLOSERS and i > 0:
                    prev = instructions[i - 1]
                    if prev.opname in {"LOAD_FAST", "LOAD_NAME"}:
                        var_name = str(prev.argval)
                        if var_name in self.resources:
                            self.resources[var_name].state = ResourceState.CLOSED
                            self.resources[var_name].close_line = current_line

                if call_stack:
                    call_stack[-1] = f"{call_stack[-1]}.{arg}"
                else:
                    call_stack.append(str(arg))
            elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
                if call_stack:
                    func_name = call_stack.pop()
                    for pattern in RESOURCE_OPENERS.keys():
                        if func_name.endswith(pattern) or func_name == pattern:
                            pending_store = func_name
                            break
            elif opname in {"STORE_FAST", "STORE_NAME"}:
                var_name = str(arg)
                if pending_store:
                    for pattern, kind in RESOURCE_OPENERS.items():
                        if pending_store.endswith(pattern) or pending_store == pattern:
                            self.resources[var_name] = Resource(
                                kind=kind,
                                name=var_name,
                                open_line=current_line,
                                open_pc=instr.offset,
                                in_context_manager=bool(self.context_stack),
                            )
                            break
                    pending_store = None
            elif opname == "BEFORE_WITH":
                self.context_stack.append("context")
            elif opname == "WITH_CLEANUP_START":
                if self.context_stack:
                    self.context_stack.pop()
            elif opname in {"RETURN_VALUE", "RETURN_CONST"}:
                self._check_leaks_at_exit(file_path, current_line, reported_leaks)
        self._check_leaks_at_exit(file_path, current_line, reported_leaks)
        return self.warnings

    def _check_leaks_at_exit(
        self, file_path: str, line: int, reported: set[str] | None = None
    ) -> None:
        """Check for resource leaks at function exit."""
        for name, resource in self.resources.items():
            if resource.is_leaked():
                if reported is not None:
                    if name in reported:
                        continue
                    reported.add(name)
                self.warnings.append(
                    ResourceWarning(
                        kind="RESOURCE_LEAK",
                        file=file_path,
                        line=resource.open_line,
                        resource_kind=resource.kind,
                        resource_name=name,
                        message=(
                            f"Resource '{name}' ({resource.kind.name}) "
                            f"opened on line {resource.open_line} may not be closed"
                        ),
                    )
                )


class ContextManagerAnalyzer:
    """
    Analyzes context manager usage patterns.
    """

    def analyze(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Analyze context manager usage."""
        warnings: list[ResourceWarning] = []
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno
        open_without_with: list[tuple[str, int]] = []
        for i, instr in enumerate(instructions):
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname == "BEFORE_WITH":
                pass
            elif opname in {"LOAD_GLOBAL", "LOAD_NAME"} and str(arg) == "open":
                found_with = False
                for j in range(i + 1, min(i + 10, len(instructions))):
                    if instructions[j].opname == "BEFORE_WITH":
                        found_with = True
                        break
                    if instructions[j].opname in {"STORE_FAST", "STORE_NAME"}:
                        break
                if not found_with:
                    open_without_with.append(("open", current_line))
        for func, line in open_without_with:
            warnings.append(
                ResourceWarning(
                    kind="MISSING_CONTEXT_MANAGER",
                    file=file_path,
                    line=line,
                    resource_kind=ResourceKind.FILE_HANDLE,
                    resource_name="file",
                    message=f"'{func}()' should be used with 'with' statement",
                    severity="warning",
                )
            )
        return warnings


@dataclass
class ObjectNode:
    """Node in reference graph."""

    name: str
    line: int
    references: set[str] = field(default_factory=set[str])


class ReferenceCycleDetector:
    """
    Detects potential reference cycles that could cause memory leaks.
    Note: This is a static approximation - actual cycles depend on runtime.
    """

    def detect(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Detect potential reference cycles."""
        warnings: list[ResourceWarning] = []
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno
        self_attrs: dict[str, int] = {}
        loading_self = False
        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname in {"LOAD_FAST", "LOAD_NAME"} and str(arg) == "self":
                loading_self = True
            elif opname == "STORE_ATTR" and loading_self:
                attr = str(arg)
                self_attrs[attr] = current_line
                loading_self = False
            elif opname in {"LOAD_ATTR", "LOAD_METHOD"} and loading_self:
                loading_self = False
            else:
                loading_self = False
        if code.co_name == "__init__":
            if "parent" in self_attrs and "children" in self_attrs:
                warnings.append(
                    ResourceWarning(
                        kind="POTENTIAL_REFERENCE_CYCLE",
                        file=file_path,
                        line=self_attrs.get("parent", code.co_firstlineno) or 0,
                        resource_kind=ResourceKind.CONTEXT_MANAGER,
                        resource_name="parent-child",
                        message=(
                            "Potential reference cycle: object has both 'parent' "
                            "and 'children' attributes - ensure proper cleanup or use weakref"
                        ),
                        severity="warning",
                    )
                )
        return warnings


class LockSafetyAnalyzer:
    """
    Analyzes lock acquisition and release patterns.
    """

    def analyze(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Analyze lock usage for potential issues."""
        warnings: list[ResourceWarning] = []
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno
        acquired_locks: dict[str, int] = {}
        loading_var: str | None = None
        loading_attr: str | None = None

        last_acquire_var: str | None = None
        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval

            if opname in {"BEFORE_WITH", "BEFORE_ASYNC_WITH"}:
                if loading_var and loading_var in acquired_locks:
                    del acquired_locks[loading_var]

                if last_acquire_var and last_acquire_var in acquired_locks:
                    del acquired_locks[last_acquire_var]
                loading_var = None
                loading_attr = None
                last_acquire_var = None
                continue
            if opname in {"WITH_EXCEPT_START", "WITH_CLEANUP_START", "WITH_CLEANUP_FINISH"}:
                continue

            if opname in {"GET_AWAITABLE", "SEND", "END_SEND", "YIELD_VALUE", "RESUME"}:
                continue
            if opname in {"LOAD_FAST", "LOAD_NAME"}:
                loading_var = str(arg)
                loading_attr = None
            elif opname in {"LOAD_ATTR", "LOAD_METHOD"}:
                attr = str(arg)
                if loading_var and attr in {"acquire", "release", "__enter__", "__exit__"}:
                    loading_attr = attr
                else:
                    loading_attr = None
            elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
                if loading_var and loading_attr:
                    if loading_attr == "acquire" or loading_attr == "__enter__":
                        acquired_locks[loading_var] = current_line
                        last_acquire_var = loading_var
                    elif loading_attr == "release" or loading_attr == "__exit__":
                        if loading_var in acquired_locks:
                            del acquired_locks[loading_var]
                        else:
                            warnings.append(
                                ResourceWarning(
                                    kind="LOCK_RELEASED_NOT_ACQUIRED",
                                    file=file_path,
                                    line=current_line,
                                    resource_kind=ResourceKind.LOCK,
                                    resource_name=loading_var,
                                    message=f"Lock '{loading_var}' released without being acquired",
                                )
                            )
                        last_acquire_var = None
                    else:
                        last_acquire_var = None
                else:
                    last_acquire_var = None
                loading_var = None
                loading_attr = None
            elif opname in {"RETURN_VALUE", "RETURN_CONST"}:
                for lock_name, acquire_line in acquired_locks.items():
                    warnings.append(
                        ResourceWarning(
                            kind="LOCK_NOT_RELEASED",
                            file=file_path,
                            line=acquire_line,
                            resource_kind=ResourceKind.LOCK,
                            resource_name=lock_name,
                            message=(
                                f"Lock '{lock_name}' acquired on line {acquire_line} "
                                f"may not be released before return"
                            ),
                        )
                    )
        return warnings


class GeneratorCleanupAnalyzer:
    """
    Analyzes generator cleanup patterns.
    """

    def analyze(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Check for generator cleanup issues."""
        warnings: list[ResourceWarning] = []
        is_generator = bool(code.co_flags & 0x20)
        if not is_generator:
            return warnings
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno
        has_finally = False
        has_close_check = False
        has_resource_open = False
        resource_line = 0
        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname == "SETUP_FINALLY":
                has_finally = True
            if opname == "LOAD_GLOBAL" and str(arg) == "GeneratorExit":
                has_close_check = True
            if opname in {"LOAD_GLOBAL", "LOAD_NAME"} and str(arg) == "open":
                has_resource_open = True
                resource_line = current_line
        if has_resource_open and not has_finally and not has_close_check:
            warnings.append(
                ResourceWarning(
                    kind="GENERATOR_RESOURCE_LEAK",
                    file=file_path,
                    line=resource_line,
                    resource_kind=ResourceKind.GENERATOR,
                    resource_name="generator",
                    message=(
                        "Generator opens resources but has no cleanup code. "
                        "If generator is not fully consumed, resources may leak."
                    ),
                    severity="warning",
                )
            )
        return warnings


class ResourceAnalyzer:
    """
    High-level interface for resource leak detection.
    """

    def __init__(self) -> None:
        self.leak_detector = ResourceLeakDetector()
        self.context_analyzer = ContextManagerAnalyzer()
        self.cycle_detector = ReferenceCycleDetector()
        self.lock_analyzer = LockSafetyAnalyzer()
        self.generator_analyzer = GeneratorCleanupAnalyzer()

    def analyze_function(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Analyze a function for resource issues."""
        warnings: list[ResourceWarning] = []
        warnings.extend(self.leak_detector.detect(code, file_path))
        warnings.extend(self.context_analyzer.analyze(code, file_path))
        warnings.extend(self.cycle_detector.detect(code, file_path))
        warnings.extend(self.lock_analyzer.analyze(code, file_path))
        warnings.extend(self.generator_analyzer.analyze(code, file_path))
        return warnings

    def analyze_module(
        self,
        module_code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Analyze all functions in a module."""
        warnings: list[ResourceWarning] = []
        warnings.extend(self.analyze_function(module_code, file_path))
        self._analyze_nested(module_code, file_path, warnings)
        return warnings

    def _analyze_nested(
        self,
        code: CodeType,
        file_path: str,
        warnings: list[ResourceWarning],
    ) -> None:
        """Recursively analyze nested functions."""
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                warnings.extend(self.analyze_function(const, file_path))
                self._analyze_nested(const, file_path, warnings)

    def analyze_file(self, file_path: str) -> list[ResourceWarning]:
        """Analyze a file for resource issues."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            code = compile(source, file_path, "exec")
            return self.analyze_module(code, file_path)
        except (OSError, SyntaxError):
            logger.debug("Resource analysis failed for file %s", file_path, exc_info=True)
            return []

