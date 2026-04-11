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

"""Taint analysis for pysymex.
This module provides taint tracking to identify data flows from
untrusted sources to sensitive sinks, useful for security analysis.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto

__all__ = [
    "TaintAnalyzer",
    "TaintFlow",
    "TaintLabel",
    "TaintPolicy",
    "TaintSink",
    "TaintSource",
    "TaintTracker",
    "TaintedValue",
]


class TaintSource(Enum):
    """Types of taint sources."""

    USER_INPUT = auto()
    FILE_READ = auto()
    NETWORK = auto()
    DATABASE = auto()
    ENVIRONMENT = auto()
    COMMAND_LINE = auto()
    DESERIALIZATION = auto()
    EXTERNAL_API = auto()


class TaintSink(Enum):
    """Types of sensitive sinks."""

    SQL_QUERY = auto()
    COMMAND_EXEC = auto()
    FILE_WRITE = auto()
    FILE_PATH = auto()
    NETWORK_SEND = auto()
    HTML_OUTPUT = auto()
    EVAL = auto()
    DESERIALIZE = auto()
    LDAP_QUERY = auto()
    XPATH_QUERY = auto()
    LOG_OUTPUT = auto()


@dataclass(frozen=True)
class TaintLabel:
    """Immutable taint label."""

    source: TaintSource
    origin: str = ""
    line_number: int = 0

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        if self.origin:
            return f"{self.source.name}({self.origin}@{self.line_number})"
        return self.source.name


@dataclass(frozen=True, slots=True)
class TaintedValue:
    """A value with associated taint labels."""

    value: object
    labels: frozenset[TaintLabel] = field(default_factory=frozenset[TaintLabel])

    def is_tainted(self) -> bool:
        """Check if this value is tainted."""
        return len(self.labels) > 0

    def with_taint(self, label: TaintLabel) -> TaintedValue:
        """Create new value with additional taint label."""
        return TaintedValue(
            value=self.value,
            labels=self.labels | {label},
        )

    def merge_taint(self, other: TaintedValue) -> TaintedValue:
        """Create new value with combined taint from both operands."""
        return TaintedValue(
            value=self.value,
            labels=self.labels | other.labels,
        )

    @staticmethod
    def clean(value: object) -> TaintedValue:
        """Create an untainted value."""
        return TaintedValue(value=value, labels=frozenset())

    @staticmethod
    def tainted(
        value: object, source: TaintSource, origin: str = "", line: int = 0
    ) -> TaintedValue:
        """Create a tainted value."""
        label = TaintLabel(source=source, origin=origin, line_number=line)
        return TaintedValue(value=value, labels=frozenset({label}))


@dataclass(frozen=True, slots=True)
class TaintFlow:
    """Represents a flow of tainted data to a sink."""

    source_labels: frozenset[TaintLabel]
    sink: TaintSink
    sink_location: str
    sink_line: int
    path: tuple[str, ...] = ()

    def format(self) -> str:
        """Format the taint flow for display."""
        sources = ", ".join(str(lb) for lb in self.source_labels)
        lines = [
            "Taint Flow Detected:",
            f"  Sources: {sources}",
            f"  Sink: {self.sink.name} at {self.sink_location}:{self.sink_line}",
        ]
        if self.path:
            lines.append(f"  Path: {' -> '.join(self.path)}")
        return "\n".join(lines)


class TaintPolicy:
    """Defines which source-sink combinations are dangerous."""

    def __init__(self) -> None:
        self._dangerous_flows: set[tuple[TaintSource, TaintSink]] = set()
        self._sanitizers: dict[tuple[TaintSource, TaintSink], set[str]] = {}
        self._setup_default_policy()

    def _setup_default_policy(self) -> None:
        """Set up default dangerous flow rules."""
        self._dangerous_flows.add((TaintSource.USER_INPUT, TaintSink.SQL_QUERY))
        self._dangerous_flows.add((TaintSource.NETWORK, TaintSink.SQL_QUERY))
        self._dangerous_flows.add((TaintSource.USER_INPUT, TaintSink.COMMAND_EXEC))
        self._dangerous_flows.add((TaintSource.NETWORK, TaintSink.COMMAND_EXEC))
        self._dangerous_flows.add((TaintSource.FILE_READ, TaintSink.COMMAND_EXEC))
        self._dangerous_flows.add((TaintSource.USER_INPUT, TaintSink.FILE_PATH))
        self._dangerous_flows.add((TaintSource.NETWORK, TaintSink.FILE_PATH))
        self._dangerous_flows.add((TaintSource.USER_INPUT, TaintSink.HTML_OUTPUT))
        self._dangerous_flows.add((TaintSource.DATABASE, TaintSink.HTML_OUTPUT))
        self._dangerous_flows.add((TaintSource.USER_INPUT, TaintSink.EVAL))
        self._dangerous_flows.add((TaintSource.NETWORK, TaintSink.EVAL))
        self._dangerous_flows.add((TaintSource.DESERIALIZATION, TaintSink.EVAL))
        self._dangerous_flows.add((TaintSource.USER_INPUT, TaintSink.DESERIALIZE))
        self._dangerous_flows.add((TaintSource.NETWORK, TaintSink.DESERIALIZE))

    def is_dangerous(self, source: TaintSource, sink: TaintSink) -> bool:
        """Evaluate if a specific source-sink flow is prohibited by this policy.

        **Policy Evaluation:**
        A flow is considered dangerous if its `TaintSource` (where data entered
        the system) is associated with the `TaintSink` (where data is consumed)
        in the internal threat model. PySyMex defaults to a conservative
        policy, blocking flows from volatile sources (User Input, Network)
        to execution-class sinks (SQL, Shell, Eval).

        Returns:
            True if the flow represents a potential security vulnerability.
        """
        return (source, sink) in self._dangerous_flows

    def add_sanitizer(
        self,
        source: TaintSource,
        sink: TaintSink,
        sanitizer: str,
    ) -> None:
        """Register a sanitizer function for a source-sink pair."""
        key = (source, sink)
        if key not in self._sanitizers:
            self._sanitizers[key] = set()
        self._sanitizers[key].add(sanitizer)

    def get_sanitizers(
        self,
        source: TaintSource,
        sink: TaintSink,
    ) -> set[str]:
        """Get sanitizers for a source-sink pair."""
        return self._sanitizers.get((source, sink), set())


class TaintTracker:
    """Tracks taint propagation during symbolic execution.

    Note: taint tracking uses ``id(value)`` as the object key. In CPython,
    ``id()`` values can be reused after garbage collection â€” a newly-allocated
    object may occupy the same memory address as a previously-sanitized object,
    causing it to be incorrectly considered tainted (or untainted). This is a
    known Python limitation for ``id()``-based identity tracking. For
    production use, add an explicit per-object taint attribute instead.
    """

    SOURCE_FUNCTIONS = {
        "input": TaintSource.USER_INPUT,
        "raw_input": TaintSource.USER_INPUT,
        "sys.argv": TaintSource.COMMAND_LINE,
        "os.environ": TaintSource.ENVIRONMENT,
        "open": TaintSource.FILE_READ,
        "read": TaintSource.FILE_READ,
        "readline": TaintSource.FILE_READ,
        "readlines": TaintSource.FILE_READ,
        "recv": TaintSource.NETWORK,
        "recvfrom": TaintSource.NETWORK,
        "urlopen": TaintSource.NETWORK,
        "requests.get": TaintSource.NETWORK,
        "requests.post": TaintSource.NETWORK,
        "pickle.load": TaintSource.DESERIALIZATION,
        "pickle.loads": TaintSource.DESERIALIZATION,
        "json.load": TaintSource.EXTERNAL_API,
        "yaml.load": TaintSource.DESERIALIZATION,
    }
    SINK_FUNCTIONS = {
        "execute": TaintSink.SQL_QUERY,
        "executemany": TaintSink.SQL_QUERY,
        "cursor.execute": TaintSink.SQL_QUERY,
        "os.system": TaintSink.COMMAND_EXEC,
        "os.popen": TaintSink.COMMAND_EXEC,
        "subprocess.call": TaintSink.COMMAND_EXEC,
        "subprocess.run": TaintSink.COMMAND_EXEC,
        "subprocess.Popen": TaintSink.COMMAND_EXEC,
        "eval": TaintSink.EVAL,
        "exec": TaintSink.EVAL,
        "compile": TaintSink.EVAL,
        "open": TaintSink.FILE_PATH,
        "send": TaintSink.NETWORK_SEND,
        "sendall": TaintSink.NETWORK_SEND,
        "write": TaintSink.FILE_WRITE,
        "print": TaintSink.LOG_OUTPUT,
        "logging.info": TaintSink.LOG_OUTPUT,
        "logging.error": TaintSink.LOG_OUTPUT,
    }
    SANITIZERS = {
        "escape": {"html", "sql"},
        "quote": {"sql"},
        "html.escape": {"html"},
        "shlex.quote": {"command"},
        "os.path.basename": {"path"},
        "int": {"sql", "command"},
        "float": {"sql"},
        "str.isalnum": {"sql", "command"},
    }

    def __init__(self, policy: TaintPolicy | None = None) -> None:
        self.policy = policy or TaintPolicy()
        self._flows: list[TaintFlow] = []
        self._taint_map: dict[int, TaintedValue] = {}
        self._sanitized: set[int] = set()

    def fork(self) -> TaintTracker:
        """Create an independent copy for state forking.

        The ``TaintPolicy`` is shared (read-only after setup).  The mutable
        containers are shallow-copied so mutations in one fork don't leak to
        the other.  ``TaintedValue`` and ``TaintFlow`` objects inside the
        containers are effectively immutable, so shallow copies are sufficient.
        """
        new = TaintTracker.__new__(TaintTracker)
        new.policy = self.policy
        new._flows = list(self._flows)
        new._taint_map = dict(self._taint_map)
        new._sanitized = set(self._sanitized)
        return new

    def mark_tainted(
        self,
        value: object,
        source: TaintSource,
        origin: str = "",
        line: int = 0,
    ) -> TaintedValue:
        """Mark a value as tainted."""
        tainted = TaintedValue.tainted(value, source, origin, line)
        self._taint_map[id(value)] = tainted
        return tainted

    def get_taint(self, value: object) -> TaintedValue | None:
        """Get taint information for a value."""
        return self._taint_map.get(id(value))

    def is_tainted(self, value: object) -> bool:
        """Check if a value is tainted."""
        taint = self.get_taint(value)
        return taint is not None and taint.is_tainted()

    def propagate_taint(
        self,
        result: object,
        *operands: object,
    ) -> TaintedValue:
        """Propagate taint labels from operands to a derivation result.

        **Propagation Algebra:**
        The result of an operation inherits the union of all taint labels
        associated with its operands: `Labels(Result) = âˆª Labels(Operand_i)`.
        This enables 'tracking through' transformations like string
        concatenation or numeric arithmetic.

        Args:
            result: The new object representing the result of the operation.
            operands: The source objects involved in the operation.

        Returns:
            A `TaintedValue` wrapper for the result (also cached internally).
        """
        labels: set[TaintLabel] = set()
        for op in operands:
            taint = self.get_taint(op)
            if taint:
                labels.update(taint.labels)
        tainted = TaintedValue(value=result, labels=frozenset(labels))
        self._taint_map[id(result)] = tainted
        return tainted

    def check_sink(
        self,
        sink: TaintSink,
        *args: object,
        location: str = "",
        line: int = 0,
    ) -> list[TaintFlow]:
        """Check sink."""
        flows: list[TaintFlow] = []
        for arg in args:
            taint = self.get_taint(arg)
            if taint and taint.is_tainted():
                for label in taint.labels:
                    if self.policy.is_dangerous(label.source, sink):
                        if id(arg) not in self._sanitized:
                            flow = TaintFlow(
                                source_labels=taint.labels,
                                sink=sink,
                                sink_location=location,
                                sink_line=line,
                            )
                            flows.append(flow)
                            self._flows.append(flow)
        return flows

    def mark_sanitized(self, value: object) -> None:
        """Mark a value as sanitized."""
        self._sanitized.add(id(value))

    def get_all_flows(self) -> list[TaintFlow]:
        """Get all detected taint flows."""
        return self._flows.copy()

    def clear(self) -> None:
        """Reset all taint tracking state."""
        self._flows.clear()
        self._taint_map.clear()
        self._sanitized.clear()


class TaintAnalyzer:
    """High-level taint analysis interface."""

    def __init__(self, policy: TaintPolicy | None = None) -> None:
        self.tracker = TaintTracker(policy)

    def analyze_function(
        self,
        func: Callable[..., object],
        tainted_params: dict[str, TaintSource] | None = None,
    ) -> list[TaintFlow]:
        """Analyze a function for taint flows.
        Args:
            func: The function to analyze
            tainted_params: Mapping of parameter names to taint sources
        Returns:
            List of detected taint flows
        """
        from pysymex.execution.executors import SymbolicExecutor

        self.tracker.clear()
        if tainted_params:
            for param, source in tainted_params.items():
                self.tracker.mark_tainted(
                    param,
                    source,
                    origin=param,
                    line=0,
                )
        executor = SymbolicExecutor()
        executor.execute_function(func)
        return self.tracker.get_all_flows()


__all__ = [
    "TaintAnalyzer",
    "TaintFlow",
    "TaintLabel",
    "TaintPolicy",
    "TaintSink",
    "TaintSource",
    "TaintTracker",
    "TaintedValue",
]


