"""
Taint Analysis for PySpectre.
This module provides taint tracking to identify security vulnerabilities
and data flow issues. It tracks how data from untrusted sources flows
through the program and alerts when it reaches sensitive sinks.
Features:
- Source identification (user input, network, files)
- Sink identification (SQL queries, system calls, eval)
- Taint propagation through operations
- Sanitizer recognition
- Path-sensitive taint tracking
"""

from __future__ import annotations
import dis
from dataclasses import dataclass, field
from enum import Enum, Flag, auto
from typing import (
    Any,
)
from .flow_sensitive import (
    BasicBlock,
    CFGBuilder,
    ControlFlowGraph,
    DataFlowAnalysis,
)


class TaintKind(Flag):
    """Categories of taint for security analysis."""

    NONE = 0
    USER_INPUT = auto()
    NETWORK = auto()
    FILE = auto()
    DATABASE = auto()
    ENVIRONMENT = auto()
    COMMAND_LINE = auto()
    EXTERNAL_API = auto()
    UNTRUSTED = USER_INPUT | NETWORK | EXTERNAL_API
    EXTERNAL = FILE | DATABASE | ENVIRONMENT | COMMAND_LINE
    ANY_SOURCE = UNTRUSTED | EXTERNAL


class SinkKind(Enum):
    """Categories of sensitive sinks."""

    EVAL = auto()
    IMPORT = auto()
    CODE_EXEC = auto()
    SYSTEM_CALL = auto()
    FILE_WRITE = auto()
    FILE_PATH = auto()
    SQL_QUERY = auto()
    SQL_EXECUTE = auto()
    HTML_OUTPUT = auto()
    URL_REDIRECT = auto()
    COOKIE = auto()
    HEADER = auto()
    NETWORK_SEND = auto()
    LOG = auto()
    PRINT = auto()
    DESERIALIZE = auto()


@dataclass(frozen=True)
class TaintLabel:
    """
    A label describing the taint status of a value.
    Tracks the source and path of tainted data.
    """

    kind: TaintKind
    source: str | None = None
    source_line: int | None = None
    path: tuple[str, ...] = ()

    def propagate(self, operation: str) -> TaintLabel:
        """Create new label with operation added to path."""
        return TaintLabel(
            kind=self.kind,
            source=self.source,
            source_line=self.source_line,
            path=self.path + (operation,),
        )

    def merge_with(self, other: TaintLabel) -> TaintLabel:
        """Merge two taint labels."""
        return TaintLabel(
            kind=self.kind | other.kind,
            source=self.source or other.source,
            source_line=self.source_line or other.source_line,
            path=self.path if len(self.path) >= len(other.path) else other.path,
        )

    @property
    def is_tainted(self) -> bool:
        """Check if this label indicates tainted data."""
        return self.kind != TaintKind.NONE

    @property
    def is_untrusted(self) -> bool:
        """Check if taint is from untrusted source."""
        return bool(self.kind & TaintKind.UNTRUSTED)


@dataclass
class TaintedValue:
    """A value with its taint information."""

    value_name: str
    labels: set[TaintLabel] = field(default_factory=set)
    confidence: float = 1.0

    def add_label(self, label: TaintLabel) -> None:
        """Add a taint label."""
        self.labels.add(label)

    def merge_labels(self, other: TaintedValue) -> None:
        """Merge labels from another tainted value."""
        for label in other.labels:
            self.labels.add(label)

    @property
    def is_tainted(self) -> bool:
        """Check if value has any taint."""
        return any(label.is_tainted for label in self.labels)

    @property
    def taint_kinds(self) -> TaintKind:
        """Get combined taint kinds."""
        result = TaintKind.NONE
        for label in self.labels:
            result |= label.kind
        return result


@dataclass
class TaintSource:
    """Definition of a taint source."""

    name: str
    kind: TaintKind
    arg_indices: set[int] = field(default_factory=set)
    return_tainted: bool = True
    description: str = ""


@dataclass
class TaintSink:
    """Definition of a sensitive sink."""

    name: str
    kind: SinkKind
    arg_indices: set[int] = field(default_factory=set)
    description: str = ""
    severity: str = "high"


@dataclass
class Sanitizer:
    """Definition of a sanitizer that removes/reduces taint."""

    name: str
    removes_kinds: TaintKind
    sanitizes_arg: int = 0
    description: str = ""


class TaintDefinitions:
    """Pre-defined sources, sinks, and sanitizers."""

    SOURCES: list[TaintSource] = [
        TaintSource("input", TaintKind.USER_INPUT, description="User keyboard input"),
        TaintSource(
            "raw_input", TaintKind.USER_INPUT, description="User keyboard input (Python 2)"
        ),
        TaintSource("request.GET", TaintKind.USER_INPUT, description="HTTP GET parameters"),
        TaintSource("request.POST", TaintKind.USER_INPUT, description="HTTP POST data"),
        TaintSource("request.args", TaintKind.USER_INPUT, description="Flask request args"),
        TaintSource("request.form", TaintKind.USER_INPUT, description="Flask form data"),
        TaintSource("request.data", TaintKind.USER_INPUT, description="Request body data"),
        TaintSource("request.json", TaintKind.USER_INPUT, description="JSON request body"),
        TaintSource("request.cookies", TaintKind.USER_INPUT, description="Cookies"),
        TaintSource("request.headers", TaintKind.USER_INPUT, description="HTTP headers"),
        TaintSource("read", TaintKind.FILE, description="File read"),
        TaintSource("readline", TaintKind.FILE, description="File readline"),
        TaintSource("readlines", TaintKind.FILE, description="File readlines"),
        TaintSource("recv", TaintKind.NETWORK, description="Socket receive"),
        TaintSource("recvfrom", TaintKind.NETWORK, description="Socket recvfrom"),
        TaintSource("urlopen", TaintKind.NETWORK, description="URL open"),
        TaintSource("get", TaintKind.NETWORK, description="HTTP GET (requests)"),
        TaintSource("post", TaintKind.NETWORK, description="HTTP POST (requests)"),
        TaintSource("fetchone", TaintKind.DATABASE, description="DB fetch one row"),
        TaintSource("fetchall", TaintKind.DATABASE, description="DB fetch all rows"),
        TaintSource("fetchmany", TaintKind.DATABASE, description="DB fetch many rows"),
        TaintSource("getenv", TaintKind.ENVIRONMENT, description="Environment variable"),
        TaintSource("environ", TaintKind.ENVIRONMENT, description="Environment dict"),
        TaintSource("sys.argv", TaintKind.COMMAND_LINE, description="Command line args"),
    ]
    SINKS: list[TaintSink] = [
        TaintSink(
            "eval", SinkKind.EVAL, {0}, description="Arbitrary code execution", severity="critical"
        ),
        TaintSink(
            "exec", SinkKind.EVAL, {0}, description="Arbitrary code execution", severity="critical"
        ),
        TaintSink(
            "compile", SinkKind.CODE_EXEC, {0}, description="Code compilation", severity="high"
        ),
        TaintSink(
            "__import__", SinkKind.IMPORT, {0}, description="Dynamic import", severity="high"
        ),
        TaintSink(
            "system",
            SinkKind.SYSTEM_CALL,
            {0},
            description="System command execution",
            severity="critical",
        ),
        TaintSink(
            "popen", SinkKind.SYSTEM_CALL, {0}, description="Process open", severity="critical"
        ),
        TaintSink(
            "spawn", SinkKind.SYSTEM_CALL, {0}, description="Process spawn", severity="critical"
        ),
        TaintSink(
            "call", SinkKind.SYSTEM_CALL, {0}, description="Subprocess call", severity="critical"
        ),
        TaintSink("run", SinkKind.SYSTEM_CALL, {0}, description="Subprocess run", severity="high"),
        TaintSink(
            "Popen", SinkKind.SYSTEM_CALL, {0}, description="Subprocess Popen", severity="high"
        ),
        TaintSink("open", SinkKind.FILE_PATH, {0}, description="File path", severity="medium"),
        TaintSink("write", SinkKind.FILE_WRITE, {0}, description="File write", severity="medium"),
        TaintSink(
            "execute", SinkKind.SQL_EXECUTE, {0}, description="SQL execution", severity="critical"
        ),
        TaintSink(
            "executemany",
            SinkKind.SQL_EXECUTE,
            {0},
            description="SQL batch execution",
            severity="critical",
        ),
        TaintSink(
            "executescript",
            SinkKind.SQL_EXECUTE,
            {0},
            description="SQL script execution",
            severity="critical",
        ),
        TaintSink(
            "render_template_string",
            SinkKind.HTML_OUTPUT,
            {0},
            description="Template injection",
            severity="high",
        ),
        TaintSink(
            "Markup", SinkKind.HTML_OUTPUT, {0}, description="HTML markup", severity="medium"
        ),
        TaintSink(
            "redirect", SinkKind.URL_REDIRECT, {0}, description="URL redirect", severity="medium"
        ),
        TaintSink("set_cookie", SinkKind.COOKIE, {1}, description="Cookie setting", severity="low"),
        TaintSink(
            "loads", SinkKind.DESERIALIZE, {0}, description="Deserialization", severity="critical"
        ),
        TaintSink(
            "load",
            SinkKind.DESERIALIZE,
            {0},
            description="Deserialization from file",
            severity="critical",
        ),
        TaintSink(
            "pickle.loads",
            SinkKind.DESERIALIZE,
            {0},
            description="Pickle loads",
            severity="critical",
        ),
        TaintSink(
            "yaml.load",
            SinkKind.DESERIALIZE,
            {0},
            description="YAML load (unsafe)",
            severity="critical",
        ),
        TaintSink("log", SinkKind.LOG, {0}, description="Logging", severity="low"),
        TaintSink("print", SinkKind.PRINT, {0}, description="Print output", severity="info"),
    ]
    SANITIZERS: list[Sanitizer] = [
        Sanitizer("escape", TaintKind.USER_INPUT, description="HTML escape"),
        Sanitizer("html.escape", TaintKind.USER_INPUT, description="HTML escape"),
        Sanitizer("cgi.escape", TaintKind.USER_INPUT, description="CGI escape"),
        Sanitizer("markupsafe.escape", TaintKind.USER_INPUT, description="MarkupSafe escape"),
        Sanitizer("quote", TaintKind.USER_INPUT, description="SQL quote"),
        Sanitizer("int", TaintKind.USER_INPUT, description="Integer conversion"),
        Sanitizer("float", TaintKind.USER_INPUT, description="Float conversion"),
        Sanitizer("bool", TaintKind.USER_INPUT, description="Boolean conversion"),
        Sanitizer("basename", TaintKind.USER_INPUT, description="Path basename"),
        Sanitizer("normpath", TaintKind.USER_INPUT, description="Path normalization"),
        Sanitizer("realpath", TaintKind.USER_INPUT, description="Real path"),
        Sanitizer("abspath", TaintKind.USER_INPUT, description="Absolute path"),
    ]


@dataclass
class TaintState:
    """
    Tracks taint status of all values at a program point.
    """

    variables: dict[str, TaintedValue] = field(default_factory=dict)
    stack: list[TaintedValue] = field(default_factory=list)

    def copy(self) -> TaintState:
        """Create a copy of this state."""
        new_state = TaintState()
        new_state.variables = {
            k: TaintedValue(v.value_name, set(v.labels), v.confidence)
            for k, v in self.variables.items()
        }
        new_state.stack = [
            TaintedValue(v.value_name, set(v.labels), v.confidence) for v in self.stack
        ]
        return new_state

    def get_taint(self, var_name: str) -> TaintedValue:
        """Get taint info for a variable."""
        if var_name not in self.variables:
            self.variables[var_name] = TaintedValue(var_name)
        return self.variables[var_name]

    def set_taint(self, var_name: str, tainted: TaintedValue) -> None:
        """Set taint info for a variable."""
        self.variables[var_name] = tainted

    def is_tainted(self, var_name: str) -> bool:
        """Check if a variable is tainted."""
        if var_name in self.variables:
            return self.variables[var_name].is_tainted
        return False

    def push(self, tainted: TaintedValue) -> None:
        """Push tainted value onto stack."""
        self.stack.append(tainted)

    def pop(self) -> TaintedValue:
        """Pop tainted value from stack."""
        if self.stack:
            return self.stack.pop()
        return TaintedValue("_unknown")

    def peek(self, depth: int = 0) -> TaintedValue | None:
        """Peek at stack value."""
        idx = -(depth + 1)
        if abs(idx) <= len(self.stack):
            return self.stack[idx]
        return None

    def merge_with(self, other: TaintState) -> TaintState:
        """Merge two taint states (for control flow merge)."""
        result = TaintState()
        all_vars = set(self.variables.keys()) | set(other.variables.keys())
        for var in all_vars:
            self_taint = self.variables.get(var)
            other_taint = other.variables.get(var)
            if self_taint and other_taint:
                merged = TaintedValue(var)
                merged.labels = self_taint.labels | other_taint.labels
                merged.confidence = min(self_taint.confidence, other_taint.confidence)
                result.variables[var] = merged
            elif self_taint:
                result.variables[var] = TaintedValue(
                    var, set(self_taint.labels), self_taint.confidence
                )
            elif other_taint:
                result.variables[var] = TaintedValue(
                    var, set(other_taint.labels), other_taint.confidence
                )
        return result

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TaintState):
            return False
        return self.variables == other.variables


@dataclass
class TaintViolation:
    """A detected taint flow from source to sink."""

    source: TaintLabel
    sink: TaintSink
    sink_line: int
    sink_pc: int
    file: str
    variable_name: str
    path_description: str

    def format(self) -> str:
        """Format the violation for display."""
        source_desc = self.source.source or "unknown source"
        return (
            f"[TAINT] {self.sink.severity.upper()}: {self.sink.kind.name}\n"
            f"  Tainted data from {source_desc} (line {self.source.source_line})\n"
            f"  reaches {self.sink.name} at line {self.sink_line}\n"
            f"  via: {' -> '.join(self.source.path) or 'direct'}"
        )


class TaintAnalyzer:
    """
    Analyzes bytecode for taint flow violations.
    Tracks how tainted data flows through the program and
    reports when it reaches sensitive sinks.
    """

    def __init__(self) -> None:
        self.sources = {s.name: s for s in TaintDefinitions.SOURCES}
        self.sinks = {s.name: s for s in TaintDefinitions.SINKS}
        self.sanitizers = {s.name: s for s in TaintDefinitions.SANITIZERS}
        self.violations: list[TaintViolation] = []

    def analyze_function(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[TaintViolation]:
        """Analyze a function for taint violations."""
        self.violations = []
        instructions = list(dis.get_instructions(code))
        if not instructions:
            return []
        state = TaintState()
        current_line = code.co_firstlineno
        for instr in instructions:
            if instr.starts_line:
                current_line = instr.starts_line
            self._process_instruction(instr, state, current_line, file_path)
        return self.violations

    def _process_instruction(
        self,
        instr: dis.Instruction,
        state: TaintState,
        line: int,
        file_path: str,
    ) -> None:
        """Process a single instruction for taint analysis."""
        opname = instr.opname
        arg = instr.argval
        if opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
            var_name = arg
            tainted = state.get_taint(var_name)
            state.push(TaintedValue(var_name, set(tainted.labels), tainted.confidence))
        elif opname == "LOAD_CONST":
            state.push(TaintedValue(f"const_{arg}"))
        elif opname == "LOAD_ATTR":
            attr_name = arg
            obj_taint = state.pop()
            full_name = f"{obj_taint.value_name}.{attr_name}"
            source = self._find_source(attr_name) or self._find_source(full_name)
            if source:
                label = TaintLabel(
                    kind=source.kind,
                    source=source.description or source.name,
                    source_line=line,
                )
                result = TaintedValue(full_name)
                result.add_label(label)
                state.push(result)
            else:
                result = TaintedValue(full_name)
                for label in obj_taint.labels:
                    result.add_label(label.propagate(f".{attr_name}"))
                state.push(result)
        elif opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
            var_name = arg
            if state.stack:
                tainted = state.pop()
                tainted.value_name = var_name
                state.set_taint(var_name, tainted)
        elif opname == "BINARY_OP":
            if len(state.stack) >= 2:
                right = state.pop()
                left = state.pop()
                result = TaintedValue(f"({left.value_name} {instr.argrepr} {right.value_name})")
                for label in left.labels:
                    result.add_label(label.propagate(f"op:{instr.argrepr}"))
                for label in right.labels:
                    result.add_label(label.propagate(f"op:{instr.argrepr}"))
                state.push(result)
        elif opname == "FORMAT_VALUE":
            if state.stack:
                value = state.pop()
                result = TaintedValue(f"format({value.value_name})")
                for label in value.labels:
                    result.add_label(label.propagate("format"))
                state.push(result)
        elif opname == "BUILD_STRING":
            count = arg or 0
            parts = []
            for _ in range(count):
                if state.stack:
                    parts.append(state.pop())
            result = TaintedValue("string")
            for part in parts:
                for label in part.labels:
                    result.add_label(label.propagate("concat"))
            state.push(result)
        elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
            self._handle_call(instr, state, line, file_path)
        elif opname == "BINARY_SUBSCR":
            if len(state.stack) >= 2:
                index = state.pop()
                container = state.pop()
                result = TaintedValue(f"{container.value_name}[{index.value_name}]")
                for label in container.labels:
                    result.add_label(label.propagate("subscript"))
                state.push(result)
        elif opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET"}:
            count = arg or 0
            elements = []
            for _ in range(count):
                if state.stack:
                    elements.append(state.pop())
            result = TaintedValue(opname.replace("BUILD_", "").lower())
            for elem in elements:
                for label in elem.labels:
                    result.add_label(label.propagate("collect"))
            state.push(result)
        elif opname == "BUILD_MAP":
            count = arg or 0
            for _ in range(count * 2):
                if state.stack:
                    state.pop()
            state.push(TaintedValue("dict"))
        elif opname == "POP_TOP":
            if state.stack:
                state.pop()
        elif opname == "DUP_TOP":
            if state.stack:
                top = state.peek()
                if top:
                    state.push(TaintedValue(top.value_name, set(top.labels), top.confidence))
        elif opname == "ROT_TWO":
            if len(state.stack) >= 2:
                a = state.pop()
                b = state.pop()
                state.push(a)
                state.push(b)
        elif opname == "RETURN_VALUE":
            pass

    def _handle_call(
        self,
        instr: dis.Instruction,
        state: TaintState,
        line: int,
        file_path: str,
    ) -> None:
        """Handle function call for taint analysis."""
        arg_count = instr.argval if instr.argval is not None else instr.arg or 0
        args: list[TaintedValue] = []
        for _ in range(arg_count):
            if state.stack:
                args.insert(0, state.pop())
        func_taint = state.pop() if state.stack else TaintedValue("unknown_func")
        func_name = func_taint.value_name
        source = self._find_source(func_name)
        if source:
            label = TaintLabel(
                kind=source.kind,
                source=source.description or source.name,
                source_line=line,
            )
            result = TaintedValue(f"{func_name}()")
            result.add_label(label)
            state.push(result)
            return
        sink = self._find_sink(func_name)
        if sink:
            for idx in sink.arg_indices:
                if idx < len(args) and args[idx].is_tainted:
                    for label in args[idx].labels:
                        violation = TaintViolation(
                            source=label,
                            sink=sink,
                            sink_line=line,
                            sink_pc=instr.offset,
                            file=file_path,
                            variable_name=args[idx].value_name,
                            path_description=" -> ".join(label.path),
                        )
                        self.violations.append(violation)
        sanitizer = self._find_sanitizer(func_name)
        if sanitizer and args:
            idx = sanitizer.sanitizes_arg
            if idx < len(args):
                arg = args[idx]
                new_labels = set()
                for label in arg.labels:
                    if not (label.kind & sanitizer.removes_kinds):
                        new_labels.add(label)
                result = TaintedValue(f"{func_name}({arg.value_name})")
                result.labels = new_labels
                state.push(result)
                return
        result = TaintedValue(f"{func_name}()")
        for arg in args:
            for label in arg.labels:
                result.add_label(label.propagate(f"call:{func_name}"))
        for label in func_taint.labels:
            result.add_label(label.propagate(f"call:{func_name}"))
        state.push(result)

    def _find_source(self, name: str) -> TaintSource | None:
        """Find a taint source by name."""
        if name in self.sources:
            return self.sources[name]
        base_name = name.split(".")[-1]
        if base_name in self.sources:
            return self.sources[base_name]
        return None

    def _find_sink(self, name: str) -> TaintSink | None:
        """Find a taint sink by name."""
        if name in self.sinks:
            return self.sinks[name]
        base_name = name.split(".")[-1]
        if base_name in self.sinks:
            return self.sinks[base_name]
        return None

    def _find_sanitizer(self, name: str) -> Sanitizer | None:
        """Find a sanitizer by name."""
        if name in self.sanitizers:
            return self.sanitizers[name]
        base_name = name.split(".")[-1]
        if base_name in self.sanitizers:
            return self.sanitizers[base_name]
        return None

    def add_source(self, source: TaintSource) -> None:
        """Add a custom taint source."""
        self.sources[source.name] = source

    def add_sink(self, sink: TaintSink) -> None:
        """Add a custom taint sink."""
        self.sinks[sink.name] = sink

    def add_sanitizer(self, sanitizer: Sanitizer) -> None:
        """Add a custom sanitizer."""
        self.sanitizers[sanitizer.name] = sanitizer


class TaintFlowAnalysis(DataFlowAnalysis[TaintState]):
    """
    Flow-sensitive taint analysis using the data flow framework.
    """

    def __init__(
        self,
        cfg: ControlFlowGraph,
        analyzer: TaintAnalyzer,
        file_path: str = "<unknown>",
    ) -> None:
        super().__init__(cfg)
        self.analyzer = analyzer
        self.file_path = file_path

    def initial_value(self) -> TaintState:
        return TaintState()

    def boundary_value(self) -> TaintState:
        return TaintState()

    def transfer(self, block: BasicBlock, in_fact: TaintState) -> TaintState:
        """Transfer function: process block for taint."""
        state = in_fact.copy()
        current_line = block.start_pc
        for instr in block.instructions:
            if instr.starts_line:
                current_line = instr.starts_line
            self.analyzer._process_instruction(instr, state, current_line, self.file_path)
        return state

    def meet(self, facts: list[TaintState]) -> TaintState:
        """Merge taint states from multiple paths."""
        if not facts:
            return TaintState()
        result = facts[0].copy()
        for state in facts[1:]:
            result = result.merge_with(state)
        return result


class TaintChecker:
    """
    High-level interface for taint checking.
    """

    def __init__(self) -> None:
        self.analyzer = TaintAnalyzer()

    def check_function(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[TaintViolation]:
        """Check a function for taint violations."""
        return self.analyzer.analyze_function(code, file_path)

    def check_flow_sensitive(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[TaintViolation]:
        """Check with flow-sensitive analysis."""
        builder = CFGBuilder()
        cfg = builder.build(code)
        analysis = TaintFlowAnalysis(cfg, self.analyzer, file_path)
        analysis.analyze()
        return self.analyzer.violations

    def add_source(self, name: str, kind: TaintKind, description: str = "") -> None:
        """Add a custom taint source."""
        self.analyzer.add_source(TaintSource(name, kind, description=description))

    def add_sink(
        self, name: str, kind: SinkKind, arg_indices: set[int], description: str = ""
    ) -> None:
        """Add a custom taint sink."""
        self.analyzer.add_sink(TaintSink(name, kind, arg_indices, description=description))

    def add_sanitizer(self, name: str, removes_kinds: TaintKind, description: str = "") -> None:
        """Add a custom sanitizer."""
        self.analyzer.add_sanitizer(Sanitizer(name, removes_kinds, description=description))
