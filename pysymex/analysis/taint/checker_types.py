"""Taint analysis types — enums, dataclasses, definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, Flag, auto

__all__ = [
    "Sanitizer",
    "SinkKind",
    "TaintDefinitions",
    "TaintKind",
    "TaintLabel",
    "TaintSink",
    "TaintSource",
    "TaintState",
    "TaintViolation",
    "TaintedValue",
]


class TaintKind(Flag):
    """Bit-flag categories of taint for security analysis.

    Composite members (``UNTRUSTED``, ``EXTERNAL``, ``ANY_SOURCE``) are
    pre-defined unions for convenient matching.
    """

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
    """Categories of sensitive sinks that should not receive tainted data."""

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
    """Label describing the taint status and provenance of a value.

    Attributes:
        kind: Taint category flags.
        source: Human-readable origin description.
        source_line: Source line where taint was introduced.
        path: Ordered sequence of operations the taint passed through.
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
    """A program value annotated with its taint labels.

    Attributes:
        value_name: Variable or expression name.
        labels: Set of ``TaintLabel`` instances.
        confidence: Detection confidence in ``[0, 1]``.
    """

    value_name: str
    labels: set[TaintLabel] = field(default_factory=set[TaintLabel])
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


@dataclass(frozen=True, slots=True)
class TaintSource:
    """Definition of a taint source function or attribute.

    Attributes:
        name: Function/attribute name (e.g. ``"input"``).
        kind: Taint category flag.
        arg_indices: Argument indices that receive taint.
        return_tainted: Whether the return value is tainted.
        description: Human-readable description.
    """

    name: str
    kind: TaintKind
    arg_indices: set[int] = field(default_factory=set[int])
    return_tainted: bool = True
    description: str = ""


@dataclass(frozen=True, slots=True)
class TaintSink:
    """Definition of a sensitive sink that must not receive tainted data.

    Attributes:
        name: Function/method name (e.g. ``"eval"``).
        kind: Sink category.
        arg_indices: Argument positions that are sensitive.
        description: Human-readable description.
        severity: Severity level string (``"critical"``, ``"high"``, etc.).
    """

    name: str
    kind: SinkKind
    arg_indices: set[int] = field(default_factory=set[int])
    description: str = ""
    severity: str = "high"


@dataclass(frozen=True, slots=True)
class Sanitizer:
    """Definition of a sanitizer that removes or reduces taint.

    Attributes:
        name: Sanitizer function name.
        removes_kinds: Taint kinds this sanitizer removes.
        sanitizes_arg: Index of the argument being sanitized.
        description: Human-readable description.
    """

    name: str
    removes_kinds: TaintKind
    sanitizes_arg: int = 0
    description: str = ""


class TaintDefinitions:
    """Pre-defined sources, sinks, and sanitizers for common frameworks.

    Class-level attributes ``SOURCES``, ``SINKS``, and ``SANITIZERS``
    store the canonical definitions used by ``TaintAnalyzer``.
    """

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
        TaintSource("requests.get", TaintKind.NETWORK, description="HTTP GET (requests)"),
        TaintSource("requests.post", TaintKind.NETWORK, description="HTTP POST (requests)"),
        TaintSource("session.get", TaintKind.NETWORK, description="HTTP GET (session)"),
        TaintSource("session.post", TaintKind.NETWORK, description="HTTP POST (session)"),
        TaintSource("httpx.get", TaintKind.NETWORK, description="HTTP GET (httpx)"),
        TaintSource("httpx.post", TaintKind.NETWORK, description="HTTP POST (httpx)"),
        TaintSource("client.get", TaintKind.NETWORK, description="HTTP GET (client)"),
        TaintSource("client.post", TaintKind.NETWORK, description="HTTP POST (client)"),
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

    variables: dict[str, TaintedValue] = field(default_factory=dict[str, TaintedValue])
    stack: list[TaintedValue] = field(default_factory=list[TaintedValue])

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


@dataclass(frozen=True, slots=True)
class TaintViolation:
    """A detected taint flow from source to sink."""

    source: TaintLabel
    sink: TaintSink
    sink_line: int
    sink_pc: int
    file: str
    variable_name: str
    path_description: str
    kind: object = None

    def format(self) -> str:
        """Format the violation for multi-line display."""
        source_desc = self.source.source or "unknown source"
        return (
            f"[TAINT] {self .sink .severity .upper ()}: {self .sink .kind .name }\n"
            f"  Tainted data from {source_desc } (line {self .source .source_line })\n"
            f"  reaches {self .sink .name } at line {self .sink_line }\n"
            f"  via: {' -> '.join (self .source .path )or 'direct'}"
        )

    def __str__(self) -> str:
        """Human-readable single-line summary."""
        source_desc = self.source.source or "unknown source"
        path_desc = " -> ".join(self.source.path) if self.source.path else "direct"
        return (
            f"Tainted data from '{source_desc }' (line {self .source .source_line }) "
            f"flows to {self .sink .kind .name } sink '{self .sink .name }' "
            f"at line {self .sink_line } via {path_desc }"
        )
