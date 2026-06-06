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

"""Core issue, severity, and detector metadata types.

Defines :class:`IssueKind`, :class:`Severity`, :class:`Issue` (the canonical
bug report dataclass), :class:`CounterexampleExtractor`, and
:class:`DetectorInfo` used throughout the detector framework.
"""

from __future__ import annotations

import dis
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors.detector.counterexample import CounterexampleExtractor

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

DisInstruction = dis.Instruction
IsSatFn = Callable[[list[z3.BoolRef]], bool]
GetModelFn = Callable[[list[z3.BoolRef]], z3.ModelRef | None]


def empty_constraints() -> list[z3.BoolRef]:
    """Create a typed empty constraint list for Issue defaults."""
    return []


if TYPE_CHECKING:
    DetectorFn = Callable[["VMState", dis.Instruction, IsSatFn], "Issue | None"]
else:
    DetectorFn = Callable[..., object]
"""Signature for a pure detector function."""


class IssueKind(Enum):
    """All issue kinds that pysymex detectors can emit."""

    DIVISION_BY_ZERO = auto()
    MODULO_BY_ZERO = auto()
    ASSERTION_ERROR = auto()
    INDEX_ERROR = auto()
    KEY_ERROR = auto()
    TYPE_ERROR = auto()
    ATTRIBUTE_ERROR = auto()
    OVERFLOW = auto()
    NULL_DEREFERENCE = auto()
    INFINITE_LOOP = auto()
    UNREACHABLE_CODE = auto()
    DEAD_CODE = auto()
    UNHANDLED_EXCEPTION = auto()
    CONTRACT_VIOLATION = auto()
    RECURSION_LIMIT = auto()
    NEGATIVE_SQRT = auto()
    INVALID_ARGUMENT = auto()
    INJECTION = auto()
    FORMAT_STRING_INJECTION = auto()
    RESOURCE_LEAK = auto()
    VALUE_ERROR = auto()
    UNBOUND_VARIABLE = auto()
    NAME_ERROR = auto()
    LOGICAL_CONTRADICTION = auto()
    RUNTIME_ERROR = auto()
    EXCEPTION = auto()
    SYNTAX_ERROR = auto()
    UNKNOWN = auto()


class Severity(Enum):
    """User-facing severity levels for :class:`Issue` findings.

    ``CRITICAL`` / ``HIGH`` / ``MEDIUM`` / ``LOW`` are structured finding
    levels. ``ERROR`` / ``WARNING`` / ``INFO`` / ``HINT`` support contract and
    diagnostic reporting surfaces that use message-oriented levels.
    """

    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    ERROR = auto()
    WARNING = auto()
    INFO = auto()
    HINT = auto()


@dataclass(frozen=True, slots=True)
class Issue:
    """Immutable record of a single bug finding produced by a detector.

    Captures the issue kind, message, solver evidence (constraints +
    model), source location, confidence, and optional suppression reason.
    Counterexamples are extracted lazily from the Z3 model on first call
    to :meth:`get_counterexample`.

    Attributes:
        kind: The :class:`IssueKind` of this finding.
        message: Human-readable description.
        constraints: Path constraints at the time of detection.
        model: Z3 model satisfying the bug constraint, or a pre-built dict.
        pc: Bytecode offset of the triggering instruction.
        confidence: Certainty score in ``[0, 1]``.
        suppression_reason: Non-``None`` when the issue has been suppressed.
    """

    kind: IssueKind
    message: str
    constraints: list[z3.BoolRef] = field(default_factory=empty_constraints)
    model: z3.ModelRef | dict[str, object] | None = None
    pc: int = 0
    line_number: int | None = None
    function_name: str | None = None
    filename: str | None = None
    stack_trace: tuple[str, ...] = ()
    class_name: str | None = None
    full_path: str | None = None
    counterexample: dict[str, object] | None = None
    is_caught: bool = False
    confidence: float = 1.0
    likelihood: float = 1.0
    severity: Severity | None = None
    file: str = ""
    line: int = 0
    column: int | None = None
    explanation: str | None = None
    related_code: str | None = None
    fix_suggestion: str | None = None
    detector_name: str | None = None
    suppression_reason: str | None = None

    def is_suppressed(self) -> bool:
        """Return True when the issue carries an explicit suppression reason."""
        return self.suppression_reason is not None

    def get_counterexample(self) -> dict[str, object]:
        """Return a counterexample dict extracted from the Z3 model.

        Uses a pre-set :attr:`counterexample` if available, then delegates
        to :class:`CounterexampleExtractor`.  Returns ``{}`` when no model
        is present.
        """
        if self.counterexample is not None:
            return self.counterexample
        if self.model is None:
            return {}
        return CounterexampleExtractor(self.model, self.constraints).extract()

    def format(self) -> str:
        """Format this issue as a human-readable string for display."""
        if self.severity is not None:
            sev = self.severity.name.lower()
            kind = self.kind.name.replace("_", " ").lower()
            loc = f"{self.file}:{self.line}"
            if self.column:
                loc += f":{self.column}"
            conf = f" ({self.confidence:.0%} confident)" if self.confidence < 1.0 else ""
            return f"[{sev}] {kind} at {loc}{conf}: {self.message}"

        lines = [f"[{self.kind.name}] {self.message}"]
        if self.filename or self.line_number or self.function_name:
            location: list[str] = []
            if self.filename:
                location.append(self.filename)
            if self.function_name:
                location.append(f"in {self.function_name}()")
            if self.line_number:
                location.append(f"line {self.line_number}")
            lines.append(f"  Location: {', '.join(location)}")
        if self.pc:
            lines.append(f"  PC: {self.pc}")
        counterexample = self.get_counterexample()
        if counterexample:
            lines.append("  Counterexample:")
            for name, value in sorted(counterexample.items()):
                lines.append(f"    {name} = {value}")
        if self.stack_trace:
            lines.append("  Stack trace:")
            for frame in self.stack_trace:
                lines.append(f"    {frame}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        """Serialise this issue to a JSON-safe dictionary."""
        return {
            "kind": self.kind.name,
            "message": self.message,
            "pc": self.pc,
            "line_number": self.line_number,
            "function_name": self.function_name,
            "filename": self.filename,
            "counterexample": self.get_counterexample(),
            "stack_trace": self.stack_trace,
            "severity": self.severity.name if self.severity is not None else None,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "explanation": self.explanation,
            "fix_suggestion": self.fix_suggestion,
            "detector_name": self.detector_name,
            "suppression_reason": self.suppression_reason,
        }


@dataclass(frozen=True, slots=True)
class DetectorInfo:
    """Immutable metadata describing a detector (name, kind, opcodes)."""

    name: str
    description: str
    issue_kind: IssueKind
    relevant_opcodes: frozenset[str] = frozenset()


__all__ = [
    "DetectorFn",
    "DetectorInfo",
    "DisInstruction",
    "GetModelFn",
    "IsSatFn",
    "Issue",
    "IssueKind",
    "Severity",
]
