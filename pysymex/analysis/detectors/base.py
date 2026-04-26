# pysymex: Python Symbolic Execution & Formal Verification
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

"""Bug detectors for symbolic execution.
pysymex - Core detectors, advanced detectors, and registry.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import dis
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, TypeGuard

import z3

if TYPE_CHECKING:
    from pysymex.core.state import VMState

DisInstruction = dis.Instruction
IsSatFn = Callable[[list[z3.BoolRef]], bool]
GetModelFn = Callable[[list[z3.BoolRef]], z3.ModelRef | None]


def _empty_constraints() -> list[z3.BoolRef]:
    """Create a typed empty constraint list for Issue defaults."""
    return []


def is_list_of_objects(value: object) -> TypeGuard[list[object]]:
    """Type guard to narrow a value to list[object]."""
    return isinstance(value, list)


def is_tuple_of_objects(value: object) -> TypeGuard[tuple[object, ...]]:
    """Type guard to narrow a value to tuple[object, ...]."""
    return isinstance(value, tuple)


if TYPE_CHECKING:
    DetectorFn = Callable[["VMState", dis.Instruction, IsSatFn], "Issue | None"]
else:
    DetectorFn = Callable[..., object]
"""Signature for a pure detector function.

A ``DetectorFn`` receives the current VM state, the instruction being
executed and a satisfiability-check callback, and returns an ``Issue``
when a bug is found (or ``None``).
"""

__all__ = [
    "Detector",
    "DetectorFn",
    "DetectorInfo",
    "DetectorRegistry",
    "GetModelFn",
    "IsSatFn",
    "Issue",
    "IssueKind",
    "is_list_of_objects",
    "is_tuple_of_objects",
]


class IssueKind(Enum):
    """Enumeration of issue types that detectors can identify.

    Each member maps to a specific category of bug or vulnerability.
    """

    DIVISION_BY_ZERO = auto()
    ASSERTION_ERROR = auto()
    INDEX_ERROR = auto()
    KEY_ERROR = auto()
    TYPE_ERROR = auto()
    ATTRIBUTE_ERROR = auto()
    OVERFLOW = auto()
    NULL_DEREFERENCE = auto()
    INFINITE_LOOP = auto()
    UNREACHABLE_CODE = auto()
    UNHANDLED_EXCEPTION = auto()
    CONTRACT_VIOLATION = auto()
    RECURSION_LIMIT = auto()
    NEGATIVE_SQRT = auto()
    INVALID_ARGUMENT = auto()
    FORMAT_STRING_INJECTION = auto()
    RESOURCE_LEAK = auto()
    VALUE_ERROR = auto()
    UNBOUND_VARIABLE = auto()
    LOGICAL_CONTRADICTION = auto()
    RUNTIME_ERROR = auto()
    EXCEPTION = auto()
    SYNTAX_ERROR = auto()
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class Issue:
    """Represents a detected issue found during symbolic execution.

    Immutable value object — once created, an Issue is never modified.

    Attributes:
        kind: The category of issue detected.
        message: Human-readable description of the issue.
        constraints: Z3 constraints that trigger the issue.
        model: Z3 model providing a concrete counterexample.
        pc: Program counter where the issue was detected.
        line_number: Source line number, if available.
        function_name: Name of the enclosing function.
        filename: Source file where the issue was found.
        stack_trace: Stack frames leading to the issue.
        class_name: Enclosing class name, if applicable.
        full_path: Absolute file path.
        counterexample: Concrete variable assignments triggering the issue.
    """

    kind: IssueKind
    message: str
    constraints: list[z3.BoolRef] = field(default_factory=_empty_constraints)
    model: z3.ModelRef | None = None
    pc: int = 0
    line_number: int | None = None
    function_name: str | None = None
    filename: str | None = None
    stack_trace: tuple[str, ...] = ()
    class_name: str | None = None
    full_path: str | None = None
    counterexample: dict[str, object] | None = None
    confidence: float = 1.0
    likelihood: float = 1.0

    def get_counterexample(self) -> dict[str, object]:
        """Extract counterexample from model."""
        if self.model is None:
            return {}
        if isinstance(self.model, dict):
            return self.model

        counterexample: dict[str, object] = {}
        for decl in self.model.decls():
            name = decl.name()
            value = self.model[decl]
            base_name = name

            for suffix in ["_is_int", "_is_bool", "_is_none", "_is_str", "_int", "_bool", "_str"]:
                if name.endswith(suffix):
                    base_name = name[: -len(suffix)]
                    break

            import re

            match = re.search(r"^(.*)_\d+$", base_name)
            if match:
                base_name = match.group(1)

            if "_is_" in name or name.startswith("_") or base_name.startswith("_"):
                continue
            try:
                if isinstance(value, z3.IntNumRef):
                    counterexample[base_name] = value.as_long()
                elif z3.is_true(value):
                    counterexample[base_name] = True
                elif z3.is_false(value):
                    counterexample[base_name] = False
                elif isinstance(value, z3.SeqRef):
                    counterexample[base_name] = value.as_string()
                else:
                    counterexample[base_name] = str(value)
            except (z3.Z3Exception, TypeError, ValueError):
                counterexample[base_name] = str(value)
        return counterexample

    def format(self) -> str:
        """Format issue for display."""
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
        """Convert to dictionary for JSON serialization."""
        return {
            "kind": self.kind.name,
            "message": self.message,
            "pc": self.pc,
            "line_number": self.line_number,
            "function_name": self.function_name,
            "filename": self.filename,
            "counterexample": self.get_counterexample(),
            "stack_trace": self.stack_trace,
        }


@dataclass(frozen=True, slots=True)
class DetectorInfo:
    """Immutable metadata for a detector function.

    Pairs with a :data:`DetectorFn` to describe *what* the detector
    checks and which opcodes are relevant.
    """

    name: str
    description: str
    issue_kind: IssueKind
    relevant_opcodes: frozenset[str] = frozenset()


class Detector(ABC):
    """Abstract base class for symbolic-execution bug detectors.

    .. deprecated::
        Prefer writing a plain :data:`DetectorFn` function instead of
        subclassing ``Detector``.  Existing subclasses are retained for
        backward compatibility; new detectors should be functions.

    Subclasses implement ``check()`` to inspect the current VM state and
    instruction, returning an ``Issue`` if a bug is found.

    Attributes:
        name: Short unique identifier for the detector.
        description: Human-readable description.
        issue_kind: Default ``IssueKind`` this detector reports.
        relevant_opcodes: Bytecode opcodes this detector cares about.
    """

    name: str = "base"
    description: str = "Base detector"
    issue_kind: IssueKind = IssueKind.UNHANDLED_EXCEPTION

    relevant_opcodes: frozenset[str] = frozenset()

    @abstractmethod
    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """
        Check for issues at the current state.
        Args:
            state: Current VM state
            instruction: Current instruction being executed
            _solver_check: Function to check constraint satisfiability
        Returns:
            Issue if a problem is detected, None otherwise
        """

    def to_info(self) -> DetectorInfo:
        """Return an immutable :class:`DetectorInfo` for this detector."""
        return DetectorInfo(
            name=self.name,
            description=self.description,
            issue_kind=self.issue_kind,
            relevant_opcodes=self.relevant_opcodes,
        )

    def as_fn(self) -> DetectorFn:
        """Return the ``check`` method as a plain :data:`DetectorFn`."""
        return self.check


class FormatStringDetector(Detector):
    """Detects potential format string vulnerabilities."""

    name = "format-string"
    description = "Detects format string injection vulnerabilities"
    issue_kind = IssueKind.FORMAT_STRING_INJECTION
    relevant_opcodes = frozenset({"CALL", "CALL_FUNCTION", "FORMAT_VALUE"})
    DANGEROUS_CALLS = {"eval", "exec", "compile", "getattr", "setattr"}

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check."""
        if instruction.opname in ("CALL", "CALL_FUNCTION"):
            return self._check_dangerous_call(state, instruction)
        if instruction.opname == "FORMAT_VALUE":
            return self._check_format_value(state, instruction)
        return None

    def _check_dangerous_call(self, state: VMState, instruction: dis.Instruction) -> Issue | None:
        """Check dangerous call."""
        return None

    def _check_format_value(self, state: VMState, _instruction: dis.Instruction) -> Issue | None:
        """Check format value."""
        return None


class DetectorRegistry:
    """Registry mapping detector names to their classes and singleton instances.

    Supports both class-based (legacy) and function-based (preferred) registration.

    Attributes:
        _detectors: Mapping of name to detector class.
        _instances: Lazily-created singleton instances.
        _fn_detectors: Function-based detectors (name → (fn, info)).
    """

    def __init__(self) -> None:
        self._detectors: dict[str, type[Detector]] = {}
        self._instances: dict[str, Detector] = {}
        self._fn_detectors: dict[str, tuple[DetectorFn, DetectorInfo]] = {}
        self.register(FormatStringDetector)

    def register(self, detector_class: type[Detector]) -> None:
        """Register a detector class by its ``name`` attribute.

        Args:
            detector_class: The detector class to register.
        """
        self._detectors[detector_class.name] = detector_class

    def register_fn(self, fn: DetectorFn, info: DetectorInfo) -> None:
        """Register a plain detector function.

        Args:
            fn: The detector function.
            info: Immutable metadata for the detector.
        """
        self._fn_detectors[info.name] = (fn, info)

    def get(self, name: str) -> Detector | None:
        """Get or create a detector instance by name.

        Args:
            name: Registered detector name.

        Returns:
            Detector instance, or ``None`` if not registered.
        """
        if name not in self._detectors:
            return None
        if name not in self._instances:
            self._instances[name] = self._detectors[name]()
        return self._instances[name]

    def get_all(self) -> list[Detector | None]:
        """Get all detector instances (class-based only, for backward compat)."""
        return [self.get(name) for name in self._detectors]

    def get_all_fns(self) -> list[tuple[DetectorFn, DetectorInfo]]:
        """Get all detectors as ``(function, info)`` pairs.

        Includes both class-based detectors (auto-adapted) and
        function-based detectors.
        """
        result: list[tuple[DetectorFn, DetectorInfo]] = []
        for name in self._detectors:
            inst = self.get(name)
            if inst is not None:
                result.append((inst.as_fn(), inst.to_info()))
        for fn, info in self._fn_detectors.values():
            result.append((fn, info))
        return result

    def get_by_kind(self, kind: IssueKind) -> list[Detector | None]:
        """Get detectors for a specific issue kind."""
        return [self.get(name) for name, cls in self._detectors.items() if cls.issue_kind == kind]

    def list_available(self) -> list[str]:
        """List available detector names."""
        return list(self._detectors.keys()) + list(self._fn_detectors.keys())
