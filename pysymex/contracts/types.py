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

"""Contract type definitions for pysymex.

This module defines the complete type system for the contract verification
subsystem.  Every type is frozen and slotted for immutability, cache
friendliness, and thread safety.

Design principles:
  - Contracts accept ``Callable[..., z3.BoolRef | bool] | str`` predicates
  - Callable predicates are compiled via **symbolic tracing** (zero AST)
  - String predicates are compiled via ``ConditionTranslator`` (backward compat)
  - All value types are ``frozen=True, slots=True``
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Union

import z3


def _default_counterexample() -> dict[str, object]:
    """Return default empty counterexample mapping."""
    return {}


def _default_contract_list() -> list[Contract]:
    """Return default empty contract list."""
    return []


def _default_loop_invariants() -> dict[int, list[Contract]]:
    """Return default empty loop-invariant mapping."""
    return {}


def _default_old_values() -> dict[str, str]:
    """Return default empty old-value mapping."""
    return {}


class ContractKind(Enum):
    """Classification of contract clauses.

    Each kind maps to a specific set of bytecode injection points where the
    contract constraint is evaluated during symbolic execution.
    """

    REQUIRES = auto()
    """Precondition — evaluated at ``FRAME_ENTRY``."""

    ENSURES = auto()
    """Postcondition — evaluated at every ``FRAME_EXIT``."""

    INVARIANT = auto()
    """Class invariant — evaluated at mutation points (``STORE_ATTR``, etc.)."""

    LOOP_INVARIANT = auto()
    """Loop invariant — evaluated at loop back-edges."""

    ASSUMES = auto()
    """Assumption — asserted without proof (narrows input space)."""

    ASSIGNS = auto()
    """Frame condition — declares which locations a function may modify."""

    PURE = auto()
    """Pure marker — function has no side effects, enables memoisation."""

    ASSERT = auto()
    """Inline assertion — checked at the specific program point."""


class VerificationResult(Enum):
    """Outcome of a single contract verification query."""

    VERIFIED = auto()
    """The contract holds for all reachable paths."""

    VIOLATED = auto()
    """A concrete counterexample was found."""

    UNKNOWN = auto()
    """Solver returned ``unknown`` (timeout or undecidable)."""

    UNREACHABLE = auto()
    """The contract's precondition is unsatisfiable on this path."""


class Severity(Enum):
    """How critical a contract violation is."""

    ERROR = auto()
    """Hard failure — the analysis should flag this prominently."""

    WARNING = auto()
    """Soft failure — the user should review but may be intentional."""


class InjectionPoint(Enum):
    """Bytecode instruction categories for contract injection.

    Each contract kind attaches to a subset of these injection points.
    Injection occurs inside the dispatcher's instruction loop — not via
    bytecode rewriting or monkey-patching.
    """

    FRAME_ENTRY = "RESUME"
    """Function entry (``RESUME`` on 3.11+, first ``LOAD_FAST`` otherwise)."""

    FRAME_EXIT = "RETURN_VALUE"
    """Function exit (``RETURN_VALUE``, ``RETURN_CONST``)."""

    STORE_LOCAL = "STORE_FAST"
    """Local variable mutation (``STORE_FAST``, ``STORE_DEREF``)."""

    STORE_ATTR = "STORE_ATTR"
    """Object mutation (``STORE_ATTR``, ``STORE_SUBSCR``)."""

    CALL_SITE = "CALL"
    """Function call (``CALL``, ``CALL_FUNCTION_EX``)."""


class EffectKind(Enum):
    """Side-effect classification for a function's contract annotation."""

    PURE = auto()
    """No side effects — same inputs always produce same outputs."""

    READS = auto()
    """Reads specific locations but does not write."""

    WRITES = auto()
    """Writes to specific locations."""


ContractPredicate = Union[Callable[..., "z3.BoolRef | bool"], str]
"""A contract predicate is either:

- A **callable** that, when invoked with Z3 symbolic variables, returns a
  ``z3.BoolRef`` via Python operator overloading (zero-AST symbolic tracing).
- A **string** expression that is parsed via ``ConditionTranslator`` into Z3
  (backward-compatible AST path).
"""


@dataclass(frozen=True, slots=True)
class Contract:
    """A single contract clause attached to a function or class.

    Attributes:
        kind: Classification of this contract (REQUIRES, ENSURES, etc.).
        predicate: The constraint source — callable or string.
        message: Human-readable description shown in violation reports.
        severity: ERROR or WARNING.
        line_number: Source line where the contract was declared (if known).
        _condition_repr: Cached string representation of the predicate for
            display purposes.
    """

    kind: ContractKind
    predicate: ContractPredicate
    message: str = ""
    severity: Severity = Severity.ERROR
    line_number: int | None = None
    _condition_repr: str = ""

    def __post_init__(self) -> None:
        """Compute the display-friendly condition representation."""
        if not self._condition_repr:
            if isinstance(self.predicate, str):
                repr_val = self.predicate
            else:
                repr_val = getattr(
                    self.predicate,
                    "__qualname__",
                    getattr(self.predicate, "__name__", repr(self.predicate)),
                )
            object.__setattr__(self, "_condition_repr", repr_val)

    @property
    def condition(self) -> str:
        """Backward-compatible condition string.

        For string predicates this is the predicate itself.
        For callable predicates this is the qualname/repr.
        """
        return self._condition_repr

    def compile(self, symbols: dict[str, z3.ExprRef]) -> z3.BoolRef:
        """Compile this contract's predicate to a Z3 boolean expression.

        Delegates to :class:`ContractCompiler` which selects the symbolic
        tracing path (callable) or AST path (string) automatically.
        """
        from pysymex.contracts.compiler import ContractCompiler

        return ContractCompiler.compile_predicate(self.predicate, symbols)


@dataclass(frozen=True, slots=True)
class ContractViolation:
    """Immutable record of a contract violation.

    Attributes:
        kind: Which contract kind was violated.
        condition: Display string for the violated condition.
        message: Human-readable description.
        line_number: Source line of the contract declaration.
        function_name: Qualified name of the function under analysis.
        counterexample: Concrete variable assignments demonstrating violation.
        bytecode_offset: Offset of the bytecode instruction at violation point.
    """

    kind: ContractKind
    condition: str
    message: str
    line_number: int | None = None
    function_name: str | None = None
    counterexample: dict[str, object] = field(default_factory=_default_counterexample)
    bytecode_offset: int | None = None

    def format(self) -> str:
        """Format this violation for human-readable display."""
        location = f" at line {self.line_number}" if self.line_number else ""
        func = f" in {self.function_name}" if self.function_name else ""
        offset = f" (offset 0x{self.bytecode_offset:02X})" if self.bytecode_offset else ""
        result = f"[{self.kind.name}]{func}{location}{offset}: {self.message}\n"
        result += f"  Condition: {self.condition}\n"
        if self.counterexample:
            result += "  Counterexample:\n"
            for var, val in self.counterexample.items():
                result += f"    {var} = {val}\n"
        return result


@dataclass
class FunctionContract:
    """Complete contract specification for a single function.

    Aggregates all contract clauses — preconditions, postconditions,
    invariants, assumptions, frame conditions, and effect annotations —
    into a single lookup structure keyed by the function's qualified name.

    Attributes:
        function_name: Simple name of the function.
        preconditions: ``@requires`` contracts.
        postconditions: ``@ensures`` contracts.
        loop_invariants: ``@loop_invariant`` contracts keyed by PC offset.
        assumptions: ``@assumes`` contracts.
        assigns_set: Frozenset of location strings from ``@assigns``.
        effect_type: ``EffectKind.PURE`` if ``@pure`` was applied.
        old_values: Mapping of variable names for ``old(x)`` references.
        result_var: Symbolic name bound to the return value (``__result__``).
    """

    function_name: str
    preconditions: list[Contract] = field(default_factory=_default_contract_list)
    postconditions: list[Contract] = field(default_factory=_default_contract_list)
    loop_invariants: dict[int, list[Contract]] = field(default_factory=_default_loop_invariants)
    assumptions: list[Contract] = field(default_factory=_default_contract_list)
    assigns_set: frozenset[str] = frozenset()
    effect_type: EffectKind = EffectKind.WRITES
    old_values: dict[str, str] = field(default_factory=_default_old_values)
    result_var: str = "__result__"

    def add_precondition(
        self,
        predicate: ContractPredicate,
        message: str | None = None,
        line: int | None = None,
        severity: Severity = Severity.ERROR,
    ) -> None:
        """Append a precondition contract."""
        condition_str = predicate if isinstance(predicate, str) else ""
        self.preconditions.append(
            Contract(
                kind=ContractKind.REQUIRES,
                predicate=predicate,
                message=message or f"Precondition: {condition_str or '<callable>'}",
                severity=severity,
                line_number=line,
            )
        )

    def add_postcondition(
        self,
        predicate: ContractPredicate,
        message: str | None = None,
        line: int | None = None,
        severity: Severity = Severity.ERROR,
    ) -> None:
        """Append a postcondition contract."""
        condition_str = predicate if isinstance(predicate, str) else ""
        self.postconditions.append(
            Contract(
                kind=ContractKind.ENSURES,
                predicate=predicate,
                message=message or f"Postcondition: {condition_str or '<callable>'}",
                severity=severity,
                line_number=line,
            )
        )

    def add_assumption(
        self,
        predicate: ContractPredicate,
        message: str | None = None,
        line: int | None = None,
    ) -> None:
        """Append an assumption contract."""
        condition_str = predicate if isinstance(predicate, str) else ""
        self.assumptions.append(
            Contract(
                kind=ContractKind.ASSUMES,
                predicate=predicate,
                message=message or f"Assumption: {condition_str or '<callable>'}",
                line_number=line,
            )
        )

    def add_loop_invariant(
        self,
        pc: int,
        predicate: ContractPredicate,
        message: str | None = None,
        line: int | None = None,
    ) -> None:
        """Append a loop invariant at a specific program counter."""
        condition_str = predicate if isinstance(predicate, str) else ""
        if pc not in self.loop_invariants:
            self.loop_invariants[pc] = []
        self.loop_invariants[pc].append(
            Contract(
                kind=ContractKind.LOOP_INVARIANT,
                predicate=predicate,
                message=message or f"Loop invariant: {condition_str or '<callable>'}",
                line_number=line,
            )
        )

    def set_assigns(self, locations: frozenset[str]) -> None:
        """Set the assigns frame condition."""
        object.__setattr__(self, "assigns_set", locations)

    def set_pure(self) -> None:
        """Mark this function as pure (no side effects)."""
        self.effect_type = EffectKind.PURE


__all__ = [
    "Contract",
    "ContractKind",
    "ContractPredicate",
    "ContractViolation",
    "EffectKind",
    "FunctionContract",
    "InjectionPoint",
    "Severity",
    "VerificationResult",
]
