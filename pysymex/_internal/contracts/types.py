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

"""Shared contract records and predicate types.

Defines :class:`~pysymex._internal.contracts.types.Contract`,
:class:`~pysymex._internal.contracts.types.FunctionContract`, and related structures consumed by
decorators, the compiler, injector, and verifier. Compilation and solver queries are
implemented in :mod:`pysymex._internal.contracts.compiler` and
:mod:`pysymex._internal.contracts.verifier` respectively.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import cast

import z3

from pysymex._internal.contracts.binding.receivers import receiver_proxy_for_symbols
from pysymex._internal.contracts.enums import ContractKind, ContractSeverity, EffectKind


def _default_counterexample() -> dict[str, object]:
    """Return default empty counterexample mapping."""
    return {}


def _default_contract_list() -> list[Contract]:
    """Return default empty contract list."""
    return []


def _default_loop_invariants() -> dict[int, list[Contract]]:
    """Return default empty loop-invariant mapping."""
    return {}


# Callable traced with Z3 overloads, or a string parsed by ConditionTranslator.
ContractPredicate = Callable[..., z3.BoolRef | bool] | str


@dataclass(frozen=True, slots=True)
class Contract:
    """One compileable contract clause (precondition, postcondition, etc.)."""

    kind: ContractKind
    predicate: ContractPredicate
    message: str = ""
    severity: ContractSeverity = ContractSeverity.ERROR
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
        """Return the condition display string.

        Returns:
            For string predicates, returns the predicate itself. For callable
            predicates, returns the function qualname/representation.

        """
        return self._condition_repr

    def compile(self, symbols: Mapping[str, z3.ExprRef]) -> z3.BoolRef:
        """Compile this contract's predicate to a Z3 boolean expression.

        Delegates to :class:`ContractCompiler` which automatically selects either the
        symbolic tracing path (callable) or AST path (string).

        Args:
            symbols: Mapping of variable names to active Z3 variable terms.

        Returns:
            A ``z3.BoolRef`` representing the compiled constraint.

        """
        from pysymex._internal.contracts.compiler import ContractCompiler

        compile_symbols = dict(symbols)
        if not callable(self.predicate):
            return ContractCompiler.compile_predicate(self.predicate, compile_symbols)

        try:
            parameters = list(inspect.signature(self.predicate).parameters.values())
        except (TypeError, ValueError):
            parameters = []

        if self.kind is ContractKind.ENSURES and "__result__" in symbols:
            try:
                first_parameter = parameters[0].name
            except IndexError:
                first_parameter = None
            if first_parameter is not None:
                compile_symbols.setdefault(first_parameter, symbols["__result__"])

        for parameter in parameters:
            receiver_proxy = receiver_proxy_for_symbols(symbols, parameter.name)
            if receiver_proxy is not None:
                compile_symbols[parameter.name] = cast("z3.ExprRef", receiver_proxy)
        return ContractCompiler.compile_predicate(self.predicate, compile_symbols)


@dataclass(frozen=True, slots=True)
class ContractViolation:
    """Immutable violation report with optional solver counterexample."""

    kind: ContractKind
    condition: str
    message: str
    line_number: int | None = None
    function_name: str | None = None
    counterexample: dict[str, object] = field(default_factory=_default_counterexample)
    bytecode_offset: int | None = None
    severity: ContractSeverity = ContractSeverity.ERROR

    def format(self) -> str:
        """Format this violation for human-readable display.

        Returns:
            A formatted multi-line string containing the violation classification,
            location, message, and counterexample assignment.

        """
        location = f" at line {self.line_number}" if self.line_number else ""
        func = f" in {self.function_name}" if self.function_name else ""
        offset = f" (offset 0x{self.bytecode_offset:02X})" if self.bytecode_offset else ""
        warning = "[WARNING] " if self.severity is ContractSeverity.WARNING else ""
        result = f"{warning}[{self.kind.name}]{func}{location}{offset}: {self.message}\n"
        result += f"  Condition: {self.condition}\n"
        if self.counterexample:
            result += "  Counterexample:\n"
            for var, val in self.counterexample.items():
                result += f"    {var} = {val}\n"
        return result


@dataclass(slots=True)
class FunctionContract:
    """Mutable aggregate of all clauses registered for one function."""

    function_name: str
    preconditions: list[Contract] = field(default_factory=_default_contract_list)
    postconditions: list[Contract] = field(default_factory=_default_contract_list)
    loop_invariants: dict[int, list[Contract]] = field(default_factory=_default_loop_invariants)
    assumptions: list[Contract] = field(default_factory=_default_contract_list)
    assigns_set: frozenset[str] = frozenset()
    assigns_declared: bool = False
    effect_type: EffectKind = EffectKind.WRITES

    def add_precondition(
        self,
        predicate: ContractPredicate,
        message: str | None = None,
        line: int | None = None,
        severity: ContractSeverity = ContractSeverity.ERROR,
    ) -> None:
        """Append a precondition contract clause.

        Args:
            predicate: Precondition predicate (callable or string).
            message: Optional narrative message.
            line: Optional line number.
            severity: Violation severity level.

        Side Effects:
            Appends a new ``Contract`` to the ``preconditions`` list.

        """
        condition_str = predicate if isinstance(predicate, str) else ""
        self.preconditions.append(
            Contract(
                kind=ContractKind.REQUIRES,
                predicate=predicate,
                message=message or f"Precondition: {condition_str or '<callable>'}",
                severity=severity,
                line_number=line,
            ),
        )

    def add_postcondition(
        self,
        predicate: ContractPredicate,
        message: str | None = None,
        line: int | None = None,
        severity: ContractSeverity = ContractSeverity.ERROR,
    ) -> None:
        """Append a postcondition contract clause.

        Args:
            predicate: Postcondition predicate (callable or string).
            message: Optional narrative message.
            line: Optional line number.
            severity: Violation severity level.

        Side Effects:
            Appends a new ``Contract`` to the ``postconditions`` list.

        """
        condition_str = predicate if isinstance(predicate, str) else ""
        self.postconditions.append(
            Contract(
                kind=ContractKind.ENSURES,
                predicate=predicate,
                message=message or f"Postcondition: {condition_str or '<callable>'}",
                severity=severity,
                line_number=line,
            ),
        )

    def add_assumption(
        self,
        predicate: ContractPredicate,
        message: str | None = None,
        line: int | None = None,
    ) -> None:
        """Append an assumption contract clause.

        Args:
            predicate: Assumption predicate (callable or string).
            message: Optional narrative message.
            line: Optional line number.

        Side Effects:
            Appends a new ``Contract`` to the ``assumptions`` list.

        """
        condition_str = predicate if isinstance(predicate, str) else ""
        self.assumptions.append(
            Contract(
                kind=ContractKind.ASSUMES,
                predicate=predicate,
                message=message or f"Assumption: {condition_str or '<callable>'}",
                line_number=line,
            ),
        )

    def add_loop_invariant(
        self,
        pc: int,
        predicate: ContractPredicate,
        message: str | None = None,
        line: int | None = None,
    ) -> None:
        """Append a loop invariant clause at a specific program counter offset.

        Args:
            pc: The program counter offset where the loop invariant is checked.
            predicate: Loop invariant predicate (callable or string).
            message: Optional narrative message.
            line: Optional line number.

        Side Effects:
            Adds a new ``Contract`` to the ``loop_invariants`` mapping for the key ``pc``.

        """
        condition_str = predicate if isinstance(predicate, str) else ""
        if pc not in self.loop_invariants:
            self.loop_invariants[pc] = []
        self.loop_invariants[pc].append(
            Contract(
                kind=ContractKind.LOOP_INVARIANT,
                predicate=predicate,
                message=message or f"Loop invariant: {condition_str or '<callable>'}",
                line_number=line,
            ),
        )

    def set_assigns(self, locations: frozenset[str]) -> None:
        """Set the modeled-write frame condition.

        Args:
            locations: Frozenset of frame-entry-visible write locations declared
                as modifiable. An empty set means no modeled writes are allowed.

        Side Effects:
            Sets ``assigns_set`` and sets ``assigns_declared`` to ``True``.

        """
        self.assigns_set = locations
        self.assigns_declared = True

    def set_pure(self) -> None:
        """Mark this function with the named no-visible-write obligation.

        ``EffectKind.PURE`` is reported separately from ``@assigns()``, but the
        current checker classifies it using the same modeled write ledger.

        Side Effects:
            Sets ``effect_type`` to ``EffectKind.PURE``.
        """
        self.effect_type = EffectKind.PURE
