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

"""Documented advanced interface for declarative contracts.

Contract declarations and their stable evidence types live here. Compiler,
runtime-capture, parser, lowering, and solver helpers remain implementation details.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ParamSpec, TypeVar

from pysymex._internal.contracts.enums import (
    ContractKind,
    ContractSeverity,
    VerificationResult,
)
from pysymex._internal.contracts.types import Contract, ContractViolation, FunctionContract

if TYPE_CHECKING:
    from collections.abc import Callable

    import z3

    from pysymex._internal.contracts.quantifiers.types import Quantifier
    from pysymex._internal.contracts.types import ContractPredicate

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")


def And(*args: z3.BoolRef | bool) -> z3.BoolRef:
    from pysymex._internal.contracts import combinators

    return combinators.And_(*args)


def Implies(left: z3.BoolRef | bool, right: z3.BoolRef | bool) -> z3.BoolRef:
    from pysymex._internal.contracts import combinators

    return combinators.Implies_(left, right)


def Not(arg: z3.BoolRef | bool) -> z3.BoolRef:
    from pysymex._internal.contracts import combinators

    return combinators.Not_(arg)


def Or(*args: z3.BoolRef | bool) -> z3.BoolRef:
    from pysymex._internal.contracts import combinators

    return combinators.Or_(*args)


def assigns(*locations: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    from pysymex._internal.contracts import decorators

    return decorators.assigns(*locations)


def assumes(
    predicate: ContractPredicate,
    message: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    from pysymex._internal.contracts import decorators

    return decorators.assumes(predicate, message)


def ensures(
    predicate: ContractPredicate,
    message: str | None = None,
    *,
    severity: ContractSeverity = ContractSeverity.ERROR,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    from pysymex._internal.contracts import decorators

    return decorators.ensures(predicate, message, severity=severity)


def invariant(
    predicate: ContractPredicate,
    message: str | None = None,
) -> Callable[[type[T]], type[T]]:
    from pysymex._internal.contracts import decorators

    return decorators.invariant(predicate, message)


def loop(
    predicate: ContractPredicate,
    message: str | None = None,
) -> Contract:
    from pysymex._internal.contracts import decorators

    return decorators.loop_invariant(predicate, message)


def pure(func: Callable[P, R]) -> Callable[P, R]:
    from pysymex._internal.contracts import decorators

    return decorators.pure(func)


def requires(
    predicate: ContractPredicate,
    message: str | None = None,
    *,
    severity: ContractSeverity = ContractSeverity.ERROR,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    from pysymex._internal.contracts import decorators

    return decorators.requires(predicate, message, severity=severity)


def exists(var: str, range_spec: tuple[int, int] | str, condition: str) -> Quantifier:
    from pysymex._internal.contracts.quantifiers import factories

    return factories.exists(var, range_spec, condition)


def unique(var: str, range_spec: tuple[int, int] | str, condition: str) -> Quantifier:
    from pysymex._internal.contracts.quantifiers import factories

    return factories.exists_unique(var, range_spec, condition)


def forall(var: str, range_spec: tuple[int, int] | str, condition: str) -> Quantifier:
    from pysymex._internal.contracts.quantifiers import factories

    return factories.forall(var, range_spec, condition)


__all__ = [
    "And",
    "Contract",
    "ContractKind",
    "ContractSeverity",
    "ContractViolation",
    "FunctionContract",
    "Implies",
    "Not",
    "Or",
    "VerificationResult",
    "assigns",
    "assumes",
    "ensures",
    "exists",
    "forall",
    "invariant",
    "loop",
    "pure",
    "requires",
    "unique",
]
