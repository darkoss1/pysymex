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

"""User-facing contract decorators (``@requires``, ``@ensures``, etc.).

Registers clauses on functions and classes at decoration time via
:mod:`pysymex.contracts.decorator_registry`. Enforcement happens later in the
executor through :mod:`pysymex.contracts.runtime`; decorators do not wrap callables.

Supported decorators:

    @requires    - precondition at function entry
    @ensures     - postcondition at function exit
    @invariant   - declared class invariant obligation
    @assumes     - assumption (asserted without proof)
    @assigns     - frame condition (declares modifiable locations)
    @pure        - declared pure-function obligation
    @loop_invariant - loop invariant helper

Each decorator accepts **both** callable predicates (zero-AST symbolic
tracing) and string predicates (AST path)::

    @requires(lambda x, y: x > 0, "x must be positive")
    @requires("y != 0", "y must be nonzero")
    def divide(x: int, y: int) -> float:
        return x / y

Thread safety:
    The global ``_contract_registry`` is protected by a ``threading.Lock``.

Decorators attach metadata without introducing executable wrapper frames.
``VerifiedExecutor`` and its VM hooks own enforcement.
"""

from __future__ import annotations

from pysymex.logger import get_logger
from collections.abc import Callable
from typing import ParamSpec, TypeVar

from pysymex.contracts.decorator_registry import (
    function_contracts,
    get_class_invariants,
    get_function_contract,
    get_line_number,
    get_or_create_contract,
)
from pysymex.contracts.types import (
    Contract,
    ContractKind,
    ContractPredicate,
    Severity,
)

logger = get_logger(__name__)

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")


__all__ = [
    "assigns",
    "assumes",
    "ensures",
    "function_contracts",
    "get_function_contract",
    "invariant",
    "loop_invariant",
    "pure",
    "requires",
]


def requires(
    predicate: ContractPredicate,
    message: str | None = None,
    *,
    severity: Severity = Severity.ERROR,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a precondition constraint that must hold at function entry.

    Preconditions are evaluated under the calling context to verify that the
    function is never invoked under invalid parameter configurations. Supports both
    string and callable (lambda) expressions.

    Args:
        predicate: A callable ``(params...) -> z3.BoolRef`` or a Python condition string.
        message: Human-readable description included in failure reports.
        severity: The reporting level if violated, default is ``Severity.ERROR``.

    Returns:
        A decorator that attaches the precondition constraint to the function's contract.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        contract = get_or_create_contract(func)
        line_num = get_line_number(func)
        contract.add_precondition(predicate, message, line_num, severity)
        setattr(func, "__contract__", contract)
        return func

    return decorator


def ensures(
    predicate: ContractPredicate,
    message: str | None = None,
    *,
    severity: Severity = Severity.ERROR,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a postcondition constraint that must hold at function exit.

    Postconditions check the relationship between function parameters and the
    returned value. If the function behavior does not satisfy this constraint, a
    contract violation is reported.

    For callable predicates, the **first parameter** is bound to the function's
    return value (usually named ``result``), followed by any parameter names of
    the function.

    For string predicates, the return value is accessed using the ``result()`` function.

    Args:
        predicate: A callable ``(result, params...) -> z3.BoolRef`` or a Python condition string.
        message: Human-readable description included in failure reports.
        severity: The reporting level if violated, default is ``Severity.ERROR``.

    Returns:
        A decorator that attaches the postcondition constraint to the function's contract.

    Limitations:
        String predicates support conservative pre-state snapshots for scalar
        locals (``old(x)``), shallow scalar attributes (``old(self.x)``), and
        modeled collection/string lengths (``old(len(xs))``). Mutable
        references, object identities, deep attributes, and collection elements
        are still reported as ``UNSUPPORTED``.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        contract = get_or_create_contract(func)
        line_num = get_line_number(func)
        contract.add_postcondition(predicate, message, line_num, severity)
        setattr(func, "__contract__", contract)
        return func

    return decorator


def invariant(
    predicate: ContractPredicate,
    message: str | None = None,
) -> Callable[[type[T]], type[T]]:
    """Declare a class invariant obligation.

    Class invariants specify consistency constraints that should hold for all instances
    of a class before and after public method execution.

    Args:
        predicate: A callable ``(self) -> z3.BoolRef`` or a Python condition string.
        message: Human-readable description included in failure reports.

    Returns:
        A decorator that attaches the invariant constraint to the class definition.

    Limitations:
        Verified execution checks constructor exits and public method entry/exit
        points when receiver state can be represented by current VM bindings.
        Private methods are not checked by default, and unmodeled receiver state
        is reported as ``UNSUPPORTED`` rather than verified.
    """

    def decorator(cls: type[T]) -> type[T]:
        invariants = get_class_invariants(cls)
        setattr(cls, "__invariants__", invariants)

        condition_repr = predicate if isinstance(predicate, str) else ""
        invariants.append(
            Contract(
                kind=ContractKind.INVARIANT,
                predicate=predicate,
                message=message or f"Invariant: {condition_repr or '<callable>'}",
            )
        )
        return cls

    return decorator


def assumes(
    predicate: ContractPredicate,
    message: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare an assumption that is asserted without proof.

    Assumptions narrow the symbolic search space of the executor by adding constraints directly
    to the path state without verifying them. Use this to model external properties (such
    as OS/runtime invariants or library preconditions).

    Args:
        predicate: A callable ``(params...) -> z3.BoolRef`` or a Python condition string.
        message: Human-readable description included in solver/state logs.

    Returns:
        A decorator that registers the assumption on the function's contract.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        contract = get_or_create_contract(func)
        line_num = get_line_number(func)
        contract.add_assumption(predicate, message, line_num)
        setattr(func, "__contract__", contract)
        return func

    return decorator


def assigns(
    *locations: str,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a frame condition constraint representing the memory locations modified.

    Args:
        locations: Monospace names of fields/attributes that the function may mutate.

    Returns:
        A decorator that registers the assigns clause on the function's contract.

    Limitations:
        The engine checks this declaration against modeled write events. It
        does not yet prove deep heap equality for every unlisted location or
        account for native side effects outside the VM write ledger.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        contract = get_or_create_contract(func)
        contract.set_assigns(frozenset(locations))
        setattr(func, "__contract__", contract)
        return func

    return decorator


def pure(func: Callable[P, R]) -> Callable[P, R]:
    """Declare that a function is pure (has no side effects).

    A pure function must not mutate global state, arguments, or object state, and should
    consistently return equivalent outputs for equivalent inputs.

    Args:
        func: The target function to mark as pure.

    Returns:
        The input function object decorated with a pure classification.

    Limitations:
        The executor checks modeled writes but does not yet use purity for
        summary caching or symbolic result reuse.
    """
    contract = get_or_create_contract(func)
    contract.set_pure()
    setattr(func, "__contract__", contract)
    return func


def loop_invariant(
    predicate: ContractPredicate,
    message: str | None = None,
) -> Contract:
    """Return a loop invariant obligation metadata block.

    Loop invariants are inductive constraints used to verify loop logic.

    Args:
        predicate: A callable or Python condition string.
        message: Human-readable description.

    Returns:
        A ``Contract`` instance representing the loop invariant clause.

    Limitations:
        Loop-level verification metadata is currently reported as ``UNSUPPORTED`` by
        the execution engine.
    """
    condition_repr = predicate if isinstance(predicate, str) else ""
    return Contract(
        kind=ContractKind.LOOP_INVARIANT,
        predicate=predicate,
        message=message or f"Loop invariant: {condition_repr or '<callable>'}",
    )
