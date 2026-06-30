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
:mod:`pysymex._internal.contracts.decorator.registry`. Enforcement happens later in the
executor through :mod:`pysymex._internal.contracts.runtime`; decorators do not wrap callables.

Supported decorators:

    @requires    - precondition at function entry
    @ensures     - postcondition at function exit
    @invariant   - declared class invariant obligation
    @assumes     - assumption (asserted without proof)
    @assigns     - frame condition (declares modifiable locations)
    @pure        - named no-visible-write obligation
    @loop_invariant - loop invariant helper

Each decorator accepts **both** callable predicates (zero-AST symbolic
tracing) and string predicates (AST path)::

    @requires(lambda x, y: x > 0, "x must be positive")
    @requires("y != 0", "y must be nonzero")
    def divide(x: int, y: int) -> float:
        return x / y

Callable predicates are executed during symbolic tracing with active Z3 terms.
They must bind at least one symbolic parameter, be side-effect-free, and return
symbolic Z3 expressions. Explicit Python bytecode mutations of globals, closure
cells, attributes, or subscripts are rejected before invocation. Arbitrary calls
and imports inside callable predicate bytecode are also unsupported, except
approved PySyMex symbolic combinators, because they can execute host code while
tracing. Python ``bool`` returns and nullary callable predicates are unsupported;
use string predicates such as ``"True"`` for constant clauses.

Thread safety:
    The global ``_contract_registry`` is protected by a ``threading.Lock``.

Decorators attach metadata without introducing executable wrapper frames.
``VerifiedExecutor`` and its VM hooks own enforcement.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ParamSpec, TypeVar

from pysymex._internal.contracts.decorator.registry import ContractRegistry
from pysymex._internal.contracts.types import Contract, ContractPredicate
from pysymex._internal.logging.root import get_logger
from pysymex.contracts import ContractKind, ContractSeverity

if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")


def requires(
    predicate: ContractPredicate,
    message: str | None = None,
    *,
    severity: ContractSeverity = ContractSeverity.ERROR,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a precondition constraint that must hold at function entry.

    Preconditions are evaluated under the calling context to verify that the
    function is never invoked under invalid parameter configurations. Supports both
    string and callable (lambda) expressions.

    Args:
        predicate: A callable ``(params...) -> z3.BoolRef`` or a Python condition string.
        message: Human-readable description included in failure reports.
        severity: The reporting level if violated, default is ``ContractSeverity.ERROR``.

    Returns:
        A decorator that attaches the precondition constraint to the function's contract.

    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        contract = ContractRegistry.get_or_create(func)
        line_num = ContractRegistry.source_line(func)
        contract.add_precondition(predicate, message, line_num, severity)
        ContractRegistry.attach_contract(func, contract)
        return func

    return decorator


def ensures(
    predicate: ContractPredicate,
    message: str | None = None,
    *,
    severity: ContractSeverity = ContractSeverity.ERROR,
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
        severity: The reporting level if violated, default is ``ContractSeverity.ERROR``.

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
        contract = ContractRegistry.get_or_create(func)
        line_num = ContractRegistry.source_line(func)
        contract.add_postcondition(predicate, message, line_num, severity)
        ContractRegistry.attach_contract(func, contract)
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
        invariants = ContractRegistry.class_invariants(cls)
        ContractRegistry.attach_invariants(cls, invariants)

        condition_repr = predicate if isinstance(predicate, str) else ""
        invariants.append(
            Contract(
                kind=ContractKind.INVARIANT,
                predicate=predicate,
                message=message or f"Invariant: {condition_repr or '<callable>'}",
            ),
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
        contract = ContractRegistry.get_or_create(func)
        line_num = ContractRegistry.source_line(func)
        contract.add_assumption(predicate, message, line_num)
        ContractRegistry.attach_contract(func, contract)
        return func

    return decorator


def assigns(
    *locations: str,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a frame condition constraint representing permitted modeled writes.

    ``@assigns()`` declares that no frame-entry-visible modeled write is permitted.
    It is checked against the same VM write ledger used by ``@pure``, but it is
    reported as a frame-condition obligation.

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
        contract = ContractRegistry.get_or_create(func)
        contract.set_assigns(frozenset(locations))
        ContractRegistry.attach_contract(func, contract)
        return func

    return decorator


def pure(func: Callable[P, R]) -> Callable[P, R]:
    """Declare a named no-visible-write obligation.

    The current verifier treats ``@pure`` as a public, user-facing spelling for
    "no frame-entry-visible modeled writes". It uses the same write ledger as
    ``@assigns()`` but preserves a distinct ``PURE`` report kind.

    Args:
        func: The target function to mark as pure.

    Returns:
        The input function object decorated with a pure classification.

    Limitations:
        This is not a full referential-transparency proof. The executor checks
        modeled writes, but it does not prove deterministic return values,
        absence of all native/external effects, or safe summary caching.

    """
    contract = ContractRegistry.get_or_create(func)
    contract.set_pure()
    ContractRegistry.attach_contract(func, contract)
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
