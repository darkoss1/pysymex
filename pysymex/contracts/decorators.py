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

"""Contract decorator functions for pysymex.

Provides the full decorator set for specifying function and class contracts:

    @requires    — precondition at function entry
    @ensures     — postcondition at function exit
    @invariant   — class invariant at mutation points
    @assumes     — assumption (asserted without proof)
    @assigns     — frame condition (declares modifiable locations)
    @pure        — pure function marker (enables memoisation)
    @loop_invariant — loop invariant helper

Each decorator accepts **both** callable predicates (zero-AST symbolic
tracing) and string predicates (backward-compatible AST path)::

    @requires(lambda x, y: x > 0, "x must be positive")
    @requires("y != 0", "y must be nonzero")
    def divide(x: int, y: int) -> float:
        return x / y

Thread safety:
    The global ``_contract_registry`` is protected by a ``threading.Lock``.
"""

from __future__ import annotations

import functools
import inspect
import logging
import threading
from collections.abc import Callable
from typing import ParamSpec, TypeVar

from pysymex.contracts.types import (
    Contract,
    ContractKind,
    ContractPredicate,
    FunctionContract,
    Severity,
)

logger = logging.getLogger(__name__)

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")


_contract_registry: dict[str, FunctionContract] = {}
_registry_lock = threading.Lock()
_class_invariant_registry: dict[type[object], list[Contract]] = {}

function_contracts: dict[str, FunctionContract] = _contract_registry


def _get_function_key(func: Callable[..., object]) -> str:
    """Compute the canonical registry key for a function."""
    module = getattr(func, "__module__", "<unknown>")
    qualname = getattr(func, "__qualname__", getattr(func, "__name__", repr(func)))
    return f"{module}.{qualname}"


def _get_or_create_contract(func: Callable[..., object]) -> FunctionContract:
    """Get or create a FunctionContract for the given function."""
    key = _get_function_key(func)
    with _registry_lock:
        if key not in _contract_registry:
            _contract_registry[key] = FunctionContract(
                function_name=getattr(func, "__name__", repr(func))
            )
        return _contract_registry[key]


def get_function_contract(func: Callable[..., object]) -> FunctionContract | None:
    """Retrieve the contract for a function, or ``None`` if undecorated.

    Args:
        func: The function to look up.

    Returns:
        The associated ``FunctionContract``, or ``None``.
    """
    key = _get_function_key(func)
    with _registry_lock:
        return _contract_registry.get(key)


def _get_line_number(func: Callable[..., object]) -> int | None:
    """Best-effort extraction of the function's source line number."""
    try:
        source_lines = inspect.getsourcelines(func)
        return source_lines[1]
    except (OSError, TypeError):
        logger.debug("Failed to get source lines for %s", func, exc_info=True)
        return None


def requires(
    predicate: ContractPredicate,
    message: str | None = None,
    *,
    severity: Severity = Severity.ERROR,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Precondition decorator — constraint must hold at function entry.

    Args:
        predicate: A callable ``(params...) -> z3.BoolRef`` or a string.
        message: Human-readable description for violation reports.
        severity: ``ERROR`` (default) or ``WARNING``.

    Example::

        @requires(lambda x, y: x > 0, "x must be positive")
        @requires("y != 0", "y must be nonzero")
        def divide(x: int, y: int) -> float:
            return x / y
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        contract = _get_or_create_contract(func)
        line_num = _get_line_number(func)
        contract.add_precondition(predicate, message, line_num, severity)

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return func(*args, **kwargs)

        setattr(wrapper, "__contract__", contract)
        setattr(func, "__contract__", contract)
        return wrapper

    return decorator


def ensures(
    predicate: ContractPredicate,
    message: str | None = None,
    *,
    severity: Severity = Severity.ERROR,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Postcondition decorator — constraint must hold at function exit.

    For callable predicates, the **first parameter** is bound to the return
    value (``result``), followed by the function's own parameters::

        @ensures(lambda result, x, y: result == x / y, "result matches division")
        def divide(x: int, y: int) -> float:
            return x / y

    For string predicates, use ``result()`` and ``old(x)``::

        @ensures("result() >= 0", "result must be non-negative")
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        contract = _get_or_create_contract(func)
        line_num = _get_line_number(func)
        contract.add_postcondition(predicate, message, line_num, severity)

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return func(*args, **kwargs)

        setattr(wrapper, "__contract__", contract)
        setattr(func, "__contract__", contract)
        return wrapper

    return decorator


def invariant(
    predicate: ContractPredicate,
    message: str | None = None,
) -> Callable[[type[T]], type[T]]:
    """Class invariant decorator — constraint must hold at mutation points.

    The invariant is checked:
      - After ``__init__`` returns
      - Before and after every public method (not starting with ``_``)

    Example::

        @invariant(lambda self: self.balance >= 0, "balance must be non-negative")
        @invariant("self.size >= 0", "size never negative")
        class BankAccount:
            def __init__(self, initial: int) -> None:
                self.balance = initial
    """

    def decorator(cls: type[T]) -> type[T]:
        invariants = _class_invariant_registry.setdefault(cls, [])
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
    """Assumption decorator — constraint asserted without proof.

    Assumptions narrow the symbolic input space without generating a
    verification obligation.  Used to encode external guarantees
    (OS behaviour, hardware properties, library postconditions).

    Example::

        @assumes(lambda n: n >= 0, "os.getpid() always nonneg")
        def get_pid() -> int:
            return os.getpid()
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        contract = _get_or_create_contract(func)
        line_num = _get_line_number(func)
        contract.add_assumption(predicate, message, line_num)

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return func(*args, **kwargs)

        setattr(wrapper, "__contract__", contract)
        setattr(func, "__contract__", contract)
        return wrapper

    return decorator


def assigns(
    *locations: str,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Frame condition decorator — declares exactly which locations are modified.

    Anything not listed is guaranteed unmodified.  Integrates with the
    aliasing analyser to short-circuit O(N²) queries.

    Example::

        @assigns("self.size", "self.data")
        def push(self, item: object) -> None:
            self.data.append(item)
            self.size += 1
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        contract = _get_or_create_contract(func)
        contract.set_assigns(frozenset(locations))

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return func(*args, **kwargs)

        setattr(wrapper, "__contract__", contract)
        setattr(func, "__contract__", contract)
        return wrapper

    return decorator


def pure(func: Callable[P, R]) -> Callable[P, R]:
    """Pure function decorator — no side effects, enables memoisation.

    A pure function produces the same output for the same symbolic inputs.
    The symbolic executor can cache and reuse its result, eliminating
    redundant solver calls.

    Example::

        @pure
        def compute_hash(data: bytes) -> int: ...
    """
    contract = _get_or_create_contract(func)
    contract.set_pure()

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        return func(*args, **kwargs)

    setattr(wrapper, "__contract__", contract)
    setattr(func, "__contract__", contract)
    return wrapper


def loop_invariant(
    predicate: ContractPredicate,
    message: str | None = None,
) -> Contract:
    """Loop invariant helper — returns a Contract for loop annotation.

    Typically used in comments or as metadata rather than as a function
    decorator::

        def sum_list(lst: list[int]) -> int:
            total = 0
            i = 0
            # loop_invariant: total == sum(lst[:i])
            while i < len(lst):
                total += lst[i]
                i += 1
            return total
    """
    condition_repr = predicate if isinstance(predicate, str) else ""
    return Contract(
        kind=ContractKind.LOOP_INVARIANT,
        predicate=predicate,
        message=message or f"Loop invariant: {condition_repr or '<callable>'}",
    )


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
