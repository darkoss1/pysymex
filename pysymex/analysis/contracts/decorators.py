"""Contract decorator functions for pysymex.

Provides the @requires, @ensures, @invariant, and @loop_invariant decorators
for specifying function/class contracts.
"""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable

from pysymex.analysis.contracts.types import (
    Contract,
    ContractKind,
    FunctionContract,
)

logger = logging.getLogger(__name__)

function_contracts: dict[str, FunctionContract] = {}


def get_function_contract(func: Callable[..., object]) -> FunctionContract | None:
    """Get the contract for a function."""
    key = f"{func .__module__ }.{func .__qualname__ }"
    return function_contracts.get(key)


def requires(
    condition: str, message: str | None = None
) -> Callable[[Callable[..., object]], Callable[..., object]]:
    """Decorator to add a precondition to a function.
    Example:
        @requires("x > 0", "x must be positive")
        @requires("y != 0", "y must be non-zero")
        def divide(x, y):
            return x / y
    """

    def decorator(func: Callable[..., object]) -> Callable[..., object]:
        """Decorator."""
        key = f"{func .__module__ }.{func .__qualname__ }"
        if key not in function_contracts:
            function_contracts[key] = FunctionContract(function_name=func.__name__)
        contract = function_contracts[key]
        try:
            source_lines = inspect.getsourcelines(func)
            line_num = source_lines[1]
        except (OSError, TypeError):
            logger.debug("Failed to get source lines for %s", func.__name__, exc_info=True)
            line_num = None
        contract.add_precondition(condition, message, line_num)

        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> object:
            """Wrapper."""
            return func(*args, **kwargs)

        wrapper.__contract__ = contract
        return wrapper

    return decorator


def ensures(
    condition: str, message: str | None = None
) -> Callable[[Callable[..., object]], Callable[..., object]]:
    """Decorator to add a postcondition to a function.
    Use 'result()' to refer to the return value.
    Use 'old(x)' to refer to the value of x before the function.
    Example:
        @ensures("result() >= 0", "result must be non-negative")
        @ensures("result() == old(x) + old(y)", "result is sum of inputs")
        def add(x, y):
            return x + y
    """

    def decorator(func: Callable[..., object]) -> Callable[..., object]:
        """Decorator."""
        key = f"{func .__module__ }.{func .__qualname__ }"
        if key not in function_contracts:
            function_contracts[key] = FunctionContract(function_name=func.__name__)
        contract = function_contracts[key]
        try:
            source_lines = inspect.getsourcelines(func)
            line_num = source_lines[1]
        except (OSError, TypeError):
            logger.debug("Failed to get source lines for %s", func.__name__, exc_info=True)
            line_num = None
        contract.add_postcondition(condition, message, line_num)

        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> object:
            """Wrapper."""
            return func(*args, **kwargs)

        wrapper.__contract__ = contract
        return wrapper

    return decorator


def invariant(condition: str, message: str | None = None):
    """Decorator to add a class invariant.
    The invariant must hold after __init__ and after every public method.
    Example:
        @invariant("self.balance >= 0", "balance must be non-negative")
        class BankAccount:
            def __init__(self, initial):
                self.balance = initial
    """

    def decorator(cls: type) -> type:
        """Decorator."""
        if not hasattr(cls, "__invariants__"):
            cls.__invariants__ = []
        cls.__invariants__.append(
            Contract(
                kind=ContractKind.INVARIANT,
                condition=condition,
                message=message or f"Invariant: {condition }",
            )
        )
        return cls

    return decorator


def loop_invariant(condition: str, message: str | None = None):
    """Marker for loop invariants (used in comments or type hints).
    Example:
        def sum_list(lst):
            total = 0
            i = 0
            # loop_invariant: total == sum(lst[:i])
            while i < len(lst):
                total += lst[i]
                i += 1
            return total
    """
    return Contract(
        kind=ContractKind.LOOP_INVARIANT,
        condition=condition,
        message=message or f"Loop invariant: {condition }",
    )


__all__ = [
    "ensures",
    "function_contracts",
    "get_function_contract",
    "invariant",
    "loop_invariant",
    "requires",
]
