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

"""Core functools callable models."""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

import z3

from pysymex._internal.core.constants import Z3_ZERO
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffectValue

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class _WrappedWrapper(Protocol):
    __name__: str
    __doc__: str | None
    __wrapped__: Callable[..., object]

    def __call__(self, *args: object, **kwargs: object) -> object: ...


@dataclass(frozen=True)
class TransparentDecorator:
    """Decorator carrier for wrappers that preserve body reachability."""

    name: str

    def __call__(self, func: object) -> object:
        """Return the wrapped callable unchanged for supported analyses."""
        return func


def apply_transparent_decorator_call(
    func_obj: object,
    args: list[object],
    kwargs: dict[str, object],
) -> object | None:
    """Model bounded lru-cache and wraps decoration as call-preserving."""
    if func_obj is functools.lru_cache and set(kwargs).issubset({"maxsize", "typed"}):
        return TransparentDecorator("lru_cache")
    if func_obj is functools.wraps and args:
        return TransparentDecorator("wraps")
    if isinstance(func_obj, TransparentDecorator) and len(args) == 1 and not kwargs:
        return args[0]
    return None


class PartialModel:
    """Model for functools.partial.

    Freezes some arguments of a function.
    """

    def __init__(self, func: object, *args: object, **kwargs: object) -> None:
        """Create a partial function application.

        Args:
            func: The function to partially apply
            *args: Positional arguments to freeze
            **kwargs: Keyword arguments to freeze

        """
        self.func = func
        self.args: tuple[object, ...] = args
        self.kwargs: dict[str, object] = kwargs

    def __call__(self, *args: object, **kwargs: object) -> object:
        """Call the partial function with remaining arguments."""
        _ = self.args + args

        from pysymex._internal.core.types.scalars.values import SymbolicValue

        result, _ = SymbolicValue.symbolic("partial_result")
        return result


class PartialConstructorModel(FunctionModel):
    """Construct callable partial applications while retaining bound values."""

    name = "partial"
    qualname = "functools.partial"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        _ = state
        if not args or (
            not callable(args[0]) and getattr(args[0], "_modeled_object", None) is None
        ):
            from pysymex._internal.core.types.scalars.values import SymbolicValue

            result, constraint = SymbolicValue.symbolic("partial_result")
            return ModelResult(value=result, constraints=[constraint])
        return ModelResult(value=PartialModel(args[0], *args[1:], **kwargs))


class ReduceModel(FunctionModel):
    """Model definite empty-input failures for ``functools.reduce``."""

    name = "reduce"
    qualname = "functools.reduce"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return a result and report CPython's definite empty-input error."""
        result, constraint = SymbolicValue.symbolic("reduce_result")
        side_effects: dict[str, SideEffectValue] = {}
        if len(args) == 2 and not kwargs and _definitely_empty_iterable(args[1], state):
            side_effects["raised_exception"] = {
                "issue_kind": "TYPE_ERROR",
                "exception_type": "TypeError",
                "message": "reduce() of empty iterable with no initial value",
                "source": "functools.reduce",
            }
        return ModelResult(value=result, constraints=(constraint,), side_effects=side_effects)


def _definitely_empty_iterable(value: object, state: VMState) -> bool:
    """Return whether a reduce operand is represented as definitely empty."""
    if isinstance(value, list):
        return len(cast("list[object]", value)) == 0
    if isinstance(value, tuple):
        return len(cast("tuple[object, ...]", value)) == 0
    if isinstance(value, SymbolicObject) and value.address != -1:
        value = state.load_heap(value.address)
    return isinstance(value, SymbolicList) and z3.eq(value.z3_len, Z3_ZERO)


def model_partial(func: Callable[..., object], *args: object, **kwargs: object) -> PartialModel:
    """Model functools.partial(func, *args, **kwargs).

    Returns a new callable with some arguments pre-filled.
    """
    return PartialModel(func, *args, **kwargs)


def model_reduce(
    function: Callable[..., object],
    iterable: SymbolicList,
    initial: object = None,
) -> object:
    """Model functools.reduce(function, iterable[, initial]).

    Apply function of two arguments cumulatively to items of iterable.

    Args:
        function: Binary function (takes 2 args, returns 1)
        iterable: Iterable to reduce
        initial: Optional initial value

    Returns:
        The reduced value (symbolic)

    Raises:
        TypeError: If iterable is empty and no initial value

    """
    result, _ = SymbolicValue.symbolic("reduce_result")
    return result


def model_wraps(wrapped: Callable[..., object], **kwargs: object) -> Callable[..., object]:
    """Model functools.wraps(wrapped, **kwargs).

    Decorator to make wrapper functions look like wrapped functions.
    """

    def decorator(wrapper: Callable[..., object]) -> Callable[..., object]:
        wrapped_wrapper = cast("_WrappedWrapper", wrapper)
        wrapped_wrapper.__name__ = getattr(wrapped, "__name__", wrapped_wrapper.__name__)
        wrapped_wrapper.__doc__ = getattr(wrapped, "__doc__", wrapped_wrapper.__doc__)
        wrapped_wrapper.__wrapped__ = wrapped
        return wrapped_wrapper

    return decorator


def model_total_ordering(cls: type) -> type:
    """Model functools.total_ordering(cls).

    Decorator that fills in comparison methods.
    Given __eq__ and one of __lt__, __le__, __gt__, __ge__,
    this fills in the rest.

    Args:
        cls: Class to decorate

    Returns:
        The decorated class

    """
    return cls


def model_singledispatch(func: Callable[..., object]) -> Callable[..., object]:
    """Model functools.singledispatch(func).

    Single-dispatch generic function decorator.
    """
    return func
