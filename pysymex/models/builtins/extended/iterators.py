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

"""Iterator builtin models."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.containers.callable_iterators import CallableSentinelIterator
from pysymex.core.types.containers.dict_views import SymbolicDictView
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.sequences import SymbolicIterator, SymbolicSet
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.havoc import HavocValue
from pysymex.models.builtins.core.iterator_items import (
    concrete_iterable_items,
    iterator_size_change_runtime_error,
    iterator_mutation_side_effect,
    literal_iterable_payload,
    remaining_concrete_iterator_items,
)
from ..base import FunctionModel, ModelResult
from .helpers import (
    known_iter_type_error as _known_iter_type_error,
    resolve_heap_object as _resolve_heap_object,
    type_error_side_effect as _type_error_side_effect,
)


def _arity_type_error(name: str, args: list[StackValue], state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{name}_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=_type_error_side_effect(
            f"builtins.{name}",
            f"{name}() received invalid positional argument count: {len(args)}",
        ),
    )


def _definite_non_callable(value: object) -> bool:
    return value is None or isinstance(
        value,
        (
            int,
            float,
            bool,
            str,
            bytes,
            bytearray,
            list,
            tuple,
            dict,
            set,
            frozenset,
            SymbolicDictView,
            SymbolicSet,
            SymbolicList,
            SymbolicString,
        ),
    )


def _iterator_source_size(value: object, state: VMState) -> int | None:
    items = concrete_iterable_items(value, state)
    if items is None:
        return None
    return len(items)


def _iterator_size_change_raises(value: object) -> bool:
    if isinstance(value, SymbolicValue) and isinstance(value.value, set):
        return True
    return isinstance(value, (dict, set, SymbolicDict, SymbolicDictView, SymbolicSet))


def _iterator_size_change_message(iterator: SymbolicIterator) -> str:
    source = iterator.iterable
    if isinstance(source, (set, SymbolicSet)) or (
        isinstance(source, SymbolicValue) and isinstance(source.value, set)
    ):
        return "Set changed size during iteration"
    return "dictionary changed size during iteration"


def _symbolic_iterator(name: str, source: object, state: VMState) -> SymbolicIterator:
    return SymbolicIterator(
        name,
        source,
        source_size=_iterator_source_size(source, state),
        size_change_raises=_iterator_size_change_raises(source),
    )


class IterModel(FunctionModel):
    """Model for iter()."""

    name = "iter"
    qualname = "builtins.iter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return _arity_type_error("iter", args, state)
        resolved = _resolve_heap_object(args[0], state)
        val = literal_iterable_payload(resolved)
        if len(args) == 2 and _definite_non_callable(val):
            result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.iter", "iter(v, w): v must be callable"
                ),
            )
        if len(args) == 2:
            return ModelResult(
                value=CallableSentinelIterator(
                    f"iter_{state.pc}",
                    producer=args[0],
                    sentinel=args[1],
                )
            )
        if isinstance(resolved, SymbolicValue) and isinstance(resolved.value, set):
            return ModelResult(value=_symbolic_iterator(f"iter_{state.pc}", resolved, state))
        if isinstance(val, list):
            return ModelResult(
                value=_symbolic_iterator(f"iter_{state.pc}", cast("list[object]", val), state)
            )
        if isinstance(val, tuple):
            return ModelResult(
                value=_symbolic_iterator(f"iter_{state.pc}", cast("tuple[object, ...]", val), state)
            )
        if isinstance(val, dict):
            return ModelResult(
                value=_symbolic_iterator(
                    f"iter_{state.pc}", cast("dict[object, object]", val), state
                )
            )
        if isinstance(val, set):
            return ModelResult(
                value=_symbolic_iterator(f"iter_{state.pc}", cast("set[object]", val), state)
            )
        if isinstance(val, frozenset):
            return ModelResult(
                value=_symbolic_iterator(f"iter_{state.pc}", cast("frozenset[object]", val), state)
            )
        if isinstance(
            val,
            (
                str,
                bytes,
                bytearray,
                SymbolicBytes,
                SymbolicDict,
                SymbolicDictView,
                SymbolicList,
                SymbolicSet,
                SymbolicString,
            ),
        ):
            return ModelResult(value=_symbolic_iterator(f"iter_{state.pc}", val, state))
        if _known_iter_type_error(val):
            result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.iter",
                    f"'{getattr(val, 'type_tag', type(val).__name__)}' object is not iterable",
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class NextModel(FunctionModel):
    """Model for next()."""

    name = "next"
    qualname = "builtins.next"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return _arity_type_error("next", args, state)
        if args:
            iterator = _resolve_heap_object(args[0], state)
            has_default = len(args) > 1
            default = args[1] if has_default else None
            if isinstance(iterator, SymbolicIterator) and iterator.is_generator:
                result, constraint = HavocValue.havoc(f"havoc_generator_next_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            if isinstance(iterator, SymbolicIterator):
                if iterator_size_change_runtime_error(iterator, state):
                    result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=_runtime_error_side_effect(
                            _iterator_size_change_message(iterator)
                        ),
                    )
                remaining_items = remaining_concrete_iterator_items(iterator, state)
                if remaining_items is not None:
                    if remaining_items:
                        return ModelResult(
                            value=remaining_items[0],
                            side_effects=iterator_mutation_side_effect(
                                iterator,
                                iterator.advance(),
                            ),
                        )
                    exhausted = iterator.exhaust()
                    if has_default:
                        return ModelResult(
                            value=default,
                            side_effects=iterator_mutation_side_effect(iterator, exhausted),
                        )
                    result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                    side_effects = iterator_mutation_side_effect(iterator, exhausted)
                    side_effects.update(_stop_iteration_side_effect())
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=side_effects,
                    )
            if isinstance(iterator, SymbolicList):
                concrete_items = iterator.concrete_items
                if concrete_items:
                    return ModelResult(value=cast("StackValue", concrete_items[0]))
                if concrete_items == [] or (
                    z3.is_int_value(iterator.z3_len) and iterator.z3_len.as_long() == 0
                ):
                    if len(args) > 1:
                        return ModelResult(value=default)
                    result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=_stop_iteration_side_effect(),
                    )
            if isinstance(iterator, (list, tuple)):
                if iterator:
                    first = cast("list[StackValue] | tuple[StackValue, ...]", iterator)[0]
                    return ModelResult(value=first)
                if len(args) > 1:
                    return ModelResult(value=default)
                result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=_stop_iteration_side_effect(),
                )
            if _known_iter_type_error(iterator):
                result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=_type_error_side_effect(
                        "builtins.next", "next() argument is not an iterator"
                    ),
                )
        result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


def _stop_iteration_side_effect() -> dict[str, object]:
    return {
        "raised_exception": {
            "issue_kind": "UNHANDLED_EXCEPTION",
            "exception_type": "StopIteration",
            "message": "",
            "source": "builtins.next",
        }
    }


def _runtime_error_side_effect(message: str) -> dict[str, object]:
    return {
        "raised_exception": {
            "issue_kind": "UNHANDLED_EXCEPTION",
            "exception_type": "RuntimeError",
            "message": message,
            "source": "builtins.next",
        }
    }


class ReversedModel(FunctionModel):
    """Model for reversed()."""

    name = "reversed"
    qualname = "builtins.reversed"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("reversed", args, state)
        val = _resolve_heap_object(args[0], state)
        source = literal_iterable_payload(val)
        if _definite_reversed_type_error(source):
            result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.reversed", "reversed() argument is not reversible"
                ),
            )
        concrete_items = concrete_iterable_items(source, state)
        if concrete_items is not None and _is_live_reversible_source(source):
            return ModelResult(
                value=SymbolicIterator(
                    f"reversed_{state.pc}",
                    source,
                    reverse=True,
                    source_size=_iterator_source_size(source, state),
                    size_change_raises=_iterator_size_change_raises(source),
                )
            )
        if concrete_items is not None and _is_exact_reversible_source(source):
            exact_reversed_items = list(reversed(concrete_items))
            return ModelResult(value=SymbolicIterator(f"reversed_{state.pc}", exact_reversed_items))
        if isinstance(val, SymbolicList):
            concrete_items = val.concrete_items
            if concrete_items is not None:
                symbolic_reversed_items = list(reversed(concrete_items))
                return ModelResult(
                    value=SymbolicIterator(f"reversed_{state.pc}", symbolic_reversed_items)
                )
            result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.z3_len == val.z3_len])
        if isinstance(val, (list, tuple, str)):
            sequence_reversed_items: list[StackValue] = list(
                reversed(cast("Sequence[StackValue]", val))
            )
            return ModelResult(
                value=SymbolicIterator(f"reversed_{state.pc}", sequence_reversed_items)
            )
        if _known_iter_type_error(val):
            result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.reversed", "reversed() argument is not reversible"
                ),
            )
        result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


def _definite_reversed_type_error(value: object) -> bool:
    if isinstance(value, (set, frozenset, SymbolicSet)):
        return True
    return _known_iter_type_error(value)


def _is_exact_reversible_source(value: object) -> bool:
    return isinstance(
        value,
        (
            list,
            tuple,
            str,
            bytes,
            bytearray,
            dict,
            SymbolicBytes,
            SymbolicDict,
            SymbolicList,
            SymbolicString,
        ),
    )


def _is_live_reversible_source(value: object) -> bool:
    return isinstance(value, (list, SymbolicList))
