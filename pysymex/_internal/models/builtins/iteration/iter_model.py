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

"""Model for builtin ``iter()``."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.callable_iterators import CallableSentinelIterator
from pysymex._internal.core.types.containers.dict_views import SymbolicDictView
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.common.dynamic import DynamicBuiltinOps
from pysymex._internal.models.builtins.iteration.ops import (
    BuiltinIteratorOps,
)
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


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
            return BuiltinIteratorOps.arity_type_error("iter", args, state)
        resolved = SymbolicObject.resolve(args[0], state)
        val = IterationSources.payload(resolved)
        if len(args) == 2 and BuiltinIteratorOps.definite_non_callable(val):
            result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.iter",
                    "iter(v, w): v must be callable",
                ),
            )
        if len(args) == 2:
            return ModelResult(
                value=CallableSentinelIterator(
                    f"iter_{state.pc}",
                    producer=args[0],
                    sentinel=args[1],
                ),
            )
        if isinstance(resolved, SymbolicValue) and isinstance(resolved.value, set):
            return ModelResult(
                value=BuiltinIteratorOps.symbolic_iterator(f"iter_{state.pc}", resolved, state),
            )
        if isinstance(val, list):
            return ModelResult(
                value=BuiltinIteratorOps.symbolic_iterator(
                    f"iter_{state.pc}",
                    cast("list[object]", val),
                    state,
                ),
            )
        if isinstance(val, tuple):
            return ModelResult(
                value=BuiltinIteratorOps.symbolic_iterator(
                    f"iter_{state.pc}",
                    cast("tuple[object, ...]", val),
                    state,
                ),
            )
        if isinstance(val, dict):
            return ModelResult(
                value=BuiltinIteratorOps.symbolic_iterator(
                    f"iter_{state.pc}",
                    cast("dict[object, object]", val),
                    state,
                ),
            )
        if isinstance(val, set):
            return ModelResult(
                value=BuiltinIteratorOps.symbolic_iterator(
                    f"iter_{state.pc}",
                    cast("set[object]", val),
                    state,
                ),
            )
        if isinstance(val, frozenset):
            return ModelResult(
                value=BuiltinIteratorOps.symbolic_iterator(
                    f"iter_{state.pc}",
                    cast("frozenset[object]", val),
                    state,
                ),
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
            return ModelResult(
                value=BuiltinIteratorOps.symbolic_iterator(f"iter_{state.pc}", val, state),
            )
        if DynamicBuiltinOps.iter_type_error(val):
            result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.iter",
                    f"'{getattr(val, 'type_tag', type(val).__name__)}' object is not iterable",
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
