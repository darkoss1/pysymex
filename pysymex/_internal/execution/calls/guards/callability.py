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

"""Definite non-callable target detection and TypeError routing."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.affinity import (
    DEFINITELY_NON_CALLABLE_AFFINITIES,
    python_type_name_for_affinity,
)
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.capabilities import symbolic_affinity
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.exceptions.type_errors import type_error_result

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


def definite_non_callable_type_name(value: object) -> str | None:
    """Return a CPython type name when *value* is definitely not callable."""
    if isinstance(value, SymbolicNoneType):
        return "NoneType"
    if isinstance(value, SymbolicValue):
        name = value.name
        if (
            not name.isidentifier()
            or getattr(value, "model_name", None) is not None
            or name.startswith(("function_", "global_", "import_", "instance_", "havoc"))
        ):
            return None
        if value.affinity_type in DEFINITELY_NON_CALLABLE_AFFINITIES:
            return python_type_name_for_affinity(value.affinity_type)
        return None
    affinity = symbolic_affinity(value)
    if affinity in DEFINITELY_NON_CALLABLE_AFFINITIES:
        return python_type_name_for_affinity(affinity)
    if isinstance(value, (int, float, bool, str, list, dict, tuple, set, bytes, bytearray)):
        return type(cast("object", value)).__name__
    return "NoneType" if value is None else None


def handle_definite_non_callable_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
) -> OpcodeResult | None:
    """Route provably non-callable callees to ``TypeError`` handlers or definite issues.

    Returns ``None`` when callability is unknown. When the type is definite and no
    handler exists, emits a feasible-path ``TYPE_ERROR`` issue instead of continuing.
    """
    type_name = definite_non_callable_type_name(func_obj)
    if type_name is None:
        return None

    message = f"'{type_name}' object is not callable"
    return type_error_result(state, ctx, instr.offset, message)
