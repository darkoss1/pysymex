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

"""Validate init arguments for a few recognized stdlib constructors at call sites.

Checks concrete or symbolic arguments against modeled ``InitParameter`` contracts and may
emit ``TYPE_ERROR`` or route to exception handlers when violations are feasible on the path.

Limitations:
    Coverage is limited to explicitly registered stdlib forms; other types use generic calls.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.solver.engine.queries import check_sat_result
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler
from pysymex.execution.calls.helpers import to_z3_expr
from pysymex.models.objects.types import InitParameter

from .instances import modeled_instance_value

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
    from pysymex.models.objects import ClassRegistry, SymbolicClass
    from pysymex.typing import StackValue


def named_tuple_call_error(
    modeled_cls: object,
    class_name: str,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> str | None:
    """Validate the bounded typed named tuple constructor contract."""
    fields = getattr(modeled_cls, "named_tuple_fields", None)
    if not isinstance(fields, tuple):
        return None
    typed_fields = cast("tuple[str, ...]", fields)
    unexpected = next((name for name in kwargs if name not in typed_fields), None)
    if unexpected is not None:
        return f"{class_name}.__new__() got an unexpected keyword argument '{unexpected}'"
    if len(args) > len(typed_fields):
        return (
            f"{class_name}.__new__() takes {len(typed_fields) + 1} positional arguments "
            f"but {len(args) + 1} were given"
        )
    duplicate = next((field for field in typed_fields[: len(args)] if field in kwargs), None)
    if duplicate is not None:
        return f"{class_name}.__new__() got multiple values for argument '{duplicate}'"
    missing = next((field for field in typed_fields[len(args) :] if field not in kwargs), None)
    if missing is not None:
        return f"{class_name}.__new__() missing required argument '{missing}'"
    return None


def concrete_named_tuple_fields(func_obj: object) -> tuple[str, ...] | None:
    """Return fields from a generated concrete named-tuple type."""
    if not isinstance(func_obj, type) or not issubclass(func_obj, tuple):
        return None
    named_tuple_type = cast("type[object]", func_obj)
    raw_fields = getattr(named_tuple_type, "_fields", None)
    if not isinstance(raw_fields, tuple):
        return None
    fields = cast("tuple[object, ...]", raw_fields)
    if not all(isinstance(field, str) for field in fields):
        return None
    return cast("tuple[str, ...]", fields)


def configure_concrete_named_tuple_class(modeled_cls: object, fields: tuple[str, ...]) -> None:
    """Apply the bounded constructor and immutability contract to a generated type."""
    setattr(modeled_cls, "named_tuple_fields", fields)
    set_init_params = getattr(modeled_cls, "set_init_params", None)
    if callable(set_init_params):
        set_init_params([InitParameter(name=field) for field in fields])


def try_literal_enum_constructor(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    modeled_cls: SymbolicClass,
    class_registry: ClassRegistry,
    class_name: str,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Validate plain literal numeric enum construction on valid and invalid paths."""
    values = modeled_cls.literal_enum_values
    if values is None or len(args) != 1 or kwargs:
        return None
    arg_expr = to_z3_expr(args[0])
    if not isinstance(arg_expr, z3.ArithRef):
        return None
    valid = z3.Or(*(arg_expr == value for value in values))
    invalid = z3.Not(valid)
    valid_sat = check_sat_result([*state.path_constraints, valid]).is_sat
    invalid_sat = check_sat_result([*state.path_constraints, invalid]).is_sat
    if invalid_sat:
        handler_state = jump_to_exception_handler(
            state.fork().add_constraint(invalid),
            ctx,
            instr.offset,
            SymbolicException(
                exc_type="ValueError",
                message=f"value is not a valid {class_name}",
                raised_at=state.pc,
                condition=invalid,
            ),
        )
        if handler_state is not None:
            branches = [handler_state]
            if valid_sat:
                branches.insert(
                    0,
                    _literal_enum_success_state(
                        state, class_registry, modeled_cls, class_name, args, valid
                    ),
                )
            return OpcodeResult.branch(branches)
    states = (
        [_literal_enum_success_state(state, class_registry, modeled_cls, class_name, args, valid)]
        if valid_sat
        else []
    )
    issues = (
        [
            Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Possible ValueError: value is not a valid {class_name}",
                constraints=[*state.path_constraints, invalid],
                pc=state.pc,
            )
        ]
        if invalid_sat
        else []
    )
    return OpcodeResult(new_states=states, issues=issues, terminal=not states)


def _literal_enum_success_state(
    state: VMState,
    class_registry: ClassRegistry,
    modeled_cls: SymbolicClass,
    class_name: str,
    args: list[StackValue],
    valid_condition: z3.BoolRef,
) -> VMState:
    """Fork a feasible path that instantiates a literal enum member and advances the PC."""
    instance = class_registry.instantiate(modeled_cls, tuple(args), {}, state.pc)
    result_val = modeled_instance_value(class_name, instance, state.pc)
    return state.fork().add_constraint(valid_condition).push(result_val).advance_pc()
