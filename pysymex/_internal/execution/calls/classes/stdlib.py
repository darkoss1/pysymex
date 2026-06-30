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

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.classes.types import InitParameter
from pysymex._internal.core.exceptions.policy import runtime_exception
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.engine.queries import check_sat_result
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.execution.calls.value.coercion import to_z3_expr
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    degraded_passes_from_events,
    may_be_feasible,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow
from pysymex._internal.execution.opcodes.common.functions.classes.instances.values import (
    modeled_instance_value,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.classes.classes import SymbolicClass
    from pysymex._internal.core.classes.registry import ClassRegistry
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue

LITERAL_ENUM_FEASIBILITY_UNKNOWN = "literal_enum_feasibility_unknown"
_LITERAL_ENUM_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=LITERAL_ENUM_FEASIBILITY_UNKNOWN,
    owner="execution.calls.classes.literal_enum",
    subject="literal enum constructor",
)


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


def configure_concrete_named_tuple_class(
    modeled_cls: SymbolicClass,
    fields: tuple[str, ...],
) -> None:
    """Apply the bounded constructor and immutability contract to a generated type."""
    modeled_cls.named_tuple_fields = fields
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
    known_prefix = StateConstraints.known_sat_prefix_len(state)
    valid_result = check_sat_result(
        [*state.path_constraints, valid],
        known_sat_prefix_len=known_prefix,
    )
    invalid_result = check_sat_result(
        [*state.path_constraints, invalid],
        known_sat_prefix_len=known_prefix,
    )
    fallback_events = unknown_feasibility_events(
        state=state,
        spec=_LITERAL_ENUM_FEASIBILITY_SPEC,
        branches=[
            FeasibilityBranch("valid", valid_result),
            FeasibilityBranch("invalid", invalid_result),
        ],
    )
    degraded_passes = degraded_passes_from_events(fallback_events)
    valid_sat = may_be_feasible(valid_result)
    invalid_sat = may_be_feasible(invalid_result)
    invalid_reportable = invalid_result.is_sat
    if invalid_sat:
        handler_state = ExceptionFlow.jump_to_handler(
            state.fork().add_constraint(invalid),
            ctx,
            instr.offset,
            runtime_exception(
                ValueError,
                f"value is not a valid {class_name}",
                state=state,
                instr=instr,
                condition=invalid,
            ),
        )
        if handler_state is not None:
            branches = [handler_state]
            if valid_sat:
                branches.insert(
                    0,
                    _literal_enum_success_state(
                        state,
                        class_registry,
                        modeled_cls,
                        class_name,
                        args,
                        valid,
                    ),
                )
            return OpcodeResult.branch(
                branches,
                degraded_passes=degraded_passes,
                fallback_events=fallback_events,
            )
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
            ),
        ]
        if invalid_reportable
        else []
    )
    return OpcodeResult(
        new_states=states,
        issues=issues,
        degraded_passes=degraded_passes,
        terminal=not states,
        fallback_events=fallback_events,
    )


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
