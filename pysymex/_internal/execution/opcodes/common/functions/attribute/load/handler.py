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

"""Implement ``LOAD_ATTR`` and related attribute reads for symbolic objects.

This module owns the public opcode dispatcher. Heap-backed object lookup, symbolic scalar lookup,
and shared result builders live in focused sibling modules to keep descriptor, modeled-object, and
fallback behavior auditable.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.memory.cow.dicts import CowDict
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.havoc import HavocValue
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.guards.attributes import validate_concrete_attribute_access
from pysymex._internal.execution.calls.guards.solver import receiver_non_none_is_static
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    append_fallback_events,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.functions.attribute.havoc import (
    load_havoc_attribute,
)
from pysymex._internal.execution.opcodes.common.functions.attribute.load.objects import (
    load_symbolic_object_attribute,
)
from pysymex._internal.execution.opcodes.common.functions.attribute.load.results import (
    attribute_error_result,
    load_path_string_attribute,
    modeled_attribute_carrier,
    none_attribute_error_result,
)
from pysymex._internal.execution.opcodes.common.functions.attribute.load.values import (
    load_symbolic_value_attribute,
    symbolic_exception_attribute,
)
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability


from pysymex._internal.models.registry import RuntimeModelRegistry

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.fallback.types import FallbackEvent
    from pysymex._internal.typing.protocols import StackValue


def _path_satisfiability_result(
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> SolverResult:
    return PathSatisfiability.result(constraints, known_sat_prefix_len=known_sat_prefix_len)


ATTRIBUTE_LOAD_NONE_FEASIBILITY_UNKNOWN = "attribute_none_feasibility_unknown"
_ATTRIBUTE_LOAD_NONE_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=ATTRIBUTE_LOAD_NONE_FEASIBILITY_UNKNOWN,
    owner="execution.opcodes.attributes",
    subject="attribute receiver None/non-None",
)


@dataclass(slots=True)
class _AttributeLoadOutcome:
    """Intermediate symbolic attribute-load state before final stack update."""

    state: VMState
    result_val: object
    obj_state: object | None
    type_name: str
    fallback_events: list[FallbackEvent]
    immediate_result: OpcodeResult | None = None


def _load_none_receiver_attribute(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    attr_name: str,
    *,
    push_null: bool,
) -> OpcodeResult:
    """Load an attribute from a receiver known to be ``None``."""
    if hasattr(None, attr_name):
        result_val = getattr(None, attr_name)
        if push_null:
            state = state.push(SymbolicNoneType())
        state = state.push(coerce_call_stack_value(result_val))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    return none_attribute_error_result(instr, state, ctx, attr_name)


def _symbolic_family_attribute_load(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    obj: object,
    attr_name: str,
    *,
    push_null: bool,
) -> _AttributeLoadOutcome:
    """Resolve symbolic/havoc attribute families before model lookup and fallback creation."""
    fallback_events: list[FallbackEvent] = []
    if isinstance(obj, SymbolicObject):
        object_load = load_symbolic_object_attribute(state, obj, attr_name, push_null=push_null)
        return _AttributeLoadOutcome(
            state=object_load.state,
            result_val=object_load.result_val,
            obj_state=object_load.obj_state,
            type_name=object_load.type_name,
            fallback_events=fallback_events,
            immediate_result=object_load.immediate_result,
        )
    if isinstance(obj, SymbolicList):
        return _AttributeLoadOutcome(state, None, None, getattr(obj, "_type", None) or "list", [])
    if isinstance(obj, SymbolicBytes):
        return _AttributeLoadOutcome(state, None, None, "bytes", [])
    if isinstance(obj, SymbolicDict):
        return _AttributeLoadOutcome(state, None, None, "dict", [])
    if isinstance(obj, SymbolicString):
        path_attribute = load_path_string_attribute(obj, attr_name)
        if path_attribute is not None:
            result_value, constraint = path_attribute
            state = state.push(result_value)
            state = state.add_constraint(constraint)
            state = state.advance_pc()
            return _AttributeLoadOutcome(
                state,
                None,
                None,
                "str",
                [],
                OpcodeResult.continue_with(state),
            )
        return _AttributeLoadOutcome(state, None, None, "str", [])
    if isinstance(obj, SymbolicException):
        result_val, exception_attr_found = symbolic_exception_attribute(obj, attr_name)
        if not exception_attr_found:
            return _AttributeLoadOutcome(
                state,
                None,
                None,
                "unknown",
                [],
                attribute_error_result(
                    instr,
                    state,
                    ctx,
                    f"'{type(obj).__name__}' has no attribute '{attr_name}'",
                ),
            )
        return _AttributeLoadOutcome(state, result_val, None, "unknown", [])
    if isinstance(obj, SymbolicValue):
        fallback_events = _symbolic_attribute_none_fallback_events(state, obj)
        none_result = _symbolic_none_attribute_result(
            instr,
            state,
            ctx,
            obj,
            attr_name,
            push_null=push_null,
        )
        if none_result is not None:
            return _AttributeLoadOutcome(
                state,
                None,
                None,
                "unknown",
                fallback_events,
                append_fallback_events(none_result, fallback_events),
            )
        value_load = load_symbolic_value_attribute(
            instr,
            state,
            ctx,
            obj,
            attr_name,
            push_null=push_null,
        )
        return _AttributeLoadOutcome(
            state,
            value_load.result_val,
            None,
            value_load.type_name,
            fallback_events,
            (
                append_fallback_events(value_load.immediate_result, fallback_events)
                if value_load.immediate_result is not None
                else None
            ),
        )

    obj_name = getattr(obj, "name", "") or getattr(obj, "_name", "")
    type_name = (
        "set" if "set" in obj_name.lower() or getattr(obj, "_type", "") == "set" else "unknown"
    )
    return _AttributeLoadOutcome(state, None, None, type_name, [])


def _load_registered_modeled_attribute(
    state: VMState,
    obj: object,
    attr_name: str,
    type_name: str,
    fallback_events: list[FallbackEvent],
    *,
    push_null: bool,
) -> OpcodeResult | None:
    """Load an attribute carrier from the runtime model registry, if present."""
    if type_name == "unknown":
        return None
    model_name = f"{type_name}.{attr_name}"
    if not RuntimeModelRegistry.default().resolve(model_name):
        return None
    res_val = modeled_attribute_carrier(f"{getattr(obj, 'name', 'obj')}.{attr_name}")
    res_val.model_name = model_name
    state = state.push(res_val)
    if push_null:
        state = state.push(coerce_call_stack_value(obj))
    state = state.advance_pc()
    return append_fallback_events(OpcodeResult.continue_with(state), fallback_events)


def _realize_missing_value(
    state: VMState,
    obj: object,
    attr_name: str,
    result_val: object,
    obj_state: object | None,
    type_name: str,
) -> tuple[VMState, object]:
    """Create and constrain a fallback symbolic attribute value when lookup was imprecise."""
    if result_val is not None:
        return state, result_val
    result_val, type_constraint = SymbolicValue.symbolic(
        f"{getattr(obj, 'name', 'obj')}.{attr_name}",
    )
    result_val.model_name = f"{type_name}.{attr_name}"
    if isinstance(obj_state, (dict, CowDict)):
        obj_state[attr_name] = result_val
    state = state.add_constraint(type_constraint)
    state = state.add_constraint(z3.Not(result_val.is_none))
    return state, result_val


def _attribute_receiver_for_load_method(
    obj: object,
    result_val: object,
    type_name: str,
) -> StackValue:
    """Return the receiver object pushed by LOAD_METHOD's CPython fast-call layout."""
    from pysymex._internal.core.classes.types import SymbolicMethod

    if isinstance(result_val, SymbolicMethod):
        return coerce_call_stack_value(obj) if result_val.is_bound else SymbolicNoneType()
    if isinstance(obj, SymbolicObject) or type_name != "unknown":
        return coerce_call_stack_value(obj)
    return SymbolicNoneType()


def handle_common_load_method(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load an attribute or method, checking heap memory for attributes."""
    obj = state.pop() if state.stack else SymbolicNoneType()
    attr_name = str(instr.argval)
    push_null = instr.opname == "LOAD_METHOD" and instr.arg is not None
    if not push_null and sys.version_info >= (3, 12) and instr.arg is not None:
        push_null = bool(instr.arg & 1)

    if isinstance(obj, SymbolicNoneType) or obj is None:
        return _load_none_receiver_attribute(
            instr,
            state,
            ctx,
            attr_name,
            push_null=push_null,
        )

    if not isinstance(
        obj,
        (
            HavocValue,
            SymbolicObject,
            SymbolicBytes,
            SymbolicList,
            SymbolicDict,
            SymbolicString,
            SymbolicValue,
            SymbolicException,
            SymbolicNoneType,
        ),
    ):
        return _load_concrete_attribute(instr, state, obj, attr_name, push_null=push_null)
    if isinstance(obj, HavocValue):
        return load_havoc_attribute(state, obj, attr_name, push_null=push_null)

    outcome = _symbolic_family_attribute_load(
        instr,
        state,
        ctx,
        obj,
        attr_name,
        push_null=push_null,
    )
    if outcome.immediate_result is not None:
        return outcome.immediate_result
    state = outcome.state

    modeled_result = _load_registered_modeled_attribute(
        state,
        obj,
        attr_name,
        outcome.type_name,
        outcome.fallback_events,
        push_null=push_null,
    )
    if modeled_result is not None:
        return modeled_result

    if isinstance(obj, SymbolicValue):
        state = _constrain_possible_none_receiver(state, obj)

    state, result_val = _realize_missing_value(
        state,
        obj,
        attr_name,
        outcome.result_val,
        outcome.obj_state,
        outcome.type_name,
    )
    state = state.push(coerce_call_stack_value(result_val))
    if push_null:
        state = state.push(_attribute_receiver_for_load_method(obj, result_val, outcome.type_name))
    state = state.advance_pc()
    return append_fallback_events(OpcodeResult.continue_with(state), outcome.fallback_events)


def _symbolic_attribute_none_fallback_events(
    state: VMState,
    obj: SymbolicValue,
) -> list[FallbackEvent]:
    """Return fallback events when symbolic attribute receiver None proof is UNKNOWN."""
    none_flag = simplify_expr(obj.is_none)
    if z3.is_false(none_flag) or z3.is_true(none_flag):
        return []
    result = _path_satisfiability_result(
        [*state.path_constraints, z3.Not(none_flag)],
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )
    return unknown_feasibility_events(
        state=state,
        spec=_ATTRIBUTE_LOAD_NONE_FEASIBILITY_SPEC,
        branches=[FeasibilityBranch("non_none", result)],
    )


def _symbolic_none_attribute_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    obj: SymbolicValue,
    attr_name: str,
    *,
    push_null: bool,
) -> OpcodeResult | None:
    """Return concrete ``None`` attribute behavior when the receiver is proved ``None``."""
    none_flag = simplify_expr(obj.is_none)
    if z3.is_false(none_flag):
        return None
    if z3.is_true(none_flag):
        if hasattr(None, attr_name):
            result_val = getattr(None, attr_name)
            if push_null:
                state = state.push(SymbolicNoneType())
            state = state.push(coerce_call_stack_value(result_val))
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
        return none_attribute_error_result(instr, state, ctx, attr_name)

    non_none_result = _path_satisfiability_result(
        [*state.path_constraints, z3.Not(none_flag)],
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )
    if not non_none_result.is_unsat:
        return None
    none_result = _path_satisfiability_result(
        [*state.path_constraints, none_flag],
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )
    if not none_result.is_sat:
        return None
    if hasattr(None, attr_name):
        result_val = getattr(None, attr_name)
        if push_null:
            state = state.push(SymbolicNoneType())
        state = state.push(coerce_call_stack_value(result_val))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    return none_attribute_error_result(instr, state, ctx, attr_name)


def _load_concrete_attribute(
    instr: dis.Instruction,
    state: VMState,
    obj: object,
    attr_name: str,
    *,
    push_null: bool,
) -> OpcodeResult:
    """Resolve concrete object attributes while preserving modeled bytes methods."""
    del instr
    if obj is object and attr_name == "__getattribute__":
        result_val = modeled_attribute_carrier("object.__getattribute__")
        result_val.model_name = "object.__getattribute__"
        if push_null:
            state = state.push(SymbolicNoneType())
        state = state.push(result_val)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    if isinstance(obj, bytes):
        model_name = f"bytes.{attr_name}"
        if RuntimeModelRegistry.default().resolve(model_name):
            res_val = modeled_attribute_carrier(f"{type(obj).__name__}_{attr_name}")
            res_val.model_name = model_name
            state = state.push(res_val)
            if push_null:
                state = state.push(obj)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
    validate_concrete_attribute_access(attr_name)
    try:
        result_val = getattr(obj, attr_name)
    except AttributeError:
        result_val, type_constraint = SymbolicValue.symbolic(f"{type(obj).__name__}_{attr_name}")
        state = state.add_constraint(type_constraint)
    if push_null:
        state = state.push(SymbolicNoneType())
    state = state.push(coerce_call_stack_value(result_val))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _constrain_possible_none_receiver(state: VMState, obj: SymbolicValue) -> VMState:
    """Preserve the existing possible-``None`` receiver narrowing policy."""
    none_check: list[z3.BoolRef] = []
    if receiver_non_none_is_static(obj):
        state = state.add_constraint(z3.Not(obj.is_none))
    else:
        none_check = [*state.path_constraints, obj.is_none]
        if not PathSatisfiability.is_sat(none_check):
            none_check = []
    if none_check:
        must_be_none = not PathSatisfiability.is_sat(
            [*state.path_constraints, z3.Not(obj.is_none)],
        )
        is_unconstrained_var = (
            z3.is_const(obj.is_none) and obj.is_none.decl().kind() == z3.Z3_OP_UNINTERPRETED
        )

        if must_be_none or not is_unconstrained_var:
            if must_be_none:
                state = state.add_constraint(z3.Not(obj.is_none))

        state = state.add_constraint(z3.Not(obj.is_none))
    return state
