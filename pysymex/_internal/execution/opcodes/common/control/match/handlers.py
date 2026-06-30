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

"""MATCH_* opcode handlers for structural pattern matching (3.10+).

Pushes mapping/sequence predicates and class or key captures onto the stack.
Uses concrete captures when available; otherwise introduces symbolic success flags
or ``SymbolicNone`` no-match sentinels without claiming definite CPython truth.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicNoneType, fresh_name
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.match.pattern_ops import MatchPatternOps

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_match_mapping(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Push whether the TOS subject is a mapping for ``match`` patterns."""
    subject: object = MatchPatternOps.subject(state.peek(), state) if state.stack else None
    if isinstance(subject, SymbolicDict):
        is_mapping = Z3_TRUE
    elif isinstance(subject, SymbolicValue):
        is_mapping = subject.is_dict
    elif subject is not None:
        is_mapping = Z3_TRUE if isinstance(subject, dict) else Z3_FALSE
    else:
        is_mapping = Z3_FALSE

    result = SymbolicValue(
        _name=f"is_mapping_{state.pc}",
        z3_int=z3.If(is_mapping, Z3_ONE, Z3_ZERO),
        is_int=Z3_FALSE,
        z3_bool=is_mapping,
        is_bool=Z3_TRUE,
        affinity_type="bool",
    )
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_match_sequence(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Push whether the TOS subject is a sequence for ``match`` patterns."""
    subject = MatchPatternOps.subject(state.peek(), state) if state.stack else None
    if isinstance(subject, SymbolicList):
        is_sequence = Z3_TRUE
    elif isinstance(subject, SymbolicValue):
        is_sequence = _symbolic_match_sequence_success(subject)
    elif subject is not None:
        is_sequence = Z3_TRUE if isinstance(subject, (list, tuple)) else Z3_FALSE
    else:
        is_sequence = Z3_FALSE

    result = SymbolicValue(
        _name=f"is_sequence_{state.pc}",
        z3_int=z3.If(is_sequence, Z3_ONE, Z3_ZERO),
        is_int=Z3_FALSE,
        z3_bool=is_sequence,
        is_bool=Z3_TRUE,
        affinity_type="bool",
    )
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _symbolic_match_sequence_success(subject: SymbolicValue) -> z3.BoolRef:
    """Return whether a symbolic carrier is definitely sequence-pattern compatible."""
    modeled_object = getattr(subject, "_modeled_object", None)
    if isinstance(modeled_object, (list, tuple)) or isinstance(subject.value, (list, tuple)):
        return Z3_TRUE
    return subject.is_list


def handle_common_match_keys(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Check if mapping has required keys for pattern matching."""
    keys_tuple = state.peek() if state.stack else None
    subject: object = (
        MatchPatternOps.subject(state.stack[-2], state) if len(state.stack) >= 2 else None
    )

    success_expr = Z3_TRUE
    concrete_keys_obj = MatchPatternOps.keys(keys_tuple)
    captured_values = MatchPatternOps.concrete_key_values(subject, keys_tuple)

    if isinstance(subject, SymbolicDict) and concrete_keys_obj is not None:
        for key in concrete_keys_obj:
            if not isinstance(key, SymbolicString):
                str_key = SymbolicString.from_const(str(key))
            else:
                str_key = key
            success_expr = z3.And(success_expr, subject.contains_key(str_key).z3_bool)
    elif isinstance(subject, dict) and concrete_keys_obj is not None:
        success_expr = Z3_TRUE if all(key in subject for key in concrete_keys_obj) else Z3_FALSE
    else:
        success_expr = z3.Bool(fresh_name("match_keys_success"))

    if captured_values is not None:
        state = state.push(captured_values)
    elif z3.is_false(simplify_expr(success_expr)):
        state = state.push(SymbolicNoneType("match_keys_no_match"))
    else:
        result = SymbolicValue(
            _name=f"match_keys_result_{state.pc}",
            z3_int=ConstraintValues.int(len(concrete_keys_obj or [])),
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_none=z3.Not(success_expr),
            is_list=success_expr,
            affinity_type="list",
        )
        state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_match_class(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Pop class pattern operands and push captured attributes or a no-match sentinel."""
    num_positional = int(instr.argval) if instr.argval else 0
    names_tuple = state.pop() if state.stack else None
    cls = state.pop() if state.stack else None
    subject = state.pop() if state.stack else None

    modeled_attrs = MatchPatternOps.dispatch_class_attrs(
        state,
        ctx,
        subject,
        cls,
        names_tuple,
        num_positional,
    )
    if isinstance(modeled_attrs, OpcodeResult):
        return modeled_attrs
    if modeled_attrs is not None:
        state = state.push(modeled_attrs)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if isinstance(cls, type) and not isinstance(subject, (SymbolicValue, SymbolicObject)):
        concrete_attrs = MatchPatternOps.concrete_class_attrs(
            subject,
            cls,
            names_tuple,
            num_positional,
        )
        if concrete_attrs is not None:
            state = state.push(concrete_attrs)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

    attr_names = (
        MatchPatternOps.class_attr_names(cls, names_tuple, num_positional)
        if isinstance(cls, type)
        else None
    )
    attr_count = len(attr_names) if attr_names is not None else num_positional

    success = z3.Bool(fresh_name("match_class_success"))
    if isinstance(subject, SymbolicObject) and isinstance(cls, type):
        success = z3.And(success, subject.z3_addr >= Z3_ZERO)
    elif isinstance(subject, SymbolicValue) and isinstance(cls, type):
        builtin_success = MatchPatternOps.builtin_match_success(subject, cls)
        if builtin_success is not None:
            success = builtin_success
    elif isinstance(cls, type):
        success = Z3_TRUE if isinstance(subject, cls) else Z3_FALSE

    if z3.is_false(simplify_expr(success)):
        state = state.push(SymbolicNoneType("match_class_no_match"))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    result = SymbolicValue(
        _name=f"match_class_result_{state.pc}",
        z3_int=ConstraintValues.int(attr_count),
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_none=z3.Not(success),
        is_list=success,
        affinity_type="list",
    )
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
