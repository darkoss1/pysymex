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

import dis
from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_ONE
from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.scalars.values import fresh_name
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.control.match_helpers import (
    builtin_match_success,
    concrete_match_key_values,
    concrete_match_class_attrs,
    modeled_match_class_attrs,
    extract_match_class_attr_names,
    extract_match_keys,
    resolve_match_subject,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_match_mapping(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push whether the TOS subject is a mapping for ``match`` patterns."""
    subject: object = resolve_match_subject(state.peek(), state) if state.stack else None
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
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push whether the TOS subject is a sequence for ``match`` patterns."""
    subject = resolve_match_subject(state.peek(), state) if state.stack else None
    if isinstance(subject, SymbolicList):
        is_sequence = Z3_TRUE
    elif isinstance(subject, SymbolicValue):
        is_sequence = subject.is_list
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


def handle_common_match_keys(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if mapping has required keys for pattern matching."""
    keys_tuple = state.peek() if state.stack else None
    subject: object = (
        resolve_match_subject(state.stack[-2], state) if len(state.stack) >= 2 else None
    )

    success_expr = Z3_TRUE
    concrete_keys_obj = extract_match_keys(keys_tuple)
    captured_values = concrete_match_key_values(subject, keys_tuple)

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
    elif z3.is_false(z3.simplify(success_expr)):
        state = state.push(SymbolicNone("match_keys_no_match"))
    else:
        result = SymbolicValue(
            _name=f"match_keys_result_{state.pc}",
            z3_int=get_int_val(len(concrete_keys_obj or [])),
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
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Pop class pattern operands and push captured attributes or a no-match sentinel."""
    num_positional = int(instr.argval) if instr.argval else 0
    names_tuple = state.pop() if state.stack else None
    cls = state.pop() if state.stack else None
    subject = state.pop() if state.stack else None

    modeled_attrs = modeled_match_class_attrs(subject, cls, names_tuple, num_positional)
    if modeled_attrs is not None:
        state = state.push(modeled_attrs)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if isinstance(cls, type) and not isinstance(subject, (SymbolicValue, SymbolicObject)):
        concrete_attrs = concrete_match_class_attrs(subject, cls, names_tuple, num_positional)
        if concrete_attrs is not None:
            state = state.push(concrete_attrs)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

    attr_names = (
        extract_match_class_attr_names(cls, names_tuple, num_positional)
        if isinstance(cls, type)
        else None
    )
    attr_count = len(attr_names) if attr_names is not None else num_positional

    success = z3.Bool(fresh_name("match_class_success"))
    if isinstance(subject, SymbolicObject) and isinstance(cls, type):
        success = z3.And(success, subject.z3_addr >= Z3_ZERO)
    elif isinstance(subject, SymbolicValue) and isinstance(cls, type):
        builtin_success = builtin_match_success(subject, cls)
        if builtin_success is not None:
            success = builtin_success
    elif isinstance(cls, type):
        success = Z3_TRUE if isinstance(subject, cls) else Z3_FALSE

    if z3.is_false(z3.simplify(success)):
        state = state.push(SymbolicNone("match_class_no_match"))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    result = SymbolicValue(
        _name=f"match_class_result_{state.pc}",
        z3_int=get_int_val(attr_count),
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
