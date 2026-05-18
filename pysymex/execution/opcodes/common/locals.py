# pysymex: Python Symbolic Execution & Formal Verification
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

"""Common local and global variable opcodes."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

import z3

from pysymex._typing import StackValue
from pysymex.core.state import UNBOUND, VMStateError, is_bound
from pysymex.core.types import SymbolicNone, SymbolicString, SymbolicValue
from pysymex.execution.dispatcher import OpcodeResult

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


def _require_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    if len(state.stack) < required_depth:
        raise VMStateError(
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )


def _decode_fast_name_tuple(instr: dis.Instruction) -> tuple[str, ...]:
    """Decode local variable names for fused fast-local opcodes (3.13+)."""
    argrepr = getattr(instr, "argrepr", "")
    if isinstance(argrepr, str) and argrepr:
        cleaned = argrepr.strip().strip("()")
        if "," in cleaned:
            parts = tuple(p.strip() for p in cleaned.split(",") if p.strip())
            if parts:
                return parts
        if cleaned:
            return (cleaned,)

    argval = instr.argval
    if isinstance(argval, str):
        cleaned = argval.strip().strip("()")
        if "," in cleaned:
            parts = tuple(p.strip() for p in cleaned.split(",") if p.strip())
            if parts:
                return parts
        if cleaned:
            return (cleaned,)
    elif isinstance(argval, tuple):
        return tuple(str(x) for x in argval)  # type: ignore[arg-type]

    return (str(argval),)


def _global_name_from_argval(argval: object) -> str:
    """Extract LOAD_GLOBAL name across CPython argval tuple variants."""
    return str(argval)


def handle_common_load_const(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load a constant onto the stack."""
    value = instr.argval
    if value is None:
        sym_val = SymbolicNone("load_const_None")
    elif isinstance(value, str):
        sym_val = SymbolicString.from_const(value)
    else:
        sym_val = SymbolicValue.from_const(value)

    state = state.push(sym_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load a local variable onto the stack."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        sym_val, type_constraint = SymbolicValue.symbolic(name)
        if any(
            s in name.lower()
            for s in ("substitutions", "config", "mapping", "settings", "options_map")
        ):
            sym_val.is_dict = z3.BoolVal(True)

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val

    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_fast_check(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load local variable with UnboundLocalError check."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        sym_val, type_constraint = SymbolicValue.symbolic(name)
        if any(
            s in name.lower()
            for s in ("substitutions", "config", "mapping", "settings", "options_map")
        ):
            sym_val.is_dict = z3.BoolVal(True)

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store top of stack into local variable."""
    name = str(instr.argval)
    _require_stack_depth(state, instr, 1, "STORE_FAST value")
    value: StackValue = state.pop()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete a local variable."""
    name = str(instr.argval)
    state = state.set_local(name, UNBOUND)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load a global variable onto the stack."""
    from pysymex.execution.opcodes.common import BUILTIN_TYPES

    name = _global_name_from_argval(instr.argval)
    push_null = False
    if hasattr(instr, "arg") and instr.arg is not None:
        if instr.arg & 1:
            push_null = True
    value = state.get_global(name)

    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(f"global_{name}")
        if name.isupper() and any(
            s in name for s in ("_SUBSTITUTIONS", "_MAP", "_DICT", "_MAPPING")
        ):
            sym_val.is_dict = z3.BoolVal(True)

        sym_val.model_name = name
        if name in BUILTIN_TYPES:
            sym_val.affinity_type = BUILTIN_TYPES[name]
        state = state.add_constraint(z3.Not(sym_val.is_none))

        state = state.set_global(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    if push_null:
        state = state.push(SymbolicNone())
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store top of stack into a global variable."""
    name = str(instr.argval)
    _require_stack_depth(state, instr, 1, "STORE_GLOBAL value")
    value = state.pop()
    state = state.set_global(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete a global variable."""
    name = str(instr.argval)
    if name in state.global_vars:
        del state.global_vars[name]
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load name from locals or globals."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value) and raw_value is not None:
        value = raw_value
    else:
        value = state.get_global(name)
    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(name)
        if name.isupper() and any(
            s in name for s in ("_SUBSTITUTIONS", "_MAP", "_DICT", "_MAPPING")
        ):
            state = state.add_constraint(sym_val.is_dict)

        import z3 as _z3

        state = state.add_constraint(_z3.Not(sym_val.is_none))

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store name in locals."""
    name = str(instr.argval)
    _require_stack_depth(state, instr, 1, "STORE_NAME value")
    value = state.pop()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete a name."""
    name = str(instr.argval)
    state = state.set_local(name, UNBOUND)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from closure/free variable."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value) and raw_value is not None:
        value = raw_value
    else:
        value = state.get_global(name)
    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(f"closure_{name}")

        import z3 as _z3

        state = state.add_constraint(_z3.Not(sym_val.is_none))

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store into closure variable."""
    name = str(instr.argval)
    _require_stack_depth(state, instr, 1, "STORE_DEREF value")
    value = state.pop()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_cell_ops(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Cell creation - mostly no-op for symbolic execution."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete closure variable."""
    name = str(instr.argval)
    state = state.set_local(name, UNBOUND)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_fast_and_clear(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load local variable and set slot to NULL (list comprehension save/restore)."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        value = SymbolicNone()
    state = state.push(value)
    state = state.set_local(name, UNBOUND)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_fast_maybe_null(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store to local that might be uninitialized (exception handling)."""
    name = str(instr.argval)
    _require_stack_depth(state, instr, 1, "STORE_FAST_MAYBE_NULL value")
    value = state.pop()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_from_dict_or_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from local namespace or closure (class body)."""
    name = str(instr.argval)
    _require_stack_depth(state, instr, 1, "LOAD_FROM_DICT_OR_DEREF namespace")
    state.pop()
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        value, constraint = SymbolicValue.symbolic(f"deref_{name}")
        state = state.add_constraint(constraint)
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_from_dict_or_globals(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from local namespace or globals (class body)."""
    name = str(instr.argval)
    _require_stack_depth(state, instr, 1, "LOAD_FROM_DICT_OR_GLOBALS namespace")
    state.pop()
    value = state.get_global(name)
    if value is None:
        value, constraint = SymbolicValue.symbolic(f"global_{name}")
        state = state.add_constraint(constraint)
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_locals(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push locals() dict onto stack."""
    locals_dict, constraint = SymbolicValue.symbolic(f"locals_{state.pc}")
    state = state.push(locals_dict)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_setup_annotations(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up __annotations__ dict (class/module level annotations)."""
    if "__annotations__" not in state.local_vars:
        state = state.set_local("__annotations__", {})
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_copy_free_vars(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Copy free variables from closure to cell variables."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_closure(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load closure cell."""
    name = str(instr.argval)
    val = state.get_local(name)
    if not is_bound(val):
        val, constraint = SymbolicValue.symbolic(f"closure_{name}_{state.pc}")
        state = state.set_local(name, val)
        state = state.add_constraint(constraint)
    state = state.push(val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_fast_load_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle fused load fast load fast (Python 3.13+)."""
    decoded = _decode_fast_name_tuple(instr)
    if len(decoded) < 2:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    name1, name2 = decoded[:2]
    for name in (name1, name2):
        raw_value = state.get_local(name)
        if is_bound(raw_value):
            value = raw_value
        else:
            sym_val, type_constraint = SymbolicValue.symbolic(f"load_fast_{name}@{state.pc}")
            state = state.set_local(name, sym_val)
            state = state.add_constraint(type_constraint)
            value = sym_val
        state = state.push(value)
    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_store_fast_load_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle fused store fast load fast (Python 3.13+)."""
    decoded = _decode_fast_name_tuple(instr)
    if len(decoded) < 2:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    name1, name2 = decoded[:2]
    value1 = state.pop()
    state = state.set_local(name1, value1)

    raw_value2 = state.get_local(name2)
    if is_bound(raw_value2):
        value2 = raw_value2
    else:
        sym_val, type_constraint = SymbolicValue.symbolic(f"load_fast_{name2}@{state.pc}")
        state = state.set_local(name2, sym_val)
        state = state.add_constraint(type_constraint)
        value2 = sym_val
    state = state.push(value2)

    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_store_fast_store_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle fused store fast store fast (Python 3.13+)."""
    decoded = _decode_fast_name_tuple(instr)
    if len(decoded) < 2:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    name1, name2 = decoded[:2]
    value1 = state.pop()
    value2 = state.pop()
    state = state.set_local(name1, value1)
    state = state.set_local(name2, value2)
    return OpcodeResult.continue_with(state.advance_pc())
