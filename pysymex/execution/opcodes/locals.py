"""Local and global variable opcodes."""

from __future__ import annotations


import dis

from typing import TYPE_CHECKING, Any


from pysymex.core.types import SymbolicNone, SymbolicString, SymbolicValue

from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState

    from pysymex.execution.dispatcher import OpcodeDispatcher


@opcode_handler("LOAD_CONST")
def handle_load_const(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load a constant onto the stack."""

    value = instr.argval

    if value is None:
        sym_val = SymbolicNone()

    elif isinstance(value, str):
        sym_val = SymbolicString.from_const(value)

    else:
        sym_val = SymbolicValue.from_const(value)

    state.push(sym_val)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_FAST", "LOAD_FAST_CHECK")
def handle_load_fast(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Load a local variable onto the stack."""

    name = str(instr.argval)

    value = state.get_local(name)

    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(name)

        state.set_local(name, sym_val)

        state.add_constraint(type_constraint)

        value = sym_val

    state.push(value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_FAST_LOAD_FAST")
def handle_load_fast_load_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load two local variables onto the stack (Python 3.13+)."""

    names: tuple[Any, ...] = (
        instr.argval if isinstance(instr.argval, tuple) else (str(instr.argval),)
    )

    for name in names:
        name = str(name)

        value = state.get_local(name)

        if value is None:
            sym_val, type_constraint = SymbolicValue.symbolic(name)

            state.set_local(name, sym_val)

            state.add_constraint(type_constraint)

            value = sym_val

        state.push(value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_FAST")
def handle_store_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store top of stack into local variable with implicit flow taint tracking."""

    name = str(instr.argval)

    value = state.pop()

    if state.control_taint and hasattr(value, "taint_labels"):
        value.taint_labels = set(value.taint_labels or set()) | set[str](state.control_taint)

    elif state.control_taint and isinstance(value, SymbolicValue):
        if not hasattr(value, "taint_labels") or value.taint_labels is None:
            value.taint_labels = set()

        value.taint_labels = value.taint_labels | set[str](state.control_taint)

    state.set_local(name, value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_FAST_STORE_FAST")
def handle_store_fast_store_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store two values into local variables (Python 3.13+) with implicit flow taint tracking."""

    names: tuple[Any, ...] = (
        instr.argval if isinstance(instr.argval, tuple) else (str(instr.argval),)
    )

    for name in names:
        name = str(name)

        value = state.pop()

        if state.control_taint and hasattr(value, "taint_labels"):
            value.taint_labels = set(value.taint_labels or set()) | set[str](state.control_taint)

        elif state.control_taint and isinstance(value, SymbolicValue):
            if not hasattr(value, "taint_labels") or value.taint_labels is None:
                value.taint_labels = set()

            value.taint_labels = value.taint_labels | set[str](state.control_taint)

        state.set_local(name, value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_FAST")
def handle_delete_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete a local variable."""

    name = str(instr.argval)

    if name in state.local_vars:
        del state.local_vars[name]

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_GLOBAL")
def handle_load_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load a global variable onto the stack."""

    if isinstance(instr.argval, tuple):
        name = str(instr.argval[1]) if len(instr.argval) > 1 else str(instr.argval[0])

    else:
        name = str(instr.argval)

    push_null = False

    if hasattr(instr, "arg") and instr.arg is not None:
        if instr.arg & 1:
            push_null = True

    value = state.get_global(name)

    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(f"global_{name}")

        sym_val.model_name = name

        state.set_global(name, sym_val)

        state.add_constraint(type_constraint)

        value = sym_val

    state.push(value)

    if push_null:
        state.push(SymbolicNone())

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_GLOBAL")
def handle_store_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store top of stack into a global variable."""

    name = str(instr.argval)

    value = state.pop()

    state.set_global(name, value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_GLOBAL")
def handle_delete_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete a global variable."""

    name = str(instr.argval)

    if name in state.global_vars:
        del state.global_vars[name]

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_NAME")
def handle_load_name(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Load name from locals or globals."""

    name = str(instr.argval)

    value = state.get_local(name) or state.get_global(name)

    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(name)

        state.set_local(name, sym_val)

        state.add_constraint(type_constraint)

        value = sym_val

    state.push(value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_NAME")
def handle_store_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store name in locals."""

    name = str(instr.argval)

    value = state.pop()

    state.set_local(name, value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_NAME")
def handle_delete_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete a name."""

    name = str(instr.argval)

    if name in state.local_vars:
        del state.local_vars[name]

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_DEREF", "LOAD_CLOSURE")
def handle_load_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from closure/free variable."""

    name = str(instr.argval)

    value = state.get_local(name) or state.get_global(name)

    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(f"closure_{name}")

        state.set_local(name, sym_val)

        state.add_constraint(type_constraint)

        value = sym_val

    state.push(value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_DEREF")
def handle_store_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store into closure variable."""

    name = str(instr.argval)

    value = state.pop()

    state.set_local(name, value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("MAKE_CELL", "COPY_FREE_VARS")
def handle_cell_ops(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Cell creation - mostly no-op for symbolic execution."""

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_DEREF")
def handle_delete_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete closure variable."""

    name = str(instr.argval)

    if name in state.local_vars:
        del state.local_vars[name]

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_FAST_AND_CLEAR")
def handle_load_fast_and_clear(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load local variable and set slot to NULL (list comprehension save/restore)."""

    name = str(instr.argval)

    value = state.get_local(name)

    if value is None:
        value = SymbolicNone()

    state.push(value)

    state.set_local(name, None)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_FAST_LOAD_FAST")
def handle_store_fast_load_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store and immediately reload a local (Python 3.13+ optimization)."""

    _argval: Any = instr.argval

    names: tuple[Any, ...] = _argval if isinstance(_argval, tuple) else (str(_argval), str(_argval))

    store_name = str(names[0])

    load_name = str(names[1]) if len(names) > 1 else store_name

    value = state.pop()

    state.set_local(store_name, value)

    loaded = state.get_local(load_name)

    if loaded is None:
        loaded, constraint = SymbolicValue.symbolic(load_name)

        state.add_constraint(constraint)

    state.push(loaded)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_FAST_MAYBE_NULL")
def handle_store_fast_maybe_null(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store to local that might be uninitialized (exception handling)."""

    name = str(instr.argval)

    value = state.pop() if state.stack else SymbolicNone()

    state.set_local(name, value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_FROM_DICT_OR_DEREF")
def handle_load_from_dict_or_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from local namespace or closure (class body)."""

    name = str(instr.argval)

    if state.stack:
        state.pop()

    value = state.get_local(name)

    if value is None:
        value, constraint = SymbolicValue.symbolic(f"deref_{name}")

        state.add_constraint(constraint)

    state.push(value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_FROM_DICT_OR_GLOBALS")
def handle_load_from_dict_or_globals(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from local namespace or globals (class body)."""

    name = str(instr.argval)

    if state.stack:
        state.pop()

    value = state.get_global(name)

    if value is None:
        value, constraint = SymbolicValue.symbolic(f"global_{name}")

        state.add_constraint(constraint)

    state.push(value)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_LOCALS")
def handle_load_locals(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push locals() dict onto stack."""

    locals_dict, constraint = SymbolicValue.symbolic(f"locals_{state.pc}")

    state.push(locals_dict)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("SETUP_ANNOTATIONS")
def handle_setup_annotations(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up __annotations__ dict (class/module level annotations)."""

    state.pc += 1

    return OpcodeResult.continue_with(state)
