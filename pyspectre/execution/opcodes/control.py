"""Control flow opcodes (jumps, branches, returns)."""

from __future__ import annotations
import dis
from typing import TYPE_CHECKING
import z3
from pyspectre.analysis.detectors import Issue, IssueKind
from pyspectre.core.solver import get_model, is_satisfiable
from pyspectre.core.types import SymbolicNone, SymbolicValue
from pyspectre.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pyspectre.core.state import VMState
    from pyspectre.execution.dispatcher import OpcodeDispatcher


@opcode_handler("RESUME", "NOP")
def handle_no_op(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle no-op instructions."""
    state.pc += 1
    return OpcodeResult.continue_with(state)


def get_truthy_expr(value) -> z3.BoolRef:
    """Get Z3 expression for when a value is truthy."""
    if hasattr(value, "could_be_truthy"):
        return value.could_be_truthy()
    if isinstance(value, SymbolicValue):
        return z3.Or(
            z3.And(value.is_bool, value.z3_bool),
            z3.And(value.is_int, value.z3_int != 0),
        )
    return z3.BoolVal(True)


@opcode_handler("RETURN_VALUE")
def handle_return_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return from function with inter-procedural support."""
    return_value = state.pop() if state.stack else None
    frame = state.pop_call()
    if frame is not None:
        state.local_vars = frame.local_vars
        state.pc = frame.return_pc
        if frame.caller_instructions is not None:
            state.current_instructions = frame.caller_instructions
            ctx.set_instructions(frame.caller_instructions)
        if return_value is not None:
            state.push(return_value)
        else:
            state.push(SymbolicNone())
        state.depth -= 1
        return OpcodeResult.continue_with(state)
    return OpcodeResult.terminate()


@opcode_handler("RETURN_CONST")
def handle_return_const(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return a constant (Python 3.13+) with inter-procedural support."""
    const_val = instr.argval
    if const_val is None:
        return_value = SymbolicNone()
    else:
        return_value = SymbolicValue.from_const(const_val)
    frame = state.pop_call()
    if frame is not None:
        state.local_vars = frame.local_vars
        state.pc = frame.return_pc
        if frame.caller_instructions is not None:
            state.current_instructions = frame.caller_instructions
            ctx.set_instructions(frame.caller_instructions)
        state.push(return_value)
        state.depth -= 1
        return OpcodeResult.continue_with(state)
    return OpcodeResult.terminate()


@opcode_handler("POP_JUMP_IF_FALSE", "POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_BACKWARD_IF_FALSE")
def handle_pop_jump_if_false(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Conditional jump if top of stack is false, with implicit flow tracking."""
    cond = state.pop()
    cond_expr = get_truthy_expr(cond)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    cond_taint = frozenset()
    if hasattr(cond, "taint_labels") and cond.taint_labels:
        cond_taint = frozenset(cond.taint_labels)
    elif hasattr(cond, "_taint") and cond._taint:
        cond_taint = frozenset(cond._taint)
    true_state = state.fork()
    true_state.add_constraint(cond_expr)
    true_state.pc = state.pc + 1
    if cond_taint:
        true_state.control_taint = true_state.control_taint | cond_taint
    false_state = state.fork()
    false_state.add_constraint(z3.Not(cond_expr))
    false_state.pc = target_index
    if cond_taint:
        false_state.control_taint = false_state.control_taint | cond_taint
    return OpcodeResult.branch([false_state, true_state])


@opcode_handler("POP_JUMP_IF_TRUE", "POP_JUMP_FORWARD_IF_TRUE", "POP_JUMP_BACKWARD_IF_TRUE")
def handle_pop_jump_if_true(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Conditional jump if top of stack is true, with implicit flow tracking."""
    cond = state.pop()
    cond_expr = get_truthy_expr(cond)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    cond_taint = frozenset()
    if hasattr(cond, "taint_labels") and cond.taint_labels:
        cond_taint = frozenset(cond.taint_labels)
    elif hasattr(cond, "_taint") and cond._taint:
        cond_taint = frozenset(cond._taint)
    true_state = state.fork()
    true_state.add_constraint(cond_expr)
    true_state.pc = target_index
    if cond_taint:
        true_state.control_taint = true_state.control_taint | cond_taint
    false_state = state.fork()
    false_state.add_constraint(z3.Not(cond_expr))
    false_state.pc = state.pc + 1
    if cond_taint:
        false_state.control_taint = false_state.control_taint | cond_taint
    return OpcodeResult.branch([true_state, false_state])


@opcode_handler("POP_JUMP_IF_NONE", "POP_JUMP_FORWARD_IF_NONE", "POP_JUMP_BACKWARD_IF_NONE")
def handle_pop_jump_if_none(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Jump if top of stack is None."""
    value = state.pop()
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    is_none = isinstance(value, SymbolicNone)
    if is_none:
        state.pc = target_index
        return OpcodeResult.continue_with(state)
    elif isinstance(value, SymbolicValue):
        none_expr = z3.And(z3.Not(value.is_int), z3.Not(value.is_bool))
        none_state = state.fork()
        none_state.add_constraint(none_expr)
        none_state.pc = target_index
        not_none_state = state.fork()
        not_none_state.add_constraint(z3.Not(none_expr))
        not_none_state.pc = state.pc + 1
        return OpcodeResult.branch([none_state, not_none_state])
    else:
        state.pc += 1
        return OpcodeResult.continue_with(state)


@opcode_handler(
    "POP_JUMP_IF_NOT_NONE", "POP_JUMP_FORWARD_IF_NOT_NONE", "POP_JUMP_BACKWARD_IF_NOT_NONE"
)
def handle_pop_jump_if_not_none(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Jump if top of stack is not None."""
    value = state.pop()
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    is_none = isinstance(value, SymbolicNone)
    if is_none:
        state.pc += 1
        return OpcodeResult.continue_with(state)
    elif isinstance(value, SymbolicValue):
        none_expr = z3.And(z3.Not(value.is_int), z3.Not(value.is_bool))
        not_none_state = state.fork()
        not_none_state.add_constraint(z3.Not(none_expr))
        not_none_state.pc = target_index
        none_state = state.fork()
        none_state.add_constraint(none_expr)
        none_state.pc = state.pc + 1
        return OpcodeResult.branch([not_none_state, none_state])
    else:
        state.pc = target_index
        return OpcodeResult.continue_with(state)


@opcode_handler(
    "JUMP_FORWARD",
    "JUMP_ABSOLUTE",
    "JUMP_BACKWARD",
    "JUMP_BACKWARD_NO_INTERRUPT",
    "JUMP",
    "JUMP_NO_INTERRUPT",
)
def handle_jump(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Unconditional jump."""
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is not None:
        state.pc = target_index
    else:
        state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP")
def handle_jump_or_pop(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Jump if true/false, otherwise pop."""
    cond = state.peek()
    cond_expr = get_truthy_expr(cond)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    jump_on_true = instr.opname == "JUMP_IF_TRUE_OR_POP"
    jump_state = state.fork()
    jump_state.add_constraint(cond_expr if jump_on_true else z3.Not(cond_expr))
    jump_state.pc = target_index
    pop_state = state.fork()
    pop_state.add_constraint(z3.Not(cond_expr) if jump_on_true else cond_expr)
    pop_state.pop()
    pop_state.pc = state.pc + 1
    return OpcodeResult.branch([jump_state, pop_state])


@opcode_handler("RAISE_VARARGS")
def handle_raise_varargs(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Raise an exception."""
    _argc = int(instr.argval) if instr.argval else 0
    is_assertion = False
    if state.stack:
        top = state.peek()
        if hasattr(top, "name") and "AssertionError" in str(getattr(top, "name", "")):
            is_assertion = True
    if is_satisfiable(state.path_constraints):
        issue = Issue(
            kind=IssueKind.ASSERTION_ERROR if is_assertion else IssueKind.EXCEPTION,
            message="Assertion may fail" if is_assertion else "Exception may be raised",
            constraints=state.copy_constraints(),
            model=get_model(state.path_constraints),
            pc=state.pc,
        )
        return OpcodeResult.error(issue)
    return OpcodeResult.terminate()


@opcode_handler("LOAD_ASSERTION_ERROR")
def handle_load_assertion_error(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load AssertionError for assert statements."""
    marker = SymbolicValue(
        _name="AssertionError",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )
    state.push(marker)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("FOR_ITER")
def handle_for_iter(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Iterate over a sequence."""
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 2
    continue_state = state.fork()
    iter_val, type_constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
    continue_state.push(iter_val)
    continue_state.add_constraint(type_constraint)
    continue_state.pc = state.pc + 1
    exit_state = state.fork()
    if exit_state.stack:
        exit_state.pop()
    exit_state.pc = target_index
    return OpcodeResult.branch([continue_state, exit_state])


@opcode_handler("GET_ITER")
def handle_get_iter(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get iterator from iterable."""
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("END_FOR")
def handle_end_for(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """End of for loop."""
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("TO_BOOL")
def handle_to_bool(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Convert top of stack to bool (Python 3.12+)."""
    if state.stack:
        value = state.pop()
        truthy = get_truthy_expr(value)
        result = SymbolicValue(
            _name=f"to_bool_{state.pc}",
            z3_int=z3.If(truthy, z3.IntVal(1), z3.IntVal(0)),
            is_int=z3.BoolVal(False),
            z3_bool=truthy,
            is_bool=z3.BoolVal(True),
        )
        state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_LEN")
def handle_get_len(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get length of top of stack (for pattern matching/sequences)."""
    if state.stack:
        value = state.peek()
        if hasattr(value, "length"):
            length = value.length
        else:
            length = z3.Int(f"len_{state.pc}")
        result = SymbolicValue(
            _name=f"len_{state.pc}",
            z3_int=length,
            is_int=z3.BoolVal(True),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
        )
        state.push(result)
        state.add_constraint(length >= 0)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("ENTER_EXECUTOR")
def handle_enter_executor(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Enter executor (Python 3.13 JIT hint, ignore)."""
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CALL_INTRINSIC_1")
def handle_call_intrinsic_1(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Call single-argument intrinsic function (print, repr, etc.)."""
    if state.stack:
        _arg = state.pop()
    intrinsic_id = int(instr.argval) if instr.argval else 0
    if intrinsic_id == 1:
        state.push(SymbolicNone())
    elif intrinsic_id == 6:
        result, constraint = SymbolicValue.symbolic(f"tuple_{state.pc}")
        state.push(result)
        state.add_constraint(constraint)
    else:
        result, constraint = SymbolicValue.symbolic(f"intrinsic1_{state.pc}")
        state.push(result)
        state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CALL_INTRINSIC_2")
def handle_call_intrinsic_2(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Call two-argument intrinsic function."""
    if state.stack:
        state.pop()
    if state.stack:
        state.pop()
    result, constraint = SymbolicValue.symbolic(f"intrinsic2_{state.pc}")
    state.push(result)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("MATCH_MAPPING")
def handle_match_mapping(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if subject is a mapping (dict) for pattern matching."""
    is_mapping = z3.Bool(f"is_mapping_{state.pc}")
    result = SymbolicValue(
        _name=f"is_mapping_{state.pc}",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=is_mapping,
        is_bool=z3.BoolVal(True),
    )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("MATCH_SEQUENCE")
def handle_match_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if subject is a sequence (list/tuple) for pattern matching."""
    is_sequence = z3.Bool(f"is_sequence_{state.pc}")
    result = SymbolicValue(
        _name=f"is_sequence_{state.pc}",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=is_sequence,
        is_bool=z3.BoolVal(True),
    )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("MATCH_KEYS")
def handle_match_keys(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if mapping has required keys for pattern matching."""
    if state.stack:
        state.pop()
    success = z3.Bool(f"match_keys_success_{state.pc}")
    success_result = SymbolicValue(
        _name=f"match_keys_success_{state.pc}",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=success,
        is_bool=z3.BoolVal(True),
    )
    values, constraint = SymbolicValue.symbolic(f"match_values_{state.pc}")
    state.push(values)
    state.add_constraint(constraint)
    state.push(success_result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("MATCH_CLASS")
def handle_match_class(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if subject matches a class pattern."""
    num_positional = int(instr.argval) if instr.argval else 0
    for _ in range(num_positional):
        if state.stack:
            state.pop()
    if state.stack:
        state.pop()
    success = z3.Bool(f"match_class_success_{state.pc}")
    attrs, constraint = SymbolicValue.symbolic(f"match_attrs_{state.pc}")
    state.push(attrs)
    state.add_constraint(constraint)
    success_result = SymbolicValue(
        _name=f"match_class_success_{state.pc}",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=success,
        is_bool=z3.BoolVal(True),
    )
    state.push(success_result)
    state.pc += 1
    return OpcodeResult.continue_with(state)
