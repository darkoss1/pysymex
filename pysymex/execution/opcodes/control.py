"""Control flow opcodes (jumps, branches, returns)."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.copy_on_write import CowDict
from pysymex.core.solver import get_model, is_satisfiable
from pysymex.core.types import Z3_FALSE, Z3_TRUE, SymbolicNone, SymbolicValue
from pysymex.core.types_containers import SymbolicIterator, SymbolicList
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


@opcode_handler("RESUME", "NOP")
def handle_no_op(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle no-op instructions."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def get_truthy_expr(value: object) -> z3.BoolRef:
    """Get Z3 expression for when a value is truthy."""
    if hasattr(value, "could_be_truthy"):
        return value.could_be_truthy()
    if isinstance(value, SymbolicValue):
        return z3.Or(
            z3.And(value.is_bool, value.z3_bool),
            z3.And(value.is_int, value.z3_int != 0),
        )

    if isinstance(value, bool):
        return z3.BoolVal(value)
    if isinstance(value, (int, float)):
        return z3.BoolVal(value != 0)
    if value is None:
        return z3.BoolVal(False)

    if isinstance(value, (str, bytes, list, tuple, dict, set, frozenset)):
        return z3.BoolVal(len(value) != 0)
    return z3.BoolVal(True)


@opcode_handler("RETURN_VALUE")
def handle_return_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return from function with inter-procedural support."""
    return_value = state.pop() if state.stack else None
    frame = state.pop_call()

    if frame is not None and getattr(frame, "summary_builder", None) is not None:
        builder = frame.summary_builder
        initial_args = getattr(builder, "_initial_args", [])

        if ctx.cross_function and hasattr(ctx.cross_function, "function_summary_cache"):
            constraints = list(state.path_constraints)

            targets: list[z3.ExprRef] = []
            if isinstance(return_value, SymbolicValue):
                if return_value.z3_int is not None:
                    targets.append(return_value.z3_int)
                if return_value.z3_bool is not None:
                    targets.append(return_value.z3_bool)

            summary_constraints = constraints

            assert builder is not None
            summary = builder.build()

            param_map: list[tuple[z3.ExprRef, z3.ExprRef]] = []
            for i, arg in enumerate(initial_args):
                if isinstance(arg, SymbolicValue):
                    param_info = summary.parameters[i] if i < len(summary.parameters) else None
                    if param_info:
                        param_z3 = param_info.to_z3()
                        if arg.z3_int is not None:
                            param_map.append((arg.z3_int, param_z3))

            canonical_return = return_value

            if isinstance(return_value, SymbolicValue):
                new_z3_int = (
                    z3.substitute(return_value.z3_int, *param_map)
                    if return_value.z3_int is not None
                    else None
                )
                new_z3_bool = (
                    z3.substitute(return_value.z3_bool, *param_map)
                    if return_value.z3_bool is not None
                    else None
                )

                canonical_return = SymbolicValue(
                    _name=return_value.name,
                    z3_int=cast("z3.ArithRef", new_z3_int),
                    is_int=return_value.is_int,
                    z3_bool=cast("z3.BoolRef", new_z3_bool),
                    is_bool=return_value.is_bool,
                )

            summary.return_var = canonical_return

            if isinstance(canonical_return, SymbolicValue):
                summary.return_var = (
                    canonical_return.z3_int
                    if canonical_return.z3_int is not None
                    else canonical_return.z3_bool
                )

            canonical_constraints: list[z3.ExprRef] = []
            for c in summary_constraints:
                canonical_constraints.append(z3.substitute(c, *param_map))

            summary.postconditions = canonical_constraints

            assert builder is not None
            ctx.cross_function.function_summary_cache.put(
                builder.summary.name, initial_args, constraints, summary
            )

    if frame is not None:
        state.local_vars = cast("CowDict", frame.local_vars)
        state = state.set_pc(frame.return_pc)
        if frame.caller_instructions is not None:
            state.current_instructions = frame.caller_instructions
            ctx.set_instructions(frame.caller_instructions)
        if return_value is not None:
            state = state.push(return_value)
        else:
            state = state.push(SymbolicNone())
        state.depth -= 1
        return OpcodeResult.continue_with(state)
    return OpcodeResult.terminate()


@opcode_handler("RETURN_CONST")
def handle_return_const(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return a constant (Python 3.13+) with inter-procedural support."""
    print(f"DEBUG: handle_return_const PC={state.pc}")
    const_val = instr.argval
    if const_val is None:
        return_value = SymbolicNone()
    else:
        return_value = SymbolicValue.from_const(const_val)
    frame = state.pop_call()
    if frame is not None:
        state.local_vars = cast("CowDict", frame.local_vars)
        state = state.set_pc(frame.return_pc)
        if frame.caller_instructions is not None:
            state.current_instructions = frame.caller_instructions
            ctx.set_instructions(frame.caller_instructions)
        state = state.push(return_value)
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
    cond_taint: frozenset[str] = frozenset()
    if hasattr(cond, "taint_labels") and cond.taint_labels:
        cond_taint = frozenset(cond.taint_labels)
    elif hasattr(cond, "_taint") and cond._taint:
        cond_taint = frozenset(cond._taint)
    true_state = state.fork()
    true_state = true_state.add_constraint(cond_expr)
    true_state = true_state.record_branch(cond_expr, True, state.pc)
    true_state = true_state.set_pc(state.pc + 1)
    if cond_taint:
        true_state.control_taint = true_state.control_taint | cond_taint
    false_state = state.fork()
    false_state = false_state.add_constraint(z3.Not(cond_expr))
    false_state = false_state.record_branch(cond_expr, False, state.pc)
    false_state = false_state.set_pc(target_index)
    if cond_taint:
        false_state.control_taint = false_state.control_taint | cond_taint
    
    # Prune infeasible paths
    branches = []
    if is_satisfiable(true_state.path_constraints):
        branches.append(true_state)
    if is_satisfiable(false_state.path_constraints):
        branches.append(false_state)
    return OpcodeResult.branch(branches)


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
    cond_taint: frozenset[str] = frozenset()
    if hasattr(cond, "taint_labels") and cond.taint_labels:
        cond_taint = frozenset(cond.taint_labels)
    elif hasattr(cond, "_taint") and cond._taint:
        cond_taint = frozenset(cond._taint)
    true_state = state.fork()
    true_state = true_state.add_constraint(cond_expr)
    true_state = true_state.record_branch(cond_expr, True, state.pc)
    true_state = true_state.set_pc(target_index)
    if cond_taint:
        true_state.control_taint = true_state.control_taint | cond_taint
    false_state = state.fork()
    false_state = false_state.add_constraint(z3.Not(cond_expr))
    false_state = false_state.record_branch(cond_expr, False, state.pc)
    false_state = false_state.set_pc(state.pc + 1)
    if cond_taint:
        false_state.control_taint = false_state.control_taint | cond_taint
    
    # Prune infeasible paths
    branches = []
    if is_satisfiable(true_state.path_constraints):
        branches.append(true_state)
    if is_satisfiable(false_state.path_constraints):
        branches.append(false_state)
    return OpcodeResult.branch(branches)


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
        state = state.set_pc(target_index)
        return OpcodeResult.continue_with(state)
    elif isinstance(value, SymbolicValue):
        none_expr = value.is_none
        none_state = state.fork()
        none_state = none_state.add_constraint(none_expr)
        none_state = none_state.record_branch(none_expr, True, state.pc)
        none_state = none_state.set_pc(target_index)
        not_none_state = state.fork()
        not_none_state = not_none_state.add_constraint(z3.Not(none_expr))
        not_none_state = not_none_state.record_branch(none_expr, False, state.pc)
        not_none_state = not_none_state.set_pc(state.pc + 1)
        
        # Prune infeasible paths
        branches = []
        if is_satisfiable(none_state.path_constraints):
            branches.append(none_state)
        if is_satisfiable(not_none_state.path_constraints):
            branches.append(not_none_state)
        return OpcodeResult.branch(branches)
    else:
        state = state.advance_pc()
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
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    elif isinstance(value, SymbolicValue):
        none_expr = value.is_none
        not_none_state = state.fork()
        not_none_state = not_none_state.add_constraint(z3.Not(none_expr))
        not_none_state = not_none_state.record_branch(none_expr, False, state.pc)
        not_none_state = not_none_state.set_pc(target_index)
        none_state = state.fork()
        none_state = none_state.add_constraint(none_expr)
        none_state = none_state.record_branch(none_expr, True, state.pc)
        none_state = none_state.set_pc(state.pc + 1)
        
        # Prune infeasible paths
        branches = []
        if is_satisfiable(not_none_state.path_constraints):
            branches.append(not_none_state)
        if is_satisfiable(none_state.path_constraints):
            branches.append(none_state)
        return OpcodeResult.branch(branches)
    else:
        state = state.set_pc(target_index)
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
        state = state.set_pc(target_index)
    else:
        state = state.advance_pc()
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
    jump_state = jump_state.add_constraint(cond_expr if jump_on_true else z3.Not(cond_expr))
    jump_state = jump_state.set_pc(target_index)
    pop_state = state.fork()
    pop_state = pop_state.add_constraint(z3.Not(cond_expr) if jump_on_true else cond_expr)
    pop_state.pop()
    pop_state = pop_state.set_pc(state.pc + 1)
    return OpcodeResult.branch([jump_state, pop_state])


@opcode_handler("RAISE_VARARGS")
def handle_raise_varargs(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Raise an exception, unwinding the block stack to find a handler.

    Scans the block stack in reverse for a ``finally`` or ``except``
    block.  If one is found, forks an exception state that jumps to the
    handler PC (lazy exception dispatch — paired with the non-forking
    ``SETUP_FINALLY``).  If no handler is found, reports the issue and
    terminates as before.
    """
    _argc = int(instr.argval) if instr.argval else 0
    is_assertion = False
    is_not_implemented = False
    if state.stack:
        top = state.peek()
        top_name = str(getattr(top, "name", "") or getattr(top, "_name", "") or "")
        if "AssertionError" in top_name:
            is_assertion = True
        elif "NotImplementedError" in top_name:
            is_not_implemented = True

    if is_not_implemented:
        return OpcodeResult.terminate()

    for idx in range(len(state.block_stack) - 1, -1, -1):
        block = state.block_stack[idx]
        if block.block_type in ("finally", "except"):
            exc_state = state.fork()
            while len(exc_state.block_stack) > idx:
                exc_state.exit_block()

            exc_val, constraint = SymbolicValue.symbolic(f"exception_{state.pc}")
            exc_state = exc_state.push(exc_val)
            exc_state = exc_state.add_constraint(constraint)
            exc_state = exc_state.set_pc(block.handler_pc)

            if is_assertion and is_satisfiable(state.path_constraints):
                issue = Issue(
                    kind=IssueKind.ASSERTION_ERROR,
                    message="Assertion may fail",
                    constraints=state.copy_constraints(),
                    model=get_model(state.path_constraints),
                    pc=state.pc,
                )
                result = OpcodeResult.branch([exc_state])
                result.issues.append(issue)
                return result

            return OpcodeResult.branch([exc_state])

    if is_assertion and is_satisfiable(state.path_constraints):
        issue = Issue(
            kind=IssueKind.ASSERTION_ERROR,
            message="Assertion may fail",
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
    state = state.push(marker)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("FOR_ITER")
def handle_for_iter(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Iterate over a sequence."""
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 2

    if not state.stack:
        return OpcodeResult.continue_with(state.set_pc(target_index))

    iterator = state.peek()
    iterable = None
    if isinstance(iterator, SymbolicIterator):
        iterable = iterator.iterable
    else:
        iterable = iterator

    from pysymex.core.types_containers import SymbolicObject
    if isinstance(iterable, SymbolicObject):
        addr = iterable.address
        if addr in state.memory:
            iterable = state.memory[addr]

    continue_state = state.fork()
    
    # Advance the iterator if it's one
    if isinstance(iterator, SymbolicIterator):
        # We replace the iterator on the stack with an advanced one
        # to ensure state isolation even if someone uses the index.
        new_it = iterator.advance()
        continue_state.stack[-1] = new_it
    
    # Create the symbolic iteration value
    iter_val, type_constraint = SymbolicValue.symbolic(f"iter_{state.pc}_{state.path_id}")
    continue_state = continue_state.push(iter_val)
    continue_state = continue_state.add_constraint(type_constraint)

    # Exit state (loop finished)
    exit_state = state.fork()
    exit_state = exit_state.set_pc(target_index)

    # Continue state PC (loop body)
    continue_state = continue_state.advance_pc()

    # Robust check for SymbolicList or SymbolicValue acting as list
    is_list_val = isinstance(iterable, SymbolicList)
    if not is_list_val and isinstance(iterable, SymbolicValue):
        # Check if it was unified from a list
        is_list_val = hasattr(iterable, "is_list") and z3.is_true(iterable.is_list) if hasattr(iterable, "is_list") else False
    
    if is_list_val:
        # Get array and length from either container or unified value
        z3_array = getattr(iterable, "z3_array", None)
        z3_len = getattr(iterable, "z3_len", None)
        
        if z3_array is not None and z3_len is not None:
            idx = iterator.index if isinstance(iterator, SymbolicIterator) else 0
            # If continuing, idx MUST be < length
            continue_state = continue_state.add_constraint(z3.IntVal(idx) < z3_len)
            # Yielded value MUST be from list
            continue_state = continue_state.add_constraint(iter_val.z3_int == z3.Select(z3_array, z3.IntVal(idx)))
            # Force types since SymbolicList currently only stores integers in Z3
            continue_state = continue_state.add_constraint(iter_val.is_int == Z3_TRUE)
            continue_state = continue_state.add_constraint(iter_val.is_bool == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_float == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_str == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_obj == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_none == Z3_FALSE)
            # If exiting, idx MUST be >= length
            exit_state = exit_state.add_constraint(z3.IntVal(idx) >= z3_len)
            
            # Prune infeasible paths immediately
            new_states = []
            if is_satisfiable(continue_state.path_constraints):
                new_states.append(continue_state)
            if is_satisfiable(exit_state.path_constraints):
                new_states.append(exit_state)
            
            return OpcodeResult.branch(new_states)
        elif z3_array is not None:
            # If we only have array, we can't safely bound idx yet, but we can still link them
            idx = z3.Int(f"iter_idx_{state.pc}_{state.path_id}")
            continue_state = continue_state.add_constraint(
                iter_val.z3_int == z3.Select(z3_array, idx)
            )
            continue_state = continue_state.add_constraint(iter_val.is_int)

    continue_state = continue_state.set_pc(state.pc + 1)

    exit_state = state.fork()
    if exit_state.stack:
        exit_state.pop()
    exit_state = exit_state.set_pc(target_index)
    return OpcodeResult.branch([continue_state, exit_state])


@opcode_handler("GET_ITER")
def handle_get_iter(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get iterator from iterable."""
    if state.stack:
        obj = state.pop()
        iterator = SymbolicIterator(f"iter_{id(obj)}", obj)
        state = state.push(iterator)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("END_FOR")
def handle_end_for(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """End of for loop — pops exhausted iterator and sentinel (CPython 3.12+)."""
    for _ in range(2):
        if state.stack:
            state.pop()
    state = state.advance_pc()
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
        state = state.push(result)
    state = state.advance_pc()
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
        state = state.push(result)
        state = state.add_constraint(length >= 0)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("ENTER_EXECUTOR")
def handle_enter_executor(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Enter executor (Python 3.13 JIT hint, ignore)."""
    state = state.advance_pc()
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
        state = state.push(SymbolicNone())
    elif intrinsic_id == 6:
        result, constraint = SymbolicValue.symbolic(f"tuple_{state.pc}")
        state = state.push(result)
        state = state.add_constraint(constraint)
    else:
        result, constraint = SymbolicValue.symbolic(f"intrinsic1_{state.pc}")
        state = state.push(result)
        state = state.add_constraint(constraint)
    state = state.advance_pc()
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
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
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
    state = state.push(result)
    state = state.advance_pc()
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
    state = state.push(result)
    state = state.advance_pc()
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
    state = state.push(values)
    state = state.add_constraint(constraint)
    state = state.push(success_result)
    state = state.advance_pc()
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
    state = state.push(attrs)
    state = state.add_constraint(constraint)
    success_result = SymbolicValue(
        _name=f"match_class_success_{state.pc}",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=success,
        is_bool=z3.BoolVal(True),
    )
    state = state.push(success_result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
