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

"""Control flow opcodes (jumps, branches, returns)."""

from __future__ import annotations

import dis
from collections.abc import Iterable
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.summaries.core import SummaryBuilder
from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.core.types.scalars import (
    Z3_FALSE,
    Z3_TRUE,
    SymbolicNone,
    SymbolicType,
    SymbolicValue,
    fresh_name,
)
from pysymex.core.types.containers import (
    SymbolicDict,
    SymbolicIterator,
    SymbolicList,
    SymbolicObject,
    SymbolicString,
)
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

_MAX_SUMMARY_CACHE_CONSTRAINTS = 24
_MAX_SUMMARY_CACHE_ARGS = 12

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


@runtime_checkable
class _SummaryCacheProtocol(Protocol):
    def put(
        self,
        func_name: str,
        args: list[object],
        path_constraints: list[z3.BoolRef],
        summary: object,
    ) -> None: ...


@runtime_checkable
class _CrossFunctionProtocol(Protocol):
    function_summary_cache: _SummaryCacheProtocol


def _is_sat_with_extra(constraints: object, extra: z3.BoolRef) -> bool:
    import z3
    from pysymex.core.solver.engine import is_satisfiable

    constraint_list = list(cast("Iterable[z3.BoolRef]", constraints))

    if z3.is_false(extra):
        return False
    if z3.is_true(extra):
        return is_satisfiable(constraint_list)

    return is_satisfiable(constraint_list + [extra], known_sat_prefix_len=len(constraint_list))


def get_truthy_expr(value: object) -> z3.BoolRef:
    """Get Z3 expression for when a value is truthy.

    **Truthiness Mapping:**
    pysymex models Python's `bool()` semantics using Z3 propositional logic:
    - **SymbolicValue**: A union of `(val.is_bool ∧ val.z3_bool) ∨ (val.is_int ∧ val.z3_int != 0)`.
    - **Concrete**: Standard Python truthiness (e.g., `bool(42) == True`).
    - **Containers**: Evaluated via `len(container) != 0`.

    When ``affinity_type`` is known (e.g. ``"int"`` or ``"bool"``), we
    bypass the full disjunctive encoding and emit a single-sort
    expression.  This eliminates type-discriminator variables from branch
    conditions and dramatically reduces treewidth in the constraint
    interaction graph — a key enabler for CHTD.

    Returns:
        A Z3 boolean expression representing the truthiness of the value.
    """

    if isinstance(value, SymbolicValue):
        aff = value.affinity_type
        if aff == "bool":
            return value.z3_bool
        if aff == "int":
            return value.z3_int != 0
        if aff == "float":
            return z3.Not(z3.fpIsZero(value.z3_float))
        if aff == "str":
            return z3.Length(value.z3_str) != 0

    if isinstance(value, SymbolicType):
        return value.could_be_truthy()

    if isinstance(value, bool):
        return z3.BoolVal(value)
    if isinstance(value, (int, float)):
        return z3.BoolVal(value != 0)
    if value is None:
        return z3.BoolVal(False)

    if isinstance(value, str):
        return z3.BoolVal(value != "")
    if isinstance(value, bytes):
        return z3.BoolVal(value != b"")
    if isinstance(value, list):
        return z3.BoolVal(value != [])
    if isinstance(value, tuple):
        return z3.BoolVal(value != ())
    if isinstance(value, dict):
        return z3.BoolVal(value != {})
    if isinstance(value, set):
        return z3.BoolVal(value != set())
    if isinstance(value, frozenset):
        return z3.BoolVal(value != frozenset())
    return z3.BoolVal(True)


@opcode_handler("RESUME", "NOP")
def handle_no_op(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle no-op instructions."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("RETURN_VALUE")
def handle_return_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return from function with inter-procedural support."""
    return_value = state.pop() if state.stack else None

    issue = None
    if state.contract_frames:
        from collections.abc import Callable

        func = cast("Callable[..., object]", state.contract_frames.pop())
        config = getattr(ctx, "config", None)
        if config and getattr(config, "enable_contract_verification", False):
            from pysymex.contracts.injector import inject_postconditions

            issue = inject_postconditions(state, func, return_value, config)

    frame = state.pop_call()

    if frame is not None and isinstance(frame.summary_builder, SummaryBuilder):
        builder = frame.summary_builder
        initial_args = builder.initial_args
        cross_function = ctx.cross_function

        if isinstance(cross_function, _CrossFunctionProtocol):
            constraints = list(state.path_constraints)

            summary_constraints = constraints

            summary = builder.build()

            param_map: list[tuple[z3.ExprRef, z3.ExprRef]] = []
            for i, arg in enumerate(initial_args):
                if isinstance(arg, SymbolicValue):
                    param_info = summary.parameters[i] if i < len(summary.parameters) else None
                    if param_info:
                        param_z3 = param_info.to_z3()
                        param_map.append((arg.z3_int, param_z3))

            canonical_return = return_value

            if isinstance(return_value, SymbolicValue):
                new_z3_int = cast("z3.ArithRef", z3.substitute(return_value.z3_int, *param_map))
                new_z3_bool = cast("z3.BoolRef", z3.substitute(return_value.z3_bool, *param_map))

                canonical_return = SymbolicValue(
                    _name=return_value.name,
                    z3_int=new_z3_int,
                    is_int=return_value.is_int,
                    z3_bool=new_z3_bool,
                    is_bool=return_value.is_bool,
                )

            summary.return_var = (
                canonical_return.z3_int if isinstance(canonical_return, SymbolicValue) else None
            )

            canonical_constraints: list[z3.BoolRef] = []
            for c in summary_constraints:
                canonical_constraints.append(cast("z3.BoolRef", z3.substitute(c, *param_map)))

            summary.postconditions = canonical_constraints

            if (
                len(constraints) <= _MAX_SUMMARY_CACHE_CONSTRAINTS
                and len(initial_args) <= _MAX_SUMMARY_CACHE_ARGS
            ):
                cross_function.function_summary_cache.put(
                    getattr(builder.summary, "name", "unknown"),
                    initial_args,
                    constraints,
                    summary,
                )

    if frame is not None:
        state.local_vars = frame.local_vars
        state = state.set_pc(frame.return_pc)
        if frame.caller_instructions is not None:
            caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
            state.current_instructions = cast("list[object]", caller_instructions)
            ctx.set_instructions(caller_instructions)
        if return_value is not None:
            state = state.push(return_value)
        else:
            state = state.push(SymbolicNone("return_None"))
        state.depth -= 1
        if issue:
            return OpcodeResult.with_issue(state, issue)
        return OpcodeResult.continue_with(state)
    if issue:
        return OpcodeResult(new_states=[], issues=[issue], terminal=True)
    return OpcodeResult.terminate()


@opcode_handler("RETURN_CONST")
def handle_return_const(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return a constant (Python 3.13+) with inter-procedural support."""
    const_val = instr.argval
    if const_val is None:
        return_value = SymbolicNone("return_None")
    else:
        return_value = SymbolicValue.from_const(const_val)

    issue = None
    if state.contract_frames:
        from collections.abc import Callable

        func = cast("Callable[..., object]", state.contract_frames.pop())
        config = getattr(ctx, "config", None)
        if config and getattr(config, "enable_contract_verification", False):
            from pysymex.contracts.injector import inject_postconditions

            issue = inject_postconditions(state, func, return_value, config)

    frame = state.pop_call()
    if frame is not None:
        state.local_vars = frame.local_vars
        state = state.set_pc(frame.return_pc)
        if frame.caller_instructions is not None:
            caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
            state.current_instructions = cast("list[object]", caller_instructions)
            ctx.set_instructions(caller_instructions)
        state = state.push(return_value)
        state.depth -= 1
        if issue:
            return OpcodeResult.with_issue(state, issue)
        return OpcodeResult.continue_with(state)
    if issue:
        return OpcodeResult(new_states=[], issues=[issue], terminal=True)
    return OpcodeResult.terminate()


@opcode_handler("POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE")
def handle_pop_jump_if_true(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Conditional jump if top of stack is true.

    **Branching Logic:**
    1. **Evaluation**: Converts the TOS to a Z3 boolean expression.
    2. **Forking**: Clones the state into *True* and *False* iterations.
    3. **Constraint Injection**:
       - The *True* branch (PC → target) receives the constraint `value != 0`.
       - The *False* branch (PC → PC+1) receives the constraint `value == 0`.
    4. **Pruning**: Only returns satisfiable branches to the executor.
    """
    cond = state.pop()
    cond_expr = get_truthy_expr(cond)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    not_cond_expr = z3.Not(cond_expr)

    true_feasible = is_satisfiable([*state.path_constraints, cond_expr])
    false_feasible = is_satisfiable([*state.path_constraints, not_cond_expr])

    branches: list[VMState] = []
    if true_feasible:
        true_state = state.fork()
        true_state = true_state.add_constraint(cond_expr)
        true_state = true_state.record_branch(cond_expr, True, state.pc)
        true_state = true_state.set_pc(target_index)
        branches.append(true_state)

    if false_feasible:
        false_state = state.fork()
        false_state = false_state.add_constraint(not_cond_expr)
        false_state = false_state.record_branch(cond_expr, False, state.pc)
        false_state = false_state.set_pc(state.pc + 1)
        branches.append(false_state)

    return OpcodeResult.branch(branches)


@opcode_handler("POP_JUMP_IF_NONE")
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
        not_none_expr = z3.Not(none_expr)

        none_feasible = _is_sat_with_extra(state.path_constraints, none_expr)
        not_none_feasible = _is_sat_with_extra(state.path_constraints, not_none_expr)

        branches: list[VMState] = []
        if none_feasible:
            none_state = state.fork()
            none_state = none_state.add_constraint(none_expr)
            none_state = none_state.record_branch(none_expr, True, state.pc)
            none_state = none_state.set_pc(target_index)
            branches.append(none_state)
        if not_none_feasible:
            not_none_state = state.fork()
            not_none_state = not_none_state.add_constraint(not_none_expr)
            not_none_state = not_none_state.record_branch(none_expr, False, state.pc)
            not_none_state = not_none_state.set_pc(state.pc + 1)
            branches.append(not_none_state)
        return OpcodeResult.branch(branches)
    else:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)


@opcode_handler("POP_JUMP_IF_NOT_NONE")
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
        not_none_expr = z3.Not(none_expr)

        not_none_feasible = _is_sat_with_extra(state.path_constraints, not_none_expr)
        none_feasible = _is_sat_with_extra(state.path_constraints, none_expr)

        branches: list[VMState] = []
        if not_none_feasible:
            not_none_state = state.fork()
            not_none_state = not_none_state.add_constraint(not_none_expr)
            not_none_state = not_none_state.record_branch(none_expr, False, state.pc)
            not_none_state = not_none_state.set_pc(target_index)
            branches.append(not_none_state)
        if none_feasible:
            none_state = state.fork()
            none_state = none_state.add_constraint(none_expr)
            none_state = none_state.record_branch(none_expr, True, state.pc)
            none_state = none_state.set_pc(state.pc + 1)
            branches.append(none_state)
        return OpcodeResult.branch(branches)
    else:
        state = state.set_pc(target_index)
        return OpcodeResult.continue_with(state)


@opcode_handler("JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT")
def handle_jump(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Unconditional jump."""
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is not None:
        state = state.set_pc(target_index)
    else:
        state = state.advance_pc()
    return OpcodeResult.continue_with(state)


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

    for idx, block in enumerate(reversed(state.block_stack)):
        actual_idx = len(state.block_stack) - 1 - idx
        if block.block_type in ("finally", "except"):
            exc_state = state.fork()
            while len(exc_state.block_stack) > actual_idx:
                exc_state.exit_block()

            exc_val, constraint = SymbolicValue.symbolic(f"exception_{state.pc}")
            exc_state = exc_state.push(exc_val)
            exc_state = exc_state.add_constraint(constraint)
            if block.handler_pc is None:
                continue
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
    """Iterate over a sequence with symbolic index tracking.

    **Iteration Mechanics:**
    1. **Iterator Retrieval**: Peeks at the TOS (expecting a `SymbolicIterator`).
    2. **Branching**:
       - **Continue Branch**: Assumes `iterator.index < len(iterable)`. Pushes the
         symbolic element at the current index.
       - **Exit Branch**: Assumes `iterator.index >= len(iterable)`. Pops the iterator
         and jumps to the end of the loop.
    3. **Container Bridge**: Successfully handles `SymbolicList` (Z3 arrays) by
       linking the yielded `SymbolicValue` to the result of `z3.Select(array, index)`.
    """
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

    from pysymex.core.types.containers import SymbolicObject

    if isinstance(iterable, SymbolicObject):
        addr = iterable.address
        memory = state.memory
        if addr in memory:
            iterable = memory[addr]

    idx = iterator.index if isinstance(iterator, SymbolicIterator) else 0
    concrete_items: str | bytes | list[object] | None = None
    known_len: int | None = None

    if isinstance(iterable, SymbolicList):
        concrete_from_list = iterable.concrete_items
        if concrete_from_list is not None:
            concrete_items = concrete_from_list
            known_len = len(concrete_from_list)
    elif isinstance(iterable, (str, bytes)):
        concrete_items = iterable
        known_len = len(concrete_items)

    if concrete_items is not None and known_len is not None:
        if idx < known_len:
            item = concrete_items[idx]
            if isinstance(
                item,
                (
                    SymbolicValue,
                    SymbolicNone,
                    SymbolicString,
                    SymbolicList,
                    SymbolicDict,
                    SymbolicObject,
                    z3.ExprRef,
                    int,
                    bool,
                    str,
                    float,
                    bytes,
                    type,
                ),
            ):
                stack_item = item
            else:
                stack_item = SymbolicValue.from_const(item)
            continue_state = state.fork()
            if isinstance(iterator, SymbolicIterator):
                continue_state.pop()
                continue_state = continue_state.push(iterator.advance())
            continue_state = continue_state.push(stack_item)
            continue_state = continue_state.advance_pc()
            return OpcodeResult.branch([continue_state])
        else:
            exit_state = state.fork()
            if exit_state.stack:
                exit_state.pop()
            exit_state = exit_state.set_pc(target_index)
            return OpcodeResult.branch([exit_state])

    continue_state = state.fork()

    if isinstance(iterator, SymbolicIterator):
        continue_state.pop()
        continue_state = continue_state.push(iterator.advance())

    iter_val, type_constraint = SymbolicValue.symbolic(f"iter_{state.pc}_{state.path_id}")
    continue_state = continue_state.push(iter_val)
    continue_state = continue_state.add_constraint(type_constraint)

    exit_state = state.fork()
    exit_state = exit_state.set_pc(target_index)

    continue_state = continue_state.advance_pc()

    if isinstance(iterable, SymbolicList):
        z3_array = iterable.z3_array
        z3_len = iterable.z3_len

        idx = iterator.index if isinstance(iterator, SymbolicIterator) else 0

        continue_state = continue_state.add_constraint(z3.IntVal(idx) < z3_len)
        continue_state = continue_state.add_constraint(
            iter_val.z3_int == z3.Select(z3_array, z3.IntVal(idx))
        )

        if iterable.element_type == "int":
            continue_state = continue_state.add_constraint(iter_val.is_int == Z3_TRUE)
            continue_state = continue_state.add_constraint(iter_val.is_bool == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_float == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_str == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_obj == Z3_FALSE)
            continue_state = continue_state.add_constraint(iter_val.is_none == Z3_FALSE)

        exit_state = exit_state.add_constraint(z3.IntVal(idx) >= z3_len)

        return OpcodeResult.branch([continue_state, exit_state])

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


@opcode_handler("GET_LEN")
def handle_get_len(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get length of top of stack (for pattern matching/sequences)."""
    if state.stack:
        value = state.peek()
        if isinstance(value, (SymbolicList, SymbolicDict, SymbolicString)):
            length = value.z3_len
        elif isinstance(value, (str, bytes)):
            length = z3.IntVal(len(value))
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


@opcode_handler("CALL_INTRINSIC_1")
def handle_call_intrinsic_1(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Call single-argument intrinsic function.

    CPython 3.12+ intrinsic IDs:
      1  INTRINSIC_PRINT           – print import * (push None)
      2  INTRINSIC_IMPORT_STAR     – from module import * (push None)
      3  INTRINSIC_STOPITERATION_ERROR – wrap StopIteration as RuntimeError
      4  INTRINSIC_ASYNC_GEN_WRAP  – wrap value for async generator yield
      5  INTRINSIC_UNARY_POSITIVE  – +x (identity for numerics)
      6  INTRINSIC_LIST_TO_TUPLE   – convert list to tuple
      7  INTRINSIC_TYPEVAR         – create TypeVar
      8  INTRINSIC_PARAMSPEC       – create ParamSpec
      9  INTRINSIC_TYPEVARTUPLE    – create TypeVarTuple
     10  INTRINSIC_SUBSCRIPT_GENERIC – generic subscript (e.g. list[int])
     11  INTRINSIC_TYPEALIAS       – create type alias
    """
    arg = state.pop() if state.stack else None
    intrinsic_id = int(instr.argval) if instr.argval else 0

    if intrinsic_id == 1:
        state = state.push(SymbolicNone())
    elif intrinsic_id == 2:
        state = state.push(SymbolicNone())
    elif intrinsic_id == 3:
        exc_val, constraint = SymbolicValue.symbolic(f"runtime_error_{state.pc}")
        state = state.push(exc_val)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 4:
        wrapped, constraint = SymbolicValue.symbolic(f"async_gen_wrap_{state.pc}")
        state = state.push(wrapped)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 5:
        if arg is not None:
            state = state.push(arg)
        else:
            val, constraint = SymbolicValue.symbolic(f"upos_{state.pc}")
            state = state.push(val)
            state = state.add_constraint(constraint)
    elif intrinsic_id == 6:
        if isinstance(arg, SymbolicList):
            state = state.push(arg)
        else:
            result, constraint = SymbolicValue.symbolic(f"tuple_{state.pc}")
            state = state.push(result)
            state = state.add_constraint(constraint)
    elif intrinsic_id in (7, 8, 9):
        _type_names = {7: "TypeVar", 8: "ParamSpec", 9: "TypeVarTuple"}
        type_val, constraint = SymbolicValue.symbolic(f"{_type_names[intrinsic_id]}_{state.pc}")
        state = state.push(type_val)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 10:
        result, constraint = SymbolicValue.symbolic(f"generic_alias_{state.pc}")
        state = state.push(result)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 11:
        alias_val, constraint = SymbolicValue.symbolic(f"type_alias_{state.pc}")
        state = state.push(alias_val)
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
    """Call two-argument intrinsic function.

    CPython 3.12+ two-argument intrinsic IDs:
      1  INTRINSIC_PREP_RERAISE           – prepare exception for re-raise
      2  INTRINSIC_TYPEVAR_WITH_BOUND     – TypeVar('T', bound=X)
      3  INTRINSIC_TYPEVAR_WITH_CONSTRAINTS – TypeVar('T', X, Y)
      4  INTRINSIC_SET_FUNCTION_TYPE_PARAMS – set __type_params__ on function
    """
    _arg2 = state.pop() if state.stack else None
    arg1 = state.pop() if state.stack else None
    intrinsic_id = int(instr.argval) if instr.argval else 0

    if intrinsic_id == 1:
        if arg1 is not None:
            state = state.push(arg1)
        else:
            exc_val, constraint = SymbolicValue.symbolic(f"reraise_{state.pc}")
            state = state.push(exc_val)
            state = state.add_constraint(constraint)
    elif intrinsic_id in (2, 3):
        _names = {2: "TypeVar_bound", 3: "TypeVar_constrained"}
        tv_val, constraint = SymbolicValue.symbolic(f"{_names[intrinsic_id]}_{state.pc}")
        state = state.push(tv_val)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 4:
        if arg1 is not None:
            state = state.push(arg1)
        else:
            func_val, constraint = SymbolicValue.symbolic(f"typed_func_{state.pc}")
            state = state.push(func_val)
            state = state.add_constraint(constraint)
    else:
        result, constraint = SymbolicValue.symbolic(f"intrinsic2_{state.pc}")
        state = state.push(result)
        state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("MATCH_MAPPING")
def handle_match_mapping(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    subject = state.peek() if state.stack else None
    if isinstance(subject, (SymbolicDict, SymbolicObject)):
        is_mapping = getattr(subject, "is_dict", Z3_TRUE)
    elif isinstance(subject, SymbolicValue):
        is_mapping = subject.is_dict
    elif subject is not None:
        is_mapping = z3.BoolVal(isinstance(subject, dict))
    else:
        is_mapping = Z3_FALSE

    result = SymbolicValue(
        _name=f"is_mapping_{state.pc}",
        z3_int=z3.If(is_mapping, z3.IntVal(1), z3.IntVal(0)),
        is_int=Z3_FALSE,
        z3_bool=is_mapping,
        is_bool=Z3_TRUE,
    )
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("MATCH_SEQUENCE")
def handle_match_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    subject = state.peek() if state.stack else None
    if isinstance(subject, SymbolicList):
        is_sequence = Z3_TRUE
    elif isinstance(subject, (SymbolicValue, SymbolicObject)):
        is_sequence = getattr(subject, "is_list", Z3_TRUE)
    elif subject is not None:
        is_sequence = z3.BoolVal(isinstance(subject, (list, tuple)))
    else:
        is_sequence = Z3_FALSE

    result = SymbolicValue(
        _name=f"is_sequence_{state.pc}",
        z3_int=z3.If(is_sequence, z3.IntVal(1), z3.IntVal(0)),
        is_int=Z3_FALSE,
        z3_bool=is_sequence,
        is_bool=Z3_TRUE,
    )
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("MATCH_KEYS")
def handle_match_keys(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if mapping has required keys for pattern matching."""
    keys_tuple = state.pop() if state.stack else None
    subject = state.peek() if state.stack else None

    success_expr = Z3_TRUE
    concrete_keys_obj: list[object] | None = None
    if isinstance(keys_tuple, SymbolicList) and keys_tuple.concrete_items is not None:
        concrete_keys_obj = keys_tuple.concrete_items

    if isinstance(subject, SymbolicDict) and concrete_keys_obj is not None:
        for key in concrete_keys_obj:
            if not isinstance(key, SymbolicString):
                str_key = SymbolicString.from_const(str(key))
            else:
                str_key = key
            success_expr = z3.And(success_expr, subject.contains_key(str_key).z3_bool)
    else:
        success_expr = z3.Bool(fresh_name("match_keys_success"))

    success_result = SymbolicValue(
        _name=f"match_keys_success_{state.pc}",
        z3_int=z3.If(success_expr, z3.IntVal(1), z3.IntVal(0)),
        is_int=Z3_FALSE,
        z3_bool=success_expr,
        is_bool=Z3_TRUE,
    )

    values, constraint = SymbolicValue.symbolic(fresh_name("match_values"))
    state = state.push(values)
    state = state.add_constraint(constraint)
    state = state.push(success_result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("MATCH_CLASS")
def handle_match_class(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    _num_positional = int(instr.argval) if instr.argval else 0
    state.pop() if state.stack else None
    cls = state.pop() if state.stack else None
    subject = state.pop() if state.stack else None

    success = z3.Bool(fresh_name("match_class_success"))
    attrs, constraint = SymbolicValue.symbolic(fresh_name("match_attrs"))

    if isinstance(subject, SymbolicObject) and isinstance(cls, type):
        success = z3.And(success, subject.z3_addr >= z3.IntVal(0))

    result = SymbolicValue(
        _name=f"match_class_success_{state.pc}",
        z3_int=z3.If(success, z3.IntVal(1), z3.IntVal(0)),
        is_int=Z3_FALSE,
        z3_bool=success,
        is_bool=Z3_TRUE,
    )
    state = state.push(attrs)
    state = state.add_constraint(constraint)
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("NOP", "RESERVED")
def handle_nop_and_reserved(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle NOP and RESERVED (No-op)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
