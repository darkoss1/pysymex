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

"""Conditional branch opcodes with solver-backed feasibility splitting.

Owns ``POP_JUMP_*``, ``JUMP_IF_TRUE/FALSE``, and truthiness lowering that forks
``VMState`` when both outcomes remain satisfiable. Uses
:func:`pysymex.core.solver.engine.path_may_be_feasible` with explicit unknown handling;
does not emit detector issues directly.
"""

from __future__ import annotations

import dis
from collections import OrderedDict
from collections.abc import Iterable
from typing import TYPE_CHECKING

import z3

from pysymex.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)
from pysymex.core.solver.constraints.theory import (
    constraints_include_bitvector_smt_theory,
    is_bitvector_smt_theory,
    is_complex_smt_theory as is_complex_smt_theory,
)
from pysymex.core.solver.constraints.chain import ConstraintChain
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.truthiness import get_truthy_expr
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.feasibility import known_sat_prefix_len_for_state
from pysymex.execution.opcodes.common.control.protocol.fallbacks import (
    MEMBERSHIP_CALL_UNAVAILABLE_REASON,
    TRUTH_CALL_UNAVAILABLE_REASON,
    UNSUPPORTED_MEMBERSHIP_PROTOCOL,
    UNSUPPORTED_TRUTH_PROTOCOL,
    unsupported_membership_event,
    unsupported_truth_event,
)
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher

logger = get_logger(__name__)

_StringWitnessTermsCacheKey = tuple[tuple[int, int], ...]
_StringWitnessExprCacheKey = tuple[int, int]
_STRING_WITNESS_TERMS_CACHE_MAX_SIZE = 8192
_STRING_WITNESS_TERMS_CACHE: OrderedDict[
    _StringWitnessTermsCacheKey,
    tuple[tuple[z3.ExprRef, ...], bool],
] = OrderedDict()
_STRING_WITNESS_EXPR_CACHE_MAX_SIZE = 8192
_STRING_WITNESS_EXPR_CACHE: OrderedDict[
    _StringWitnessExprCacheKey,
    tuple[z3.ExprRef, bool],
] = OrderedDict()


def _is_sat_with_extra(
    constraints: Iterable[z3.BoolRef],
    extra: z3.BoolRef,
    *,
    known_sat_prefix_len: int | None = None,
) -> bool:
    """Return whether path constraints remain satisfiable with an extra literal."""
    import z3

    from pysymex.core.solver.engine.policies import path_may_be_feasible

    if z3.is_false(extra):
        return False
    if z3.is_true(extra):
        constraint_list = list(constraints)
        return path_may_be_feasible(
            constraint_list,
            known_sat_prefix_len=known_sat_prefix_len,
        )
    if is_bitvector_smt_theory(extra):
        logger.debug("Skipping expensive branch feasibility query for bit-vector SMT path context")
        return True

    if isinstance(constraints, ConstraintChain):
        if constraints.has_bitvector_smt_theory():
            logger.debug(
                "Skipping expensive branch feasibility query for bit-vector SMT path context"
            )
            return True
        constraint_list = constraints.to_list()
    else:
        constraint_list = list(constraints)
        if constraints_include_bitvector_smt_theory(constraint_list):
            logger.debug(
                "Skipping expensive branch feasibility query for bit-vector SMT path context"
            )
            return True

    return path_may_be_feasible(
        constraint_list + [extra],
        known_sat_prefix_len=known_sat_prefix_len,
    )


def branch_feasible(
    constraints: Iterable[z3.BoolRef],
    extra: z3.BoolRef,
    *,
    known_sat_prefix_len: int | None = None,
) -> bool:
    """Return branch feasibility through the solver source of truth."""
    return _is_sat_with_extra(
        constraints,
        extra,
        known_sat_prefix_len=known_sat_prefix_len,
    )


def _preferred_truth_order(
    constraints: Iterable[z3.BoolRef],
    cond_expr: z3.BoolRef,
    not_cond_expr: z3.BoolRef,
    *,
    default_order: tuple[bool, bool] = (True, False),
) -> tuple[bool, bool]:
    """Return branch truth order, preferring a concrete string/integer witness if any."""
    if not _has_string_witness_terms((cond_expr,)):
        return default_order
    constraint_list = list(constraints)
    if not constraint_list:
        return default_order

    from pysymex.analysis.detectors.feasibility import (
        string_integer_context_truth_value,
        string_integer_witness_model,
    )

    preferred_truth = string_integer_context_truth_value(constraint_list, cond_expr)
    if preferred_truth is not None:
        return (preferred_truth, not preferred_truth)
    true_has_witness = string_integer_witness_model([*constraint_list, cond_expr]) is not None
    false_has_witness = string_integer_witness_model([*constraint_list, not_cond_expr]) is not None
    if false_has_witness and not true_has_witness:
        return (False, True)
    return default_order


def _has_string_witness_terms(expressions: tuple[z3.ExprRef, ...]) -> bool:
    if is_process_cache_disabled():
        return _uncached_has_string_witness_terms(expressions)

    cache_key = _string_witness_terms_cache_key(expressions)
    cached = _STRING_WITNESS_TERMS_CACHE.get(cache_key)
    if cached is not None:
        _cached_expressions, cached_result = cached
        _STRING_WITNESS_TERMS_CACHE.move_to_end(cache_key)
        return cached_result

    result = _uncached_has_string_witness_terms(expressions)
    _STRING_WITNESS_TERMS_CACHE[cache_key] = (expressions, result)
    if len(_STRING_WITNESS_TERMS_CACHE) > _STRING_WITNESS_TERMS_CACHE_MAX_SIZE:
        _STRING_WITNESS_TERMS_CACHE.popitem(last=False)
    return result


def _string_witness_terms_cache_key(
    expressions: tuple[z3.ExprRef, ...],
) -> _StringWitnessTermsCacheKey:
    return tuple((id(expr.ctx_ref()), expr.get_id()) for expr in expressions)


def _uncached_has_string_witness_terms(expressions: tuple[z3.ExprRef, ...]) -> bool:
    pending: list[z3.ExprRef] = list(expressions)
    visited: set[int] = set()
    cacheable_misses: list[z3.ExprRef] = []
    while pending:
        if len(visited) > 256:
            return False
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        cached = _string_witness_expr_cache_lookup(expression)
        if cached is True:
            return True
        if cached is False:
            continue
        cacheable_misses.append(expression)
        if _is_string_witness_term(expression):
            _string_witness_expr_cache_store(expression, True)
            return True
        pending.extend(expression.children())
    for expression in cacheable_misses:
        _string_witness_expr_cache_store(expression, False)
    return False


def _string_witness_expr_cache_lookup(expression: z3.ExprRef) -> bool | None:
    if is_process_cache_disabled():
        return None

    cache_key = _string_witness_expr_cache_key(expression)
    cached = _STRING_WITNESS_EXPR_CACHE.get(cache_key)
    if cached is None:
        return None
    _cached_expression, cached_result = cached
    _STRING_WITNESS_EXPR_CACHE.move_to_end(cache_key)
    return cached_result


def _string_witness_expr_cache_store(expression: z3.ExprRef, result: bool) -> None:
    if is_process_cache_disabled():
        return

    cache_key = _string_witness_expr_cache_key(expression)
    _STRING_WITNESS_EXPR_CACHE[cache_key] = (expression, result)
    if len(_STRING_WITNESS_EXPR_CACHE) > _STRING_WITNESS_EXPR_CACHE_MAX_SIZE:
        _STRING_WITNESS_EXPR_CACHE.popitem(last=False)


def _string_witness_expr_cache_key(expression: z3.ExprRef) -> _StringWitnessExprCacheKey:
    return (id(expression.ctx_ref()), expression.get_id())


def _is_string_witness_term(expression: z3.ExprRef) -> bool:
    try:
        decl = expression.decl()
    except (AttributeError, z3.Z3Exception):
        return False
    if decl.kind() != z3.Z3_OP_UNINTERPRETED:
        return False
    name = str(decl.name())
    return name.startswith("ord_") or "count" in name or name.startswith("bin_")


def clear_string_witness_caches() -> None:
    """Clear process-local branch string-witness probe caches."""
    _STRING_WITNESS_TERMS_CACHE.clear()
    _STRING_WITNESS_EXPR_CACHE.clear()


register_process_cache_clearer(
    "execution.string_witness_caches",
    clear_string_witness_caches,
)


def try_dispatch_modeled_truth_protocol(
    value: object,
    state: VMState,
    ctx: OpcodeDispatcher,
    *,
    resume_pc: int | None = None,
    retained_operand: StackValue | None = None,
    membership_operation: str | None = None,
) -> OpcodeResult | None:
    """Execute a modeled ``__bool__`` or fallback ``__len__`` truth method."""
    if not isinstance(value, SymbolicValue):
        return None
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    protocol_method = "__bool__"
    truth_method = lookup_modeled_method(value, protocol_method)
    if truth_method is None:
        protocol_method = "__len__"
        truth_method = lookup_modeled_method(value, protocol_method)
        if truth_method is None:
            return None
    frame_protocol_method = protocol_method
    if membership_operation is not None:
        suffix = "bool" if protocol_method == "__bool__" else "len"
        frame_protocol_method = f"{membership_operation}_truth_{suffix}__"

    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        truth_method,
        [],
        {},
        protocol_method=frame_protocol_method,
        resume_pc=resume_pc,
        protocol_retained_operand=retained_operand,
    )
    if result is not None:
        return result
    if membership_operation is not None:
        degraded_pass = UNSUPPORTED_MEMBERSHIP_PROTOCOL
        fallback_event = unsupported_membership_event(
            state=state,
            reason=MEMBERSHIP_CALL_UNAVAILABLE_REASON,
        )
    else:
        degraded_pass = UNSUPPORTED_TRUTH_PROTOCOL
        fallback_event = unsupported_truth_event(
            state=state,
            reason=TRUTH_CALL_UNAVAILABLE_REASON,
        )
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[degraded_pass],
        fallback_events=[fallback_event],
        terminal=True,
    )


def resolve_heap_backed_truth_operand(value: object, state: VMState) -> object:
    """Return builtin container storage for object handles whose truth is length-based."""
    from pysymex.core.types.containers.dicts import SymbolicDict
    from pysymex.core.types.containers.lists import SymbolicList
    from pysymex.core.types.containers.objects import SymbolicObject
    from pysymex.core.types.scalars.strings import SymbolicString

    if not isinstance(value, SymbolicObject) or value.address == -1:
        return value

    stored = state.memory.get(value.address)
    if isinstance(stored, (SymbolicDict, SymbolicList, SymbolicString)):
        return stored
    return value


def handle_common_pop_jump_bool(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    *,
    jump_when_true: bool,
) -> OpcodeResult:
    """Branch on stack truthiness and jump on the requested boolean outcome."""
    cond = state.pop()
    truth_operand = resolve_heap_backed_truth_operand(cond, state)
    modeled_result = try_dispatch_modeled_truth_protocol(
        truth_operand,
        state,
        ctx,
        resume_pc=state.pc,
    )
    if modeled_result is not None:
        return modeled_result

    cond_expr = get_truthy_expr(truth_operand)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    not_cond_expr = z3.Not(cond_expr)

    known_prefix_len = known_sat_prefix_len_for_state(state)
    true_feasible = branch_feasible(
        state.path_constraints,
        cond_expr,
        known_sat_prefix_len=known_prefix_len,
    )
    false_feasible = branch_feasible(
        state.path_constraints,
        not_cond_expr,
        known_sat_prefix_len=known_prefix_len,
    )

    true_pc = target_index if jump_when_true else state.pc + 1
    false_pc = state.pc + 1 if jump_when_true else target_index
    fallthrough_first_order = (not jump_when_true, jump_when_true)

    branches: list[VMState] = []
    for truth_value in _preferred_truth_order(
        state.path_constraints,
        cond_expr,
        not_cond_expr,
        default_order=fallthrough_first_order,
    ):
        if truth_value and true_feasible:
            true_state = state.fork()
            true_state = true_state.add_constraint(cond_expr)
            true_state = true_state.record_branch(cond_expr, True, state.pc)
            true_state = true_state.set_pc(true_pc)
            branches.append(true_state)
        elif not truth_value and false_feasible:
            false_state = state.fork()
            false_state = false_state.add_constraint(not_cond_expr)
            false_state = false_state.record_branch(cond_expr, False, state.pc)
            false_state = false_state.set_pc(false_pc)
            branches.append(false_state)

    return OpcodeResult.branch(branches)


def handle_common_pop_jump_if_none(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``POP_JUMP_IF_NONE`` / ``POP_JUMP_IF_NOT_NONE``: pop and branch on ``None``.

    CPython stack effect: pops the tested value. Forks when ``is_none`` is symbolic and
    both branches stay satisfiable; otherwise takes the feasible single successor.
    """
    value = state.pop()
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1

    if isinstance(value, SymbolicNone):
        return OpcodeResult.continue_with(state.set_pc(target_index))

    if isinstance(value, SymbolicValue):
        none_expr = value.is_none
        not_none_expr = z3.Not(none_expr)
        known_prefix_len = known_sat_prefix_len_for_state(state)
        none_feasible = branch_feasible(
            state.path_constraints,
            none_expr,
            known_sat_prefix_len=known_prefix_len,
        )
        not_none_feasible = branch_feasible(
            state.path_constraints,
            not_none_expr,
            known_sat_prefix_len=known_prefix_len,
        )

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

    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_pop_jump_if_not_none(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Jump if top of stack is not None."""
    value = state.pop()
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1

    if isinstance(value, SymbolicNone):
        return OpcodeResult.continue_with(state.advance_pc())

    if isinstance(value, SymbolicValue):
        none_expr = value.is_none
        not_none_expr = z3.Not(none_expr)
        known_prefix_len = known_sat_prefix_len_for_state(state)
        not_none_feasible = branch_feasible(
            state.path_constraints,
            not_none_expr,
            known_sat_prefix_len=known_prefix_len,
        )
        none_feasible = branch_feasible(
            state.path_constraints,
            none_expr,
            known_sat_prefix_len=known_prefix_len,
        )

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

    return OpcodeResult.continue_with(state.set_pc(target_index))


def handle_common_jump(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Handle an unconditional absolute target jump."""
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is not None:
        state = state.set_pc(target_index)
    else:
        state = state.advance_pc()
    return OpcodeResult.continue_with(state)
