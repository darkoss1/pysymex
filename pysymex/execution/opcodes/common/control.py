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

"""Common control flow operations for opcodes."""

from __future__ import annotations

import dis
import types
from collections.abc import Iterable, Sized
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

import z3

from pysymex.analysis.summaries.core import SummaryBuilder
from pysymex.core.solver.constraints import quick_contradiction_check
from pysymex.core.types.scalars import (
    Z3_FALSE,
    Z3_TRUE,
    SymbolicNone,
    SymbolicType,
    SymbolicValue,
    fresh_name,
)
from pysymex.core.types import (
    SymbolicDict,
    SymbolicIterator,
    SymbolicList,
    SymbolicObject,
    SymbolicString,
)
from pysymex.execution.dispatcher import OpcodeResult

_MAX_SUMMARY_CACHE_CONSTRAINTS = 24
_MAX_SUMMARY_CACHE_ARGS = 12

if TYPE_CHECKING:
    from pysymex._typing import StackValue
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


def _decl_kind(expr: z3.ExprRef) -> int | None:
    try:
        return expr.decl().kind()
    except (AttributeError, z3.Z3Exception):
        return None


def _constraints_contain_hash(constraints: object, constraint_hash: int) -> bool | None:
    contains_hash = getattr(constraints, "contains_hash", None)
    if callable(contains_hash):
        try:
            result = contains_hash(constraint_hash)
        except (TypeError, ValueError, z3.Z3Exception):
            return None
        if isinstance(result, bool):
            return result
    return None


def _constraints_have_false_literal(constraints: object) -> bool:
    has_false = getattr(constraints, "has_false_literal", None)
    if callable(has_false):
        try:
            result = has_false()
        except (TypeError, ValueError, z3.Z3Exception):
            return False
        return bool(result)
    return False


def _has_new_direct_contradiction(
    constraints: object,
    extra: z3.BoolRef,
) -> bool:
    """Return whether ``extra`` directly contradicts the existing path."""
    if _constraints_have_false_literal(constraints):
        return True

    constraint_iterable = cast("Iterable[z3.BoolRef]", constraints)
    extra_kind = _decl_kind(extra)
    if extra_kind == z3.Z3_OP_FALSE:
        return True
    if extra_kind == z3.Z3_OP_TRUE:
        return quick_contradiction_check(list(constraint_iterable))

    if extra_kind == z3.Z3_OP_NOT:
        target = extra.arg(0)
        target_hash = target.hash()
        contains_hash = _constraints_contain_hash(constraints, target_hash)
        if contains_hash is False:
            return False
        for constraint in constraint_iterable:
            kind = _decl_kind(constraint)
            if kind == z3.Z3_OP_FALSE:
                return True
            if constraint.hash() == target_hash and z3.eq(constraint, target):
                return True
        return False

    negated_extra = z3.Not(extra)
    negated_extra_hash = negated_extra.hash()
    contains_hash = _constraints_contain_hash(constraints, negated_extra_hash)
    if contains_hash is False:
        return False

    extra_hash = extra.hash()
    for constraint in constraint_iterable:
        kind = _decl_kind(constraint)
        if kind == z3.Z3_OP_FALSE:
            return True
        if kind == z3.Z3_OP_NOT:
            target = constraint.arg(0)
            if target.hash() == extra_hash and z3.eq(target, extra):
                return True
    return False


def is_complex_smt_theory(expr: object) -> bool:
    """Return whether a Z3 expression involves complex floating-point, array, or nonlinear SMT theories."""
    import z3

    if not isinstance(expr, z3.ExprRef):
        return False

    if isinstance(expr, (z3.FPRef, z3.ArrayRef)):
        return True

    try:
        decl = expr.decl()
        kind = decl.kind()
        name = str(decl.name()).lower()
    except (AttributeError, z3.Z3Exception):
        return False

    if kind in (z3.Z3_OP_DIV, z3.Z3_OP_MOD) or name in ("div", "mod", "rem"):
        return True

    if kind == z3.Z3_OP_MUL:
        try:
            non_const_count = 0
            for child in expr.children():
                if not isinstance(child, (z3.IntNumRef, z3.RatNumRef)):
                    non_const_count += 1
            if non_const_count > 1:
                return True
        except (AttributeError, z3.Z3Exception):
            pass

    try:
        children = expr.children()
    except (AttributeError, z3.Z3Exception):
        return False

    for child in children:
        if is_complex_smt_theory(child):
            return True

    return False


def _is_feasible_without_solver(constraints: object, extra: z3.BoolRef) -> bool:
    """Return branch feasibility using only cheap contradiction checks."""
    if z3.is_false(extra):
        return False
    if z3.is_true(extra):
        constraint_list = list(cast("Iterable[z3.BoolRef]", constraints))
        return not quick_contradiction_check(constraint_list)
    return not _has_new_direct_contradiction(constraints, extra)


def branch_feasible(constraints: object, extra: z3.BoolRef) -> bool:
    """Use SMT with adaptive constraint thresholds depending on SMT theory complexity."""
    is_complex = is_complex_smt_theory(extra)
    if not is_complex:
        try:
            constraint_iterable = cast("Iterable[z3.BoolRef]", constraints)
            for c in constraint_iterable:
                if is_complex_smt_theory(c):
                    is_complex = True
                    break
        except Exception:
            pass

    threshold = 8 if is_complex else 24

    try:
        constraint_count = len(cast("Sized", constraints))
    except TypeError:
        constraint_list = list(cast("Iterable[z3.BoolRef]", constraints))
        if len(constraint_list) < threshold:
            return _is_sat_with_extra(constraint_list, extra)
        return _is_feasible_without_solver(constraint_list, extra)

    if constraint_count < threshold:
        constraint_list = list(cast("Iterable[z3.BoolRef]", constraints))
        return _is_sat_with_extra(constraint_list, extra)
    return _is_feasible_without_solver(constraints, extra)


def get_truthy_expr(value: object) -> z3.BoolRef:
    """Get Z3 expression for when a value is truthy."""

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


def handle_common_return_value(
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

    if state.call_stack:
        state.local_vars = state.call_stack[-1].local_vars

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
        state.stack = state.stack[: frame.stack_depth]
        state.local_vars = frame.local_vars
        state = state.set_pc(frame.return_pc)
        if frame.caller_instructions is not None:
            caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
            state.current_instructions = cast("list[object]", caller_instructions)
            ctx.set_instructions(caller_instructions)

        if not frame.is_init_call:
            if return_value is not None:
                state = state.push(return_value)
            else:
                state = state.push(SymbolicNone("return_None"))
        else:
            # For __init__ calls, we push the instance itself
            if frame.init_instance is not None:
                state = state.push(frame.init_instance)
            else:
                state = state.push(SymbolicNone("missing_init_instance"))

        state.depth -= 1
        if issue:
            return OpcodeResult.with_issue(state, issue)
        return OpcodeResult.continue_with(state)
    if issue:
        return OpcodeResult(new_states=[], issues=[issue], terminal=True)
    return OpcodeResult.terminate()


def handle_common_raise_varargs(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Raise an exception, unwinding the block stack to find a handler."""
    _argc = int(instr.argval) if instr.argval else 0
    is_not_implemented = False
    if state.stack:
        top = state.peek()
        top_name = str(getattr(top, "name", "") or getattr(top, "_name", "") or "")
        if "NotImplementedError" in top_name:
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

            return OpcodeResult.branch([exc_state])

    return OpcodeResult.terminate()


def handle_common_for_iter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Iterate over a sequence with symbolic index tracking."""
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
            exit_state = exit_state.push(SymbolicNone())
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
        exit_state = exit_state.push(SymbolicNone())

        return OpcodeResult.branch([continue_state, exit_state])

    continue_state = continue_state.set_pc(state.pc + 1)

    exit_state = state.fork()
    exit_state = exit_state.push(SymbolicNone())
    exit_state = exit_state.set_pc(target_index)
    return OpcodeResult.branch([continue_state, exit_state])


def handle_common_get_iter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get iterator from iterable."""
    if state.stack:
        obj = state.pop()
        iterator = SymbolicIterator(f"iter_{id(obj)}", obj)
        state = state.push(iterator)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_get_len(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get length of top of stack (for pattern matching/sequences)."""
    if state.stack:
        value = _resolve_match_subject(state.peek(), state)
        if isinstance(value, (SymbolicList, SymbolicDict, SymbolicString)):
            length = value.z3_len
        elif isinstance(value, Sized):
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


def _resolve_match_subject(subject: object, state: VMState) -> object:
    """Resolve heap-backed symbolic object handles for pattern matching tests."""
    if isinstance(subject, SymbolicObject) and subject.address != -1:
        return state.memory.get(subject.address, subject)
    return subject


def _extract_match_keys(keys_tuple: object) -> list[object] | None:
    if isinstance(keys_tuple, SymbolicList) and keys_tuple.concrete_items is not None:
        return keys_tuple.concrete_items
    if isinstance(keys_tuple, tuple):
        return list(cast("tuple[object, ...]", keys_tuple))
    if isinstance(keys_tuple, list):
        return list(cast("list[object]", keys_tuple))
    return None


_MATCH_SELF_TYPES = {
    bool,
    bytearray,
    bytes,
    dict,
    float,
    frozenset,
    int,
    list,
    set,
    str,
    tuple,
}


def _extract_match_class_attr_names(
    cls: type, names_tuple: object, positional: int
) -> list[str] | None:
    keywords_obj = _extract_match_keys(names_tuple)
    if keywords_obj is None:
        return None

    keywords: list[str] = []
    for item in keywords_obj:
        if not isinstance(item, str):
            return None
        keywords.append(item)

    positional_names: list[str]
    if cls in _MATCH_SELF_TYPES:
        if positional > 1:
            return None
        positional_names = ["__match_self__"] if positional else []
    else:
        match_args_obj = getattr(cls, "__match_args__", ())
        if not isinstance(match_args_obj, tuple):
            return None
        match_args = cast("tuple[object, ...]", match_args_obj)
        if positional > len(match_args):
            return None
        positional_names = []
        for item in match_args[:positional]:
            if not isinstance(item, str):
                return None
            positional_names.append(item)

    names = [*positional_names, *keywords]
    if len(set(names)) != len(names):
        return None
    return names


def _builtin_match_success(subject: SymbolicValue, cls: type) -> z3.BoolRef | None:
    if cls is bool:
        return subject.is_bool
    if cls is int:
        return z3.Or(subject.is_int, subject.is_bool)
    if cls is float:
        return subject.is_float
    if cls is str:
        return subject.is_str
    if cls in (list, tuple):
        return subject.is_list
    if cls is dict:
        return subject.is_dict
    if cls is object:
        return z3.BoolVal(True)
    if cls is type(None):
        return subject.is_none
    return None


def _concrete_match_class_attrs(
    subject: object, cls: type, names_tuple: object, positional: int
) -> tuple["StackValue", ...] | SymbolicNone | None:
    attr_names = _extract_match_class_attr_names(cls, names_tuple, positional)
    if attr_names is None:
        return None
    if not isinstance(subject, cls):
        return SymbolicNone("match_class_no_match")

    attrs: list[StackValue] = []
    for name in attr_names:
        if name == "__match_self__":
            attrs.append(cast("StackValue", subject))
            continue
        try:
            attrs.append(cast("StackValue", getattr(subject, name)))
        except AttributeError:
            return SymbolicNone("match_class_missing_attr")
    return tuple(attrs)


def _enhanced_class_from_pattern(cls: object) -> object | None:
    if not isinstance(cls, SymbolicValue) or getattr(cls, "affinity_type", None) != "type":
        return None

    enhanced_obj = getattr(cls, "_enhanced_object", None)
    try:
        from pysymex.core.objects.oop import EnhancedClass, enhanced_class_registry
    except ImportError:
        return None

    if isinstance(enhanced_obj, EnhancedClass):
        return enhanced_obj
    if not isinstance(enhanced_obj, types.CodeType):
        return None

    enhanced_cls = enhanced_class_registry.get_by_code_object(enhanced_obj)
    if enhanced_cls is not None:
        return enhanced_cls
    return None


def _enhanced_object_from_subject(subject: object) -> object | None:
    enhanced_obj = getattr(subject, "_enhanced_object", None)
    try:
        from pysymex.core.objects.oop import EnhancedObject
    except ImportError:
        return None

    if isinstance(enhanced_obj, EnhancedObject):
        return enhanced_obj
    if isinstance(subject, EnhancedObject):
        return subject
    return None


def _enhanced_class_is_subclass(subject_class: object, pattern_class: object) -> bool | None:
    subject_base = getattr(subject_class, "base", None)
    pattern_base = getattr(pattern_class, "base", None)
    is_subclass_of = getattr(subject_base, "is_subclass_of", None)
    if callable(is_subclass_of) and pattern_base is not None:
        result = is_subclass_of(pattern_base)
        if isinstance(result, bool):
            return result
    return None


def _enhanced_match_args(enhanced_cls: object) -> tuple[str, ...] | None:
    class_vars = getattr(enhanced_cls, "class_vars", None)
    if isinstance(class_vars, dict):
        typed_class_vars = cast("dict[str, object]", class_vars)
        value = typed_class_vars.get("__match_args__")
        if isinstance(value, tuple):
            typed_value = cast("tuple[object, ...]", value)
            if all(isinstance(item, str) for item in typed_value):
                return cast("tuple[str, ...]", typed_value)

    base = getattr(enhanced_cls, "base", None)
    lookup_attribute = getattr(base, "lookup_attribute", None)
    attr = lookup_attribute("__match_args__") if callable(lookup_attribute) else None
    value = getattr(attr, "value", None)
    if isinstance(value, tuple):
        typed_value = cast("tuple[object, ...]", value)
        if all(isinstance(item, str) for item in typed_value):
            return cast("tuple[str, ...]", typed_value)
    return None


def _enhanced_match_class_attr_names(
    enhanced_cls: object, names_tuple: object, positional: int
) -> list[str] | None:
    keywords_obj = _extract_match_keys(names_tuple)
    if keywords_obj is None:
        return None

    keywords: list[str] = []
    for item in keywords_obj:
        if not isinstance(item, str):
            return None
        keywords.append(item)

    match_args = _enhanced_match_args(enhanced_cls)
    if positional:
        if match_args is None or positional > len(match_args):
            return None
        positional_names = list(match_args[:positional])
    else:
        positional_names = []

    names = [*positional_names, *keywords]
    if len(set(names)) != len(names):
        return None
    return names


def _enhanced_match_class_attrs(
    subject: object, cls: object, names_tuple: object, positional: int
) -> tuple["StackValue", ...] | SymbolicNone | None:
    subject_obj = _enhanced_object_from_subject(subject)
    pattern_cls = _enhanced_class_from_pattern(cls)
    if subject_obj is None or pattern_cls is None:
        return None

    subject_cls = getattr(subject_obj, "enhanced_class", None)
    match_result = _enhanced_class_is_subclass(subject_cls, pattern_cls)
    if match_result is False:
        return SymbolicNone("match_class_no_match")
    if match_result is not True:
        return None

    attr_names = _enhanced_match_class_attr_names(pattern_cls, names_tuple, positional)
    if attr_names is None:
        return None

    attrs: list[StackValue] = []
    get_attribute = getattr(subject_obj, "get_attribute", None)
    if not callable(get_attribute):
        return None
    for name in attr_names:
        raw_attr = get_attribute(name)
        if not isinstance(raw_attr, tuple):
            return None
        typed_attr = cast("tuple[object, ...]", raw_attr)
        if len(typed_attr) != 2:
            return None
        value, found = typed_attr
        if not isinstance(found, bool) or not found:
            return SymbolicNone("match_class_missing_attr")
        attrs.append(cast("StackValue", value))
    return tuple(attrs)


def handle_common_match_mapping(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    subject = _resolve_match_subject(state.peek(), state) if state.stack else None
    if isinstance(subject, SymbolicDict):
        is_mapping = Z3_TRUE
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


def handle_common_match_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    subject = _resolve_match_subject(state.peek(), state) if state.stack else None
    if isinstance(subject, SymbolicList):
        is_sequence = Z3_TRUE
    elif isinstance(subject, SymbolicValue):
        is_sequence = subject.is_list
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


def handle_common_match_keys(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if mapping has required keys for pattern matching."""
    keys_tuple = state.pop() if state.stack else None
    subject = _resolve_match_subject(state.peek(), state) if state.stack else None

    success_expr = Z3_TRUE
    concrete_keys_obj = _extract_match_keys(keys_tuple)

    if isinstance(subject, SymbolicDict) and concrete_keys_obj is not None:
        for key in concrete_keys_obj:
            if not isinstance(key, SymbolicString):
                str_key = SymbolicString.from_const(str(key))
            else:
                str_key = key
            success_expr = z3.And(success_expr, subject.contains_key(str_key).z3_bool)
    elif isinstance(subject, dict) and concrete_keys_obj is not None:
        success_expr = z3.BoolVal(all(key in subject for key in concrete_keys_obj))
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


def handle_common_match_class(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    num_positional = int(instr.argval) if instr.argval else 0
    names_tuple = state.pop() if state.stack else None
    cls = state.pop() if state.stack else None
    subject = state.pop() if state.stack else None

    enhanced_attrs = _enhanced_match_class_attrs(subject, cls, names_tuple, num_positional)
    if enhanced_attrs is not None:
        state = state.push(enhanced_attrs)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if isinstance(cls, type) and not isinstance(subject, (SymbolicValue, SymbolicObject)):
        concrete_attrs = _concrete_match_class_attrs(subject, cls, names_tuple, num_positional)
        if concrete_attrs is not None:
            state = state.push(concrete_attrs)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

    attr_names = (
        _extract_match_class_attr_names(cls, names_tuple, num_positional)
        if isinstance(cls, type)
        else None
    )
    attr_count = len(attr_names) if attr_names is not None else num_positional

    success = z3.Bool(fresh_name("match_class_success"))
    if isinstance(subject, SymbolicObject) and isinstance(cls, type):
        success = z3.And(success, subject.z3_addr >= z3.IntVal(0))
    elif isinstance(subject, SymbolicValue) and isinstance(cls, type):
        builtin_success = _builtin_match_success(subject, cls)
        if builtin_success is not None:
            success = builtin_success
    elif isinstance(cls, type):
        success = z3.BoolVal(isinstance(subject, cls))

    if z3.is_false(z3.simplify(success)):
        state = state.push(SymbolicNone("match_class_no_match"))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    result = SymbolicValue(
        _name=f"match_class_result_{state.pc}",
        z3_int=z3.IntVal(attr_count),
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
