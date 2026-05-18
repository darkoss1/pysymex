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

"""Common function call opcodes."""

from __future__ import annotations

import dis
import inspect
import logging
import copy
import sys
import types
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Protocol, TypeGuard, cast

import z3

from pysymex._constants import DANGEROUS_ATTR_NAMES
from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.summaries import FunctionSummary, SummaryBuilder, instantiate_summary
from pysymex.core.cache import get_instructions as _cached_get_instructions
from pysymex.core.memory.cow import CowDict
from pysymex.core.solver.constraints import quick_contradiction_check
from pysymex.core.solver.engine import is_satisfiable
from pysymex.core.state import VMStateError
from pysymex.core.types import SymbolicDict, SymbolicList, SymbolicObject, SymbolicType
from pysymex.core.types.havoc import HavocValue
from pysymex.core.types.scalars import (
    Z3_TRUE,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pysymex.execution.dispatcher import OpcodeResult
from pysymex.execution.model_effects import issues_from_model_side_effects
from pysymex.execution.opcodes.common.lowering import CallLowerer
from pysymex.models.builtins import FunctionModel, get_default_model_registry
from pysymex.models.stdlib import get_stdlib_model
from pysymex.sandbox.errors import SecurityViolationError

logger = logging.getLogger(__name__)


def _path_is_sat(constraints: list[z3.BoolRef]) -> bool:
    """Check path satisfiability with a cheap fallback on deep paths."""
    if quick_contradiction_check(constraints):
        return False
    if len(constraints) < 12:
        return is_satisfiable(constraints)
    return True


def _is_uninterpreted_bool_const(expr: z3.BoolRef) -> bool:
    try:
        return z3.is_const(expr) and expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
    except z3.Z3Exception:
        return False


def _can_constrain_receiver_non_none_without_solver(obj: SymbolicValue) -> bool:
    """Return whether LOAD_ATTR can take the non-None continuation without SMT."""
    if z3.is_false(obj.is_none) or z3.is_true(obj.is_none):
        return True
    return _is_uninterpreted_bool_const(obj.is_none)


def _definite_non_callable_type_name(value: object) -> str | None:
    """Return a CPython type name when *value* is definitely not callable."""
    if isinstance(value, SymbolicValue):
        name = value.name
        if (
            not name.isidentifier()
            or getattr(value, "model_name", None) is not None
            or name.startswith(("function_", "global_", "import_", "instance_", "havoc"))
        ):
            return None
        if value.affinity_type in {"int", "float", "bool", "str", "list", "dict"}:
            return value.affinity_type
        return None
    if isinstance(value, (int, float, bool, str, list, dict, tuple, set, bytes, bytearray)):
        return type(cast(object, value)).__name__
    return "NoneType" if value is None else None


def _handle_definite_non_callable_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
) -> OpcodeResult | None:
    type_name = _definite_non_callable_type_name(func_obj)
    if type_name is None:
        return None

    handler_pc = ctx.find_exception_handler(instr.offset)
    if handler_pc is not None:
        return OpcodeResult.continue_with(state.set_pc(handler_pc))

    issue = Issue(
        kind=IssueKind.TYPE_ERROR,
        message=f"Possible TypeError: '{type_name}' object is not callable",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


_MAX_SUMMARY_CACHE_CONSTRAINTS = 24
_MAX_SUMMARY_CACHE_ARGS = 12
_MAX_CALLABILITY_CHECK_CONSTRAINTS = 64


def _concrete_string(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString):
        raw_name = value.name
        if len(raw_name) >= 2 and raw_name[0] == raw_name[-1] and raw_name[0] in {"'", '"'}:
            return raw_name[1:-1]
        return None
    if isinstance(value, SymbolicValue) and isinstance(value.value, str):
        return value.value
    return None


def _require_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    """Enforce minimum stack depth for opcode execution."""
    if len(state.stack) < required_depth:
        raise VMStateError(
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )


def _validate_concrete_attribute_access(attr_name: str) -> None:
    if attr_name in DANGEROUS_ATTR_NAMES:
        raise SecurityViolationError(
            "attribute access",
            f"attribute '{attr_name}' is blocked for concrete objects",
        )


def _is_call_null_marker(value: object) -> bool:
    return value is None or isinstance(value, SymbolicNone)


def _resolve_model(model_name: str) -> FunctionModel | None:
    """Resolve a model by name across all registries."""
    model = get_default_model_registry().get(model_name) or get_stdlib_model(model_name)
    if model:
        return model

    from pysymex.models.stdlib.collections import get_collections_model
    from pysymex.models.stdlib.functools import get_functools_model
    from pysymex.models.stdlib.itertools import get_itertools_model
    from pysymex.models.concurrency.threading import get_threading_model

    lookup: Callable[..., object]
    for lookup in (
        get_threading_model,
        get_collections_model,
        get_itertools_model,
        get_functools_model,
    ):
        result: object = lookup(model_name)
        if result is not None:
            return cast("FunctionModel | None", result)
    return None


if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


class _SummaryCacheProtocol(Protocol):
    """Protocol for cross-function summary cache."""

    def get(
        self,
        name: str,
        args: list[StackValue],
        constraints: list[z3.BoolRef],
    ) -> object: ...


class _CrossFunctionProtocol(Protocol):
    """Protocol for cross-function analyzer objects."""

    function_summary_cache: _SummaryCacheProtocol


class _ObjectMapProtocol(Protocol):
    """Mapping-like runtime protocol used for strict key/value narrowing."""

    def __contains__(self, key: object, /) -> bool: ...

    def __getitem__(self, key: object, /) -> object: ...

    def __setitem__(self, key: object, value: object, /) -> None: ...

    def items(self) -> Iterable[tuple[object, object]]: ...


def _is_object_map(value: object) -> TypeGuard[_ObjectMapProtocol]:
    """Return ``True`` when *value* behaves like a mutable mapping."""
    return (
        hasattr(value, "items")
        and callable(getattr(value, "items", None))
        and hasattr(value, "__contains__")
        and hasattr(value, "__getitem__")
        and hasattr(value, "__setitem__")
    )


def _to_z3_expr(value: StackValue) -> z3.ExprRef | None:
    """Best-effort conversion from stack values to Z3 expressions."""
    if isinstance(value, SymbolicValue):
        return value.to_z3()
    if isinstance(value, int) and not isinstance(value, bool):
        return z3.IntVal(value)
    if isinstance(value, bool):
        return z3.BoolVal(value)
    if isinstance(value, float):
        return z3.RealVal(value)
    if isinstance(value, str):
        return z3.StringVal(value)
    return None


def _as_mapping(value: object) -> dict[str, object] | None:
    """Return a concrete ``dict[str, object]`` for mapping-like values."""
    if _is_object_map(value):
        return {k: v for k, v in value.items() if isinstance(k, str)}
    return None


def _as_stack_value(value: object) -> StackValue:
    """Best-effort conversion into the StackValue domain used by VMState."""
    if value is None:
        return None
    try:
        from pysymex.core.objects.oop import EnhancedMethod
    except ImportError:
        EnhancedMethod = None  # type: ignore[assignment]
    if EnhancedMethod is not None and isinstance(value, EnhancedMethod):
        return cast("StackValue", value)
    if isinstance(
        value,
        (
            SymbolicValue,
            SymbolicNone,
            SymbolicString,
            SymbolicList,
            SymbolicDict,
            SymbolicObject,
            SymbolicType,
            int,
            bool,
            str,
            float,
            bytes,
            type,
            list,
            dict,
            tuple,
        ),
    ):
        return cast("StackValue", value)
    if callable(value):
        return cast("StackValue", value)
    return SymbolicValue.from_const(value)


def _bind_heap_enhanced_method(value: object, receiver: StackValue) -> object:
    try:
        from pysymex.core.objects.oop import EnhancedMethod
    except ImportError:
        return value
    if isinstance(value, EnhancedMethod) and not value.is_bound:
        return value.bind_to_instance(receiver)
    return value


def _map_get(value: _ObjectMapProtocol, key: str) -> tuple[bool, object | None]:
    """Read a mapping entry while preserving existence vs None values."""
    if key in value:
        return True, value[key]
    return False, None


def _map_set(value: _ObjectMapProtocol, key: str, item: StackValue) -> None:
    """Store a value in a mapping-like object."""
    value[key] = item


def _map_to_stack_dict(value: _ObjectMapProtocol) -> dict[str, StackValue]:
    """Convert a mutable mapping-like object to ``dict[str, StackValue]``."""
    return {k: _as_stack_value(v) for k, v in value.items() if isinstance(k, str)}


def coerce_kw_names(raw_kw_names: object) -> tuple[str, ...]:
    """Normalize keyword name payloads into a tuple of keyword names."""
    if isinstance(raw_kw_names, tuple):
        tuple_items = cast("tuple[object, ...]", raw_kw_names)
        return tuple(name for name in tuple_items if isinstance(name, str))
    if isinstance(raw_kw_names, list):
        list_items = cast("list[object]", raw_kw_names)
        return tuple(name for name in list_items if isinstance(name, str))
    if isinstance(raw_kw_names, str):
        cleaned = raw_kw_names.strip().strip("()")
        if not cleaned:
            return ()
        if "," in cleaned:
            return tuple(part.strip() for part in cleaned.split(",") if part.strip())
        return (cleaned,)
    return ()


_coerce_kw_names = coerce_kw_names


def _apply_model(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
) -> OpcodeResult | None:
    """Apply a built-in or stdlib model if available."""
    kwargs = kwargs or {}
    model_name = func_obj if isinstance(func_obj, str) else getattr(func_obj, "model_name", None)
    func_name = getattr(func_obj, "_name", "") or getattr(func_obj, "name", "")
    if func_name == "__build_class__":
        return _apply_build_class_model(state, args)
    if model_name is None and isinstance(func_name, str) and func_name.endswith(".close"):
        model_name = func_name
    if isinstance(model_name, str) and model_name.endswith(".close"):
        state = state.push(SymbolicNone())
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    if model_name:
        model = _resolve_model(model_name)
        if not model:
            return None

        # Check if model has apply method (some models may be plain functions)
        if not hasattr(model, "apply"):
            return None

        result = model.apply(args, kwargs, state)
    else:
        direct_result = get_default_model_registry().apply(func_obj, args, kwargs, state)
        if direct_result is None:
            return None
        result = direct_result
    generated_issues: list[Issue] = []
    if result.side_effects:
        generated_issues.extend(
            issues_from_model_side_effects(
                result.side_effects,
                state.pc,
                path_constraints=list(state.path_constraints),
                is_sat=is_satisfiable,
            )
        )
        if "list_mutation" in result.side_effects:
            mut = _as_mapping(result.side_effects["list_mutation"])
            if mut is None:
                mut = {}
            orig_lst = mut.get("original_list")
            updated_lst = mut.get("updated_list")
            if orig_lst and updated_lst:
                updated_stack_val = _as_stack_value(updated_lst)

                found_in_memory = False
                for addr, obj in state.memory.items():
                    if obj is orig_lst:
                        state = state.store_heap(addr, updated_stack_val)
                        found_in_memory = True
                        break
                if not found_in_memory:
                    new_stack: list[StackValue] = []
                    for item in state.stack:
                        if item is orig_lst:
                            new_stack.append(updated_stack_val)
                            found_in_memory = True
                        else:
                            new_stack.append(item)
                    if found_in_memory:
                        state = state.replace(stack=new_stack)

        if "dict_mutation" in result.side_effects:
            mut = _as_mapping(result.side_effects["dict_mutation"])
            if mut is None:
                mut = {}
            orig_dict = mut.get("original_dict")
            updated_dict = mut.get("updated_dict")
            if orig_dict and updated_dict:
                updated_stack_val = _as_stack_value(updated_dict)
                found_in_memory = False
                for addr, obj in state.memory.items():
                    if obj is orig_dict:
                        state = state.store_heap(addr, updated_stack_val)
                        found_in_memory = True
                        break
                if not found_in_memory:
                    new_stack: list[StackValue] = []
                    for item in state.stack:
                        if item is orig_dict:
                            new_stack.append(updated_stack_val)
                            found_in_memory = True
                        else:
                            new_stack.append(item)
                    if found_in_memory:
                        state = state.replace(stack=new_stack)

    state = state.push(result.value)
    for constraint in result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    state = state.advance_pc()
    return OpcodeResult(new_states=[state], issues=generated_issues)


def _perform_interprocedural_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
    is_init: bool = False,
    init_instance: StackValue | None = None,
) -> OpcodeResult | None:
    """Attempt to perform an inter-procedural call to a user-defined function.

    Supports:
    - Standard functions and methods.
    - Python 3.12+ Generic Functions (calling the generic parameter code object).
    - Positional and Keyword arguments.
    """
    MAX_CALL_DEPTH = 10
    if state.call_depth() >= MAX_CALL_DEPTH:
        return None

    from pysymex.core.state import CallFrame

    kwargs = kwargs or {}
    try:
        from pysymex.core.objects.oop import EnhancedMethod
    except ImportError:
        EnhancedMethod = None  # type: ignore[assignment]

    func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)

    if EnhancedMethod is not None and isinstance(func_obj, EnhancedMethod):
        method_args, method_kwargs = func_obj.get_call_args(
            tuple(args),
            cast("dict[str, object]", dict(kwargs)),
        )
        args = cast("list[StackValue]", list(method_args))
        kwargs = cast("dict[str, StackValue]", method_kwargs)
        func_code = getattr(func_obj.func, "__code__", None) or getattr(
            func_obj.func, "_func_code", None
        )
        if func_code is None and isinstance(func_obj.func, types.CodeType):
            func_code = func_obj.func
        func_obj = func_obj.func

    if func_code is None and hasattr(func_obj, "value"):
        inner = getattr(func_obj, "value", None)
        if inner is not None:
            func_code = getattr(inner, "__code__", None) or getattr(inner, "_func_code", None)
            func_obj = inner
    if func_code is None and hasattr(func_obj, "_enhanced_object"):
        inner = getattr(func_obj, "_enhanced_object", None)
        if inner is not None:
            if hasattr(inner, "co_code"):
                func_code = inner
            else:
                func_code = getattr(inner, "__code__", None) or getattr(inner, "_func_code", None)
            func_obj = inner

    func_name = getattr(func_obj, "__name__", None) or getattr(func_obj, "_func_name", "anonymous")

    if not isinstance(func_code, types.CodeType):
        return None

    if func_code.co_flags & inspect.CO_GENERATOR:
        gen_val, constraint = SymbolicValue.symbolic(f"generator_call_{state.pc}")
        state = state.push(gen_val)
        state = state.add_constraint(constraint)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    try:
        callee_instructions = _cached_get_instructions(func_code)
    except (TypeError, ValueError):
        return None

    arg_count = func_code.co_argcount
    pos_arg_names = func_code.co_varnames[:arg_count]
    defaults_obj = getattr(func_obj, "__defaults__", None)
    if isinstance(defaults_obj, tuple):
        defaults_tuple = cast("tuple[object, ...]", defaults_obj)
        defaults_count = len(defaults_tuple)
    else:
        defaults_count = 0
    required_positional_count = max(0, arg_count - defaults_count)
    missing_required = [
        name
        for index, name in enumerate(pos_arg_names[:required_positional_count])
        if index >= len(args) and name not in kwargs
    ]
    if missing_required:
        missing = str(missing_required[0])
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message=f"Possible TypeError: {func_name}() missing required argument '{missing}'",
            constraints=list(state.path_constraints),
            pc=state.pc,
        )
        return OpcodeResult.error(issue)

    builder = None
    if ctx.cross_function and hasattr(ctx.cross_function, "function_summary_cache"):
        builder = SummaryBuilder(func_name)
        builder.set_qualname(func_name)
        builder.set_initial_args(cast("list[object]", list(args)))
        for name in pos_arg_names:
            builder.add_parameter(name)

    new_locals: dict[str, StackValue] = {}

    try:
        closure = getattr(func_obj, "__closure__", None)
        freevars = list(getattr(func_code, "co_freevars", ()))
        if closure and freevars:
            for fv_name, cell in zip(freevars, closure, strict=False):
                try:
                    new_locals[fv_name] = cell.cell_contents
                except ValueError:
                    continue
    except (AttributeError, TypeError):
        logger.debug("Unable to copy closure cells for %s", func_name)

    for i, name in enumerate(pos_arg_names):
        if i < len(args):
            new_locals[name] = args[i]
        elif name in kwargs:
            new_locals[name] = kwargs[name]
        else:
            val, constraint = SymbolicValue.symbolic(f"arg_{name}")
            new_locals[name] = val
            state = state.add_constraint(constraint)

    if func_code.co_flags & 0x04:
        vararg_name = func_code.co_varnames[arg_count]
        extra_pos = args[arg_count:] if len(args) > arg_count else []

        vararg_items = cast("list[object]", list(extra_pos))
        vararg_list = SymbolicList.empty(vararg_name).extend(vararg_items)
        new_locals[vararg_name] = vararg_list
        arg_count += 1

    if func_code.co_flags & 0x08:
        kwarg_name = func_code.co_varnames[arg_count]
        unused_kwargs: dict[str, StackValue] = {
            k: v for k, v in kwargs.items() if k not in pos_arg_names
        }
        new_locals[kwarg_name] = unused_kwargs

    from pysymex.core.state import wrap_cow_dict

    frame = CallFrame(
        function_name=func_name,
        return_pc=state.pc + 1,
        local_vars=state.local_vars,
        stack_depth=len(state.stack),
        caller_instructions=cast("list[object]", list(ctx.instructions)),
        summary_builder=builder,
        is_init_call=is_init,
        init_instance=init_instance,
    )

    # Update state to use NEW locals (callee)
    state.local_vars = wrap_cow_dict(new_locals)
    state = state.push_call(frame)

    config = getattr(ctx, "config", None)
    if config and getattr(config, "enable_contract_verification", False):
        from pysymex.contracts.injector import inject_call_preconditions

        issue = inject_call_preconditions(
            state, cast("Callable[..., object]", func_obj), args, kwargs
        )
        if issue:
            return OpcodeResult(new_states=[], issues=[issue], terminal=True)
        state.contract_frames.append(func_obj)

    state.local_vars = wrap_cow_dict(new_locals)
    state.current_instructions = cast("list[object]", list(callee_instructions))
    ctx.set_instructions(list(callee_instructions))
    state = state.set_pc(0)
    state.depth += 1

    return OpcodeResult.continue_with(state)


def perform_interprocedural_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
) -> OpcodeResult | None:
    """Public internal wrapper for opcode helpers that dispatch user callables."""
    return _perform_interprocedural_call(state, ctx, func_obj, args, kwargs)


def _apply_build_class_model(state: VMState, args: list[StackValue]) -> OpcodeResult | None:
    """Model CPython ``__build_class__`` without executing class-body side effects."""
    if len(args) < 2:
        return None
    body_func = args[0]
    class_name = _concrete_string(args[1])
    if class_name is None:
        class_name = getattr(body_func, "_name", None) or getattr(body_func, "name", None)
    if not isinstance(class_name, str) or not class_name:
        class_name = f"class_{state.pc}"

    code_obj = getattr(body_func, "_enhanced_object", None)
    class_val = SymbolicValue(
        _name=class_name,
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        affinity_type="type",
    )
    if isinstance(code_obj, types.CodeType):
        class_val.attach_enhanced_object(code_obj)
    state = state.push(class_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


_CLASS_BODY_DECORATOR_NOOPS = frozenset({"CACHE", "PRECALL"})


def _class_body_effective_instructions(class_body: types.CodeType) -> list[dis.Instruction]:
    return [
        instr
        for instr in dis.get_instructions(class_body)
        if instr.opname not in _CLASS_BODY_DECORATOR_NOOPS
    ]


def _property_marker_getter(_obj: object) -> object:
    return SymbolicValue.symbolic("property_value")[0]


def _property_marker_setter(_obj: object, _value: object) -> None:
    return None


def _last_make_function_before(
    instructions: list[dis.Instruction],
    store_index: int,
) -> int | None:
    if store_index < 1 or instructions[store_index - 1].opname != "CALL":
        return None
    for index in range(store_index - 2, -1, -1):
        instr = instructions[index]
        if instr.opname == "MAKE_FUNCTION":
            return index
        if instr.opname in {"STORE_NAME", "STORE_GLOBAL", "RETURN_VALUE", "RETURN_CONST"}:
            return None
    return None


def _code_const_before_make_function(
    instructions: list[dis.Instruction],
    make_index: int,
) -> int | None:
    for index in range(make_index - 1, -1, -1):
        instr = instructions[index]
        if instr.opname == "LOAD_CONST" and isinstance(instr.argval, types.CodeType):
            return index
        if instr.opname in {"STORE_NAME", "STORE_GLOBAL", "RETURN_VALUE", "RETURN_CONST"}:
            return None
    return None


def _previous_class_body_store_index(
    instructions: list[dis.Instruction],
    before_index: int,
) -> int:
    for index in range(before_index - 1, -1, -1):
        if instructions[index].opname in {"STORE_NAME", "STORE_GLOBAL"}:
            return index
    return -1


def _is_property_getter_assignment(
    instructions: list[dis.Instruction],
    store_index: int,
) -> bool:
    make_index = _last_make_function_before(instructions, store_index)
    if make_index is None:
        return False
    code_index = _code_const_before_make_function(instructions, make_index)
    if code_index is None:
        return False
    boundary = _previous_class_body_store_index(instructions, code_index)
    return any(
        instr.opname == "LOAD_NAME" and instr.argval == "property"
        for instr in instructions[boundary + 1 : code_index]
    )


def _is_property_setter_assignment(
    instructions: list[dis.Instruction],
    store_index: int,
    property_name: str,
) -> bool:
    make_index = _last_make_function_before(instructions, store_index)
    if make_index is None:
        return False
    code_index = _code_const_before_make_function(instructions, make_index)
    if code_index is None:
        return False
    boundary = _previous_class_body_store_index(instructions, code_index)
    search = instructions[boundary + 1 : code_index]
    for index, instr in enumerate(search[:-1]):
        next_instr = search[index + 1]
        if (
            instr.opname == "LOAD_NAME"
            and instr.argval == property_name
            and next_instr.opname == "LOAD_ATTR"
            and next_instr.argval == "setter"
        ):
            return True
    return False


def _decorated_method_kind(
    instructions: list[dis.Instruction],
    method_name: str,
) -> str | None:
    for index, instr in enumerate(instructions):
        if instr.opname not in {"STORE_NAME", "STORE_GLOBAL"} or instr.argval != method_name:
            continue
        make_index = _last_make_function_before(instructions, index)
        if make_index is None:
            continue
        code_index = _code_const_before_make_function(instructions, make_index)
        if code_index is None:
            continue
        code_obj = instructions[code_index].argval
        if not isinstance(code_obj, types.CodeType) or code_obj.co_name != method_name:
            continue
        boundary = _previous_class_body_store_index(instructions, code_index)
        decorators = {
            str(decorator.argval)
            for decorator in instructions[boundary + 1 : code_index]
            if decorator.opname == "LOAD_NAME" and isinstance(decorator.argval, str)
        }
        if "staticmethod" in decorators:
            return "static"
        if "classmethod" in decorators:
            return "class"
    return None


def _register_property_descriptors(enhanced_cls: object, class_body: types.CodeType) -> None:
    try:
        from pysymex.core.objects.oop import EnhancedClass
    except ImportError:
        return
    if not isinstance(enhanced_cls, EnhancedClass):
        return
    instructions = _class_body_effective_instructions(class_body)
    for index, instr in enumerate(instructions):
        if instr.opname not in {"STORE_NAME", "STORE_GLOBAL"} or not isinstance(instr.argval, str):
            continue
        property_name = instr.argval
        if _is_property_getter_assignment(instructions, index):
            enhanced_cls.add_property(property_name, fget=_property_marker_getter)
        elif _is_property_setter_assignment(instructions, index, property_name):
            existing = enhanced_cls.properties.get(property_name)
            fget = getattr(existing, "fget", None) or _property_marker_getter
            enhanced_cls.add_property(
                property_name,
                fget=fget,
                fset=_property_marker_setter,
            )


def _register_class_body_methods(enhanced_cls: object, class_body: types.CodeType | type) -> None:
    try:
        from pysymex.core.objects.oop import EnhancedClass, MethodType, extract_init_params
    except ImportError:
        return
    if not isinstance(enhanced_cls, EnhancedClass):
        return

    if isinstance(class_body, type):
        for name, member in class_body.__dict__.items():
            if isinstance(member, (types.FunctionType, types.MethodType)):
                func_code = getattr(member, "__code__", None)
                if func_code:
                    enhanced_cls.add_method(
                        name,
                        func_code,
                        method_type=MethodType.INSTANCE,
                        parameters=list(func_code.co_varnames[: func_code.co_argcount]),
                    )
            elif isinstance(member, classmethod):
                func = getattr(cast("object", member), "__func__", None)
                func_code = getattr(func, "__code__", None) if func else None
                if func_code:
                    enhanced_cls.add_method(
                        name,
                        func_code,
                        method_type=MethodType.CLASS,
                        parameters=list(func_code.co_varnames[: func_code.co_argcount]),
                    )
            elif isinstance(member, staticmethod):
                func = getattr(cast("object", member), "__func__", None)
                func_code = getattr(func, "__code__", None) if func else None
                if func_code:
                    enhanced_cls.add_method(
                        name,
                        func_code,
                        method_type=MethodType.STATIC,
                        parameters=list(func_code.co_varnames[: func_code.co_argcount]),
                    )
        return

    slots = _extract_literal_slots(class_body)
    if slots is not None:
        enhanced_cls.slots = slots
    instructions = _class_body_effective_instructions(class_body)
    for const in class_body.co_consts:
        if not isinstance(const, types.CodeType):
            continue
        method_name = const.co_name
        if method_name in {"<listcomp>", "<dictcomp>", "<setcomp>", "<genexpr>"}:
            continue
        method_kind = _decorated_method_kind(instructions, method_name)
        method_type = MethodType.INSTANCE
        if method_kind == "static":
            method_type = MethodType.STATIC
        elif method_kind == "class":
            method_type = MethodType.CLASS
        enhanced_cls.add_method(
            method_name,
            const,
            method_type=method_type,
            parameters=list(const.co_varnames[: const.co_argcount]),
        )
        if method_name == "__init__":
            enhanced_cls.set_init_params(extract_init_params(const))
    _register_property_descriptors(enhanced_cls, class_body)


def _enhanced_class_from_symbolic_class_value(obj: SymbolicValue) -> object | None:
    if getattr(obj, "affinity_type", None) != "type":
        return None
    class_body = getattr(obj, "_enhanced_object", None)
    if not isinstance(class_body, types.CodeType):
        return None
    try:
        from pysymex.core.objects.oop import enhanced_class_registry
    except ImportError:
        return None
    enhanced_cls = enhanced_class_registry.get_by_code_object(class_body)
    if enhanced_cls is None:
        class_name = getattr(obj, "_name", None) or getattr(obj, "name", None) or class_body.co_name
        enhanced_cls = enhanced_class_registry.register_class(str(class_name))
        enhanced_class_registry.register_code_object(class_body, enhanced_cls)
        _register_class_body_methods(enhanced_cls, class_body)
    return enhanced_cls


def _class_level_enhanced_attribute(obj: SymbolicValue, attr_name: str) -> tuple[object, bool]:
    enhanced_cls = _enhanced_class_from_symbolic_class_value(obj)
    if enhanced_cls is None:
        return None, False
    get_method = getattr(enhanced_cls, "get_method", None)
    if callable(get_method):
        method = get_method(attr_name)
        if method is not None:
            method_type = getattr(method, "method_type", None)
            if getattr(method_type, "name", "") == "CLASS":
                bind_to_class = getattr(method, "bind_to_class", None)
                base = getattr(enhanced_cls, "base", None)
                if callable(bind_to_class) and base is not None:
                    return bind_to_class(base), True
            return method, True
    class_vars = getattr(enhanced_cls, "class_vars", {})
    if isinstance(class_vars, dict) and attr_name in class_vars:
        typed_class_vars = cast("dict[str, object]", class_vars)
        return typed_class_vars[attr_name], True
    return None, False


def _extract_literal_slots(class_body: types.CodeType) -> tuple[str, ...] | None:
    instructions = list(dis.get_instructions(class_body))
    for index, instr in enumerate(instructions):
        if instr.opname not in {"STORE_NAME", "STORE_GLOBAL"} or instr.argval != "__slots__":
            continue
        if index < 1:
            return None
        value_instr = instructions[index - 1]
        if value_instr.opname != "LOAD_CONST":
            return None
        value = value_instr.argval
        if isinstance(value, str):
            slots = (value,)
        elif isinstance(value, tuple):
            tuple_items = cast("tuple[object, ...]", value)
            if not all(isinstance(item, str) for item in tuple_items):
                return None
            slots = tuple(str(item) for item in tuple_items)
        else:
            return None
        if "__dict__" in slots:
            return None
        return slots
    return None


def _init_code_is_straight_line(init_code: types.CodeType) -> bool:
    for instr in dis.get_instructions(init_code):
        if instr.opcode in dis.hasjrel or instr.opcode in dis.hasjabs:
            return False
    return True


def _simple_init_assignment_value(
    instructions: list[dis.Instruction],
    store_index: int,
) -> tuple[str, object] | None:
    if store_index < 1:
        return None
    previous = instructions[store_index - 1]
    if previous.opname == "LOAD_FAST_LOAD_FAST":
        names_obj = previous.argval
        if isinstance(names_obj, tuple):
            names = cast("tuple[object, ...]", names_obj)
            if len(names) == 2 and names[1] in {"self", "cls"} and isinstance(names[0], str):
                return ("param", names[0])
        return None
    if previous.opname != "LOAD_FAST" or previous.argval not in {"self", "cls"}:
        return None
    if store_index < 2:
        return None
    value_instr = instructions[store_index - 2]
    if value_instr.opname == "LOAD_FAST" and isinstance(value_instr.argval, str):
        return ("param", value_instr.argval)
    if value_instr.opname == "LOAD_CONST":
        return ("const", value_instr.argval)
    return None


def _value_from_init_assignment(
    value_info: tuple[str, object],
    param_values: dict[str, object],
) -> tuple[object, bool]:
    value_kind, value_key = value_info
    if value_kind == "param" and isinstance(value_key, str) and value_key in param_values:
        return param_values[value_key], True
    if value_kind == "const":
        return value_key, True
    return None, False


def _init_condition_expr(condition: object) -> z3.BoolRef | None:
    if isinstance(condition, bool):
        return z3.BoolVal(condition)
    if isinstance(condition, SymbolicValue) and z3.is_true(z3.simplify(condition.is_bool)):
        return condition.z3_bool
    return None


def _conditional_init_value(
    attr_name: str,
    condition: z3.BoolRef,
    true_value: object,
    false_value: object,
) -> object:
    if z3.is_true(z3.simplify(condition)):
        return true_value
    if z3.is_false(z3.simplify(condition)):
        return false_value
    true_symbol = SymbolicValue.from_const(true_value)
    false_symbol = SymbolicValue.from_const(false_value)
    return SymbolicValue(
        _name=f"init_{attr_name}",
        z3_int=z3.If(condition, true_symbol.z3_int, false_symbol.z3_int),
        is_int=z3.If(condition, true_symbol.is_int, false_symbol.is_int),
        z3_bool=z3.If(condition, true_symbol.z3_bool, false_symbol.z3_bool),
        is_bool=z3.If(condition, true_symbol.is_bool, false_symbol.is_bool),
        is_float=z3.If(condition, true_symbol.is_float, false_symbol.is_float),
        z3_str=z3.If(condition, true_symbol.z3_str, false_symbol.z3_str),
        is_str=z3.If(condition, true_symbol.is_str, false_symbol.is_str),
        z3_addr=z3.If(condition, true_symbol.z3_addr, false_symbol.z3_addr),
        is_obj=z3.If(condition, true_symbol.is_obj, false_symbol.is_obj),
        is_list=z3.If(condition, true_symbol.is_list, false_symbol.is_list),
        is_dict=z3.If(condition, true_symbol.is_dict, false_symbol.is_dict),
        is_path=z3.If(condition, true_symbol.is_path, false_symbol.is_path),
        is_none=z3.If(condition, true_symbol.is_none, false_symbol.is_none),
        affinity_type=(
            true_symbol.affinity_type
            if true_symbol.affinity_type == false_symbol.affinity_type
            else "unknown"
        ),
    )


def _single_init_assignment_between(
    instructions: list[dis.Instruction],
    *,
    start_index: int,
    end_index: int,
) -> tuple[str, tuple[str, object]] | None:
    assignments: list[tuple[str, tuple[str, object]]] = []
    for index in range(start_index, end_index):
        instr = instructions[index]
        if instr.opname != "STORE_ATTR" or not isinstance(instr.argval, str):
            continue
        value_info = _simple_init_assignment_value(instructions, index)
        if value_info is None:
            return None
        assignments.append((instr.argval, value_info))
    if len(assignments) != 1:
        return None
    return assignments[0]


def _apply_simple_conditional_init_assignments(
    init_code: types.CodeType,
    instance: object,
    param_values: dict[str, object],
) -> bool:
    set_attribute = getattr(instance, "set_attribute", None)
    if not callable(set_attribute):
        return False
    instructions = list(dis.get_instructions(init_code))
    false_jump_ops = {
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_FORWARD_IF_FALSE",
        "POP_JUMP_BACKWARD_IF_FALSE",
    }
    jumps = [instr for instr in instructions if instr.opname in false_jump_ops]
    if len(jumps) != 1:
        return False
    jump = jumps[0]
    jump_index = instructions.index(jump)
    condition_index = jump_index - 1
    if condition_index >= 0 and instructions[condition_index].opname == "TO_BOOL":
        condition_index -= 1
    if condition_index < 0:
        return False
    condition_instr = instructions[condition_index]
    if condition_instr.opname != "LOAD_FAST" or not isinstance(condition_instr.argval, str):
        return False
    condition_value = param_values.get(condition_instr.argval)
    if condition_value is None:
        return False
    condition = _init_condition_expr(condition_value)
    if condition is None:
        return False
    false_start = next(
        (index for index, instr in enumerate(instructions) if instr.offset == jump.argval),
        None,
    )
    if false_start is None or false_start <= jump_index + 1:
        return False
    true_assignment = _single_init_assignment_between(
        instructions,
        start_index=jump_index + 1,
        end_index=false_start,
    )
    false_assignment = _single_init_assignment_between(
        instructions,
        start_index=false_start,
        end_index=len(instructions),
    )
    if true_assignment is None or false_assignment is None:
        return False
    true_attr, true_value_info = true_assignment
    false_attr, false_value_info = false_assignment
    if true_attr != false_attr:
        return False
    true_value, true_found = _value_from_init_assignment(true_value_info, param_values)
    false_value, false_found = _value_from_init_assignment(false_value_info, param_values)
    if not true_found or not false_found:
        return False
    set_attribute(true_attr, _conditional_init_value(true_attr, condition, true_value, false_value))
    return True


def _apply_straight_line_init_assignments(
    enhanced_cls: object,
    instance: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> bool:
    get_method = getattr(enhanced_cls, "get_method", None)
    if not callable(get_method) or get_method("__setattr__") is not None:
        return False
    init_method = get_method("__init__")
    init_code = getattr(init_method, "func", None)
    if not isinstance(init_code, types.CodeType):
        return False
    parameters = list(getattr(init_method, "parameters", []))
    init_values = getattr(instance, "init_values", {})
    param_values: dict[str, object] = {}
    positional_params = [
        str(name) for name in parameters if isinstance(name, str) and name not in {"self", "cls"}
    ]
    for index, name in enumerate(positional_params):
        if name in kwargs:
            param_values[name] = kwargs[name]
        elif index < len(args):
            param_values[name] = args[index]
        elif isinstance(init_values, dict) and name in init_values:
            param_values[name] = init_values[name]

    if not _init_code_is_straight_line(init_code):
        return _apply_simple_conditional_init_assignments(init_code, instance, param_values)

    set_attribute = getattr(instance, "set_attribute", None)
    if not callable(set_attribute):
        return False
    instructions = list(dis.get_instructions(init_code))
    applied = False
    for index, instr in enumerate(instructions):
        if instr.opname != "STORE_ATTR" or not isinstance(instr.argval, str):
            continue
        value_info = _simple_init_assignment_value(instructions, index)
        if not isinstance(value_info, tuple) or len(value_info) != 2:
            continue
        value_kind, value_key = value_info
        if value_kind == "param" and isinstance(value_key, str) and value_key in param_values:
            set_attribute(instr.argval, param_values[value_key])
            applied = True
        elif value_kind == "const":
            set_attribute(instr.argval, value_key)
            applied = True
    return applied


def _clone_enhanced_object(value: object) -> object | None:
    try:
        from pysymex.core.objects.oop import EnhancedObject
        from pysymex.core.objects.types import SymbolicObject as OopSymbolicObject
    except ImportError:
        return None
    if not isinstance(value, EnhancedObject):
        return None
    base = value.base
    cloned_base = OopSymbolicObject(
        cls=base.cls,
        attributes=dict(base.attributes),
        _id=base.id,
        slots=base.slots,
    )
    return EnhancedObject(
        base=cloned_base,
        enhanced_class=value.enhanced_class,
        initialized=value.initialized,
        init_values=dict(value.init_values),
        _modified_attrs=set(value.modified_attrs),
        _accessed_attrs=set(value.accessed_attrs),
    )


def _copy_symbolic_value_with_enhanced_object(obj: SymbolicValue) -> SymbolicValue | None:
    cloned_enhanced = _clone_enhanced_object(getattr(obj, "_enhanced_object", None))
    if cloned_enhanced is None:
        return None
    cloned_obj = copy.copy(obj)
    cloned_obj.attach_enhanced_object(cloned_enhanced)
    return cloned_obj


def _replace_identity_references(state: VMState, old: object, new: StackValue) -> None:
    state.stack = [new if item is old else item for item in state.stack]
    for name, value in list(state.local_vars.items()):
        if value is old:
            state.local_vars[name] = new
    for name, value in list(state.global_vars.items()):
        if value is old:
            state.global_vars[name] = new
    from pysymex.core.state import CallFrame

    new_call_stack: list[CallFrame] = []
    for frame in state.call_stack:
        modified = False
        new_locals = frame.local_vars
        for name, value in list(frame.local_vars.items()):
            if value is old:
                if not modified:
                    new_locals = frame.local_vars.cow_fork()
                    modified = True
                new_locals[name] = new
        new_init_instance = frame.init_instance
        if frame.init_instance is old:
            new_init_instance = new
            modified = True

        if modified:
            new_frame = CallFrame(
                function_name=frame.function_name,
                return_pc=frame.return_pc,
                local_vars=new_locals,
                stack_depth=frame.stack_depth,
                caller_instructions=frame.caller_instructions,
                summary_builder=frame.summary_builder,
                is_init_call=frame.is_init_call,
                init_instance=new_init_instance,
            )
            new_call_stack.append(new_frame)
        else:
            new_call_stack.append(frame)
    state.call_stack = new_call_stack


def _try_enhanced_class_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Try to handle a call via enhanced OOP class registry.

    If ``func_obj`` matches a registered class in the
    :class:`EnhancedClassRegistry`, create an
    :class:`EnhancedObject` instance and push it onto the stack.
    Returns None if not applicable.
    """
    try:
        from pysymex.core.objects import ObjectState
        from pysymex.core.objects.oop import (
            create_enhanced_instance,
            enhanced_class_registry,
            extract_init_params,
        )

        func_name = (
            getattr(func_obj, "_name", None)
            or getattr(func_obj, "name", None)
            or (func_obj.__name__ if isinstance(func_obj, type) else None)
        )
        if func_name is None:
            return None

        # Only handle real classes or SymbolicValues with affinity_type="type"
        if not isinstance(func_obj, type):
            if (
                not isinstance(func_obj, SymbolicValue)
                or getattr(func_obj, "affinity_type", None) != "type"
            ):
                return None

        class_name = func_name
        if class_name.startswith("module_"):
            return None

        func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)
        if func_code is None and isinstance(func_obj, type):
            init_func = getattr(func_obj, "__init__", None)
            if init_func and hasattr(init_func, "__code__"):
                func_code = init_func.__code__

        if func_code is None:
            enhanced_code = getattr(func_obj, "_enhanced_object", None)
            if isinstance(enhanced_code, types.CodeType):
                func_code = enhanced_code

        enhanced_cls = None
        if func_code is not None:
            enhanced_cls = enhanced_class_registry.get_by_code_object(func_code)
            if enhanced_cls is None:
                enhanced_cls = enhanced_class_registry.register_class(class_name)
                enhanced_class_registry.register_code_object(func_code, enhanced_cls)
                _register_class_body_methods(
                    enhanced_cls, func_obj if isinstance(func_obj, type) else func_code
                )
                if not enhanced_cls.init_params and getattr(func_code, "co_name", "") != class_name:
                    params = extract_init_params(func_code)
                    if params:
                        enhanced_cls.set_init_params(params)
        else:
            enhanced_cls = enhanced_class_registry.get_class(class_name)

        if enhanced_cls is None and isinstance(func_obj, type):
            enhanced_cls = enhanced_class_registry.register_class(class_name)
            _register_class_body_methods(enhanced_cls, func_obj)

        if enhanced_cls is None:
            return None

        obj_state = ObjectState()
        kwargs_obj = cast("dict[str, object]", dict(kwargs))
        instance, constraints = create_enhanced_instance(
            enhanced_cls, obj_state, tuple(args), kwargs_obj, pc=state.pc
        )

        result_val = SymbolicValue(
            _name=f"instance_{class_name}_{state.pc}",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            is_obj=z3.BoolVal(True),
            is_none=z3.BoolVal(False),
            is_path=z3.BoolVal(False),
            affinity_type=class_name,
        )
        result_val.attach_enhanced_object(instance)

        for c in constraints:
            state = state.add_constraint(cast("z3.BoolRef", c))

        # Handle complex __init__ by performing an inter-procedural call
        init_method = enhanced_cls.lookup_method("__init__")
        if _apply_straight_line_init_assignments(enhanced_cls, instance, args, kwargs):
            state = state.push(result_val)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

        if init_method is not None:
            res = _perform_interprocedural_call(
                state,
                ctx,
                init_method,
                [result_val] + args,
                kwargs,
                is_init=True,
                init_instance=result_val,
            )
            if res:
                return res

        state = state.push(result_val)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    except (ImportError, AttributeError, TypeError, KeyError, z3.Z3Exception):
        return None


def handle_common_call(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle function calls, applying models if available."""
    argc = int(instr.argval) if instr.argval else 0
    _require_stack_depth(state, instr, argc + 1, "CALL arguments plus callable")

    args: list[StackValue] = []
    for _ in range(argc):
        args.append(state.pop())
    if len(args) > 1:
        args.reverse()

    kwargs: dict[str, StackValue] = {}
    kw_names_raw = state.pending_kw_names
    if kw_names_raw is not None:
        kw_names = _coerce_kw_names(kw_names_raw)
        kw_count = len(kw_names)
        if len(args) >= kw_count:
            kw_vals = args[-kw_count:]
            args = args[:-kw_count]
            kwargs = dict(zip(kw_names, kw_vals, strict=False))
        state.pending_kw_names = None

    _require_stack_depth(state, instr, 1, "callable after argument pop")

    lowerer = CallLowerer(state.pc)
    top_value = state.pop()

    receiver_or_null: StackValue = SymbolicNone()
    if state.stack:
        peeked = state.peek()
        if _is_call_null_marker(peeked) and lowerer.is_likely_callable(top_value):
            state.pop()
            func_obj = top_value
        elif not lowerer.is_likely_callable(top_value):
            receiver_or_null = top_value
            func_obj = state.pop()
        else:
            func_obj = top_value
            receiver_or_null = state.pop()
    else:
        func_obj = top_value

    if func_obj is None:
        if not isinstance(receiver_or_null, SymbolicNone) and receiver_or_null is not None:
            raise VMStateError("CALL stack is malformed: callable slot is NULL")
        return OpcodeResult(new_states=[], issues=[], terminal=True)

    layout = lowerer.resolve_layout(func_obj, receiver_or_null, args, kwargs)

    non_callable_result = _handle_definite_non_callable_call(instr, state, ctx, layout.func_obj)
    if non_callable_result is not None:
        return non_callable_result

    if isinstance(layout.func_obj, SymbolicValue):
        is_none = lowerer.emit_none_check(layout.func_obj)
        handler_pc = ctx.find_exception_handler(instr.offset)
        non_none_constraint = z3.Not(is_none)
        if (
            handler_pc is None
            and _is_uninterpreted_bool_const(is_none)
            and not quick_contradiction_check([*state.path_constraints, non_none_constraint])
        ):
            state = state.add_constraint(non_none_constraint)
            return _dispatch_resolved_call(
                instr, state, ctx, layout.func_obj, layout.args, layout.kwargs
            )
        can_succeed = _path_is_sat([*state.path_constraints, non_none_constraint])
        can_raise = _path_is_sat([*state.path_constraints, is_none])
        if can_raise and not can_succeed:
            if handler_pc is None:
                return OpcodeResult.terminate()
            error_state = state.fork().add_constraint(is_none).set_pc(handler_pc)
            return OpcodeResult.continue_with(error_state)
        if can_raise and handler_pc is not None:
            error_state = state.fork().add_constraint(is_none).set_pc(handler_pc)
            state = state.fork().add_constraint(z3.Not(is_none))
            result = _dispatch_resolved_call(
                instr, state, ctx, layout.func_obj, layout.args, layout.kwargs
            )
            if result.new_states:
                return OpcodeResult.branch(
                    [*result.new_states, error_state], result.issues, result.degraded_passes
                )
            return OpcodeResult.branch([error_state], result.issues, result.degraded_passes)
        if can_raise:
            state = state.add_constraint(z3.Not(is_none))

    return _dispatch_resolved_call(instr, state, ctx, layout.func_obj, layout.args, layout.kwargs)


def _dispatch_resolved_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: StackValue,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult:
    result = _apply_model(state, func_obj, args, kwargs)
    if result:
        return result

    oop_result = _try_enhanced_class_call(state, ctx, func_obj, args, kwargs)
    if oop_result is not None:
        return oop_result

    call_name = (
        getattr(func_obj, "model_name", None)
        or getattr(func_obj, "__name__", None)
        or getattr(func_obj, "_func_name", None)
        or getattr(func_obj, "name", "")
    )

    if ctx.cross_function and hasattr(ctx.cross_function, "function_summary_cache"):
        cross_function = cast("_CrossFunctionProtocol", ctx.cross_function)
        cache = cross_function.function_summary_cache
        path_constraints_snapshot = list(state.path_constraints)
        summary = None
        if (
            len(path_constraints_snapshot) <= _MAX_SUMMARY_CACHE_CONSTRAINTS
            and len(args) <= _MAX_SUMMARY_CACHE_ARGS
        ):
            summary = cache.get(call_name, args, path_constraints_snapshot)
        if isinstance(summary, FunctionSummary):
            z3_args: list[z3.ExprRef] = []
            for arg in args:
                expr = _to_z3_expr(arg)
                if expr is None:
                    z3_args = []
                    break
                z3_args.append(expr)

            z3_kwargs: dict[str, z3.ExprRef] = {}
            if z3_args:
                for key, value in kwargs.items():
                    expr = _to_z3_expr(value)
                    if expr is None:
                        z3_kwargs = {}
                        z3_args = []
                        break
                    z3_kwargs[key] = expr

            if z3_args:
                pre, post, ret_val = instantiate_summary(summary, z3_args, z3_kwargs)
                state = state.add_constraint(pre)
                state = state.add_constraint(post)
                if ret_val is None:
                    state = state.push(SymbolicNone())
                else:
                    state = state.push(SymbolicValue.from_z3(ret_val))
                state = state.advance_pc()
                return OpcodeResult.continue_with(state)

    result = _perform_interprocedural_call(state, ctx, func_obj, args, kwargs)
    if result:
        return result

    ret, tc = HavocValue.havoc(f"havoc_call@{state.pc}")
    state = state.push(ret)
    state = state.add_constraint(tc)
    state = state.advance_pc()

    return OpcodeResult.continue_with(state)


def _dispatch_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult:
    """Shared dispatch logic for CALL, CALL_KW, etc."""

    if isinstance(func_obj, (SymbolicNone, SymbolicValue)):
        import z3

        is_none = Z3_TRUE if isinstance(func_obj, SymbolicNone) else func_obj.is_none
        none_check = [*state.path_constraints, is_none]
        if _path_is_sat(none_check):
            must_be_none = not _path_is_sat([*state.path_constraints, z3.Not(is_none)])
            if must_be_none:
                state = state.add_constraint(z3.Not(is_none))
            state = state.add_constraint(z3.Not(is_none))

    model_name = getattr(func_obj, "model_name", None)
    if model_name:
        res = _apply_model(state, func_obj, args, kwargs)
        if res:
            return res

    result = _perform_interprocedural_call(state, ctx, func_obj, args, kwargs)
    if result:
        return result

    ret, tc = HavocValue.havoc(f"havoc_call@{state.pc}")
    state = state.push(ret)
    state = state.add_constraint(tc)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_method(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load an attribute or method, checking heap memory for attributes."""

    if state.stack:
        obj = state.pop()
    else:
        obj = SymbolicNone()

    if isinstance(obj, SymbolicNone) or obj is None:
        result_val, type_constraint = SymbolicValue.symbolic(f"none_attr_{state.pc}")
        state = state.push(result_val)
        state = state.add_constraint(type_constraint)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    attr_name = str(instr.argval)
    push_null = False
    obj_state: StackValue | None = None
    if instr.opname == "LOAD_METHOD" and instr.arg is not None:
        push_null = True
    elif sys.version_info >= (3, 12) and hasattr(instr, "arg") and instr.arg is not None:
        if instr.arg & 1:
            push_null = True

    if not isinstance(
        obj,
        (
            HavocValue,
            SymbolicObject,
            SymbolicList,
            SymbolicDict,
            SymbolicString,
            SymbolicValue,
            SymbolicNone,
        ),
    ):
        _validate_concrete_attribute_access(attr_name)
        try:
            result_val = getattr(obj, attr_name)
        except AttributeError:
            result_val, type_constraint = SymbolicValue.symbolic(
                f"{type(obj).__name__}_{attr_name}"
            )
            state = state.add_constraint(type_constraint)
        if push_null:
            state = state.push(SymbolicNone())
        state = state.push(_as_stack_value(result_val))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if isinstance(obj, HavocValue):
        havoc_attr_map: dict[str, tuple[HavocValue, z3.BoolRef]] = obj.get_cached_attributes()
        if attr_name in havoc_attr_map:
            havoc_attr, havoc_tc = havoc_attr_map[attr_name]
        else:
            try:
                havoc_attr, havoc_tc = obj.__getattr__(attr_name)
            except AttributeError:
                # Special Python attributes (starting with _) are not allowed on HavocValue
                # Use a havoc value instead to maintain type consistency
                havoc_attr, havoc_tc = HavocValue.havoc(f"{obj._name}.{attr_name}")  # type: ignore[private-usage]  # will be fixed later
            havoc_attr_map[attr_name] = (havoc_attr, havoc_tc)

        if push_null:
            state = state.push(obj)
        state = state.push(havoc_attr)
        state = state.add_constraint(havoc_tc)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    result_val: object = None
    type_name = "unknown"
    if isinstance(obj, SymbolicObject):
        if obj.address != -1:
            obj_state = state.load_heap(obj.address)
            if isinstance(obj_state, SymbolicList):
                type_name = "list"
            elif isinstance(obj_state, SymbolicDict):
                type_name = "dict"
            elif obj_state is None:
                typed_obj_state: dict[str, StackValue] = {}
                obj_state = typed_obj_state
                state = state.store_heap(obj.address, obj_state)
            elif _is_object_map(obj_state):
                _module_found, module_name_obj = _map_get(obj_state, "__module_name__")
                if isinstance(module_name_obj, str) and module_name_obj:
                    type_name = module_name_obj
            if type_name != "unknown":
                model_name = f"{type_name}.{attr_name}"
                if _resolve_model(model_name):
                    res_val, tc = SymbolicValue.symbolic(
                        f"{getattr(obj, 'name', 'obj')}.{attr_name}"
                    )
                    res_val.model_name = model_name
                    state = state.push(res_val)
                    if push_null:
                        state = state.push(obj)
                    state = state.add_constraint(tc)
                    state = state.advance_pc()
                    return OpcodeResult.continue_with(state)

            if _is_object_map(obj_state):
                found_attr, raw_attr_value = _map_get(obj_state, attr_name)
            else:
                found_attr = False
                raw_attr_value = None
            if found_attr:
                result_val = _as_stack_value(_bind_heap_enhanced_method(raw_attr_value, obj))
            else:
                result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
                if _is_object_map(obj_state):
                    _map_set(obj_state, attr_name, result_val)
                    state = state.store_heap(obj.address, _map_to_stack_dict(obj_state))
                state = state.add_constraint(type_constraint)
        else:
            addresses = list(obj.potential_addresses)
            if not addresses:
                result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
                state = state.add_constraint(type_constraint)
            else:
                values: list[tuple[object, object]] = []
                for addr in addresses:
                    mem_obj = state.load_heap(addr)
                    if _is_object_map(mem_obj):
                        found_attr, raw_attr_value = _map_get(mem_obj, attr_name)
                    else:
                        found_attr = False
                        raw_attr_value = None
                    if found_attr:
                        val = _as_stack_value(_bind_heap_enhanced_method(raw_attr_value, obj))
                    else:
                        val, _ = SymbolicValue.symbolic(f"obj_{addr}.{attr_name}")
                        if _is_object_map(mem_obj):
                            _map_set(mem_obj, attr_name, val)
                            state = state.store_heap(addr, _map_to_stack_dict(mem_obj))
                        else:
                            state = state.store_heap(addr, {attr_name: val})
                    values.append((addr, val))
                if len(values) == 1:
                    result_val = values[0][1]
                else:
                    _base_addr, base_val = values[-1]
                    if not isinstance(base_val, SymbolicValue):
                        base_val = SymbolicValue.from_const(base_val)
                    merged_z3_int = base_val.z3_int
                    merged_z3_bool = base_val.z3_bool
                    merged_is_int = base_val.is_int
                    merged_is_bool = base_val.is_bool
                    for addr, val in reversed(values[:-1]):
                        if not isinstance(val, SymbolicValue):
                            val = SymbolicValue.from_const(val)
                        cond = obj.z3_addr == addr
                        merged_z3_int = z3.If(cond, val.z3_int, merged_z3_int)
                        merged_z3_bool = z3.If(cond, val.z3_bool, merged_z3_bool)
                        merged_is_int = z3.If(cond, val.is_int, merged_is_int)
                        merged_is_bool = z3.If(cond, val.is_bool, merged_is_bool)
                    result_val = SymbolicValue(
                        _name=f"{obj.name}.{attr_name}",
                        z3_int=merged_z3_int,
                        is_int=merged_is_int,
                        z3_bool=merged_z3_bool,
                        is_bool=merged_is_bool,
                    )
    elif isinstance(obj, SymbolicList):
        type_name = "list"
    elif isinstance(obj, SymbolicDict):
        type_name = "dict"
    elif isinstance(obj, SymbolicString):
        type_name = "str"
    elif isinstance(obj, SymbolicValue):
        class_attr_value, class_attr_found = _class_level_enhanced_attribute(obj, attr_name)
        if class_attr_found:
            result_val = _as_stack_value(class_attr_value)
        enhanced_obj = getattr(obj, "_enhanced_object", None)
        if (
            result_val is None
            and enhanced_obj is not None
            and hasattr(enhanced_obj, "get_attribute")
        ):
            get_attribute = getattr(enhanced_obj, "get_attribute")
            # Pass 'obj' as bound_instance so EnhancedMethod binds to the SymbolicValue wrapper
            attr_value, found = get_attribute(attr_name, bound_instance=obj)
            if found:
                result_val = _as_stack_value(attr_value)
        # Infer type_name from discriminators if they are concretely True
        object_type = obj.type_tag
        if object_type in {"file", "TextIO", "BinaryIO"}:
            type_name = "file"
        elif z3.is_true(z3.simplify(obj.is_dict)):
            type_name = "dict"
        elif z3.is_true(z3.simplify(obj.is_list)):
            type_name = "list"
        elif z3.is_true(z3.simplify(obj.is_str)):
            type_name = "str"
        elif isinstance(obj.value, set) or getattr(obj, "_type", "") == "set":
            type_name = "set"
    else:
        obj_name = getattr(obj, "name", "") or getattr(obj, "_name", "")
        if "set" in obj_name.lower() or getattr(obj, "_type", "") == "set":
            type_name = "set"

    if type_name != "unknown":
        model_name = f"{type_name}.{attr_name}"
        if _resolve_model(model_name):
            res_val, tc = SymbolicValue.symbolic(f"{getattr(obj, 'name', 'obj')}.{attr_name}")
            res_val.model_name = model_name
            state = state.push(res_val)
            if push_null:
                state = state.push(obj)
            state = state.add_constraint(tc)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
    if isinstance(obj, SymbolicValue):
        none_check: list[z3.BoolRef] = []
        if _can_constrain_receiver_non_none_without_solver(obj):
            state = state.add_constraint(z3.Not(obj.is_none))
        else:
            none_check = [*state.path_constraints, obj.is_none]
            if not _path_is_sat(none_check):
                none_check = []
        if none_check:
            must_be_none = not _path_is_sat([*state.path_constraints, z3.Not(obj.is_none)])
            is_unconstrained_var = (
                z3.is_const(obj.is_none) and obj.is_none.decl().kind() == z3.Z3_OP_UNINTERPRETED
            )

            if must_be_none or not is_unconstrained_var:
                if must_be_none:
                    state = state.add_constraint(z3.Not(obj.is_none))

            state = state.add_constraint(z3.Not(obj.is_none))

    if result_val is None:
        result_val, type_constraint = SymbolicValue.symbolic(
            f"{getattr(obj, 'name', 'obj')}.{attr_name}"
        )
        result_val.model_name = f"{type_name}.{attr_name}"
        if isinstance(obj_state, (dict, CowDict)):
            obj_state[attr_name] = result_val
        state = state.add_constraint(type_constraint)

        import z3 as _z3

        state = state.add_constraint(_z3.Not(result_val.is_none))

    state = state.push(_as_stack_value(result_val))
    if push_null:
        state = state.push(
            _as_stack_value(obj)
            if isinstance(obj, SymbolicObject) or type_name != "unknown"
            else SymbolicNone()
        )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store attribute on object, updating heap memory."""

    if state.stack:
        obj = state.pop()
    else:
        return OpcodeResult.continue_with(state.advance_pc())
    if state.stack:
        value = state.pop()
    else:
        return OpcodeResult.continue_with(state.advance_pc())
    attr_name = str(instr.argval)
    if isinstance(obj, SymbolicObject):
        if obj.address != -1:
            obj_state = state.load_heap(obj.address)
            if obj_state is None:
                state = state.store_heap(obj.address, {attr_name: value})
            elif _is_object_map(obj_state):
                _map_set(obj_state, attr_name, value)
                state = state.store_heap(obj.address, _map_to_stack_dict(obj_state))
    elif isinstance(obj, SymbolicValue):
        cloned_obj = _copy_symbolic_value_with_enhanced_object(obj)
        if cloned_obj is not None:
            enhanced_obj = getattr(cloned_obj, "_enhanced_object", None)
            set_attribute = getattr(enhanced_obj, "set_attribute", None)
            if callable(set_attribute):
                set_attribute(attr_name, value)
                _replace_identity_references(state, obj, cloned_obj)
    elif isinstance(obj, SymbolicNone) or (
        isinstance(obj, SymbolicValue)
        and not _path_is_sat([*state.path_constraints, z3.Not(obj.is_none)])
    ):
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete attribute from object."""
    if state.stack:
        state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_make_function(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Create a function object."""
    code_obj = None
    if state.stack:
        code_obj = state.pop()
    flags = int(instr.argval) if instr.argval else 0
    if flags & 0x01:
        if state.stack:
            state.pop()
    if flags & 0x02:
        if state.stack:
            state.pop()
    annotations = None
    if flags & 0x04:
        if state.stack:
            annotations = state.pop()
    if flags & 0x08:
        if state.stack:
            state.pop()
    func_val = SymbolicValue(
        _name=f"function_{state.pc}",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )
    if isinstance(code_obj, SymbolicValue):
        stored_code_obj = code_obj.value
        if isinstance(stored_code_obj, types.CodeType):
            code_obj = stored_code_obj
    if isinstance(code_obj, types.CodeType):
        func_val.attach_enhanced_object(code_obj)
    if annotations is not None:
        if isinstance(annotations, SymbolicDict):
            func_val.set_annotations(annotations)
        elif _is_object_map(annotations):
            func_val.set_annotations(_map_to_stack_dict(annotations))
    state = state.push(func_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_build_class(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load __build_class__ builtin with enhanced OOP support."""

    try:
        from pysymex.core.objects.oop import enhanced_class_registry

        state.building_class = True
        state.class_registry = enhanced_class_registry
    except (ImportError, AttributeError):
        logger.debug("Enhanced class registry unavailable for LOAD_BUILD_CLASS")
    builtin_val = SymbolicValue(
        _name="__build_class__",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )
    state = state.push(builtin_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_import_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import a module (import x)."""
    _fromlist = state.pop() if state.stack else None
    level_val = state.pop() if state.stack else 0
    level = int(level_val) if isinstance(level_val, (int, float)) else 0

    module_name = str(instr.argval) if instr.argval else ""

    # Handle relative imports
    full_name = module_name
    if level > 0:
        package = state.global_vars.get("__package__")
        if isinstance(package, str) and package:
            parts = package.split(".")
            if level == 1:
                full_name = f"{package}.{module_name}" if module_name else package
            else:
                up = level - 1
                if up < len(parts):
                    base = ".".join(parts[:-up])
                    full_name = f"{base}.{module_name}" if module_name else base
                else:
                    full_name = module_name

    addr = hash(full_name) & 0xFFFFFFFF
    module_val = SymbolicObject(full_name, addr, z3.IntVal(addr), {addr})

    state = state.store_heap(addr, {"__module_name__": full_name})

    state = state.push(module_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_import_from(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import attribute from module (from x import y)."""
    attr_name = str(instr.argval) if instr.argval else "unknown_attr"

    # Module is TOS
    module = state.stack[-1] if state.stack else None

    # Special case: typing.TYPE_CHECKING should be False to reduce noise
    module_name = getattr(module, "_name", "")
    if module_name == "typing" and attr_name == "TYPE_CHECKING":
        state = state.push(False)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    # Try to resolve from module if it's a SymbolicObject
    res_val: StackValue = None
    if isinstance(module, SymbolicObject):
        if module.address != -1:
            obj_state = state.load_heap(module.address)
            if _is_object_map(obj_state):
                found, raw_val = _map_get(obj_state, attr_name)
                if found:
                    res_val = _as_stack_value(raw_val)

    if res_val is None:
        # Fallback to symbolic value but make it an Object to avoid 'None' callable issues
        id_suffix = hash(f"import_{attr_name}_{state.pc}") & 0xFFFF
        import_name = f"import_{attr_name}"
        z3_addr = z3.Int(f"{import_name}_{id_suffix}_addr")
        res_val = SymbolicObject(
            _name=import_name, address=id_suffix, z3_addr=z3_addr, potential_addresses={id_suffix}
        )
        res_val.model_name = attr_name

        # Ensure it's not None
        state = state.add_constraint(z3_addr != 0)

    state = state.push(res_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_super_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load attribute from super() (Python 3.12+)."""
    for _ in range(3):
        if state.stack:
            state.pop()
    attr_name = str(instr.argval) if instr.argval else "unknown"
    attr_val, constraint = SymbolicValue.symbolic(f"super_{attr_name}")
    state = state.push(attr_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_super_variants(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load method/attribute from super() variants (Python 3.12+)."""
    if state.stack:
        state.pop()
    if state.stack:
        state.pop()
    attr_name = str(instr.argval) if instr.argval else "unknown"
    method_val, constraint = SymbolicValue.symbolic(f"super_method_{attr_name}")
    state = state.push(method_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_call_function_ex(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle CALL_FUNCTION_EX (Python 3.11+)."""
    has_kwargs = False
    if instr.arg is not None:
        has_kwargs = (instr.arg & 1) == 1

    required_items = 3 if has_kwargs else 2
    if len(state.stack) < required_items:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    empty_kwargs: dict[str, StackValue] = {}
    kwargs_val: StackValue = state.pop() if has_kwargs else empty_kwargs
    args_val = state.pop()
    func_obj = state.pop()

    args = [args_val]
    kwargs: dict[str, StackValue] = {}
    if isinstance(kwargs_val, SymbolicDict):
        kwargs = {"**kwargs": kwargs_val}
    elif _is_object_map(kwargs_val):
        for key, value in kwargs_val.items():
            if isinstance(key, str):
                kwargs[key] = _as_stack_value(value)

    return _dispatch_call(instr, state, ctx, func_obj, args, kwargs)


def handle_common_call_intrinsic_2(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle CALL_INTRINSIC_2 (Python 3.12+)."""
    _ = state.pop()
    _ = state.pop()

    val, type_constraint = SymbolicValue.symbolic(f"intrinsic2_{state.pc}")
    state = state.add_constraint(type_constraint)
    state = state.push(val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_set_function_attribute(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    if len(state.stack) < 2:
        return OpcodeResult.continue_with(state.advance_pc())
    state.pop()
    func_obj = state.pop()
    state = state.push(func_obj)
    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_precall(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle PRECALL (Python 3.11)."""
    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_kw_names(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle KW_NAMES (Python 3.11+)."""
    state.pending_kw_names = instr.argval
    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_import_star(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle IMPORT_STAR."""
    if state.stack:
        state.pop()
    return OpcodeResult.continue_with(state.advance_pc())
