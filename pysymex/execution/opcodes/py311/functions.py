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

"""Function call opcodes."""

from __future__ import annotations

import dis
import logging
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Protocol, TypeGuard, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.summaries import FunctionSummary, SummaryBuilder, instantiate_summary
from pysymex.core.cache import get_instructions as _cached_get_instructions
from pysymex.core.memory.cow import CowDict
from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.core.state import wrap_cow_dict
from pysymex.core.types.containers import SymbolicDict, SymbolicList, SymbolicObject
from pysymex.core.types.havoc import HavocValue
from pysymex.core.types.scalars import (
    Z3_TRUE,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler
from pysymex.models.builtins import FunctionModel, default_model_registry
from pysymex.models.stdlib import get_stdlib_model

logger = logging.getLogger(__name__)

_MAX_SUMMARY_CACHE_CONSTRAINTS = 24
_MAX_SUMMARY_CACHE_ARGS = 12
_MAX_CALLABILITY_CHECK_CONSTRAINTS = 64


def _resolve_model(model_name: str) -> FunctionModel | None:
    """Resolve a model by name across all registries."""
    model = default_model_registry.get(model_name) or get_stdlib_model(model_name)
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
    if isinstance(
        value,
        (
            SymbolicValue,
            SymbolicNone,
            SymbolicString,
            SymbolicList,
            SymbolicDict,
            SymbolicObject,
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


def _map_get(value: _ObjectMapProtocol, key: str) -> tuple[bool, object | None]:
    """Read a mapping entry while preserving existence vs ``None`` values."""
    if key in value:
        return True, value[key]
    return False, None


def _map_set(value: _ObjectMapProtocol, key: str, item: StackValue) -> None:
    """Store a value in a mapping-like object."""
    value[key] = item


def _map_to_stack_dict(value: _ObjectMapProtocol) -> dict[str, StackValue]:
    """Convert a mutable mapping-like object to ``dict[str, StackValue]``."""
    return {k: _as_stack_value(v) for k, v in value.items() if isinstance(k, str)}


@opcode_handler("PRECALL")
def handle_precall(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle setup before a function call."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _apply_model(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
) -> OpcodeResult | None:
    """Apply a built-in or stdlib model if available."""
    kwargs = kwargs or {}
    model_name = func_obj if isinstance(func_obj, str) else getattr(func_obj, "model_name", None)
    if not model_name:
        return None

    model = _resolve_model(model_name)
    if not model:
        return None

    result = model.apply(args, kwargs, state)
    opcode_res = OpcodeResult.continue_with(state)

    if result.side_effects:
        if "potential_exception" in result.side_effects:
            exc = _as_mapping(result.side_effects["potential_exception"])
            if exc is None:
                exc = {}

            cond = exc.get("condition")
            full_cond = list(state.path_constraints)
            if isinstance(cond, z3.BoolRef):
                full_cond.append(cond)
            if is_satisfiable(full_cond):
                kind = IssueKind.TYPE_ERROR
                exc_type = str(exc.get("type", "TypeError"))
                if exc_type == "KeyError":
                    kind = IssueKind.KEY_ERROR
                elif exc_type == "IndexError":
                    kind = IssueKind.INDEX_ERROR
                elif exc_type == "ValueError":
                    kind = IssueKind.VALUE_ERROR

                opcode_res.issues.append(
                    Issue(
                        kind=kind,
                        message=str(exc.get("message", "Modeled call raised an exception")),
                        constraints=full_cond,
                        model=get_model(full_cond),
                        pc=state.pc,
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
                        state.memory[addr] = updated_stack_val
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
                        state.memory[addr] = updated_stack_val
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
    return opcode_res


def _perform_interprocedural_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
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
    func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)

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

    if func_code is None:
        return None
    try:
        callee_instructions = _cached_get_instructions(func_code)
    except (TypeError, ValueError):
        return None

    arg_count = func_code.co_argcount
    pos_arg_names = func_code.co_varnames[:arg_count]

    builder = None
    if ctx.cross_function and hasattr(ctx.cross_function, "function_summary_cache"):
        builder = SummaryBuilder(func_name)
        builder.set_qualname(func_name)
        builder.set_initial_args(cast("list[object]", list(args)))
        for name in pos_arg_names:
            builder.add_parameter(name)

    frame = CallFrame(
        function_name=func_name,
        return_pc=state.pc + 1,
        local_vars=state.local_vars.cow_fork(),
        stack_depth=len(state.stack),
        caller_instructions=state.current_instructions,
        summary_builder=builder,
    )
    state = state.push_call(frame)

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
        logger.debug("Closure inspection failed for %s", func_name)

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
        unused_kwargs = {k: v for k, v in kwargs.items() if k not in pos_arg_names}
        new_locals[kwarg_name] = unused_kwargs

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


def _try_enhanced_class_call(
    state: VMState, func_obj: object, args: list[StackValue], kwargs: dict[str, StackValue]
) -> OpcodeResult | None:
    """Try to handle a call via enhanced OOP class registry.

    If ``func_obj`` matches a registered class in the
    :class:`EnhancedClassRegistry`, create an
    :class:`EnhancedObject` instance and push it onto the stack.
    Returns ``None`` if not applicable.
    """
    try:
        from pysymex.core.objects import ObjectState
        from pysymex.core.objects.oop import (
            create_enhanced_instance,
            enhanced_class_registry,
            extract_init_params,
        )

        func_name = getattr(func_obj, "_name", None) or getattr(func_obj, "name", None)
        if func_name is None:
            return None

        class_name = func_name
        if class_name.startswith("module_"):
            return None

        enhanced_cls = enhanced_class_registry.get_class(class_name)
        if enhanced_cls is None:
            func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)
            if func_code is not None:
                code_id = id(func_code)
                enhanced_cls = enhanced_class_registry.get_by_code(code_id)
                if enhanced_cls is None:
                    enhanced_cls = enhanced_class_registry.register_class(class_name)
                    enhanced_class_registry.register_by_code(code_id, enhanced_cls)
                    params = extract_init_params(func_code)
                    if params:
                        enhanced_cls.set_init_params(params)

        if enhanced_cls is None:
            return None

        obj_state = ObjectState()
        kwargs_obj = cast("dict[str, object]", dict(kwargs))
        instance, constraints = create_enhanced_instance(
            enhanced_cls, obj_state, tuple(args), kwargs_obj, pc=state.pc
        )

        result_val, type_constraint = SymbolicValue.symbolic(f"instance_{class_name}_{state.pc}")

        object.__setattr__(result_val, "_enhanced_object", instance)
        state = state.push(result_val)
        state = state.add_constraint(type_constraint)
        for c in constraints:
            state = state.add_constraint(cast("z3.BoolRef", c))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    except (ImportError, AttributeError, TypeError, KeyError, z3.Z3Exception):
        return None


@opcode_handler("CALL", "CALL_FUNCTION_EX")
def handle_call(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle function calls, applying models if available."""
    argc = int(instr.argval) if instr.argval else 0
    args: list[StackValue] = []
    for _ in range(argc):
        if state.stack:
            args.append(state.pop())
    if len(args) > 1:
        args.reverse()

    kwargs: dict[str, StackValue] = {}
    kw_names = getattr(state, "pending_kw_names", None)
    if kw_names is not None and isinstance(kw_names, (tuple, list)):
        if len(args) >= len(kw_names):  # type: ignore[arg-type]  # will be fixed later
            kw_vals = args[-len(kw_names) :]  # type: ignore[arg-type]  # will be fixed later
            args = args[: -len(kw_names)]  # type: ignore[arg-type]  # will be fixed later
            kwargs = dict(zip(kw_names, kw_vals, strict=False))  # type: ignore[arg-type]  # will be fixed later
        state.pending_kw_names = None

    receiver_or_null = state.pop() if state.stack else SymbolicNone()

    if state.stack:
        func_obj = state.pop()
    else:
        func_obj = receiver_or_null
        receiver_or_null = SymbolicNone()

    if not isinstance(receiver_or_null, SymbolicNone):
        args.insert(0, receiver_or_null)

    if isinstance(func_obj, (SymbolicNone, SymbolicValue)):
        is_none = Z3_TRUE if isinstance(func_obj, SymbolicNone) else func_obj.is_none
        simplified_none = z3.simplify(is_none)
        if z3.is_true(simplified_none):
            none_check = [*state.path_constraints, is_none]
            issue = Issue(
                kind=IssueKind.TYPE_ERROR,
                message=f"Possible TypeError: object '{getattr(func_obj, 'name', 'obj')}' is not callable (is None)",
                constraints=list(none_check),
                model=get_model(none_check),
                pc=state.pc,
            )
            return OpcodeResult.error(issue, state=state)

        if not z3.is_false(simplified_none):
            if len(state.path_constraints) <= _MAX_CALLABILITY_CHECK_CONSTRAINTS:
                none_check = [*state.path_constraints, is_none]
                if is_satisfiable(none_check):
                    must_be_none = not is_satisfiable([*state.path_constraints, z3.Not(is_none)])
                    is_unconstrained_var = (
                        z3.is_const(is_none) and is_none.decl().kind() == z3.Z3_OP_UNINTERPRETED
                    )

                    if must_be_none or not is_unconstrained_var:
                        issue = Issue(
                            kind=IssueKind.TYPE_ERROR,
                            message=f"Possible TypeError: object '{getattr(func_obj, 'name', 'obj')}' is not callable (is None)",
                            constraints=list(none_check),
                            model=get_model(none_check),
                            pc=state.pc,
                        )

                        if must_be_none:
                            return OpcodeResult.error(issue, state=state)

                    state = state.add_constraint(z3.Not(is_none))
            else:
                state = state.add_constraint(z3.Not(is_none))

    call_name = (
        getattr(func_obj, "model_name", None)
        or getattr(func_obj, "__name__", None)
        or getattr(func_obj, "_func_name", None)
        or getattr(func_obj, "name", "")
    )

    result = _apply_model(state, func_obj, args, kwargs)
    if result:
        return result

    oop_result = _try_enhanced_class_call(state, func_obj, args, kwargs)
    if oop_result is not None:
        return oop_result

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

    result = _perform_interprocedural_call(state, ctx, func_obj, args)
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
    from pysymex.analysis.detectors import Issue, IssueKind
    from pysymex.core.solver.engine import get_model, is_satisfiable

    if isinstance(func_obj, (SymbolicNone, SymbolicValue)):
        import z3

        is_none = Z3_TRUE if isinstance(func_obj, SymbolicNone) else func_obj.is_none
        none_check = [*state.path_constraints, is_none]
        if is_satisfiable(none_check):
            must_be_none = not is_satisfiable([*state.path_constraints, z3.Not(is_none)])
            if must_be_none:
                issue = Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message="Possible TypeError: object is not callable (is None)",
                    constraints=list(none_check),
                    model=get_model(none_check),
                    pc=state.pc,
                )
                return OpcodeResult.error(issue, state=state)
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


@opcode_handler("LOAD_METHOD", "LOAD_ATTR")
def handle_load_method(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load an attribute or method, checking heap memory for attributes."""

    if state.stack:
        obj = state.pop()
    else:
        obj = SymbolicNone()

    if isinstance(obj, SymbolicNone):
        issue = Issue(
            kind=IssueKind.NULL_DEREFERENCE,
            message=f"Definite None dereference: access '{instr.argval}' on None",
            constraints=list(state.path_constraints),
            model=get_model(state.path_constraints),
            pc=state.pc,
        )
        return OpcodeResult(new_states=[], issues=[issue], terminal=True)
    attr_name = str(instr.argval)
    push_null = False
    obj_state: StackValue | None = None
    if hasattr(instr, "arg") and instr.arg is not None:
        if instr.arg & 1:
            push_null = True

    if isinstance(obj, HavocValue):
        havoc_attr_map = obj.get_cached_attributes()
        if attr_name in havoc_attr_map:
            havoc_attr, havoc_tc = havoc_attr_map[attr_name]
        else:
            havoc_attr, havoc_tc = obj.__getattr__(attr_name)
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
            obj_state = state.memory.get(obj.address)
            if isinstance(obj_state, SymbolicList):
                type_name = "list"
            elif isinstance(obj_state, SymbolicDict):
                type_name = "dict"
            elif obj_state is None:
                typed_obj_state: dict[str, StackValue] = {}
                obj_state = typed_obj_state
                state.memory[obj.address] = obj_state
            elif _is_object_map(obj_state):
                _module_found, module_name = _map_get(obj_state, "__module_name__")
                if isinstance(module_name, str) and module_name:
                    type_name = module_name

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
                result_val = _as_stack_value(raw_attr_value)
            else:
                result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
                if _is_object_map(obj_state):
                    _map_set(obj_state, attr_name, result_val)
                    state.memory[obj.address] = _map_to_stack_dict(obj_state)
                state = state.add_constraint(type_constraint)
        else:
            addresses = list(obj.potential_addresses)
            if not addresses:
                result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
                state = state.add_constraint(type_constraint)
            else:
                values: list[tuple[object, object]] = []
                for addr in addresses:
                    mem_obj = state.memory.get(addr)
                    if _is_object_map(mem_obj):
                        found_attr, raw_attr_value = _map_get(mem_obj, attr_name)
                    else:
                        found_attr = False
                        raw_attr_value = None
                    if found_attr:
                        val = _as_stack_value(raw_attr_value)
                    else:
                        val, _ = SymbolicValue.symbolic(f"obj_{addr}.{attr_name}")
                        if _is_object_map(mem_obj):
                            _map_set(mem_obj, attr_name, val)
                            state.memory[addr] = _map_to_stack_dict(mem_obj)
                        else:
                            state.memory[addr] = {attr_name: val}
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
        none_check = [*state.path_constraints, obj.is_none]
        if is_satisfiable(none_check):
            must_be_none = not is_satisfiable([*state.path_constraints, z3.Not(obj.is_none)])
            is_unconstrained_var = (
                z3.is_const(obj.is_none) and obj.is_none.decl().kind() == z3.Z3_OP_UNINTERPRETED
            )

            if must_be_none or not is_unconstrained_var:
                issue = Issue(
                    kind=IssueKind.NULL_DEREFERENCE,
                    message=f"Possible None dereference: access '{attr_name}' on {obj.name}",
                    constraints=list(none_check),
                    model=get_model(none_check),
                    pc=state.pc,
                )

                if must_be_none:
                    return OpcodeResult(new_states=[], issues=[issue], terminal=True)

            state = state.add_constraint(z3.Not(obj.is_none))

    if result_val is None:
        res_type = type(obj_state).__name__ if obj_state is not None else "unknown"
        if obj_state is not None and not isinstance(obj_state, (dict, CowDict)):
            issue = Issue(
                kind=IssueKind.ATTRIBUTE_ERROR,
                message=f"AttributeError: '{res_type}' object has no attribute '{attr_name}'",
                constraints=list(state.path_constraints),
                model=get_model(state.path_constraints),
                pc=state.pc,
            )

            return OpcodeResult(new_states=[], issues=[issue], terminal=True)

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


@opcode_handler("STORE_ATTR")
def handle_store_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store attribute on object, updating heap memory."""

    if state.stack:
        obj = state.pop()
    else:
        return OpcodeResult.error(
            Issue(IssueKind.RUNTIME_ERROR, "Stack underflow", [], None, state.pc)
        )
    if state.stack:
        value = state.pop()
    else:
        return OpcodeResult.error(
            Issue(IssueKind.RUNTIME_ERROR, "Stack underflow", [], None, state.pc)
        )
    attr_name = str(instr.argval)
    if isinstance(obj, SymbolicObject):
        if obj.address != -1:
            obj_state = state.memory.get(obj.address)
            if obj_state is None:
                state.memory[obj.address] = {attr_name: value}
            elif _is_object_map(obj_state):
                _map_set(obj_state, attr_name, value)
                state.memory[obj.address] = _map_to_stack_dict(obj_state)
            else:
                issue = Issue(
                    kind=IssueKind.ATTRIBUTE_ERROR,
                    message=f"AttributeError: object has no attribute '{attr_name}'",
                    constraints=list(state.path_constraints),
                    model=get_model(state.path_constraints),
                    pc=state.pc,
                )
                return OpcodeResult.error(issue, state=state)
    elif isinstance(obj, SymbolicNone) or (
        isinstance(obj, SymbolicValue)
        and not is_satisfiable([*state.path_constraints, z3.Not(obj.is_none)])
    ):
        issue = Issue(
            kind=IssueKind.NULL_DEREFERENCE,
            message=f"Definite None dereference: store '{attr_name}' on None",
            constraints=list(state.path_constraints),
            model=get_model(state.path_constraints),
            pc=state.pc,
        )
        return OpcodeResult(new_states=[], issues=[issue], terminal=True)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_ATTR")
def handle_delete_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete attribute from object."""
    if state.stack:
        state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("MAKE_FUNCTION")
def handle_make_function(
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
    if flags & 0x04:
        if state.stack:
            state.pop()
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
    if code_obj is not None:
        object.__setattr__(func_val, "_enhanced_object", code_obj)
    state = state.push(func_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_BUILD_CLASS")
def handle_load_build_class(
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


@opcode_handler("KW_NAMES")
def handle_kw_names(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Set up keyword argument names for next CALL (Python 3.11+)."""
    state.pending_kw_names = instr.argval
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("IMPORT_NAME")
def handle_import_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import a module (import x)."""
    if state.stack:
        state.pop()
    if state.stack:
        state.pop()
    module_name = str(instr.argval) if instr.argval else "unknown_module"

    addr = hash(module_name) & 0xFFFFFFFF
    module_val = SymbolicObject(module_name, addr, z3.IntVal(addr), {addr})

    memory_map = cast("dict[int, object]", state.memory)
    memory_map[addr] = {"__module_name__": module_name}

    state = state.push(module_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("IMPORT_FROM")
def handle_import_from(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import attribute from module (from x import y)."""
    attr_name = str(instr.argval) if instr.argval else "unknown_attr"
    attr_val, type_constraint = SymbolicValue.symbolic(f"import_{attr_name}")
    attr_val.model_name = attr_name

    state = state.add_constraint(z3.Not(attr_val.is_none))

    state = state.push(attr_val)
    state = state.add_constraint(type_constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("IMPORT_STAR")
def handle_import_star(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import all from module (from x import *)."""
    if state.stack:
        state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CALL_FUNCTION_EX")
def handle_call_function_ex(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle CALL_FUNCTION_EX (Python 3.11+)."""
    has_kwargs = False
    if instr.arg is not None:
        has_kwargs = (instr.arg & 1) == 1

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
