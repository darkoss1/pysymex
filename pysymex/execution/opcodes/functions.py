"""Function call opcodes."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import dis
from collections.abc import Callable
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.summaries import SummaryBuilder, instantiate_summary
from pysymex.core.havoc import HavocValue, union_taint
from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions
from pysymex.core.solver import get_model, is_satisfiable
from pysymex.core.types import (
    Z3_TRUE,
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicObject,
    SymbolicString,
    SymbolicValue,
)
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler
from pysymex.models.builtins import FunctionModel, default_model_registry
from pysymex.models.stdlib import get_stdlib_model


def _resolve_model(model_name: str) -> FunctionModel | None:
    """Resolve a model by name across all registries."""
    model = default_model_registry.get(model_name) or get_stdlib_model(model_name)
    if model:
        return model

    from pysymex.models.collections_models import get_collections_model
    from pysymex.models.functools_models import get_functools_model
    from pysymex.models.itertools_models import get_itertools_model
    from pysymex.models.threading_models import get_threading_model

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


@opcode_handler("PRECALL")
def handle_precall(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle setup before a function call."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _check_taint_sinks(state: VMState, call_name: str, args: list[StackValue]) -> list[Issue]:
    """Check if tainted data flows to dangerous sinks."""
    issues: list[Issue] = []
    if not call_name or not hasattr(state, "taint_tracker") or state.taint_tracker is None:
        return issues

    from pysymex.analysis.taint import TaintSink, TaintTracker

    sink_type = TaintTracker.SINK_FUNCTIONS.get(call_name)
    if sink_type is None:
        return issues

    _SINK_TO_ISSUE = {
        TaintSink.SQL_QUERY: IssueKind.SQL_INJECTION,
        TaintSink.COMMAND_EXEC: IssueKind.COMMAND_INJECTION,
        TaintSink.EVAL: IssueKind.CODE_INJECTION,
        TaintSink.FILE_PATH: IssueKind.PATH_TRAVERSAL,
        TaintSink.FILE_WRITE: IssueKind.PATH_TRAVERSAL,
        TaintSink.NETWORK_SEND: IssueKind.UNHANDLED_EXCEPTION,
        TaintSink.LOG_OUTPUT: IssueKind.FORMAT_STRING_INJECTION,
    }

    flows = state.taint_tracker.check_sink(
        sink_type,
        *args,
        location=call_name,
        line=state.pc,
    )
    if flows:
        issue_kind = _SINK_TO_ISSUE.get(sink_type, IssueKind.UNHANDLED_EXCEPTION)
        issues.append(
            Issue(
                kind=issue_kind,
                message=f"Tainted data flows to dangerous sink '{call_name}' ({sink_type.name})",
                constraints=list(state.path_constraints),
                model=get_model(list(state.path_constraints)),
                pc=state.pc,
            )
        )
    return issues


def _apply_model(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
) -> OpcodeResult | None:
    """Apply a built-in or stdlib model if available."""
    kwargs = kwargs or {}
    model_name = getattr(func_obj, "model_name", None)
    if not model_name:
        return None

    model = _resolve_model(model_name)
    if not model:
        return None

    result = model.apply(args, kwargs, state)
    opcode_res = OpcodeResult.continue_with(state)

    if result.side_effects and "potential_exception" in result.side_effects:
        exc = result.side_effects["potential_exception"]
        cond = exc.get("condition")
        full_cond = list(state.path_constraints)
        if cond is not None:
            full_cond.append(cond)
        if is_satisfiable(full_cond):
            kind = IssueKind.TYPE_ERROR
            if exc["type"] == "KeyError":
                kind = IssueKind.KEY_ERROR
            elif exc["type"] == "IndexError":
                kind = IssueKind.INDEX_ERROR

            opcode_res.issues.append(
                Issue(
                    kind=kind,
                    message=exc["message"],
                    constraints=full_cond,
                    model=get_model(full_cond),
                    pc=state.pc,
                )
            )

    state = state.push(result.value)
    for constraint in result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    state = state.advance_pc()
    return opcode_res


def _perform_interprocedural_call(
    state: VMState, ctx: OpcodeDispatcher, func_obj: object, args: list[StackValue]
) -> OpcodeResult | None:
    """Attempt to perform an inter-procedural call to a user-defined function."""
    MAX_CALL_DEPTH = 10
    from pysymex.core.types import SymbolicValue

    func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)
    func_name = getattr(func_obj, "__name__", None) or getattr(func_obj, "_func_name", "anonymous")

    if func_code is None:
        return None

    try:
        callee_instructions = _cached_get_instructions(func_code)
    except (TypeError, ValueError):
        return None

    arg_count = func_code.co_argcount
    argnames = func_code.co_varnames[:arg_count]

    builder = None
    if ctx.cross_function and hasattr(ctx.cross_function, "function_summary_cache"):
        builder = SummaryBuilder(func_name)
        builder.set_qualname(func_name)
        builder._initial_args = args
        for i, name in enumerate(argnames):
            if i < len(args):
                builder.add_parameter(name)

    from pysymex.core.state import CallFrame

    frame = CallFrame(
        function_name=func_name,
        return_pc=state.pc + 1,
        local_vars=state.local_vars.cow_fork(),
        stack_depth=len(state.stack),
        caller_instructions=state.current_instructions,
        summary_builder=builder,
    )
    state = state.push_call(frame)

    new_locals = {}
    for i, name in enumerate(argnames):
        if i < len(args):
            new_locals[name] = args[i]
        else:
            val, constraint = SymbolicValue.symbolic(f"arg_{name}")
            new_locals[name] = val
            state = state.add_constraint(constraint)

    if func_code.co_flags & 0x04:
        vararg_name = func_code.co_varnames[arg_count]
        extra_args = args[arg_count:] if len(args) > arg_count else []

        z3_array = z3.Array(f"{vararg_name}_{state.pc}_arr", z3.IntSort(), z3.IntSort())

        for idx, val in enumerate(extra_args):
            if hasattr(val, "z3_int"):
                z3_array = z3.Store(z3_array, idx, val.z3_int)
            else:

                sym_val = SymbolicValue.from_const(val)
                z3_array = z3.Store(z3_array, idx, sym_val.z3_int)
        new_locals[vararg_name] = SymbolicList(vararg_name, z3_array, z3.IntVal(len(extra_args)))
        arg_count += 1

    if func_code.co_flags & 0x08:
        kwarg_name = func_code.co_varnames[arg_count]

        new_locals[kwarg_name] = SymbolicDict.empty(kwarg_name)

    from pysymex.core.state import wrap_cow_dict

    state.local_vars = wrap_cow_dict(new_locals)

    state.current_instructions = list(callee_instructions)
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
        from pysymex.core.object_model import ObjectState
        from pysymex.core.oop_support import (
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
        instance, constraints = create_enhanced_instance(
            enhanced_cls, obj_state, tuple(args), kwargs, pc=state.pc
        )

        result_val, type_constraint = SymbolicValue.symbolic(f"instance_{class_name}_{state.pc}")

        result_val._enhanced_object = instance
        state = state.push(result_val)
        state = state.add_constraint(type_constraint)
        for c in constraints:
            state = state.add_constraint(cast("z3.BoolRef", c))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    except (ImportError, AttributeError, TypeError, KeyError, z3.Z3Exception):
        return None


@opcode_handler("CALL", "CALL_FUNCTION", "CALL_FUNCTION_KW", "CALL_FUNCTION_EX")
def handle_call(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle function calls, applying models if available."""
    argc = int(instr.argval) if instr.argval else 0
    args: list[StackValue] = []
    for _ in range(argc):
        if state.stack:
            args.insert(0, state.pop())

    kwargs: dict[str, StackValue] = {}
    kw_names = getattr(state, "pending_kw_names", None)
    if kw_names is not None:
        if len(args) >= len(kw_names):
            kw_vals = args[-len(kw_names) :]
            args = args[: -len(kw_names)]
            kwargs = dict(zip(kw_names, kw_vals, strict=False))
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
        none_check = [*state.path_constraints, is_none]
        if is_satisfiable(none_check):
            issue = Issue(
                kind=IssueKind.TYPE_ERROR,
                message=f"Possible TypeError: object '{getattr(func_obj, 'name', 'obj')}' is not callable (is None)",
                constraints=list(none_check),
                model=get_model(none_check),
                pc=state.pc,
            )

            state.add_constraint(z3.Not(is_none))
            if not is_satisfiable(list(state.path_constraints)):
                return OpcodeResult.error(issue, state=state)

            state._pending_taint_issues.append(issue)

    result = _apply_model(state, func_obj, args, kwargs)
    if result:
        return result

    oop_result = _try_enhanced_class_call(state, func_obj, args, kwargs)
    if oop_result is not None:
        return oop_result

    call_name = (
        getattr(func_obj, "model_name", None)
        or getattr(func_obj, "__name__", None)
        or getattr(func_obj, "_func_name", None)
        or getattr(func_obj, "name", "")
    )
    taint_issues = _check_taint_sinks(state, call_name, args)
    if taint_issues:
        if not hasattr(state, "_pending_taint_issues"):
            state._pending_taint_issues = []
        state._pending_taint_issues.extend(taint_issues)

    if ctx.cross_function and hasattr(ctx.cross_function, "function_summary_cache"):
        cache = ctx.cross_function.function_summary_cache
        summary = cache.get(call_name, args, list(state.path_constraints))
        if summary:
            pre, post, ret_val = instantiate_summary(summary, list(args), kwargs)
            state = state.add_constraint(pre)
            state = state.add_constraint(post)
            state = state.push(ret_val)

            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

    result = _perform_interprocedural_call(state, ctx, func_obj, args)
    if result:
        if hasattr(state, "_pending_taint_issues"):
            result.issues.extend(state._pending_taint_issues)
        return result

    combined_taint = union_taint(args)
    ret, tc = HavocValue.havoc(f"havoc_call@{state.pc}", taint_labels=combined_taint)
    state = state.push(ret)
    state = state.add_constraint(tc)
    state = state.advance_pc()

    result = OpcodeResult.continue_with(state)
    if hasattr(state, "_pending_taint_issues"):
        result.issues.extend(state._pending_taint_issues)
        delattr(state, "_pending_taint_issues")
    return result


@opcode_handler("CALL_KW")
def handle_call_kw(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle function calls with keyword arguments."""
    argc = int(instr.argval) if instr.argval else 0
    args: list[StackValue] = []
    kw_names = None
    if state.stack:
        kw_names = state.pop()
    for _ in range(argc):
        if state.stack:
            args.insert(0, state.pop())
    if state.stack:
        receiver_or_null = state.pop()
    else:
        receiver_or_null = SymbolicNone()
    if state.stack:
        func_obj = state.pop()
    else:
        func_obj = SymbolicNone()
    if not isinstance(receiver_or_null, SymbolicNone):
        args.insert(0, receiver_or_null)
    model_name = getattr(func_obj, "model_name", None)
    model: FunctionModel | None = None
    if model_name:
        model = _resolve_model(model_name)
    if model:
        kw_kwargs: dict[str, StackValue] = {}
        kw_names_val = getattr(kw_names, "value", kw_names)
        if isinstance(kw_names_val, tuple):
            names: tuple[object, ...] = cast("tuple[object, ...]", kw_names_val)
            if len(names) <= len(args):
                kw_vals = args[-len(names) :]
                args = args[: -len(names)]
                for k, v in zip(names, kw_vals, strict=False):
                    kw_kwargs[str(k)] = v
        model_result: object = model.apply(args, kw_kwargs, state)
        state = state.push(model_result.value)
        for constraint in cast("list[object]", model_result.constraints or []):
            state = state.add_constraint(cast("z3.BoolRef", constraint))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    combined_taint = union_taint(args)
    ret, tc = HavocValue.havoc(f"havoc_callkw@{state.pc}", taint_labels=combined_taint)
    state = state.push(ret)
    state = state.add_constraint(tc)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CALL_METHOD")
def handle_call_method(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle method calls."""
    argc = int(instr.argval) if instr.argval else 0
    method_args: list[object] = []
    for _ in range(argc):
        if state.stack:
            method_args.insert(0, state.pop())
    if state.stack:
        self_val = state.pop()
        method_args.insert(0, self_val)
    if state.stack:
        state.pop()
    combined_taint = union_taint(method_args)
    ret, tc = HavocValue.havoc(f"havoc_method@{state.pc}", taint_labels=combined_taint)
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
    if hasattr(instr, "arg") and instr.arg is not None:
        if instr.arg & 1:
            push_null = True

    if isinstance(obj, HavocValue):
        if attr_name in obj._attributes:
            havoc_attr, havoc_tc = obj._attributes[attr_name]
        else:
            obj_taint = getattr(obj, "taint_labels", None)
            havoc_attr, havoc_tc = HavocValue.havoc(
                f"{getattr(obj, 'name', 'havoc')}.{attr_name}",
                taint_labels=obj_taint,
            )
            havoc_attr.model_name = f"havoc.{attr_name}"
            obj._attributes[attr_name] = (havoc_attr, havoc_tc)

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
            if obj_state is None:
                obj_state = {}
                state.memory[obj.address] = obj_state
            if attr_name in obj_state:
                result_val: object = obj_state[attr_name]
            else:
                result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
                obj_state[attr_name] = result_val
                state = state.add_constraint(type_constraint)
        else:
            addresses = list(obj.potential_addresses)
            if not addresses:
                result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
                state = state.add_constraint(type_constraint)
            else:
                values: list[tuple[object, object]] = []
                for addr in addresses:
                    mem = state.memory.get(addr, {})
                    if attr_name in mem:
                        val = mem[attr_name]
                    else:
                        val, _ = SymbolicValue.symbolic(f"obj_{addr}.{attr_name}")
                        mem[attr_name] = val
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
                        cond: object = obj.z3_addr == addr
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
    if isinstance(obj, SymbolicValue):

        none_check = [*state.path_constraints, obj.is_none]
        if is_satisfiable(none_check):

            issue = Issue(
                kind=IssueKind.NULL_DEREFERENCE,
                message=f"Possible None dereference: access '{attr_name}' on {obj.name}",
                constraints=list(none_check),
                model=get_model(none_check),
                pc=state.pc,
            )

            state.add_constraint(z3.Not(obj.is_none))

            if not is_satisfiable(list(state.path_constraints)):
                return OpcodeResult(new_states=[], issues=[issue], terminal=True)

            state._pending_taint_issues.append(issue)

    if result_val is None:
        result_val, type_constraint = SymbolicValue.symbolic(
            f"{getattr(obj, 'name', 'obj')}.{attr_name}"
        )
        result_val.model_name = f"{type_name}.{attr_name}"
        state = state.add_constraint(type_constraint)
    state = state.push(result_val)
    if push_null:
        state.push(
            obj if isinstance(obj, SymbolicObject) or type_name != "unknown" else SymbolicNone()
        )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_ATTR")
def handle_store_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store attribute on object, updating heap memory."""
    if state.stack:
        value = state.pop()
    else:
        return OpcodeResult.error(
            Issue(IssueKind.RUNTIME_ERROR, "Stack underflow", [], None, state.pc)
        )
    if state.stack:
        obj = state.pop()
    else:
        return OpcodeResult.error(
            Issue(IssueKind.RUNTIME_ERROR, "Stack underflow", [], None, state.pc)
        )
    attr_name = str(instr.argval)
    if isinstance(obj, SymbolicObject):
        if obj.address != -1:
            from pysymex.core.state import _wrap_cow_dict

            obj_state = state.memory.get(obj.address)
            if obj_state is None:
                obj_state = _wrap_cow_dict({})
            else:

                obj_state = _wrap_cow_dict(obj_state).cow_fork()

            obj_state[attr_name] = value
            state.memory[obj.address] = obj_state
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
    if state.stack:
        state.pop()
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
    state = state.push(func_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_BUILD_CLASS")
def handle_load_build_class(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load __build_class__ builtin with enhanced OOP support."""

    try:
        from pysymex.core.oop_support import enhanced_class_registry

        state._building_class = True
        state._class_registry = enhanced_class_registry
    except (ImportError, AttributeError):
        pass  # Used as expected type-check or feature fallback
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
    module_val = SymbolicValue(
        _name=f"module_{module_name}",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )
    module_val.model_name = module_name
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


@opcode_handler("LOAD_SUPER_ATTR")
def handle_load_super_attr(
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


@opcode_handler("LOAD_SUPER_METHOD", "LOAD_ZERO_SUPER_ATTR", "LOAD_ZERO_SUPER_METHOD")
def handle_load_super_variants(
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


@opcode_handler("SET_FUNCTION_ATTRIBUTE")
def handle_set_function_attribute(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set function attribute (__name__, __doc__, etc.)."""
    if state.stack:
        state.pop()
    if state.stack:
        func = state.pop()
    else:
        func = SymbolicNone()
    state = state.push(func)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
