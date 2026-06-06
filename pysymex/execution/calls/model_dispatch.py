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

"""Call target model dispatch, callability checks, and modeled invocation.

Consumes resolved call targets from opcode stack lowering, routes builtins and user functions,
and surfaces definite ``TypeError`` paths. Primary consumer of
:mod:`pysymex.execution.calls.interprocedural`.
"""

from __future__ import annotations

import builtins
import dis
from collections.abc import Callable
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.detectors.feasibility import hard_theory_witness_model
from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.effects.locations import item_write_location
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.solver.engine.policies import path_may_be_feasible
from pysymex.core.solver.engine.queries import check_sat_result
from pysymex.core.state.types import VMStateError
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.detectors.suppression import issue_is_caught_by_exception_handler
from pysymex.execution.model_effects import issues_from_model_side_effects
from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler
from pysymex.execution.opcodes.common.exceptions.type_errors import type_error_result
from pysymex.execution.calls.helpers import as_mapping, as_stack_value
from pysymex.execution.opcodes.common.path_feasibility import path_is_sat as path_is_sat
from pysymex.models.builtins import get_default_model_registry
from pysymex.models.builtins.registry import RegisteredModel, RegisteredResult
from pysymex.models.builtins.results import (
    is_potential_exception_effect,
    is_potential_exception_effect_sequence,
    is_raised_exception_effect,
)
from pysymex.models.stdlib import get_stdlib_model
from pysymex.sandbox.errors import SecurityViolationError

_BLOCKED_CONCRETE_ATTR_NAMES: frozenset[str] = frozenset(
    {
        "__subclasses__",
        "__bases__",
        "__mro__",
        "__globals__",
        "__builtins__",
        "__loader__",
        "__spec__",
        "__code__",
        "__closure__",
        "__func__",
        "__self__",
        "__wrapped__",
        "__getattribute__",
        "__reduce__",
        "__reduce_ex__",
        "__traceback__",
        "tb_frame",
        "f_globals",
        "f_locals",
        "f_code",
        "f_builtins",
        "f_back",
        "gi_frame",
        "gi_code",
        "cr_frame",
        "cr_code",
        "ag_frame",
        "ag_code",
    }
)
_ISSUE_KIND_BY_EXCEPTION_TYPE: dict[str, IssueKind] = {
    "AttributeError": IssueKind.ATTRIBUTE_ERROR,
    "IndexError": IssueKind.INDEX_ERROR,
    "KeyError": IssueKind.KEY_ERROR,
    "OverflowError": IssueKind.OVERFLOW,
    "TypeError": IssueKind.TYPE_ERROR,
    "ValueError": IssueKind.VALUE_ERROR,
    "ZeroDivisionError": IssueKind.DIVISION_BY_ZERO,
}

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def reportable_issue_path_is_sat(constraints: list[z3.BoolRef]) -> bool:
    """Require definite satisfiability before emitting model-side-effect issues."""
    if hard_theory_witness_model(constraints) is not None:
        return True
    return check_sat_result(constraints).is_sat


def is_uninterpreted_bool_const(expr: z3.BoolRef) -> bool:
    """Return whether *expr* is an uninterpreted Z3 boolean constant."""
    try:
        return z3.is_const(expr) and expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
    except z3.Z3Exception:
        return False


def can_constrain_receiver_non_none_without_solver(obj: SymbolicValue) -> bool:
    """Return whether LOAD_ATTR can take the non-None continuation without SMT."""
    if z3.is_false(obj.is_none) or z3.is_true(obj.is_none):
        return True
    return is_uninterpreted_bool_const(obj.is_none)


def definite_non_callable_type_name(value: object) -> str | None:
    """Return a CPython type name when *value* is definitely not callable."""
    if isinstance(value, SymbolicNone):
        return "NoneType"
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


def handle_definite_non_callable_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
) -> OpcodeResult | None:
    """Route provably non-callable callees to ``TypeError`` handlers or definite issues.

    Returns ``None`` when callability is unknown. When the type is definite and no
    handler exists, emits a feasible-path ``TYPE_ERROR`` issue instead of continuing.
    """
    type_name = definite_non_callable_type_name(func_obj)
    if type_name is None:
        return None

    message = f"'{type_name}' object is not callable"
    return type_error_result(state, ctx, instr.offset, message)


MAX_SUMMARY_CACHE_CONSTRAINTS = 24
MAX_SUMMARY_CACHE_ARGS = 12
MAX_CALLABILITY_CHECK_CONSTRAINTS = 64


def require_stack_depth(
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


def validate_concrete_attribute_access(attr_name: str) -> None:
    """Reject introspection attribute names on concrete VM objects."""
    if attr_name in _BLOCKED_CONCRETE_ATTR_NAMES:
        raise SecurityViolationError(
            "attribute access",
            f"attribute '{attr_name}' is blocked for concrete objects",
        )


def is_call_null_marker(value: object) -> bool:
    """Return whether a stack slot is the CALL-method null placeholder."""
    return value is None or isinstance(value, SymbolicNone)


def resolve_model(model_name: str) -> RegisteredModel | None:
    """Resolve a model by name across all registries."""
    model = get_default_model_registry().get(model_name) or get_stdlib_model(model_name)
    if model:
        return model

    from pysymex.models.stdlib.collections import get_collections_model
    from pysymex.models.stdlib.functools import get_functools_model
    from pysymex.models.stdlib.itertools import get_itertools_model
    from pysymex.models.concurrency.threading.registry import get_threading_model

    lookup: Callable[..., object]
    for lookup in (
        get_threading_model,
        get_collections_model,
        get_itertools_model,
        get_functools_model,
    ):
        result: object = lookup(model_name)
        if result is not None:
            return cast("RegisteredModel | None", result)
    return None


def apply_model(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
    ctx: OpcodeDispatcher | None = None,
    instr: dis.Instruction | None = None,
) -> OpcodeResult | None:
    """Apply a built-in or stdlib model if available."""
    kwargs = kwargs or {}
    from pysymex.execution.opcodes.common.generators import try_resume_generator_call

    generator_result = try_resume_generator_call(state, func_obj, args, kwargs, ctx, instr)
    if generator_result is not None:
        return generator_result
    model_name = func_obj if isinstance(func_obj, str) else getattr(func_obj, "model_name", None)
    func_name = getattr(func_obj, "_name", "") or getattr(func_obj, "name", "")
    from pysymex.execution.opcodes.common.functions.protocol.builtins import (
        dispatch_modeled_protocol_builtin,
    )

    protocol_result = dispatch_modeled_protocol_builtin(
        state, func_obj, model_name, args, kwargs, ctx
    )
    if protocol_result is not None:
        return protocol_result
    if func_name == "__build_class__":
        from pysymex.execution.opcodes.common.functions.classes import apply_build_class_model

        return apply_build_class_model(state, args, kwargs)
    if model_name is None and isinstance(func_name, str) and func_name.endswith(".close"):
        model_name = func_name
    if isinstance(model_name, str) and model_name.endswith(".close"):
        state = state.push(SymbolicNone())
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    if model_name:
        model = resolve_model(model_name)
        if not model:
            return None

            # Check if model has apply method (some models may be plain functions)
        if not hasattr(model, "apply"):
            return None

        result = model.apply(args, kwargs, state)
    else:
        direct_result = get_default_model_registry().apply(func_obj, args, kwargs, state)
        if direct_result is not None:
            result = direct_result
        else:
            module_name = getattr(func_obj, "__module__", None)
            func_name_attr = getattr(func_obj, "__name__", None)
            if not isinstance(module_name, str) or not isinstance(func_name_attr, str):
                return None
            if module_name.split(".", 1)[0] not in {
                "ast",
                "functools",
                "_functools",
                "operator",
                "_operator",
                "os",
                "pathlib",
                "heapq",
                "_heapq",
                "bisect",
                "_bisect",
                "itertools",
                "math",
            }:
                return None
            model = resolve_model(f"{module_name}.{func_name_attr}") or resolve_model(
                func_name_attr
            )
            if model is None or not hasattr(model, "apply"):
                return None
            result = model.apply(args, kwargs, state)

    exception_branch = _branch_on_caught_raised_exception(state, ctx, instr, result)
    if exception_branch is None:
        exception_branch = _branch_on_caught_potential_exception(state, ctx, instr, result)
    if exception_branch is not None:
        return exception_branch

    generated_issues: list[Issue] = []
    if result.side_effects:
        generated_issues.extend(
            issues_from_model_side_effects(
                result.side_effects,
                state.pc,
                path_constraints=list(state.path_constraints),
                path_may_be_feasible=reportable_issue_path_is_sat,
                last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
            )
        )
        if "list_mutation" in result.side_effects:
            mut = as_mapping(result.side_effects["list_mutation"])
            if mut is None:
                mut = {}
            orig_lst = mut.get("original_list")
            updated_lst = mut.get("updated_list")
            if orig_lst is not None and updated_lst is not None:
                write_target = args[0] if args else orig_lst
                state = _record_modeled_item_write(state, write_target, mut.get("operation"))
                from pysymex.execution.opcodes.common.functions.classes import (
                    propagate_list_mutation_reference,
                )

                state = propagate_list_mutation_reference(
                    state, orig_lst, as_stack_value(updated_lst)
                )

        if "dict_mutation" in result.side_effects:
            mut = as_mapping(result.side_effects["dict_mutation"])
            if mut is None:
                mut = {}
            orig_dict = mut.get("original_dict")
            updated_dict = mut.get("updated_dict")
            if orig_dict is not None and updated_dict is not None:
                write_target = args[0] if args else orig_dict
                state = _record_modeled_item_write(state, write_target, mut.get("operation"))
                from pysymex.execution.opcodes.common.functions.classes import (
                    propagate_container_mutation_reference,
                )

                updated_stack_val = as_stack_value(updated_dict)
                state = propagate_container_mutation_reference(state, orig_dict, updated_stack_val)

        if "iterator_mutation" in result.side_effects:
            mut = as_mapping(result.side_effects["iterator_mutation"])
            if mut is None:
                mut = {}
            original_iterator = mut.get("original_iterator")
            updated_iterator = mut.get("updated_iterator")
            if original_iterator is not None and updated_iterator is not None:
                write_target = args[0] if args else original_iterator
                state = _record_modeled_item_write(state, write_target, mut.get("operation"))
                from pysymex.execution.opcodes.common.functions.classes import (
                    propagate_container_mutation_reference,
                )

                state = propagate_container_mutation_reference(
                    state,
                    original_iterator,
                    as_stack_value(updated_iterator),
                )
        source_mutations = result.side_effects.get("iterator_source_mutations")
        if isinstance(source_mutations, list):
            for source_mutation in cast("list[object]", source_mutations):
                mut = as_mapping(source_mutation)
                if mut is None:
                    continue
                original_iterator = mut.get("original_iterator")
                updated_iterator = mut.get("updated_iterator")
                if original_iterator is None or updated_iterator is None:
                    continue
                from pysymex.execution.opcodes.common.functions.classes import (
                    propagate_container_mutation_reference,
                )

                state = propagate_container_mutation_reference(
                    state,
                    original_iterator,
                    as_stack_value(updated_iterator),
                )

    state = state.push(result.value)
    for constraint in result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    state = state.advance_pc()
    return OpcodeResult(new_states=[state], issues=generated_issues)


def _record_modeled_item_write(state: VMState, target: object, operation: object) -> VMState:
    """Record an effect-ledger write for a modeled mutating container method."""
    location = item_write_location(state, target)
    source = f"model.{operation}" if isinstance(operation, str) and operation else "model.mutation"
    return state.record_write_event(
        WriteEvent(WriteKind.ITEM, location.name, state.pc, location.precise, source)
    )


def _branch_on_caught_raised_exception(
    state: VMState,
    ctx: OpcodeDispatcher | None,
    instr: dis.Instruction | None,
    result: RegisteredResult,
) -> OpcodeResult | None:
    """Enter an exception handler for definite modeled exceptions when one exists."""
    if ctx is None or instr is None or not result.side_effects:
        return None
    effect = result.side_effects.get("raised_exception")
    if not is_raised_exception_effect(effect):
        return None
    if not _raised_model_exception_is_caught(state, ctx, instr, effect):
        return None

    handler_state = jump_to_exception_handler(
        state.fork(),
        ctx,
        instr.offset,
        SymbolicException(
            exc_type=_modeled_exception_type(effect["exception_type"]),
            message=effect["message"],
            raised_at=state.pc,
        ),
    )
    if handler_state is None or not path_may_be_feasible(list(state.path_constraints)):
        return None
    return OpcodeResult.continue_with(handler_state)


def _raised_model_exception_is_caught(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    effect: object,
) -> bool:
    """Return whether a definite model-raised exception is caught at the call site."""
    if not is_raised_exception_effect(effect):
        return False
    issue_kind = IssueKind.__members__.get(effect["issue_kind"], IssueKind.RUNTIME_ERROR)
    probe_issue = Issue(
        kind=issue_kind,
        message=f"Path raises unhandled exception: {effect['exception_type']}",
        pc=state.pc,
    )
    return issue_is_caught_by_exception_handler(ctx, probe_issue, instr, state)


def _modeled_exception_type(name: str) -> type[BaseException] | str:
    """Resolve builtin model exception names to concrete CPython exception classes."""
    candidate = getattr(builtins, name, None)
    if isinstance(candidate, type) and issubclass(candidate, BaseException):
        return candidate
    return name


def _branch_on_caught_potential_exception(
    state: VMState,
    ctx: OpcodeDispatcher | None,
    instr: dis.Instruction | None,
    result: RegisteredResult,
) -> OpcodeResult | None:
    """Fork success and handler paths for modeled potential-exception side effects."""
    if ctx is None or instr is None or not result.side_effects:
        return None

    effects: list[object] = []
    single_effect = result.side_effects.get("potential_exception")
    if is_potential_exception_effect(single_effect):
        effects.append(single_effect)
    effect_sequence = result.side_effects.get("potential_exceptions")
    if is_potential_exception_effect_sequence(effect_sequence):
        effects.extend(effect_sequence)

    branches: list[VMState] = []
    caught_conditions: list[z3.BoolRef] = []
    uncaught_effects: list[object] = []
    for effect in effects:
        if not is_potential_exception_effect(effect):
            continue
        condition = effect["condition"]
        if not path_may_be_feasible([*state.path_constraints, condition]):
            continue

        if _potential_model_exception_is_caught(state, ctx, instr, effect):
            handler_state = jump_to_exception_handler(
                state.fork().add_constraint(condition),
                ctx,
                instr.offset,
                SymbolicException(
                    exc_type=effect["type"],
                    message=effect["message"],
                    raised_at=state.pc,
                    condition=condition,
                ),
            )
            if handler_state is not None:
                branches.append(handler_state)
                caught_conditions.append(condition)
                continue

        uncaught_effects.append(effect)

    if not branches:
        return None

    success_condition = _none_of(caught_conditions)
    if path_may_be_feasible([*state.path_constraints, success_condition]):
        success_state = _push_model_success(
            state.fork().add_constraint(success_condition),
            result,
        )
        branches.insert(0, success_state)

    issues = _issues_from_uncaught_potential_effects(
        state,
        uncaught_effects,
        success_condition,
    )
    return OpcodeResult.branch(branches, issues)


def _potential_model_exception_is_caught(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    effect: object,
) -> bool:
    """Return whether a conditional model exception is caught at the call site."""
    if not is_potential_exception_effect(effect):
        return False
    issue_kind = _ISSUE_KIND_BY_EXCEPTION_TYPE.get(effect["type"], IssueKind.UNHANDLED_EXCEPTION)
    probe_issue = Issue(
        kind=issue_kind,
        message=f"Path raises unhandled exception: {effect['type']}",
        pc=state.pc,
    )
    return issue_is_caught_by_exception_handler(ctx, probe_issue, instr, state)


def _none_of(conditions: list[z3.BoolRef]) -> z3.BoolRef:
    """Return a condition that excludes every condition in *conditions*."""
    if len(conditions) == 1:
        return z3.Not(conditions[0])
    return z3.Not(z3.Or(*conditions))


def _issues_from_uncaught_potential_effects(
    state: VMState,
    effects: list[object],
    success_condition: z3.BoolRef,
) -> list[Issue]:
    """Publish uncaught modeled exceptions left over after handler branching."""
    adjusted_effects: list[dict[str, object]] = []
    for effect in effects:
        if not is_potential_exception_effect(effect):
            continue
        adjusted_effects.append(
            {
                "type": effect["type"],
                "message": effect["message"],
                "condition": z3.And(effect["condition"], success_condition),
            }
        )
    if not adjusted_effects:
        return []
    return issues_from_model_side_effects(
        {"potential_exceptions": adjusted_effects},
        state.pc,
        path_constraints=list(state.path_constraints),
        path_may_be_feasible=reportable_issue_path_is_sat,
        last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
    )


def _push_model_success(state: VMState, result: RegisteredResult) -> VMState:
    """Push a modeled return value and advance past the calling opcode."""
    state = state.push(result.value)
    for constraint in result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return state.advance_pc()
