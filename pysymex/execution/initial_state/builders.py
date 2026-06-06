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

"""Build initial VM states for function and code-object execution."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import inspect
import types
from typing import TYPE_CHECKING, cast, get_type_hints

import z3

from pysymex.core.builtins import get_all_builtins
from pysymex.core.memory.cow.collections import CowDict
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.initial_state.factory import SymbolicInputFactory
from pysymex.execution.initial_state.hints import hint_to_type_str
from pysymex.execution.initial_state.types import SymbolicCreatedValue
from pysymex.execution.session.state import ExecutionSession
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.typing import StackValue

__all__ = ["create_code_initial_state", "create_function_initial_state"]

logger = get_logger(__name__)


def create_code_initial_state(
    code: types.CodeType,
    symbolic_vars: Mapping[str, str] | None = None,
    initial_globals: Mapping[str, StackValue] | None = None,
) -> VMState:
    """Build the starting state for ``execute_code`` targets.

    Module/``exec`` code uses a shared root namespace. Symbolic inputs for that
    surface must therefore be visible both to root ``LOAD_NAME`` users and to
    nested functions that resolve the same name through ``LOAD_GLOBAL``. Builtin
    names are seeded into globals so ``LOAD_NAME``/``LOAD_GLOBAL`` can resolve
    concrete builtin functions and exception classes before falling back to
    symbolic unknowns.
    """
    factory = SymbolicInputFactory()
    initial_state = VMState()
    mirror_symbolic_inputs_to_globals = code.co_name == "<module>"
    builtin_globals = {
        name: cast("StackValue", value) for name, value in get_all_builtins().items()
    }
    initial_state.global_vars = CowDict(builtin_globals)
    if initial_globals:
        for name, value in initial_globals.items():
            initial_state.global_vars[name] = value
    symbolic_var_map = dict(symbolic_vars or {})

    argcount = code.co_argcount + code.co_kwonlyargcount
    varargs_name = None
    varkw_name = None
    if code.co_flags & 0x04:
        varargs_name = code.co_varnames[argcount]
        argcount += 1
    if code.co_flags & 0x08:
        varkw_name = code.co_varnames[argcount]
        argcount += 1

    for param in code.co_varnames[:argcount]:
        if param not in symbolic_var_map:
            if param == varargs_name:
                symbolic_var_map[param] = "tuple"
            elif param == varkw_name:
                symbolic_var_map[param] = "dict"
            else:
                symbolic_var_map[param] = "any"

    for name, type_hint in symbolic_var_map.items():
        sym_val, constraint = factory.create_symbolic_for_context_type(
            name, type_hint, initial_globals
        )
        initial_state = initial_state.set_local(name, sym_val)
        if mirror_symbolic_inputs_to_globals:
            initial_state = initial_state.set_global(name, sym_val)
        initial_state = initial_state.add_constraint(constraint)

    return factory.flush_temp_memory(initial_state)


def create_function_initial_state(
    func: Callable[..., object],
    symbolic_args: Mapping[str, str],
    initial_values: Mapping[str, object] | None,
    *,
    config: ExecutionConfig,
    session: ExecutionSession,
) -> VMState:
    """Build the starting state for ``execute_function`` targets."""
    factory = SymbolicInputFactory()
    state = VMState()
    for name, value in get_all_builtins().items():
        state.global_vars[name] = cast("StackValue", value)

    parameters: dict[str, inspect.Parameter] = {}
    try:
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        parameters = dict(sig.parameters)
    except (ValueError, TypeError):
        params = list(func.__code__.co_varnames[: func.__code__.co_argcount])

    inferred_types: dict[str, str] = {}
    if config.use_type_hints:
        try:
            hints = get_type_hints(func)
            for param, hint in hints.items():
                if param in params:
                    inferred_types[param] = hint_to_type_str(hint)
        except (TypeError, NameError, AttributeError, ValueError):
            logger.debug("Type hint extraction failed for %s", func.__name__, exc_info=True)

    for name in params:
        param = parameters.get(name)
        param_kind = param.kind if param is not None else inspect.Parameter.POSITIONAL_OR_KEYWORD
        if param_kind == inspect.Parameter.VAR_POSITIONAL:
            type_hint = "list"
        elif param_kind == inspect.Parameter.VAR_KEYWORD:
            type_hint = "dict"
        else:
            type_hint = symbolic_args.get(name) or inferred_types.get(name, "any")

        sym_val, constraint = factory.create_symbolic_for_type(name, type_hint)
        state = state.set_local(name, sym_val)
        state = state.add_constraint(constraint)

        if config.heuristic_assume_non_null_self:
            state = assume_non_null_self(state, name=name, sym_val=sym_val)

        if initial_values and name in initial_values:
            state = constrain_initial_value(
                state,
                sym_val=sym_val,
                value=initial_values[name],
            )

    state = factory.flush_temp_memory(state)

    if config.enable_contract_verification:
        from pysymex.contracts.runtime.entry import inject_preconditions_initial

        state, contract_issues, post_ok = inject_preconditions_initial(
            state,
            func,
            include_preconditions=config.check_contract_preconditions,
            include_postconditions=config.check_contract_postconditions,
        )
        session.issues.extend(contract_issues)
        from pysymex.contracts.invariants import (
            InvariantCheckPoint,
            check_class_invariants,
            has_invariant_exit_obligations,
        )
        from pysymex.contracts.decorators import get_function_contract
        from pysymex.contracts.types import EffectKind

        if config.check_contract_class_invariants:
            session.issues.extend(check_class_invariants(state, func, InvariantCheckPoint.ENTRY))
            has_invariant_exit = has_invariant_exit_obligations(func)
        else:
            has_invariant_exit = False

        contract = get_function_contract(func)
        has_effect_obligation = bool(
            contract and (contract.assigns_declared or contract.effect_type is EffectKind.PURE)
        )
        should_track_return_obligations = (
            post_ok and (config.check_contract_postconditions or has_effect_obligation)
        ) or has_invariant_exit
        if should_track_return_obligations:
            from pysymex.contracts.binding import runtime_contract_frame

            state.contract_frames.append(
                runtime_contract_frame(
                    func,
                    dict(state.local_vars.items()),
                    state.memory,
                    effect_start_index=len(state.write_events),
                )
            )

    return state


def assume_non_null_self(state: VMState, *, name: str, sym_val: SymbolicCreatedValue) -> VMState:
    """Apply the non-null ``self``/``cls`` heuristic when the carrier supports it."""
    lower_name = name.lower()
    if lower_name not in ("self", "cls") and not lower_name.startswith(("self_", "cls_")):
        return state
    maybe_none_expr = getattr(sym_val, "is_none", None)
    if isinstance(maybe_none_expr, z3.BoolRef):
        return state.add_constraint(z3.Not(maybe_none_expr))
    maybe_addr_expr = getattr(sym_val, "z3_addr", None)
    if isinstance(maybe_addr_expr, z3.ExprRef):
        return state.add_constraint(maybe_addr_expr != 0)
    return state


def constrain_initial_value(
    state: VMState, *, sym_val: SymbolicCreatedValue, value: object
) -> VMState:
    """Constrain a symbolic scalar to a caller-provided concrete initial value."""
    if not isinstance(sym_val, SymbolicValue):
        return state
    if isinstance(value, int) and not isinstance(value, bool):
        return state.add_constraint(sym_val.z3_int == value)
    if isinstance(value, bool):
        return state.add_constraint(sym_val.z3_bool == value)
    return state
