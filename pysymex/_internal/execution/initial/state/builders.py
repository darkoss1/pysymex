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

import inspect
from typing import TYPE_CHECKING, cast, get_type_hints

from pysymex._internal.core.builtins import get_all_builtins
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.calls.default.materialization.objects import (
    realize_named_default_objects,
)
from pysymex._internal.execution.calls.default.materialization.values import (
    as_named_default_stack_values,
)
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
from pysymex._internal.execution.initial.state.constraints import (
    assume_non_null_self,
    constrain_initial_value,
    supports_scalar_initial_constraint,
)
from pysymex._internal.execution.initial.state.contracts import inject_initial_obligations
from pysymex._internal.execution.initial.state.factory.core import SymbolicInputFactory
from pysymex._internal.execution.initial.state.hints import hint_to_type_str
from pysymex._internal.execution.initial.state.receivers import (
    bind_bound_receiver,
    bound_receiver_local_name,
    bound_receiver_object,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.typing.protocols import StackValue

logger = get_logger(__name__)
_NO_INITIAL_VALUE = object()


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
            raw_hints_obj = getattr(func, "__annotations__", {})
            if isinstance(raw_hints_obj, dict):
                raw_hints = cast("dict[str, object]", raw_hints_obj)
                for param, hint in raw_hints.items():
                    if param in params:
                        inferred_types[param] = hint_to_type_str(hint)

    bound_receiver_name = bound_receiver_local_name(func, params)
    bound_receiver = bound_receiver_object(func)
    if bound_receiver_name is not None and bound_receiver is not None:
        state = bind_bound_receiver(state, bound_receiver_name, bound_receiver)

    omitted_defaults: dict[str, object] = {}
    for name in params:
        param = parameters.get(name)
        if param is None:
            continue
        if initial_values is not None and name in initial_values:
            continue
        if name in symbolic_args:
            continue
        if param.default is inspect.Parameter.empty:
            continue
        if param.kind not in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            continue
        omitted_defaults[name] = param.default
    default_stack_values = as_named_default_stack_values(omitted_defaults)
    state, default_stack_values = realize_named_default_objects(
        state,
        omitted_defaults,
        default_stack_values,
    )

    for name in params:
        param = parameters.get(name)
        param_kind = param.kind if param is not None else inspect.Parameter.POSITIONAL_OR_KEYWORD
        initial_value: object = _NO_INITIAL_VALUE
        if initial_values is not None and name in initial_values:
            initial_value = initial_values[name]
        has_initial_value = initial_value is not _NO_INITIAL_VALUE
        if has_initial_value and not supports_scalar_initial_constraint(initial_value):
            state = state.set_local(name, coerce_call_stack_value(initial_value))
            continue

        if (
            not has_initial_value
            and name not in symbolic_args
            and name in default_stack_values
            and param_kind
            in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            )
        ):
            state = state.set_local(name, default_stack_values[name])
            continue

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
    return inject_initial_obligations(state, func, config=config, session=session)
