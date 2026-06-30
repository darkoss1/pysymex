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

"""Function entrypoint local/global seeding for symbolic execution."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.calls.default.materialization.objects import (
    realize_named_default_objects,
)
from pysymex._internal.execution.calls.default.materialization.values import as_named_stack_value
from pysymex._internal.execution.entrypoint.globals.callables import CallableGlobals
from pysymex._internal.execution.entrypoint.globals.containers import EntrypointContainerGlobals
from pysymex._internal.execution.entrypoint.globals.contracts import ContractGlobals
from pysymex._internal.execution.entrypoint.globals.instances import InstanceGlobals
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import CodeType

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

logger = get_logger(__name__)


def seed_function_execution_context(
    *,
    initial_state: VMState,
    func: Callable[..., object],
    code: CodeType,
) -> VMState:
    """Bind closure cells and same-module globals before function exploration."""
    try:
        closure = getattr(func, "__closure__", None)
        freevars = list(getattr(code, "co_freevars", ()))
        if closure and freevars:
            closure_values: dict[str, object] = {}
            for fv_name, cell in zip(freevars, closure, strict=False):
                try:
                    closure_values[fv_name] = cell.cell_contents
                except ValueError:
                    continue
            converted_closure_values = {
                name: _closure_cell_stack_value(name, value)
                for name, value in closure_values.items()
            }
            initial_state, converted_closure_values = realize_named_default_objects(
                initial_state,
                closure_values,
                converted_closure_values,
            )
            for fv_name, value in converted_closure_values.items():
                initial_state = initial_state.set_local(fv_name, value)
    except (AttributeError, TypeError):
        logger.debug("Closure cell binding skipped", exc_info=True)

    try:
        module_vars: dict[str, StackValue] = {}
        for g_name, g_val in CallableGlobals.select(func).items():
            module_vars[g_name] = cast("StackValue", g_val)
        instance_globals = InstanceGlobals.select(func, code)
        prefixed_instance_globals = {
            f"global.{name}": value for name, value in instance_globals.items()
        }
        converted_instances = {
            name: cast("StackValue", value) for name, value in prefixed_instance_globals.items()
        }
        initial_state, converted_instances = realize_named_default_objects(
            initial_state,
            prefixed_instance_globals,
            converted_instances,
        )
        for g_name in instance_globals:
            module_vars[g_name] = converted_instances[f"global.{g_name}"]
        for g_name, g_val in EntrypointContainerGlobals.select(func, code).items():
            module_vars[g_name] = as_named_stack_value(g_name, g_val)
        for g_name, g_val in ContractGlobals.select(func, code).items():
            module_vars[g_name] = cast("StackValue", g_val)
        if module_vars:
            for g_name, g_val in module_vars.items():
                initial_state.global_vars[g_name] = g_val
    except (AttributeError, TypeError):
        logger.debug("Module global seeding skipped", exc_info=True)
    return initial_state


def _closure_cell_stack_value(name: str, value: object) -> StackValue:
    """Return the VM carrier for a Python closure cell value."""
    if isinstance(value, list):
        return as_named_stack_value(name, cast("list[object]", value))
    if isinstance(value, dict):
        return as_named_stack_value(name, cast("dict[object, object]", value))
    if isinstance(value, set):
        return as_named_stack_value(name, cast("set[object]", value))
    return cast("StackValue", value)
