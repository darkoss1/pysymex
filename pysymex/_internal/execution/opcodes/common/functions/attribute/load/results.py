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

"""Shared result builders for ``LOAD_ATTR`` and ``LOAD_METHOD``."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.exceptions.policy import attribute_error
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.path_strings import (
    PATH_STRING_PREFIXES,
    PATH_STRING_STRING_PROPERTIES,
)
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow
from pysymex._internal.core.types.containers.sequence_precision import (
    PATH_SUFFIXES_SEQUENCE_KIND,
)

if TYPE_CHECKING:
    import dis

    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def modeled_attribute_carrier(name: str) -> SymbolicValue:
    """Return a definite model-call token without scalar type-tag constraints."""
    return SymbolicValue(
        _name=name,
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_obj=Z3_TRUE,
        is_none=Z3_FALSE,
    )


def load_path_string_attribute(
    obj: SymbolicString,
    attr_name: str,
) -> tuple[StackValue, z3.BoolRef] | None:
    """Build bounded pathlib property values for modeled path-like strings."""
    if not obj.name.startswith(PATH_STRING_PREFIXES):
        return None
    if attr_name == "suffixes":
        suffixes, constraint = SymbolicList.symbolic(f"{obj.name}.suffixes", element_type="str")
        suffixes.set_derived_sequence(PATH_SUFFIXES_SEQUENCE_KIND, obj.z3_str)
        return suffixes, constraint
    if attr_name in PATH_STRING_STRING_PROPERTIES:
        return SymbolicString.symbolic(f"{obj.name}.{attr_name}")
    return None


def attribute_error_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    message: str,
) -> OpcodeResult:
    """Jump to an ``AttributeError`` handler or emit a definite attribute-error issue."""
    exc = AttributeError(message)
    modeled_exc = attribute_error(str(exc), state=state, instr=instr)
    handler_state = ExceptionFlow.jump_to_handler(state, ctx, instr.offset, modeled_exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    issue = Issue(
        kind=IssueKind.ATTRIBUTE_ERROR,
        message=f"Possible AttributeError: {exc}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def none_attribute_error_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    attr_name: str,
) -> OpcodeResult:
    """Route missing ``None`` attributes through handlers or emit a null-deref issue."""
    exc = AttributeError(f"'NoneType' object has no attribute '{attr_name}'")
    modeled_exc = attribute_error(str(exc), state=state, instr=instr)
    handler_state = ExceptionFlow.jump_to_handler(state, ctx, instr.offset, modeled_exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    issue = Issue(
        kind=IssueKind.NULL_DEREFERENCE,
        message=f"Attribute access '{attr_name}' on None",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)
