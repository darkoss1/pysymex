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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Formatting opcode handlers for Python 3.13.

Python 3.13 f-string formatting uses:

- CONVERT_VALUE
- FORMAT_SIMPLE
- FORMAT_WITH_SPEC

FORMAT_VALUE is intentionally not implemented here because it is a legacy
opcode from older Python versions.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.types import (
    AdvancedSymbolicFloat,
    SymbolicFloat,
    SymbolicString,
    SymbolicValue,
)
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


_SYMBOLIC_TYPES = (
    SymbolicValue,
    SymbolicString,
    SymbolicFloat,
    AdvancedSymbolicFloat,
)


def _make_issue(
    state: VMState,
    kind: IssueKind,
    message: str,
) -> Issue:
    return Issue(
        kind=kind,
        message=message,
        pc=state.pc,
        constraints=list(state.path_constraints),
    )


def _runtime_error(state: VMState, message: str) -> OpcodeResult:
    return OpcodeResult.error(
        _make_issue(
            state=state,
            kind=IssueKind.RUNTIME_ERROR,
            message=message,
        )
    )


def _type_error(state: VMState, message: str) -> OpcodeResult:
    return OpcodeResult.error(
        _make_issue(
            state=state,
            kind=IssueKind.TYPE_ERROR,
            message=message,
        )
    )


def _is_symbolic(value: object) -> bool:
    return isinstance(value, _SYMBOLIC_TYPES)


def _push_symbolic_string(state: VMState, name: str) -> OpcodeResult:
    result, constraint = SymbolicString.symbolic(name)
    state = state.add_constraint(constraint)
    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())


@opcode_handler("CONVERT_VALUE")
def handle_convert_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """CONVERT_VALUE - Apply f-string conversion.

    Operand:

    - 1: str(value)
    - 2: repr(value)
    - 3: ascii(value)
    """
    _ = ctx

    value = state.pop()
    conversion = instr.arg if instr.arg is not None else 0

    if conversion not in (1, 2, 3):
        return _runtime_error(
            state,
            f"Invalid CONVERT_VALUE operand: {conversion!r}",
        )

    if _is_symbolic(value):
        return _push_symbolic_string(
            state,
            f"converted_{state.pc}_{conversion}",
        )

    try:
        if conversion == 1:
            result = str(value)
        elif conversion == 2:
            result = repr(value)
        else:
            result = ascii(value)
    except Exception as exc:
        return _runtime_error(
            state,
            f"Conversion error: {exc}",
        )

    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())


@opcode_handler("FORMAT_SIMPLE")
def handle_format_simple(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """FORMAT_SIMPLE - Format value with an empty format spec.

    Stack before:

        [..., value]

    Stack after:

        [..., format(value, "")]
    """
    _ = (instr, ctx)

    value = state.pop()

    if _is_symbolic(value):
        return _push_symbolic_string(
            state,
            f"formatted_simple_{state.pc}",
        )

    try:
        formatted = format(value, "")
    except Exception as exc:
        return _runtime_error(
            state,
            f"Formatting error: {exc}",
        )

    state = state.push(formatted)
    return OpcodeResult.continue_with(state.advance_pc())


@opcode_handler("FORMAT_WITH_SPEC")
def handle_format_with_spec(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """FORMAT_WITH_SPEC - Format value using a format spec.

    Stack before:

        [..., value, spec]

    Stack after:

        [..., format(value, spec)]
    """
    _ = (instr, ctx)

    spec = state.pop()
    value = state.pop()

    if _is_symbolic(value) or _is_symbolic(spec):
        return _push_symbolic_string(
            state,
            f"formatted_spec_{state.pc}",
        )

    if not isinstance(spec, str):
        return _type_error(
            state,
            "FORMAT_WITH_SPEC format spec must be str",
        )

    try:
        formatted = format(value, spec)
    except Exception as exc:
        return _runtime_error(
            state,
            f"Formatting error: {exc}",
        )

    state = state.push(formatted)
    return OpcodeResult.continue_with(state.advance_pc())
