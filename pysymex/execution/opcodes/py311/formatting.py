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

"""Formatting opcode handlers for Python 3.11.

Python 3.11 uses FORMAT_VALUE for f-string formatting.

FORMAT_VALUE flags:

- 0x00: no conversion
- 0x01: str(value)
- 0x02: repr(value)
- 0x03: ascii(value)
- 0x04: format spec is present on the stack
.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers)."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.types.advanced_float import AdvancedSymbolicFloat
from pysymex.core.types.numeric.float import SymbolicFloat
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import opcode_handler
from pysymex.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


_SYMBOLIC_TYPES = (
    SymbolicValue,
    SymbolicString,
    SymbolicFloat,
    AdvancedSymbolicFloat,
)

_VALID_FORMAT_VALUE_FLAGS = 0x07


def _make_issue(
    state: VMState,
    kind: IssueKind,
    message: str,
) -> Issue:
    """Build an :class:`Issue` at the current PC with path constraints."""
    return Issue(
        kind=kind,
        message=message,
        pc=state.pc,
        constraints=list(state.path_constraints),
    )


def _runtime_error(state: VMState, message: str) -> OpcodeResult:
    """Return a definite runtime-error opcode result for formatting failures."""
    return OpcodeResult.error(
        _make_issue(
            state=state,
            kind=IssueKind.RUNTIME_ERROR,
            message=message,
        )
    )


def _type_error(state: VMState, message: str) -> OpcodeResult:
    """Return a definite type-error opcode result for invalid format operands."""
    return OpcodeResult.error(
        _make_issue(
            state=state,
            kind=IssueKind.TYPE_ERROR,
            message=message,
        )
    )


def _is_symbolic(value: object) -> bool:
    """Return whether *value* requires symbolic f-string formatting."""
    return isinstance(value, _SYMBOLIC_TYPES)


def _push_symbolic_string(state: VMState, name: str) -> OpcodeResult:
    """Push a fresh symbolic string and advance past the formatting opcode."""
    result, constraint = SymbolicString.symbolic(name)
    state = state.add_constraint(constraint)
    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())


@opcode_handler("FORMAT_VALUE")
def handle_format_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """FORMAT_VALUE - Format a value for an f-string.

    Stack without format spec:

        [..., value]

    Stack with format spec:

        [..., value, spec]

    Stack after:

        [..., formatted_string]
    """
    _ = ctx

    flags = instr.arg if instr.arg is not None else 0

    if flags & ~_VALID_FORMAT_VALUE_FLAGS:
        return _runtime_error(
            state,
            f"Invalid FORMAT_VALUE flags: {flags:#x}",
        )

    has_spec = bool(flags & 0x04)
    conversion = flags & 0x03

    spec_raw = state.pop() if has_spec else ""
    value = state.pop()

    if _is_symbolic(value) or _is_symbolic(spec_raw):
        return _push_symbolic_string(
            state,
            f"formatted_value_{state.pc}_conv_{conversion}_spec_{int(has_spec)}",
        )

    if not isinstance(spec_raw, str):
        return _type_error(
            state,
            "FORMAT_VALUE format spec must be str",
        )

    format_spec: str = spec_raw

    try:
        if conversion == 0x01:
            value = str(value)
        elif conversion == 0x02:
            value = repr(value)
        elif conversion == 0x03:
            value = ascii(value)

        formatted = format(value, format_spec)
    except Exception as exc:
        return _runtime_error(
            state,
            f"Formatting error: {exc}",
        )

    state = state.push(formatted)
    return OpcodeResult.continue_with(state.advance_pc())
