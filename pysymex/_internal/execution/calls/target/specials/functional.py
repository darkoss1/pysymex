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

"""Transparent stdlib functional-call adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def dispatch_supported_suppress_call(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Apply supported ``contextlib.suppress`` calls as direct model results."""
    from pysymex._internal.models.stdlib.contextlib.stubs import apply_supported_suppress_call

    suppress_result = apply_supported_suppress_call(func_obj, list(args), dict(kwargs))
    if suppress_result is None:
        return None

    state = state.push(cast("StackValue", suppress_result)).advance_pc()
    return OpcodeResult.continue_with(state)


def dispatch_transparent_decorator_call(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Apply transparent decorator calls as direct model results."""
    from pysymex._internal.models.stdlib.functools.core import apply_transparent_decorator_call

    decorator_result = apply_transparent_decorator_call(func_obj, list(args), dict(kwargs))
    if decorator_result is None:
        return None

    state = state.push(cast("StackValue", decorator_result)).advance_pc()
    return OpcodeResult.continue_with(state)
