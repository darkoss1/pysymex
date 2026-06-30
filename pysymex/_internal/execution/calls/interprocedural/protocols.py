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

"""Coroutine and generator handoff for interprocedural targets."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import types

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.typing.protocols import StackValue


def maybe_create_protocol_callable(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    func_code: types.CodeType,
    *,
    protocol_method: str | None,
) -> OpcodeResult | None:
    """Create coroutine or generator objects before normal callee-frame entry."""
    if func_code.co_flags & inspect.CO_COROUTINE:
        from pysymex._internal.execution.opcodes.common.coroutines.dispatch import (
            create_coroutine_call,
        )
        from pysymex._internal.execution.opcodes.common.coroutines.objects import (
            COROUTINE_RESUME_PROTOCOL,
        )

        if protocol_method != COROUTINE_RESUME_PROTOCOL:
            return create_coroutine_call(state, func_obj, args, kwargs)

    if func_code.co_flags & inspect.CO_GENERATOR and protocol_method != "__generator_resume__":
        from pysymex._internal.execution.opcodes.common.generators.lifecycle import (
            create_generator_call,
        )

        return create_generator_call(state, func_obj, args, kwargs)
    return None
