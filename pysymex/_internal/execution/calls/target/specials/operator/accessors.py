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

"""Operator accessor callable adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.typing.protocols import StackValue


def dispatch_operator_accessor_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Lower modeled ``operator.itemgetter`` and ``operator.attrgetter`` callables."""
    from pysymex._internal.models.stdlib.operator.models import (
        AttrGetterCallable,
        ItemGetterCallable,
    )

    if isinstance(func_obj, ItemGetterCallable) and len(args) == 1 and not kwargs:
        from pysymex._internal.execution.opcodes.common.collections.read.handler import (
            handle_common_binary_subscr,
        )

        subscript_state = state.push(args[0]).push(func_obj.index)
        return handle_common_binary_subscr(
            instr,
            subscript_state,
            ctx,
            report_mixed_list_error=True,
        )

    if isinstance(func_obj, AttrGetterCallable) and len(args) == 1 and not kwargs:
        from pysymex._internal.execution.opcodes.common.functions.attribute.load.handler import (
            handle_common_load_method,
        )

        load_instr = instr._replace(opname="LOAD_ATTR", arg=0, argval=func_obj.attr_name)
        return handle_common_load_method(load_instr, state.push(args[0]), ctx)

    return None
