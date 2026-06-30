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

"""Handler registry operations for opcode dispatch."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.dispatcher.types import OpcodeHandler
    from pysymex._internal.execution.dispatch.result import OpcodeResult


def handler_decorator(
    handlers: dict[str, OpcodeHandler],
    opcodes: tuple[str, ...],
) -> Callable[[OpcodeHandler], OpcodeHandler]:
    """Return a decorator that writes opcodes into *handlers*."""

    def decorator(handler: OpcodeHandler) -> OpcodeHandler:
        for opcode in opcodes:
            handlers[opcode] = handler
        return handler

    return decorator


def register_handler(
    handlers: dict[str, OpcodeHandler],
    opcode: str,
    handler: OpcodeHandler,
) -> None:
    """Register one opcode handler in *handlers*."""
    handlers[opcode] = handler


def dispatch_registered_handler(
    local_handlers: dict[str, OpcodeHandler],
    global_handlers: dict[str, OpcodeHandler],
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Invoke the registered local or global handler for one instruction."""
    handler = local_handlers.get(instr.opname)
    if handler is None:
        handler = global_handlers.get(instr.opname)
    if handler is None:
        msg = f"Opcode not supported: {instr.opname}"
        raise RuntimeError(msg)
    return handler(instr, state, ctx)


def has_registered_handler(
    local_handlers: dict[str, OpcodeHandler],
    global_handlers: dict[str, OpcodeHandler],
    opcode: str,
) -> bool:
    """Return whether an opcode has a local or global handler."""
    return opcode in local_handlers or opcode in global_handlers


def registered_opcode_names(
    local_handlers: dict[str, OpcodeHandler],
    global_handlers: dict[str, OpcodeHandler],
) -> set[str]:
    """Return local and global registered opcode names."""
    return set(local_handlers.keys()) | set(global_handlers.keys())


def global_handler_module(
    global_handlers: dict[str, OpcodeHandler],
    opcode: str,
) -> str | None:
    """Return the module name for a global opcode handler."""
    handler = global_handlers.get(opcode)
    if handler is None:
        return None
    return handler.__module__


def clear_handlers(
    handlers: dict[str, OpcodeHandler],
    module_prefixes: tuple[str, ...] | None = None,
) -> None:
    """Clear all handlers, or only handlers whose defining module matches a prefix."""
    if module_prefixes is None:
        handlers.clear()
        return
    for opcode, handler in tuple(handlers.items()):
        if handler.__module__.startswith(module_prefixes):
            del handlers[opcode]
