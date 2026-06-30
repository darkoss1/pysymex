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

"""Bytecode instruction, exception, and line metadata installation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.execution.engine.bytecode.metadata.exceptions import (
    exception_entries_for_execution,
)
from pysymex._internal.execution.engine.bytecode.metadata.lines import build_line_mapping

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import CodeType

    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.session.state.core import ExecutionSession


def prepare_bytecode_execution(
    *,
    session: ExecutionSession,
    dispatcher: OpcodeDispatcher,
    code: CodeType,
    bytecode_source: Callable[..., object] | CodeType,
) -> None:
    """Install bytecode, exception, and line metadata for the active run."""
    session.instructions = list(get_instructions(code))
    dispatcher.set_instructions(session.instructions)
    entries = exception_entries_for_execution(bytecode_source, code)
    dispatcher.set_exception_entries(list(entries))
    build_line_mapping(session=session, code=code)
