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

"""Terminal-oriented builtin call models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult

from ..core.helpers import type_error_side_effect

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue


class SystemExitCallModel(FunctionModel):
    """Shared behavior for callables whose successful call raises SystemExit."""

    source = "exit"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) > 1 or kwargs:
            result, constraint = SymbolicValue.symbolic(f"{self.name}_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    self.source, f"{self.name}() accepts at most one argument"
                ),
            )

        status: StackValue | None = args[0] if args else None
        if isinstance(status, SymbolicValue):
            message = f"SymbolicExitStatus({status.name})"
        else:
            message = "" if status is None else str(status)

        result, constraint = SymbolicValue.symbolic(f"{self.name}_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={
                "raised_exception": {
                    "issue_kind": "RUNTIME_ERROR",
                    "exception_type": "SystemExit",
                    "message": message,
                    "source": self.source,
                }
            },
        )


class ExitModel(SystemExitCallModel):
    """Model for interactive builtin exit()."""

    name = "exit"
    qualname = "builtins.exit"
    source = "exit"


class QuitModel(SystemExitCallModel):
    """Model for interactive builtin quit()."""

    name = "quit"
    qualname = "builtins.quit"
    source = "quit"
