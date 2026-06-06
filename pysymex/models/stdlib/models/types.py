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

"""Symbolic models for types."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.identity.addressing import next_address
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class SimpleNamespaceModel(FunctionModel):
    """Model for types.SimpleNamespace()."""

    name = "SimpleNamespace"
    qualname = "types.SimpleNamespace"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        addr = next_address()
        result, constraint = SymbolicObject.symbolic(f"namespace_{state.pc}", addr)
        obj_state = {}
        if kwargs:
            for k, v in kwargs.items():
                obj_state[k] = v
        state.memory[addr] = obj_state
        return ModelResult(value=result, constraints=[constraint])


types_models = [
    SimpleNamespaceModel(),
]


__all__ = ["SimpleNamespaceModel", "types_models"]
