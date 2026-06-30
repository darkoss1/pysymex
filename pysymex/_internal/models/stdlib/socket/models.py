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

"""Network models with explicit external-state degradation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import (
    ModelDegradation,
    ModelResult,
    SideEffects,
    SideEffectValue,
)
from pysymex._internal.models.stdlib.coercion import (
    const_bytes,
    symbolic_int_range,
    symbolic_object,
)

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _network_degradation(operation: str) -> ModelDegradation:
    return ModelDegradation(
        kind="unknown",
        label=operation,
        owner="socket models",
        reason="network peer state and failures are external to symbolic execution",
    )


class SocketConstructorModel(FunctionModel):
    name = "socket"
    qualname = "socket.socket"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        value, constraint = symbolic_object(f"socket_{state.pc}", "socket.socket")
        return ModelResult(value=value, constraints=[constraint], side_effects={"network": True})


class CreateConnectionModel(FunctionModel):
    name = "create_connection"
    qualname = "socket.create_connection"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        value, constraint = symbolic_object(f"socket_{state.pc}", "socket.socket")
        if not args and "address" not in kwargs:
            return ModelResult(
                value=value,
                constraints=[constraint],
                side_effects=SideEffects.type_error(self.qualname, "missing address"),
            )
        return ModelResult(
            value=value,
            constraints=[constraint],
            side_effects={"network": True},
            degradations=[_network_degradation(self.qualname)],
        )


class SocketNameQueryModel(FunctionModel):
    aliases: tuple[str, ...] = ()

    def __init__(self, name: Literal["gethostname", "gethostbyname"]) -> None:
        self.name = name
        self.qualname = f"socket.{name}"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        expected = 0 if self.name == "gethostname" else 1
        value, constraint = SymbolicString.symbolic(f"{self.name}_{state.pc}")
        if kwargs or len(args) != expected:
            return ModelResult(
                value=value,
                constraints=[constraint],
                side_effects=SideEffects.type_error(self.qualname, "invalid hostname query"),
            )
        return ModelResult(
            value=value,
            constraints=[constraint],
            side_effects={"network": True},
            degradations=[_network_degradation(self.qualname)],
        )


class SocketMethodModel(FunctionModel):
    aliases: tuple[str, ...] = ()

    def __init__(self, method: Literal["connect", "send", "sendall", "recv", "close"]) -> None:
        self.name = f"socket_socket_{method}"
        self.qualname = f"socket.socket.{method}"
        self._method = method

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        effects: dict[str, SideEffectValue] = {"network": True}
        if self._method in {"connect", "sendall", "close"}:
            return ModelResult.none(effects)
        if self._method == "send":
            data = args[-1] if args else None
            concrete = const_bytes(data) if data is not None else None
            result = symbolic_int_range(
                f"socket_send_{state.pc}",
                0,
                len(concrete) if concrete is not None else None,
            )
            return ModelResult(
                value=result.value,
                constraints=result.constraints,
                side_effects=effects,
                degradations=[_network_degradation(self.qualname)],
            )
        value = SymbolicBytes.symbolic(f"socket_recv_{state.pc}")
        size = args[-1] if args else None
        constraints: list[z3.BoolRef] = []
        if isinstance(size, int) and size >= 0:
            constraints.append(value.z3_len <= size)
        return ModelResult(
            value=value,
            constraints=constraints,
            side_effects=effects,
            degradations=[_network_degradation(self.qualname)],
        )


socket_models: list[FunctionModel] = [
    SocketConstructorModel(),
    CreateConnectionModel(),
    SocketNameQueryModel("gethostname"),
    SocketNameQueryModel("gethostbyname"),
    *(SocketMethodModel(method) for method in ("connect", "send", "sendall", "recv", "close")),
]
