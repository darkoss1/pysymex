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

"""Function models for the :mod:`threading` standard-library family."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pysymex._internal.core.types.base import SymbolicType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import (
    ModelDegradation,
    ModelResult,
    SideEffectValue,
)
from pysymex._internal.models.stdlib.coercion import symbolic_object
from pysymex._internal.models.stdlib.threading.state.locks import (
    BoundedSemaphoreModel,
    LockModel,
    RLockModel,
    SemaphoreModel,
)
from pysymex._internal.models.stdlib.threading.state.sync import (
    BarrierModel,
    ConditionModel,
    EventModel,
)
from pysymex._internal.models.stdlib.threading.state.threads import ThreadModel

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _scheduling_degradation(operation: str) -> ModelDegradation:
    return ModelDegradation(
        kind="unknown",
        label=operation,
        owner="threading models",
        reason="thread scheduling and cross-thread mutation are not deterministic",
    )


class ThreadingConstructorModel(FunctionModel):
    """Construct one modeled threading primitive behind a symbolic object."""

    def __init__(self, type_name: str, factory: Callable[..., object]) -> None:
        self.name = type_name
        self.qualname = f"threading.{type_name}"
        self._factory = factory

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        value, constraint = symbolic_object(f"threading_{self.name}_{state.pc}", self.qualname)
        if not any(isinstance(argument, SymbolicType) for argument in (*args, *kwargs.values())):
            try:
                value.attach_modeled_object(self._factory(*args, **kwargs))
            except (TypeError, ValueError):
                # Argument diagnostics remain owned by execution. The model still
                # preserves the precise runtime type of the constructor result.
                pass
        return ModelResult(
            value=value,
            constraints=[constraint],
            side_effects={"concurrency": True},
        )


class ThreadConstructorModel(ThreadingConstructorModel):
    """Model ``threading.Thread`` construction."""

    def __init__(self) -> None:
        super().__init__("Thread", ThreadModel)


class CurrentThreadModel(FunctionModel):
    name = "current_thread"
    qualname = "threading.current_thread"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        value, constraint = symbolic_object(f"current_thread_{state.pc}", "threading.Thread")
        value.attach_modeled_object(ThreadModel(name="current_thread"))
        return ModelResult(value=value, constraints=[constraint])


class ThreadOperationModel(FunctionModel):
    aliases: tuple[str, ...] = ()

    def __init__(self, owner: Literal["Thread", "Event"], method: str) -> None:
        self.name = f"threading_{owner}_{method}"
        self.qualname = f"threading.{owner}.{method}"
        self._method = method

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        effects: dict[str, SideEffectValue] = {"concurrency": True, "mutates_arg": 0}
        receiver = args[0] if args else None
        payload = getattr(receiver, "_modeled_object", None)
        method = getattr(payload, self._method, None)
        if callable(method):
            result = method(*args[1:], **kwargs)
            if result is None:
                return ModelResult.none(effects)
            return ModelResult(value=SymbolicValue.from_const(result), side_effects=effects)
        if self._method in {"start", "join", "set", "clear"}:
            return ModelResult.none(effects)
        value, constraint = SymbolicValue.symbolic_bool(f"{self.name}_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint],
            side_effects={"concurrency": True},
            degradations=[_scheduling_degradation(self.qualname)],
        )


threading_models: list[FunctionModel] = [
    ThreadConstructorModel(),
    ThreadingConstructorModel("Lock", LockModel),
    ThreadingConstructorModel("RLock", RLockModel),
    ThreadingConstructorModel("Semaphore", SemaphoreModel),
    ThreadingConstructorModel("BoundedSemaphore", BoundedSemaphoreModel),
    ThreadingConstructorModel("Event", EventModel),
    ThreadingConstructorModel("Condition", ConditionModel),
    ThreadingConstructorModel("Barrier", BarrierModel),
    CurrentThreadModel(),
    ThreadOperationModel("Thread", "start"),
    ThreadOperationModel("Thread", "join"),
    ThreadOperationModel("Thread", "is_alive"),
    ThreadOperationModel("Event", "set"),
    ThreadOperationModel("Event", "clear"),
    ThreadOperationModel("Event", "wait"),
]
