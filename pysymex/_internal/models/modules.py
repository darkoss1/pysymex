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

"""Registry and materialization boundary for symbolic module models."""

from __future__ import annotations

import zlib
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.objects import SymbolicObject

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def module_address(name: str) -> int:
    """Return a stable heap address for a modeled module namespace."""
    return zlib.crc32(f"module:{name}".encode())


def new_module_object(name: str) -> SymbolicObject:
    """Create the heap reference used for a modeled module."""
    address = module_address(name)
    return SymbolicObject(name, address, ConstraintValues.int(address), {address})


class ModuleModel(ABC):
    """Own the import-time namespace and nested state of one module."""

    name: str

    @abstractmethod
    def materialize(self, state: VMState) -> tuple[SymbolicObject, VMState]:
        """Build this module in path-local heap state."""


class GenericModuleModel(ModuleModel):
    """Fallback module with no known attributes beyond its identity."""

    def __init__(self, name: str) -> None:
        self.name = name

    def materialize(self, state: VMState) -> tuple[SymbolicObject, VMState]:
        module = new_module_object(self.name)
        data: dict[str, StackValue] = {"__module_name__": self.name}
        return module, state.store_heap(module.address, data)


class ModuleModelRegistry:
    """Exact-name registry for symbolic module materializers."""

    def __init__(self) -> None:
        self._models: dict[str, ModuleModel] = {}

    def register(self, model: ModuleModel) -> None:
        if not model.name or model.name in self._models:
            msg = f"duplicate or empty module model name: {model.name!r}"
            raise ValueError(msg)
        self._models[model.name] = model

    def get(self, name: str) -> ModuleModel | None:
        return self._models.get(name)

    def materialize(
        self,
        name: str,
        state: VMState,
        *,
        registered_only: bool = False,
    ) -> tuple[SymbolicObject, VMState] | None:
        model = self.get(name)
        if model is None:
            if registered_only:
                return None
            model = GenericModuleModel(name)
        return model.materialize(state)


_default_registry: ModuleModelRegistry | None = None


def get_default_module_model_registry() -> ModuleModelRegistry:
    """Return the lazily assembled module registry."""
    global _default_registry
    if _default_registry is None:
        from pysymex._internal.models.stdlib.module_registry import stdlib_module_models

        registry = ModuleModelRegistry()
        for model in stdlib_module_models():
            registry.register(model)
        _default_registry = registry
    return _default_registry


def materialize_module(
    name: str,
    state: VMState,
    *,
    registered_only: bool = False,
) -> tuple[SymbolicObject, VMState] | None:
    """Materialize a module through the shared models boundary."""
    return get_default_module_model_registry().materialize(
        name,
        state,
        registered_only=registered_only,
    )
