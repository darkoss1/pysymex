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

"""Composition root for all callable model families."""

from __future__ import annotations

from pysymex._internal.models.builtins.registry.models import (
    ModelRegistry,
    RegisteredModel,
    get_default_model_registry,
)
from pysymex._internal.models.stdlib.registry import (
    ExtendedStdlibRegistry,
    extended_stdlib_registry,
)


class RuntimeModelRegistry:
    """Resolve model names and callables without exposing family registries."""

    def __init__(
        self,
        builtin_registry: ModelRegistry | None = None,
        stdlib_registry: ExtendedStdlibRegistry | None = None,
    ) -> None:
        self._builtin_registry = builtin_registry or get_default_model_registry()
        self._stdlib_registry = stdlib_registry or extended_stdlib_registry

    @classmethod
    def default(cls) -> RuntimeModelRegistry:
        """Return the process-wide composed model registry."""
        global _default_runtime_registry
        if _default_runtime_registry is None:
            _default_runtime_registry = cls()
        return _default_runtime_registry

    def get(self, name: str) -> RegisteredModel | None:
        """Resolve an exact model name or qualname."""
        return self._builtin_registry.get(name) or self._stdlib_registry.get(name)

    def resolve(self, name: str) -> RegisteredModel | None:
        """Resolve an exact model name or qualname."""
        return self.get(name)

    def resolve_callable(self, func: object) -> RegisteredModel | None:
        """Resolve a concrete builtin or stdlib callable by exact ownership."""
        return self._builtin_registry.resolve_callable(
            func,
        ) or self._stdlib_registry.resolve_callable(func)

    def models(self) -> tuple[RegisteredModel, ...]:
        """Return each registered model instance once for audits and tooling."""
        combined = (*self._builtin_registry.models(), *self._stdlib_registry.models())
        return tuple({id(model): model for model in combined}.values())


_default_runtime_registry: RuntimeModelRegistry | None = None
