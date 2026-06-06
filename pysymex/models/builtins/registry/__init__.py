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

"""Registry for Python builtin function models."""

from __future__ import annotations

import builtins
from typing import TYPE_CHECKING, TypeAlias

from pysymex.logger import get_logger
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.builtins.types import TypeModel, TypeModelResult

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

logger = get_logger(__name__)

RegisteredModel: TypeAlias = FunctionModel | TypeModel
RegisteredResult: TypeAlias = ModelResult | TypeModelResult


def _builtin_callable_key(func: object) -> str:
    """Return the stable model lookup key for a seeded builtin callable."""
    func_name = getattr(func, "__name__", None)
    if isinstance(func_name, str):
        return func_name
    for interactive_name in ("exit", "quit", "help", "copyright", "credits", "license"):
        if func is getattr(builtins, interactive_name):
            return interactive_name
    return str(func)


class ModelRegistry:
    """Registry for builtin function and type models."""

    def __init__(self) -> None:
        """Initialize a new ModelRegistry instance."""
        self._models: dict[str, RegisteredModel] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register default builtin models and standard library models."""
        from pysymex.models.builtins.registry.defaults import default_builtin_models

        for model in default_builtin_models():
            self.register(model)

    def register(self, model: RegisteredModel) -> None:
        """Register a builtin model."""
        current = self._models.get(model.name)
        current_is_builtin = current is not None and current.qualname.startswith("builtins.")
        incoming_is_builtin = model.qualname.startswith("builtins.")
        if not current_is_builtin or incoming_is_builtin:
            self._models[model.name] = model
        if model.qualname != model.name:
            self._models[model.qualname] = model
        if logger.state.trace_enabled:
            logger.trace("registered builtin model name=%s qualname=%s", model.name, model.qualname)

    def get(self, name: str) -> RegisteredModel | None:
        """Get a model by name."""
        return self._models.get(name)

    def apply(
        self,
        func: object,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> RegisteredResult | None:
        """Try to apply a model for a function."""
        key = _builtin_callable_key(func)
        model = self.get(key)
        if model:
            if logger.state.trace_enabled:
                logger.trace("applying builtin model: %s", key)
            return model.apply(args, kwargs, state)
        if logger.state.trace_enabled:
            logger.trace("no builtin model for %s", key)
        return None

    def list_models(self) -> list[str]:
        """List all registered model names."""
        return list({m.name for m in self._models.values()})


_default_model_registry: ModelRegistry | None = None


def get_default_model_registry() -> ModelRegistry:
    """Return the lazily initialized builtin model registry."""
    global _default_model_registry
    if _default_model_registry is None:
        _default_model_registry = ModelRegistry()
        logger.verbose(
            "Initialized builtin model registry with %d models",
            len(_default_model_registry.list_models()),
        )
    return _default_model_registry
