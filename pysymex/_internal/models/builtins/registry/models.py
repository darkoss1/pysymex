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
from typing import TYPE_CHECKING, cast

from pysymex._internal.logging.root import get_logger
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.contracts.types import TypeModel, TypeModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

logger = get_logger(__name__)

RegisteredModel = FunctionModel | TypeModel
RegisteredResult = ModelResult | TypeModelResult


def _builtin_callable_key(func: object) -> str | None:
    """Return the stable owner-qualified model lookup key for a builtin callable."""
    func_name = getattr(func, "__name__", None)
    if isinstance(func_name, str):
        builtin_obj = getattr(builtins, func_name, None)
        if func is builtin_obj:
            return func_name
        module_name = getattr(func, "__module__", None)
        if module_name == "builtins":
            func_qualname = getattr(func, "__qualname__", None)
            if isinstance(func_qualname, str) and "." in func_qualname:
                return func_qualname
            return None

        func_qualname = getattr(func, "__qualname__", None)
        if module_name is None and isinstance(func_qualname, str) and "." in func_qualname:
            owner_name, _, _ = func_qualname.partition(".")
            owner_obj = getattr(builtins, owner_name, None)
            if isinstance(owner_obj, type) and getattr(owner_obj, func_name, None) is func:
                return func_qualname

        owner = getattr(func, "__self__", None)
        if owner is not None:
            owner_type = owner if isinstance(owner, type) else type(owner)
            if owner_type.__module__ == "builtins":
                return f"{owner_type.__name__}.{func_name}"
        return None
    for interactive_name in ("exit", "quit", "help", "copyright", "credits", "license"):
        if func is getattr(builtins, interactive_name):
            return interactive_name
    return None


class ModelRegistry:
    """Registry for builtin function and type models."""

    def __init__(self) -> None:
        """Initialize a new ModelRegistry instance."""
        self._models: dict[str, RegisteredModel] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register default builtin models and standard library models."""
        from pysymex._internal.models.builtins.registry.defaults import default_builtin_models

        for model in default_builtin_models():
            self.register(model)

    def register(self, model: RegisteredModel) -> None:
        """Register a builtin model."""
        self._register_exact(model.qualname, model)
        if model.qualname.startswith("builtins.") and model.qualname.count(".") == 1:
            self._register_exact(model.name, model)
        aliases_value = getattr(model, "aliases", ())
        if not isinstance(aliases_value, tuple):
            msg = f"model aliases must be a tuple of strings: {model.qualname}"
            raise TypeError(msg)
        unchecked_aliases = cast("tuple[object, ...]", aliases_value)
        if not all(isinstance(alias, str) for alias in unchecked_aliases):
            msg = f"model aliases must be a tuple of strings: {model.qualname}"
            raise TypeError(msg)
        aliases = cast("tuple[str, ...]", unchecked_aliases)
        for alias in aliases:
            self._register_exact(alias, model)
        if logger.state.trace_enabled:
            logger.trace("registered builtin model name=%s qualname=%s", model.name, model.qualname)

    def _register_exact(self, key: str, model: RegisteredModel) -> None:
        existing = self._models.get(key)
        if existing is not None and existing is not model:
            msg = (
                f"duplicate builtin model key {key!r}: "
                f"{type(existing).__name__} and {type(model).__name__}"
            )
            raise ValueError(
                msg,
            )
        self._models[key] = model

    def get(self, name: str | None) -> RegisteredModel | None:
        """Get a model by name."""
        if name is None:
            return None
        return self._models.get(name)

    def resolve_callable(self, func: object) -> RegisteredModel | None:
        """Resolve a concrete builtin callable without invoking its model."""
        return self.get(_builtin_callable_key(func))

    def apply(
        self,
        func: object,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> RegisteredResult | None:
        """Try to apply a model for a function."""
        key = _builtin_callable_key(func)
        model = self.resolve_callable(func)
        if model:
            if logger.state.trace_enabled:
                logger.trace("applying builtin model: %s", key)
            return model.apply(args, kwargs, state)
        if logger.state.trace_enabled:
            logger.trace("no builtin model for %s", key)
        return None

    def list_models(self) -> list[str]:
        """List all registered model qualnames."""
        return sorted({m.qualname for m in self._models.values()})

    def models(self) -> tuple[RegisteredModel, ...]:
        """Return each registered model instance once."""
        return tuple({id(model): model for model in self._models.values()}.values())


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
