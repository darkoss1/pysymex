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

"""Extended Standard Library Models for pysymex v1.2.

Slim hub that re-exports all stdlib model classes from extraction modules:
- stdlib_math: Mathematical functions (sqrt, ceil, floor, sin, cos, etc.)
- stdlib_containers: collections, itertools, functools
- stdlib_system: os.path, json, datetime, random, types
- stdlib_data: enum, dataclasses, operator
- stdlib_io: copy, io, heapq, bisect
"""

from __future__ import annotations

import sys as python_sys
from types import ModuleType
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.logging.root import get_logger
from pysymex._internal.models.stdlib.ast.models import ast_models
from pysymex._internal.models.stdlib.collections.counter import COUNTER_MODELS
from pysymex._internal.models.stdlib.collections.defaultdict import DEFAULTDICT_MODELS
from pysymex._internal.models.stdlib.collections.deque import DEQUE_MODELS
from pysymex._internal.models.stdlib.contextlib.managers import ContextManagerModel
from pysymex._internal.models.stdlib.contextlib.stacks import ExitStackConstructorModel
from pysymex._internal.models.stdlib.dataclasses.models import dataclasses_models
from pysymex._internal.models.stdlib.datetime.models import datetime_models
from pysymex._internal.models.stdlib.enum.models import enum_models
from pysymex._internal.models.stdlib.functools.core import PartialConstructorModel, ReduceModel
from pysymex._internal.models.stdlib.itertools.runtime import itertools_runtime_models
from pysymex._internal.models.stdlib.itertools.sequences import AccumulateModel, ChainModel
from pysymex._internal.models.stdlib.json.models import json_models
from pysymex._internal.models.stdlib.math.registry import math_models
from pysymex._internal.models.stdlib.operator.models import operator_models
from pysymex._internal.models.stdlib.os.core import os_models
from pysymex._internal.models.stdlib.os.path import ospath_models
from pysymex._internal.models.stdlib.random.models import random_models
from pysymex._internal.models.stdlib.regex.matching import (
    ReFullmatchModel,
    ReMatchModel,
    ReSearchModel,
)
from pysymex._internal.models.stdlib.regex.registry import ReCompileModel, ReEscapeModel
from pysymex._internal.models.stdlib.regex.sequences import ReFindallModel, ReSplitModel, ReSubModel
from pysymex._internal.models.stdlib.sys.registry import sys_models
from pysymex._internal.models.stdlib.types.models import types_models

logger = get_logger(__name__)

collections_models: list[FunctionModel] = [*COUNTER_MODELS, *DEFAULTDICT_MODELS, *DEQUE_MODELS]
contextlib_function_models: list[FunctionModel] = [
    ContextManagerModel(),
    ExitStackConstructorModel(),
]
itertools_models: list[FunctionModel] = [
    AccumulateModel(),
    ChainModel(),
    *itertools_runtime_models,
]
functools_models: list[FunctionModel] = [PartialConstructorModel(), ReduceModel()]

re_models = [
    ReMatchModel(),
    ReSearchModel(),
    ReFullmatchModel(),
    ReFindallModel(),
    ReSubModel(),
    ReSplitModel(),
    ReCompileModel(),
    ReEscapeModel(),
]


def _model_aliases(model: FunctionModel) -> tuple[str, ...]:
    """Return additional exact lookup names declared by a model."""
    raw_aliases: object = getattr(model, "aliases", ())
    if not isinstance(raw_aliases, tuple):
        return ()
    aliases: list[str] = []
    for alias in cast("tuple[object, ...]", raw_aliases):
        if not isinstance(alias, str):
            return ()
        aliases.append(alias)
    return tuple(aliases)


class ExtendedStdlibRegistry:
    """Registry for extended stdlib models."""

    def __init__(self) -> None:
        """Initialize a new ExtendedStdlibRegistry instance."""
        self._models: dict[str, FunctionModel] = {}
        self._models_by_name: dict[str, list[FunctionModel]] = {}
        self._register_all()

    def _register_all(self) -> None:
        """Register all stdlib models."""
        from pysymex._internal.models.stdlib.bisect.models import bisect_models
        from pysymex._internal.models.stdlib.copy.models import copy_models
        from pysymex._internal.models.stdlib.family_registry import stdlib_family_models
        from pysymex._internal.models.stdlib.heapq.models import heapq_models
        from pysymex._internal.models.stdlib.io.models import io_models
        from pysymex._internal.models.stdlib.pathlib.registry import PATHLIB_MODELS

        all_models = (
            math_models
            + sys_models
            + os_models
            + contextlib_function_models
            + collections_models
            + itertools_models
            + functools_models
            + ospath_models
            + ast_models
            + json_models
            + re_models
            + random_models
            + datetime_models
            + types_models
            + operator_models
            + copy_models
            + io_models
            + heapq_models
            + stdlib_family_models
            + bisect_models
            + enum_models
            + dataclasses_models
            + PATHLIB_MODELS
        )
        for model in all_models:
            self.register(model)

    def register(self, model: FunctionModel) -> None:
        """Register a model."""
        name_models = self._models_by_name.setdefault(model.name, [])
        if model not in name_models:
            name_models.append(model)
        self._register_exact(model.qualname, model)
        for alias in _model_aliases(model):
            self._register_exact(alias, model)
        if logger.state.trace_enabled:
            logger.trace("registered stdlib model name=%s qualname=%s", model.name, model.qualname)

    def _register_exact(self, key: str, model: FunctionModel) -> None:
        existing = self._models.get(key)
        if existing is not None and existing is not model:
            msg = (
                f"duplicate stdlib model key {key!r}: "
                f"{type(existing).__name__} and {type(model).__name__}"
            )
            raise ValueError(
                msg,
            )
        self._models[key] = model

    def get(self, name: str) -> FunctionModel | None:
        """Get an exact model key or an unambiguous short model name."""
        model = self._models.get(name)
        if model is None:
            candidates = self._models_by_name.get(name, ())
            if len(candidates) == 1:
                model = candidates[0]
        if logger.state.trace_enabled and model is None:
            logger.trace("no stdlib model for %s", name)
        return model

    def resolve_callable(self, func: object) -> FunctionModel | None:
        """Resolve a concrete stdlib callable without matching user-defined names."""
        func_name = getattr(func, "__name__", None)
        if not isinstance(func_name, str):
            return None

        module_name = getattr(func, "__module__", None)
        func_qualname = getattr(func, "__qualname__", None)
        owner = getattr(func, "__self__", None)
        owner_type: type[object] | None = None
        if owner is not None and not isinstance(owner, ModuleType):
            owner_type = owner if isinstance(owner, type) else type(owner)
            if not isinstance(module_name, str):
                module_name = owner_type.__module__

        if not isinstance(module_name, str):
            # Static descriptors such as ``bytes.maketrans`` expose an exact
            # public ``__qualname__`` but no ``__module__`` or ``__self__``.
            if isinstance(func_qualname, str) and "." in func_qualname:
                return self.get(func_qualname)
            return None

        candidates: list[str] = []
        if isinstance(func_qualname, str):
            candidates.append(f"{module_name}.{func_qualname}")
        if owner_type is not None:
            candidates.append(f"{module_name}.{owner_type.__name__}.{func_name}")
        candidates.append(f"{module_name}.{func_name}")

        for candidate in dict.fromkeys(candidates):
            model = self.get(candidate)
            if model is not None:
                return model

        # C-backed stdlib callables frequently expose their implementation
        # module (for example ``nt.getcwd``) instead of their public owner.
        # Exact identity against the public module is safe and avoids
        # degrading those calls merely because ``__module__`` is private or
        # platform-specific.
        identity_matches: list[FunctionModel] = []
        for model in self._models_by_name.get(func_name, []):
            public_module_name = model.qualname.split(".", 1)[0]
            public_module = python_sys.modules.get(public_module_name)
            if public_module is not None and getattr(public_module, func_name, None) is func:
                identity_matches.append(model)
        if len(identity_matches) == 1:
            return identity_matches[0]

        top_level_module = module_name.split(".", 1)[0]
        if (
            not top_level_module.startswith("_")
            or top_level_module not in python_sys.stdlib_module_names
        ):
            return None
        return None

    def list_models(self) -> list[str]:
        """List all registered model qualnames."""
        return sorted({m.qualname for m in self._models.values()})

    def models(self) -> tuple[FunctionModel, ...]:
        """Return each registered model instance once."""
        return tuple({id(model): model for model in self._models.values()}.values())


extended_stdlib_registry = ExtendedStdlibRegistry()
logger.verbose(
    "Initialized stdlib model registry with %d models",
    len(extended_stdlib_registry.list_models()),
)


def get_stdlib_model(name: str) -> FunctionModel | None:
    """Get a stdlib model by name."""
    return extended_stdlib_registry.get(name)
