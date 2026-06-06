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

# pyright: reportUnsupportedDunderAll=false

"""
Extended Standard Library Models for pysymex v1.2.

Slim hub that re-exports all stdlib model classes from extraction modules:
- stdlib_math: Mathematical functions (sqrt, ceil, floor, sin, cos, etc.)
- stdlib_containers: collections, itertools, functools
- stdlib_system: os.path, json, datetime, random, types
- stdlib_data: enum, dataclasses, operator
- stdlib_io: copy, io, heapq, bisect
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.models.builtins.base import FunctionModel
from pysymex.logger import get_logger
from pysymex.models.stdlib.regex import (
    ReCompileModel,
    ReEscapeModel,
    ReFindallModel,
    ReFullmatchModel,
    ReMatchModel,
    ReSearchModel,
    ReSplitModel,
    ReSubModel,
    REGEX_MODELS as REGEX_MODELS,
    PatternCompiler as PatternCompiler,
    compile_pattern as compile_pattern,
)
from pysymex.models.stdlib.dataclasses import (
    DATACLASSES_MODELS as DATACLASSES_MODELS,
    FieldInfo as FieldInfo,
    asdict_model as asdict_model,
    astuple_model as astuple_model,
    dataclass_model as dataclass_model,
    field_model as field_model,
    fields_model as fields_model,
    get_dataclasses_model as get_dataclasses_model,
    is_dataclass_model as is_dataclass_model,
    make_dataclass_model as make_dataclass_model,
    replace_model as replace_model,
)
from pysymex.models.stdlib.data import (
    dataclasses_models,
    enum_models,
    operator_models,
)
from pysymex.models.stdlib.math import (
    math_models,
)
from pysymex.models.stdlib.models.datetime import datetime_models
from pysymex.models.stdlib.models.ast import ast_models
from pysymex.models.stdlib.models.json import json_models
from pysymex.models.stdlib.models.ospath import ospath_models
from pysymex.models.stdlib.models.random import random_models
from pysymex.models.stdlib.models.types import types_models
from pysymex.models.stdlib.collections.defaultdict import DEFAULTDICT_MODELS
from pysymex.models.stdlib.collections.deque import DEQUE_MODELS
from pysymex.models.stdlib.contextlib.managers import ContextManagerModel
from pysymex.models.stdlib.contextlib.stacks import ExitStackConstructorModel
from pysymex.models.stdlib.itertools.sequences import AccumulateModel, ChainModel
from pysymex.models.stdlib.functools.core import PartialConstructorModel, ReduceModel
from pysymex.models.containers.strings.registry import STRING_MODELS
from pysymex.models.stdlib.sys import sys_models
from pysymex.models.stdlib.os import os_models
from pysymex.models.stdlib.exports import STDLIB_ALL

logger = get_logger(__name__)

collections_models: list[FunctionModel] = [*DEFAULTDICT_MODELS, *DEQUE_MODELS]
contextlib_function_models: list[FunctionModel] = [
    ContextManagerModel(),
    ExitStackConstructorModel(),
]
itertools_models: list[FunctionModel] = [AccumulateModel(), ChainModel()]
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


class ExtendedStdlibRegistry:
    """Registry for extended stdlib models."""

    def __init__(self) -> None:
        """Initialize a new ExtendedStdlibRegistry instance."""
        self._models: dict[str, FunctionModel] = {}
        self._register_all()

    def _register_all(self) -> None:
        """Register all stdlib models."""
        from pysymex.models.stdlib.models.bisect import bisect_models
        from pysymex.models.stdlib.models.copy import copy_models
        from pysymex.models.stdlib.models.heapq import heapq_models
        from pysymex.models.stdlib.models.io_stream import io_models
        from pysymex.models.stdlib.pathlib.registry import PATHLIB_MODELS
        from pysymex.models.containers.sets.registry import SET_MODELS

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
            + bisect_models
            + enum_models
            + dataclasses_models
            + SET_MODELS
            + STRING_MODELS
            + PATHLIB_MODELS
        )
        for model in all_models:
            self.register(model)

    def register(self, model: FunctionModel) -> None:
        """Register a model."""
        self._models[model.name] = model
        self._models[model.qualname] = model
        if logger.state.trace_enabled:
            logger.trace("registered stdlib model name=%s qualname=%s", model.name, model.qualname)

    def get(self, name: str) -> FunctionModel | None:
        """Get a model by name."""
        model = self._models.get(name)
        if logger.state.trace_enabled and model is None:
            logger.trace("no stdlib model for %s", name)
        return model

    def list_models(self) -> list[str]:
        """List all registered model names."""
        return sorted({m.name for m in self._models.values()})

    def list_modules(self) -> dict[str, list[str]]:
        """List models grouped by module."""
        modules: dict[str, list[str]] = {}
        for model in self._models.values():
            if "." in model.qualname:
                module = model.qualname.rsplit(".", 1)[0]
            else:
                module = "builtins"
            if module not in modules:
                modules[module] = []
            if model.name not in modules[module]:
                modules[module].append(model.name)
        return {k: sorted(v) for k, v in sorted(modules.items())}


extended_stdlib_registry = ExtendedStdlibRegistry()
logger.verbose(
    "Initialized stdlib model registry with %d models",
    len(extended_stdlib_registry.list_models()),
)


def get_stdlib_model(name: str) -> FunctionModel | None:
    """Get a stdlib model by name."""
    return extended_stdlib_registry.get(name)


def list_stdlib_models() -> list[str]:
    """List all stdlib models."""
    return extended_stdlib_registry.list_models()


def list_stdlib_modules() -> dict[str, list[str]]:
    """List stdlib models by module."""
    return extended_stdlib_registry.list_modules()


__all__ = STDLIB_ALL
