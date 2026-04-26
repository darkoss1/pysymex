# pysymex: Python Symbolic Execution & Formal Verification
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
from pysymex.models.stdlib.regex import (
    ReCompileModel,
    ReEscapeModel,
    ReFindallModel,
    ReMatchModel,
    ReSearchModel,
    ReSplitModel,
    ReSubModel,
)
from pysymex.models.stdlib.data import (
    dataclasses_models,
    enum_models,
    operator_models,
)
from pysymex.models.stdlib.io import (
    bisect_models,
    copy_models,
    heapq_models,
    io_models,
)
from pysymex.models.stdlib.math import (
    math_models,
)
from pysymex.models.stdlib.system import (
    datetime_models,
    json_models,
    ospath_models,
    random_models,
    types_models,
)
from pysymex.models.containers.strings import STRING_MODELS

collections_models: list[FunctionModel] = []
itertools_models: list[FunctionModel] = []
functools_models: list[FunctionModel] = []

re_models = [
    ReMatchModel(),
    ReSearchModel(),
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
        from pysymex.models.stdlib.pathlib import PATHLIB_MODELS
        from pysymex.models.containers.sets import SET_MODELS

        all_models = (
            math_models
            + collections_models
            + itertools_models
            + functools_models
            + ospath_models
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

    def get(self, name: str) -> FunctionModel | None:
        """Get a model by name."""
        return self._models.get(name)

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


def get_stdlib_model(name: str) -> FunctionModel | None:
    """Get a stdlib model by name."""
    return extended_stdlib_registry.get(name)


def list_stdlib_models() -> list[str]:
    """List all stdlib models."""
    return extended_stdlib_registry.list_models()


def list_stdlib_modules() -> dict[str, list[str]]:
    """List stdlib models by module."""
    return extended_stdlib_registry.list_modules()
