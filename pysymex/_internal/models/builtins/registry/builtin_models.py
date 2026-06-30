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

"""Single source of truth for builtin-only model assembly."""

from __future__ import annotations

from pysymex._internal.models.builtins.attributes.registry import attribute_models
from pysymex._internal.models.builtins.conversions.registry import conversion_models
from pysymex._internal.models.builtins.exceptions.registry import exception_models
from pysymex._internal.models.builtins.iteration.registry import iteration_models
from pysymex._internal.models.builtins.memoryview.registry import memoryview_method_models
from pysymex._internal.models.builtins.numeric.registry import numeric_text_models
from pysymex._internal.models.builtins.reflection.registry import reflection_models
from pysymex._internal.models.builtins.runtime.registry import runtime_io_models
from pysymex._internal.models.builtins.types.registry import builtin_type_models
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.types import TypeModel

BuiltinModel = FunctionModel | TypeModel


def builtin_models() -> list[BuiltinModel]:
    """Build builtin-only models grouped by semantic package."""
    return [
        *conversion_models,
        *iteration_models,
        *numeric_text_models,
        *reflection_models,
        *attribute_models,
        *runtime_io_models,
        *memoryview_method_models,
        *exception_models,
        *builtin_type_models(),
    ]
