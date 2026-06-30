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

"""Registry for symbolic tuple models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.models.builtins.types.containers.tuples.construction import (
    TupleConstructorModel,
)
from pysymex._internal.models.builtins.types.containers.tuples.operations import (
    TupleAddModel,
    TupleEqModel,
    TupleHashModel,
    TupleMulModel,
    TupleSliceModel,
)
from pysymex._internal.models.builtins.types.containers.tuples.queries import (
    TupleContainsModel,
    TupleCountModel,
    TupleGetitemModel,
    TupleIndexModel,
    TupleLenModel,
)

if TYPE_CHECKING:
    from pysymex._internal.models.contracts.function import FunctionModel

TUPLE_MODELS: list[FunctionModel] = [
    TupleConstructorModel(),
    TupleGetitemModel(),
    TupleContainsModel(),
    TupleLenModel(),
    TupleCountModel(),
    TupleIndexModel(),
    TupleAddModel(),
    TupleMulModel(),
    TupleSliceModel(),
    TupleEqModel(),
    TupleHashModel(),
]
