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

"""Lower ``BUILD_*`` and subscript operations to symbolic containers."""

from __future__ import annotations

from pysymex._internal.execution.opcodes.common.lowering.collections.builders import (
    BuildLoweringMixin,
)
from pysymex._internal.execution.opcodes.common.lowering.collections.subscript import (
    SubscriptLoweringMixin,
)


class CollectionLowerer(SubscriptLoweringMixin, BuildLoweringMixin):
    """Translate Python collection operations to VM values and SMT formulas."""

    def __init__(self, pc: int) -> None:
        """Record the bytecode offset used for collection lowering."""
        self.pc = pc
