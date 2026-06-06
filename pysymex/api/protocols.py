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

"""Public protocol aliases for user-facing API boundaries."""

from __future__ import annotations

from pysymex.execution.protocols import ExecutionContext
from pysymex.reporting.formatters import Formatter
from pysymex.typing import DetectorProtocol
from pysymex.typing import SolverProtocol
from pysymex.typing import StateViewProtocol
from pysymex.typing import SymbolicContainerProtocol
from pysymex.typing import SymbolicStringProtocol
from pysymex.typing import SymbolicTypeProtocol

__all__ = [
    "DetectorProtocol",
    "ExecutionContext",
    "Formatter",
    "SolverProtocol",
    "StateViewProtocol",
    "SymbolicContainerProtocol",
    "SymbolicStringProtocol",
    "SymbolicTypeProtocol",
]
