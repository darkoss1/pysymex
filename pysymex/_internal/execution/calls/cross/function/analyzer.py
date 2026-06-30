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

"""Runtime cross-function shell used for execution summary caching."""

from __future__ import annotations

from pysymex._internal.execution.calls.cross.function.summary.cache.core import FunctionSummaryCache


class CrossFunctionAnalyzer:
    """Container for runtime interprocedural function summaries."""

    def __init__(self) -> None:
        """Initialize the runtime summary cache."""
        self.function_summary_cache = FunctionSummaryCache()
