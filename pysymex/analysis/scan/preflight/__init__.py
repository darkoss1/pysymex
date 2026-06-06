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

"""AST preflight diagnostics before symbolic execution.

Fast, source-only checks for patterns that are hard to model in the VM or that
should be reported without running the executor.
"""

from __future__ import annotations

from pysymex.analysis.scan.preflight.bytearray import collect_bytearray_modulo_index_diagnostics
from pysymex.analysis.scan.preflight.equality_zero import (
    collect_equality_guarded_zero_division_diagnostics,
)
from pysymex.analysis.scan.preflight.guarded_index import collect_guarded_index_offset_diagnostics
from pysymex.analysis.scan.preflight.infeasible_branch import (
    collect_infeasible_branch_division_suppressions,
)
from pysymex.analysis.scan.preflight.masked_zero import collect_masked_zero_division_diagnostics
from pysymex.analysis.scan.preflight.self_canceling_zero import (
    collect_self_canceling_zero_division_diagnostics,
)
from pysymex.analysis.scan.records import IssueRecord

__all__ = [
    "IssueRecord",
    "collect_bytearray_modulo_index_diagnostics",
    "collect_equality_guarded_zero_division_diagnostics",
    "collect_guarded_index_offset_diagnostics",
    "collect_infeasible_branch_division_suppressions",
    "collect_masked_zero_division_diagnostics",
    "collect_self_canceling_zero_division_diagnostics",
]
