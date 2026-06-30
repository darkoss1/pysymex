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

Owns source-only scan checks and suppressions that are computed before the
symbolic executor runs. Scanner callers should ask this module for a single
preflight result instead of selecting detector-family collectors themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.preflight.bytearray.core import (
    find_bytearray_modulo_index,
)
from pysymex._internal.analysis.scan.preflight.equality.zero.core import (
    find_equality_guarded_zero_division,
)
from pysymex._internal.analysis.scan.preflight.guarded.index.core import (
    find_guarded_index_offset,
)
from pysymex._internal.analysis.scan.preflight.masked.zero.core import (
    find_masked_zero_division,
)
from pysymex._internal.analysis.scan.preflight.self.canceling.zero import (
    find_self_canceling_zero_division,
)
from pysymex._internal.analysis.scan.preflight.witness.core import (
    find_concrete_witness,
)

if TYPE_CHECKING:
    from pysymex._internal.analysis.records import IssueRecord


@dataclass(frozen=True, slots=True)
class ScanPreflightResult:
    """Source-only findings and suppressions used by a file scan."""

    issues: tuple[IssueRecord, ...]


def find_scan_preflight(content: str) -> ScanPreflightResult:
    """Run all source-only preflight scan diagnostics for one target file."""
    issues: list[IssueRecord] = []
    issues.extend(find_concrete_witness(content))
    issues.extend(find_bytearray_modulo_index(content))
    issues.extend(find_equality_guarded_zero_division(content))
    issues.extend(find_guarded_index_offset(content))
    issues.extend(find_masked_zero_division(content))
    issues.extend(find_self_canceling_zero_division(content))

    return ScanPreflightResult(issues=tuple(issues))
