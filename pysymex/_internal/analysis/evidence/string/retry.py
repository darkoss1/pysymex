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

"""String-model retry context detection for detector feasibility evidence."""

from __future__ import annotations

import z3

from pysymex._internal.analysis.evidence.errors import EVIDENCE_SOLVER_FAILURES
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)


def has_string_retry_context(constraints: list[z3.BoolRef]) -> bool:
    """Return whether detached retry is justified by string-model-derived slots."""
    pending: list[z3.ExprRef] = list(constraints)
    visited: set[int] = set()
    while pending:
        expression = pending.pop()
        expression_id = expression.get_id()
        if expression_id in visited:
            continue
        visited.add(expression_id)
        try:
            if expression.decl().kind() == z3.Z3_OP_UNINTERPRETED and _retry_name_matches(
                expression.decl().name(),
            ):
                return True
            pending.extend(expression.children())
        except EVIDENCE_SOLVER_FAILURES:
            logger.debug("Detached model retry context probe failed", exc_info=True)
            return False
    return False


def _retry_name_matches(name: str) -> bool:
    """Return whether a Z3 symbol name belongs to string-derived model precision."""
    if "count" in name:
        return True
    return name.startswith(("bin_", "find_", "rfind_", "index_", "rindex_", "ord_"))
