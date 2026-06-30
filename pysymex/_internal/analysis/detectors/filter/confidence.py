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

"""Issue confidence scoring."""

from __future__ import annotations

from typing import TypeGuard

from pysymex._internal.analysis.detectors.filter.core import is_typing_false_positive
from pysymex._internal.analysis.detectors.filter.types import (
    Confidence,
    FilterIssueLike,
    ModelDeclLike,
)
from pysymex._internal.guards import RuntimeObjectGuards
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)


def _is_decl_list(value: object) -> TypeGuard[list[ModelDeclLike]]:
    """Return whether a value is a list of declaration-like objects."""
    if not RuntimeObjectGuards.list(value):
        return False
    for item in value:
        name_attr = getattr(item, "name", None)
        if not callable(name_attr):
            return False
    return True


def _model_involves_havoc(issue: FilterIssueLike) -> bool:
    """Return True if the issue's Z3 counter-example uses havoc variables."""
    if issue.model is None:
        return False
    try:
        decls_fn = getattr(issue.model, "decls", None)
        if not callable(decls_fn):
            return True
        decls = decls_fn()
        if not _is_decl_list(decls):
            return True
        for decl in decls:
            if decl.name().startswith("havoc_"):
                return True
    except Exception:
        logger.debug("Failed to inspect issue model declarations for havoc markers", exc_info=True)
        return True
    return False


def calculate_confidence(issue: FilterIssueLike) -> Confidence:
    """Calculate confidence level for an issue."""
    from pysymex._internal.analysis.detectors.detector.types import IssueKind

    havoc = _model_involves_havoc(issue)

    if issue.kind == IssueKind.DIVISION_BY_ZERO and issue.model is not None:
        return Confidence.MEDIUM if havoc else Confidence.HIGH

    if issue.kind == IssueKind.ASSERTION_ERROR:
        return Confidence.MEDIUM

    if issue.kind == IssueKind.TYPE_ERROR:
        if is_typing_false_positive(issue):
            return Confidence.LOW
        return Confidence.MEDIUM

    if issue.kind in (IssueKind.INDEX_ERROR, IssueKind.KEY_ERROR):
        if issue.model is not None:
            return Confidence.LOW if havoc else Confidence.MEDIUM
        return Confidence.LOW

    if issue.model is not None:
        return Confidence.LOW if havoc else Confidence.MEDIUM

    return Confidence.LOW
