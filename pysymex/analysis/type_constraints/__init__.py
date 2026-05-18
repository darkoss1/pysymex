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

"""Public exports for type constraint analysis."""

from __future__ import annotations

from pysymex.analysis.detectors.protocols import Protocol, ProtocolChecker
from pysymex.analysis.type_constraints.checker import TypeConstraintChecker
from pysymex.analysis.type_constraints.encoder import TypeEncoder
from pysymex.analysis.type_constraints.types import (
    SymbolicType,
    TypeIssue,
    TypeIssueKind,
    TypeKind,
    Variance,
)

__all__ = [
    "Protocol",
    "ProtocolChecker",
    "SymbolicType",
    "TypeConstraintChecker",
    "TypeEncoder",
    "TypeIssue",
    "TypeIssueKind",
    "TypeKind",
    "Variance",
]
