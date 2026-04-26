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

"""Contract types — backward-compatible re-exports.

The canonical type definitions now live in :mod:`pysymex.contracts.types`.
This module re-exports them so that existing import paths continue to work::

    from pysymex.analysis.contracts.types import Contract, ContractKind
"""

from __future__ import annotations

from pysymex.contracts.types import (
    Contract,
    ContractKind,
    ContractViolation,
    FunctionContract,
    VerificationResult,
)

__all__ = [
    "Contract",
    "ContractKind",
    "ContractViolation",
    "FunctionContract",
    "VerificationResult",
]
