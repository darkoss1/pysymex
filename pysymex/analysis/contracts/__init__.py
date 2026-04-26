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

"""Contract-based verification for pysymex — backward-compatible hub.

This module re-exports the contract system from its canonical location
in :mod:`pysymex.contracts`.  All existing import paths are preserved::

    from pysymex.analysis.contracts import ContractVerifier, requires, ensures
    from pysymex.analysis.contracts import ContractCompiler
    from pysymex.analysis.contracts.types import Contract, ContractKind

The canonical implementation now lives in:
  - ``pysymex.contracts.types``      — type definitions
  - ``pysymex.contracts.compiler``   — ContractCompiler
  - ``pysymex.contracts.decorators`` — decorator functions
  - ``pysymex.contracts.verifier``   — verification engine
"""

from __future__ import annotations

from pysymex.analysis.contracts.compiler import ContractCompiler

from pysymex.contracts.decorators import (
    ensures,
    function_contracts,
    get_function_contract,
    invariant,
    loop_invariant,
    requires,
)

from pysymex.contracts.types import (
    Contract,
    ContractKind,
    ContractViolation,
    FunctionContract,
    VerificationResult,
)

from pysymex.contracts.verifier import (
    ContractVerifier,
    VerificationReport,
)

__all__ = [
    "Contract",
    "ContractCompiler",
    "ContractKind",
    "ContractVerifier",
    "ContractViolation",
    "FunctionContract",
    "VerificationReport",
    "VerificationResult",
    "ensures",
    "function_contracts",
    "get_function_contract",
    "invariant",
    "loop_invariant",
    "requires",
]
