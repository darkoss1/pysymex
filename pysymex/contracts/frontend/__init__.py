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

"""Contract frontend adapters.

Frontend modules normalize declarations from a syntax surface into
``ContractClauseIR`` records. They do not compile predicates, query solvers,
mutate VM state, or format reports.
"""

from __future__ import annotations

from pysymex.contracts.frontend.asserts import (
    ASSERT_FRONTEND,
    assertion_clause_irs_from_source,
)
from pysymex.contracts.frontend.common import UnsupportedFrontendSyntax
from pysymex.contracts.frontend.deal import DEAL_FRONTEND, deal_clause_irs_from_source
from pysymex.contracts.frontend.icontract import (
    ICONTRACT_FRONTEND,
    icontract_clause_irs_from_source,
)
from pysymex.contracts.frontend.native import (
    NATIVE_FRONTEND,
    native_clause_ir_from_contract,
    native_function_clause_irs,
)
from pysymex.contracts.frontend.pep316 import PEP316_FRONTEND, pep316_clause_irs_from_source

__all__ = [
    "ASSERT_FRONTEND",
    "DEAL_FRONTEND",
    "ICONTRACT_FRONTEND",
    "NATIVE_FRONTEND",
    "PEP316_FRONTEND",
    "UnsupportedFrontendSyntax",
    "assertion_clause_irs_from_source",
    "deal_clause_irs_from_source",
    "icontract_clause_irs_from_source",
    "native_clause_ir_from_contract",
    "native_function_clause_irs",
    "pep316_clause_irs_from_source",
]
