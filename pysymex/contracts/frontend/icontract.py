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

"""Source-only adapter for supported ``icontract`` decorators."""

from __future__ import annotations

from pysymex.contracts.contract_enums import ContractKind
from pysymex.contracts.frontend.decorators import (
    LambdaDecoratorFrontendSpec,
    lambda_decorator_clause_irs_from_source,
)
from pysymex.contracts.ir.clauses import ContractClauseIR

ICONTRACT_FRONTEND = "icontract"

_ICONTRACT_SPEC = LambdaDecoratorFrontendSpec(
    frontend=ICONTRACT_FRONTEND,
    module_name="icontract",
    kind_by_decorator={
        "require": ContractKind.REQUIRES,
        "ensure": ContractKind.ENSURES,
        "invariant": ContractKind.INVARIANT,
    },
    message_keyword="description",
    message_label="description",
)


def icontract_clause_irs_from_source(
    source: str,
    *,
    module: str | None = None,
    filename: str = "<string>",
) -> tuple[ContractClauseIR, ...]:
    """Lower supported ``icontract`` decorator clauses from source into IR."""
    return lambda_decorator_clause_irs_from_source(
        source,
        _ICONTRACT_SPEC,
        module=module,
        filename=filename,
    )


__all__ = ["ICONTRACT_FRONTEND", "icontract_clause_irs_from_source"]
