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

"""Contract report issue types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pysymex._internal.contracts.enums import VerificationResult
from pysymex.contracts import ContractKind, ContractSeverity

if TYPE_CHECKING:
    from pysymex._internal.contracts.ir.evidence import EvidenceResult


@dataclass
class ContractIssue:
    """A contract-related issue found during execution."""

    kind: ContractKind
    condition: str
    message: str
    line_number: int | None = None
    function_name: str | None = None
    counterexample: dict[str, object] = field(default_factory=dict[str, object])
    severity: ContractSeverity = ContractSeverity.ERROR
    result: VerificationResult = VerificationResult.VIOLATED
    evidence: EvidenceResult | None = None

    def format(self) -> str:
        """Format for display."""
        location = f" at line {self.line_number}" if self.line_number else ""
        func = f" in {self.function_name}" if self.function_name else ""
        status = self.result.name
        warning = "[WARNING] " if self.severity is ContractSeverity.WARNING else ""
        result = f"[{status}] {warning}{self.kind.name}{func}{location}: {self.message}\n"
        result += f"  Condition: {self.condition}\n"
        if self.counterexample:
            result += "  Counterexample:\n"
            for var, val in self.counterexample.items():
                result += f"    {var} = {val}\n"
        return result
