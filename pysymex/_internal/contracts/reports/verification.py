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

"""Aggregate counters and formatted summaries for contract checks.

:class:`~pysymex._internal.contracts.reports.verification.VerificationReport` collects per-clause
results produced by :class:`~pysymex._internal.contracts.verifier.ContractVerifier` (or compatible
callers). It does not compile predicates or query the solver.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.types import Contract, ContractViolation


def _empty_violations() -> list[ContractViolation]:
    """Create a typed empty contract-violation list."""
    return []


@dataclass
class VerificationReport:
    """Running totals and violation records for one analyzed function."""

    function_name: str
    total_contracts: int = 0
    verified: int = 0
    violated: int = 0
    unknown: int = 0
    unsupported: int = 0
    unreachable: int = 0
    violations: list[ContractViolation] = field(default_factory=_empty_violations)

    @property
    def is_verified(self) -> bool:
        """Return whether every recorded clause reached ``VERIFIED``."""
        return (
            self.violated == 0
            and self.unknown == 0
            and self.unsupported == 0
            and self.unreachable == 0
        )

    @property
    def has_violations(self) -> bool:
        """Check if any contract violations were detected.

        Returns:
            ``True`` if at least one violation occurred; otherwise ``False``.

        """
        return self.violated > 0

    def add_result(
        self,
        contract: Contract,
        result: VerificationResult,
        counterexample: dict[str, object] | None = None,
        function_name: str | None = None,
    ) -> None:
        """Record the verification result of a single contract clause.

        Args:
            contract: The contract clause checked.
            result: The verification outcome from the solver query.
            counterexample: Optional dictionary showing variables mapping to
                concrete witness values on violation.
            function_name: Qualified name of the target function.

        Side Effects:
            Increments the respective counter and appends to ``violations`` if
            the result is ``VerificationResult.VIOLATED``.

        """
        self.total_contracts += 1
        if result == VerificationResult.VERIFIED:
            self.verified += 1
        elif result == VerificationResult.VIOLATED:
            self.violated += 1
            self.violations.append(
                ContractViolation(
                    kind=contract.kind,
                    condition=contract.condition,
                    message=contract.message or contract.condition,
                    line_number=contract.line_number,
                    function_name=function_name,
                    counterexample=counterexample or {},
                    severity=contract.severity,
                ),
            )
        elif result == VerificationResult.UNSUPPORTED:
            self.unsupported += 1
        elif result == VerificationResult.UNREACHABLE:
            self.unreachable += 1
        else:
            self.unknown += 1

    def format(self) -> str:
        """Format the aggregated report into a human-readable display string.

        Returns:
            A formatted multi-line summary of results and counterexamples.

        """
        lines = [
            f"Verification Report: {self.function_name}",
            "=" * 50,
            f"Total contracts: {self.total_contracts}",
            f"  Verified: {self.verified}",
            f"  Violated: {self.violated}",
            f"  Unknown:  {self.unknown}",
            f"  Unsupported: {self.unsupported}",
            f"  Unreachable: {self.unreachable}",
        ]
        if self.is_verified:
            lines.append("\n[OK] All contracts verified!")
        elif self.has_violations:
            lines.append("\n[FAIL] Contract violations found:")
            for v in self.violations:
                lines.append("")
                lines.append(v.format())
        return "\n".join(lines)
