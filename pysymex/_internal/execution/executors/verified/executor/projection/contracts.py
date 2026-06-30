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

"""UNKNOWN contract-adjacent issue projection for verified execution."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.reports.issues import ContractIssue
from pysymex._internal.core.outcome import IssueKind
from pysymex.contracts import ContractKind

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue

_CONTRACT_UNKNOWN_MARKERS = ("precondition", "postcondition", "assumption")


def is_adjacent_contract_unknown(issue: Issue) -> bool:
    """Return whether a core UNKNOWN issue describes a contract obligation."""
    lower_message = issue.message.lower()
    return issue.kind is IssueKind.UNKNOWN and any(
        marker in lower_message for marker in _CONTRACT_UNKNOWN_MARKERS
    )


def project_unknown_contract_issue(issue: Issue) -> ContractIssue | None:
    """Project a core UNKNOWN contract issue into verified contract output.

    Returns ``None`` for callee-owned pre/postcondition or assumption messages
    that are already represented by runtime contract outcome aggregation.
    """
    if not is_adjacent_contract_unknown(issue):
        return None

    lower_message = issue.message.lower()
    if (
        "postcondition" in lower_message
        or ("precondition" in lower_message and " of " in lower_message)
        or ("assumption" in lower_message and " of " in lower_message)
    ):
        return None

    return ContractIssue(
        kind=_unknown_message_contract_kind(lower_message),
        condition=issue.message,
        message=issue.message,
        line_number=issue.line_number,
        function_name=issue.function_name,
        counterexample={},
        result=_unknown_message_contract_result(lower_message),
    )


def _unknown_message_contract_kind(lower_message: str) -> ContractKind:
    """Return the declared contract kind encoded in a lower-cased UNKNOWN message."""
    if "precondition" in lower_message:
        return ContractKind.REQUIRES
    if "assumption" in lower_message:
        return ContractKind.ASSUMES
    return ContractKind.ENSURES


def _unknown_message_contract_result(lower_message: str) -> VerificationResult:
    """Return the verification result encoded in a lower-cased UNKNOWN message."""
    if "could not be checked" in lower_message or "could not be modeled" in lower_message:
        return VerificationResult.UNSUPPORTED
    return VerificationResult.UNKNOWN
