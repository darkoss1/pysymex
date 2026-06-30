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

"""Structural input protocols for report formatters."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence


class TerminationProofLike(Protocol):
    """Protocol representing a structural termination proof object.

    Requires objects to expose status and descriptive message details regarding
    the termination analysis outcome.

    Attributes:
        status: The termination status value.
        message: Narrative describing the termination outcome.

    """

    status: object
    message: object


class VerifiedResultLike(Protocol):
    """Protocol representing verification results for formatting.

    Requires attributes tracking verified function details, path statistics,
    discovered contract and arithmetic issues, and degraded analyzer passes.

    Attributes:
        function_name: Identifier of the verified function.
        termination_proof: Optional associated termination proof object.
        arithmetic_issues: Sequence of arithmetic vulnerability findings.
        contract_issues: Sequence of contract violation findings.
        degraded_passes: Sequence of verification passes that degraded to concrete mode.
        paths_explored: Total paths encountered during exploration.
        paths_completed: Total paths successfully explored to termination.

    """

    function_name: object
    termination_proof: TerminationProofLike | None
    arithmetic_issues: Sequence[object]
    contract_issues: Sequence[object]
    degraded_passes: Sequence[str]
    paths_explored: object
    paths_completed: object
