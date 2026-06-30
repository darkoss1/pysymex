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

"""JSON formatter for scan results."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from pysymex._internal.cli.formatters.base import CliFormatter, verify_result_to_dict
from pysymex._internal.config.defaults import VERSION
from pysymex._internal.contracts.reports.evidence import verified_results_evidence_report

if TYPE_CHECKING:
    from collections.abc import Sequence


class JsonFormatter(CliFormatter):
    """Outputs scan results as structured JSON."""

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
        """Format symbolic execution scan results as a JSON-encoded string.

        Args:
            results (Sequence[Any]): Sequence of symbolic execution results.
            total (int): Total number of issues found.
            duration (float): Execution duration in seconds.
            reproduce (bool): True if reproduction test cases are requested, False otherwise.
                Defaults to False.
            show_stats (bool): True to include performance statistics in the report.
                Defaults to False.

        Returns:
            str: JSON string containing symbolic execution scan results.

        """
        output_data = {
            "pysymex_version": VERSION,
            "mode": "symbolic",
            "files_scanned": len(results),
            "total_issues": total,
            "results": [r.to_dict() for r in results if hasattr(r, "to_dict")],
            "duration": duration,
        }
        return json.dumps(output_data, indent=2, default=str)

    def format_verify(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
    ) -> str:
        """Format formal verification results as a JSON-encoded string.

        Args:
            results (Sequence[Any]): Sequence of verification results.
            total (int): Total number of verification issues found.
            duration (float): Verification execution duration in seconds.

        Returns:
            str: JSON string containing verification execution results.

        """
        output_data = verified_results_evidence_report(
            results,
            total=total,
            duration=duration,
            pysymex_version=VERSION,
        )
        result_entries = cast("list[dict[str, object]]", output_data["results"])
        for result_data, result in zip(result_entries, results, strict=True):
            result_data.update(verify_result_to_dict(result))
        return json.dumps(output_data, indent=2, default=str)
