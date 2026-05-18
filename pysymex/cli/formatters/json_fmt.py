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

"""JSON formatter for scan results."""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from pysymex.config import VERSION
from pysymex.cli.formatters.base import Formatter, verify_result_to_dict


class JsonFormatter(Formatter):
    """Outputs scan results as structured JSON."""

    def format_static(
        self,
        issues: Sequence[Any],
        total: int,
        suppressed: int,
        duration: float,
    ) -> str:
        output_data = {
            "pysymex_version": VERSION,
            "mode": "static",
            "total_issues": total,
            "suppressed_issues": suppressed,
            "issues": [i.to_dict() for i in issues if hasattr(i, "to_dict")],
            "duration": duration,
        }
        return json.dumps(output_data, indent=2, default=str)

    def format_pipeline(
        self,
        results: Mapping[str, Any],
        all_issues: list[tuple[str, Any]],
        total: int,
        duration: float,
    ) -> str:
        output_data = {
            "pysymex_version": VERSION,
            "mode": "pipeline",
            "files_scanned": len(results),
            "total_issues": total,
            "results": {
                fp: {
                    "issues": len(r.issues),
                    "analysis_time": getattr(r, "analysis_time", 0.0),
                    "functions_analyzed": getattr(r, "functions_analyzed", 0),
                    "lines_of_code": getattr(r, "lines_of_code", 0),
                }
                for fp, r in results.items()
            },
            "duration": duration,
        }
        return json.dumps(output_data, indent=2, default=str)

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
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
        output_data = {
            "pysymex_version": VERSION,
            "mode": "verify",
            "functions_verified": len(results),
            "total_issues": total,
            "results": [verify_result_to_dict(result) for result in results],
            "duration": duration,
        }
        return json.dumps(output_data, indent=2, default=str)
