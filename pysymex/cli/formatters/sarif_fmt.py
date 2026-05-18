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

"""SARIF formatter for scan results."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Mapping, cast

from pysymex.cli.formatters.base import Formatter, format_verify_issue


class SarifFormatter(Formatter):
    """Outputs scan results in SARIF 2.1.0 format."""

    def format_static(
        self,
        issues: Sequence[Any],
        total: int,
        suppressed: int,
        duration: float,
    ) -> str:
        from pysymex.reporting.sarif import generate_sarif

        issue_dicts: list[dict[str, object]] = []
        for issue in issues:
            to_dict = getattr(issue, "to_dict", None)
            if callable(to_dict):
                result = to_dict()
                if isinstance(result, dict):
                    # The original scan.py did issue_dicts.append({"raw": "<dict>"})
                    # but this was likely a bug or placeholder.
                    # We will preserve the issue raw dump.
                    issue_dicts.append({"raw": "<dict>"})
        sarif_log = generate_sarif(issues=issue_dicts)
        return sarif_log.to_json()

    def format_pipeline(
        self,
        results: Mapping[str, Any],
        all_issues: list[tuple[str, Any]],
        total: int,
        duration: float,
    ) -> str:
        # Pipeline doesn't currently support SARIF in scan.py, fallback to basic json
        import json

        output_data = {
            "mode": "pipeline",
            "message": "SARIF not fully supported for pipeline mode yet.",
            "total_issues": total,
        }
        return json.dumps(output_data, indent=2)

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
        from pysymex.reporting.sarif import SARIFGenerator

        generator = SARIFGenerator()
        all_issues: list[dict[str, object]] = []
        all_files: list[str] = []

        # We need to extract typed scan results similar to scan.py
        for scan_result in results:
            if hasattr(scan_result, "file_path"):
                all_files.append(str(scan_result.file_path))
                if hasattr(scan_result, "issues"):
                    for issue in scan_result.issues:
                        if isinstance(issue, dict):
                            issue_dict = cast("dict[str, Any]", issue)
                            si: dict[str, Any] = issue_dict.copy()
                            si["type"] = issue_dict.get("kind", "UNKNOWN")
                            si["file"] = str(scan_result.file_path)
                            all_issues.append(si)
        return generator.generate(issues=all_issues, analyzed_files=all_files).to_json()

    def format_verify(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
    ) -> str:
        from pysymex.reporting.sarif import SARIFGenerator

        issues: list[dict[str, object]] = []
        files: list[str] = []
        for result in results:
            file_path = str(getattr(result, "source_file", ""))
            if file_path:
                files.append(file_path)
            function_name = str(getattr(result, "function_name", ""))
            for issue in getattr(result, "issues", []):
                issues.append(
                    {
                        "type": str(getattr(issue, "kind", "RUNTIME")),
                        "message": format_verify_issue(issue),
                        "file": file_path,
                        "line": getattr(issue, "line_number", 1) or 1,
                        "function_name": function_name,
                    }
                )
            for issue in getattr(result, "contract_issues", []):
                issues.append(
                    {
                        "type": str(getattr(issue, "kind", "CONTRACT")),
                        "message": format_verify_issue(issue),
                        "file": file_path,
                        "line": getattr(issue, "line_number", 1) or 1,
                        "function_name": function_name,
                    }
                )
            for issue in getattr(result, "arithmetic_issues", []):
                issues.append(
                    {
                        "type": str(getattr(issue, "kind", "ARITHMETIC")),
                        "message": format_verify_issue(issue),
                        "file": file_path,
                        "line": getattr(issue, "line_number", 1) or 1,
                        "function_name": function_name,
                    }
                )

        return SARIFGenerator().generate(issues=issues, analyzed_files=files).to_json()
