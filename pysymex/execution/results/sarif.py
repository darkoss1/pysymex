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

"""Execution-result SARIF compatibility serialization."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pysymex.config import VERSION

if TYPE_CHECKING:
    from pysymex.execution.results.result import ExecutionResult

__all__ = ["execution_result_to_sarif"]


def execution_result_to_sarif(
    result: ExecutionResult,
    output_path: str | None = None,
) -> dict[str, object]:
    """Return execution-result issue data as SARIF and optionally write it.

    The output intentionally preserves the historic ``ExecutionResult.to_sarif``
    dictionary shape. It does not import :mod:`pysymex.reporting.sarif` because
    execution is a runtime layer and reporting is a presentation layer.
    """
    sarif_results: list[dict[str, object]] = []
    rule_ids: set[str] = set()
    for issue in result.issues:
        rule_id = issue.kind.name.lower()
        rule_ids.add(rule_id)
        sarif_result: dict[str, object] = {
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": issue.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": (issue.filename or result.source_file or "").replace("\\", "/")
                        },
                        "region": {"startLine": issue.line_number or 1},
                    }
                }
            ],
        }
        counterexample = issue.get_counterexample()
        if counterexample:
            sarif_result["properties"] = {"triggeringInput": counterexample}
        sarif_results.append(sarif_result)

    invocation_properties: dict[str, object] = {
        "pathsExplored": result.paths_explored,
        "pathsCompleted": result.paths_completed,
        "pathsPruned": result.paths_pruned,
        "coverageInstructions": len(result.coverage),
        "totalTimeSeconds": round(result.total_time_seconds, 3),
    }
    if result.degraded_passes:
        invocation_properties["degradedPasses"] = list(result.degraded_passes)

    sarif_dict: dict[str, object] = {
        "version": "2.1.0",
        "$schema": ("https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"),
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pysymex",
                        "version": VERSION,
                        "rules": [
                            {
                                "id": rule_id,
                                "name": rule_id,
                                "shortDescription": {"text": f"Issue {rule_id}"},
                            }
                            for rule_id in sorted(rule_ids)
                        ],
                    }
                },
                "results": sarif_results,
                "artifacts": [{"location": {"uri": result.source_file.replace("\\", "/")}}]
                if result.source_file
                else [],
                "invocations": [
                    {
                        "executionSuccessful": not result.degraded_passes,
                        "properties": invocation_properties,
                    }
                ],
            }
        ],
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as sarif_file:
            json.dump(sarif_dict, sarif_file, indent=2, default=str)

    return sarif_dict
