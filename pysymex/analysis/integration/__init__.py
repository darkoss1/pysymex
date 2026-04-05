# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
Scanner Integration Module for pysymex.
This module integrates all the new analysis components with the
main scanning pipeline, providing a unified interface for:
- Type inference
- Flow-sensitive analysis
- Pattern recognition
- Taint analysis
- Abstract interpretation
- Enhanced detectors
This creates a comprehensive static analysis pipeline that minimizes
false positives while maximizing bug detection.

Types are in scanner_integration_types, core logic in scanner_integration_core.
This hub re-exports everything and holds the entry-point functions.
"""

from __future__ import annotations

import os
import sys

from .core import (
    AnalysisPipeline,
    ReportGenerator,
)
from .types import (
    AnalysisConfig,
    AnalysisResult,
    AnalysisSummary,
    FunctionContext,
    ModuleContext,
    ReportFormat,
)

__all__ = [
    "AnalysisConfig",
    "AnalysisPipeline",
    "AnalysisResult",
    "AnalysisSummary",
    "FunctionContext",
    "ModuleContext",
    "ReportFormat",
    "ReportGenerator",
    "analyze",
    "main",
]


def analyze(
    target: str,
    config: AnalysisConfig | None = None,
    output_format: ReportFormat = ReportFormat.TEXT,
) -> str:
    """
    Main entry point for analysis.
    Args:
        target: File or directory to analyze
        config: Analysis configuration
        output_format: Output format for report
    Returns:
        Formatted report string
    """
    pipeline = AnalysisPipeline(config)
    if os.path.isfile(target):
        results = {target: pipeline.analyze_file(target)}
    elif os.path.isdir(target):
        results = pipeline.analyze_directory(target)
    else:
        raise ValueError(f"Target not found: {target}")
    generator = ReportGenerator(results)
    if output_format == ReportFormat.TEXT:
        return generator.generate_text()
    elif output_format == ReportFormat.JSON:
        return generator.generate_json()
    elif output_format == ReportFormat.SARIF:
        return generator.generate_sarif()
    else:
        return generator.generate_text()


def main(argv: list[str] | None = None) -> int:
    """Command-line interface."""
    import argparse

    parser = argparse.ArgumentParser(description="pysymex Enhanced Static Analysis")
    parser.add_argument(
        "target",
        help="File or directory to analyze",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--no-type-inference",
        action="store_true",
        help="Disable type inference",
    )
    parser.add_argument(
        "--no-taint",
        action="store_true",
        help="Disable taint analysis",
    )
    parser.add_argument(
        "--include-info",
        action="store_true",
        help="Include info-level issues",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.5,
        help="Minimum confidence threshold (0-1)",
    )
    args = parser.parse_args(argv)
    config = AnalysisConfig(
        type_inference=not args.no_type_inference,
        taint_analysis=not args.no_taint,
        include_info=args.include_info,
        min_confidence=args.min_confidence,
    )
    format_map = {
        "text": ReportFormat.TEXT,
        "json": ReportFormat.JSON,
        "sarif": ReportFormat.SARIF,
    }
    output_format = format_map[args.format]
    try:
        report = analyze(args.target, config, output_format)
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
        else:
            print(report)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
