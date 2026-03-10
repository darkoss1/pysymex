"""Scanner with multi-phase analysis pipeline.

This module provides the main :class:`Scanner` orchestrator that
coordinates all analysis phases (type inference, pattern recognition,
flow analysis, bug detection, dead code, resources, security, exceptions)
into a single scan pipeline.

Implementation split across sub-modules for maintainability:
- pipeline_types: ScannerConfig, IssueCategory, ScanIssue, etc.
- pipeline_phases: All concrete AnalysisPhase implementations
- This file: Scanner orchestrator, main() CLI, re-exports
"""

from __future__ import annotations

import json
import logging
import sys
from collections import defaultdict
from pathlib import Path

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

from ..exceptions.handler import ExceptionHandlerAnalyzer
from ..none_check import NoneCheckAnalyzer
from .phases import (
    BugDetectionPhase,
    DeadCodePhase,
    ExceptionPhase,
    FlowAnalysisPhase,
    PatternRecognitionPhase,
    ResourcePhase,
    SecurityPhase,
    TypeInferencePhase,
)
from .phases import (
    _apply_common_suppression as _apply_common_suppression,
)
from .phases import (
    _apply_exception_suppression as _apply_exception_suppression,
)
from .phases import (
    _extract_var_name_from_message as _extract_var_name_from_message,
)
from .phases import (
    _group_issues as _group_issues,
)
from .phases import (
    _is_function_or_class_def as _is_function_or_class_def,
)
from .phases import (
    _is_used_in_annotations as _is_used_in_annotations,
)
from .types import (
    SUGGESTION_MAP,
    AnalysisContext,
    AnalysisPhase,
    IssueCategory,
    ScanIssue,
    ScannerConfig,
)
from .types import (
    _attach_suggestion as _attach_suggestion,
)

logger = logging.getLogger(__name__)

__all__ = [
    "SUGGESTION_MAP",
    "AnalysisContext",
    "AnalysisPhase",
    "BugDetectionPhase",
    "DeadCodePhase",
    "ExceptionPhase",
    "FlowAnalysisPhase",
    "IssueCategory",
    "PatternRecognitionPhase",
    "ResourcePhase",
    "ScanIssue",
    "Scanner",
    "ScannerConfig",
    "SecurityPhase",
    "TypeInferencePhase",
]


class Scanner:
    """
    Enhanced scanner with multi-phase analysis pipeline.
    """

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self.config = config or ScannerConfig()
        self.phases: list[AnalysisPhase] = [
            TypeInferencePhase(),
            PatternRecognitionPhase(),
            FlowAnalysisPhase(),
            BugDetectionPhase(),
            DeadCodePhase(),
            ResourcePhase(),
            SecurityPhase(),
            ExceptionPhase(),
        ]
        self.stats: dict[str, int] = defaultdict(int)

    def scan_file(self, file_path: str) -> list[ScanIssue]:
        """Scan a single file."""
        issues: list[ScanIssue] = []
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            code = compile(source, file_path, "exec")

            eh_analyzer = ExceptionHandlerAnalyzer()
            handlers = eh_analyzer.analyze_source(source)
            nc_analyzer = NoneCheckAnalyzer()
            nc_analyzer.analyze_source(source)
            ctx = AnalysisContext(
                file_path=file_path,
                source=source,
                code=code,
                exception_handlers=handlers,
                none_check_analyzer=nc_analyzer,
            )
            issues.extend(self._run_phases(ctx))
            self._scan_nested(code, source, file_path, issues)
            self.stats["files_scanned"] += 1
            self.stats["issues_found"] += len(issues)
        except SyntaxError as e:
            issues.append(
                ScanIssue(
                    category=IssueCategory.BUG,
                    kind="SYNTAX_ERROR",
                    severity="error",
                    file=file_path,
                    line=e.lineno or 0,
                    message=f"Syntax error: {e .msg }",
                    confidence=1.0,
                )
            )
            self.stats["syntax_errors"] += 1
        except Exception as e:
            if self.config.verbose:
                logger.warning("Error scanning %s: %s", file_path, e)
            self.stats["scan_errors"] += 1
        return issues

    def _scan_nested(
        self,
        code: object,
        source: str,
        file_path: str,
        issues: list[ScanIssue],
        *,
        _dedup_keys: set[tuple[str, int, int]] | None = None,
        _semantic_keys: set[tuple[str, str, str]] | None = None,
    ) -> None:
        """Scan nested functions.

        Parameters
        ----------
        _dedup_keys:
            Internal set tracking ``(kind, line, message_prefix)`` for dedup.
        _semantic_keys:
            Internal set tracking ``(kind, function_name, var_name)`` for
            semantic deduplication -- same variable, same function, same
            issue kind is reported only once.
        """
        if _dedup_keys is None:
            _dedup_keys = {(e.kind, e.line, hash(e.message) if e.message else 0) for e in issues}
        if _semantic_keys is None:
            _semantic_keys = set()
            for e in issues:
                vn = _extract_var_name_from_message(e.message)
                if vn:
                    _semantic_keys.add((e.kind, e.function_name, vn))

        for const in code.co_consts:
            if hasattr(const, "co_code"):
                if len(_cached_get_instructions(const)) > self.config.max_function_size:
                    self.stats["skipped_large_functions"] += 1
                    continue
                ctx = AnalysisContext(
                    file_path=file_path,
                    source=source,
                    code=const,
                )
                new_issues = self._run_phases(ctx)
                for issue in new_issues:

                    key = (issue.kind, issue.line, hash(issue.message) if issue.message else 0)
                    if key in _dedup_keys:
                        continue

                    var_name = _extract_var_name_from_message(issue.message)
                    if var_name:
                        semantic_key = (issue.kind, issue.function_name, var_name)
                        if semantic_key in _semantic_keys:
                            continue
                        _semantic_keys.add(semantic_key)
                    _dedup_keys.add(key)
                    issues.append(issue)
                self._scan_nested(
                    const,
                    source,
                    file_path,
                    issues,
                    _dedup_keys=_dedup_keys,
                    _semantic_keys=_semantic_keys,
                )

    def _run_phases(self, ctx: AnalysisContext) -> list[ScanIssue]:
        """Run all analysis phases."""
        all_issues: list[ScanIssue] = []
        for phase in self.phases:
            try:
                issues = phase.analyze(ctx, self.config)
                for issue in issues:
                    _attach_suggestion(issue)
                all_issues.extend(issues)
            except (RuntimeError, TypeError, ValueError) as e:
                if self.config.verbose:
                    logger.warning("Phase %s failed: %s", phase.name, e)
                self.stats[f"{phase .name }_errors"] += 1
        return all_issues

    def scan_directory(
        self,
        directory: str,
        pattern: str = "**/*.py",
    ) -> list[ScanIssue]:
        """Scan all Python files in directory."""
        all_issues: list[ScanIssue] = []
        path = Path(directory)
        for file_path in path.glob(pattern):
            if file_path.is_file():
                issues = self.scan_file(str(file_path))
                all_issues.extend(issues)
        return all_issues

    def generate_report(
        self,
        issues: list[ScanIssue],
        format: str = "text",
    ) -> str:
        """Generate report from issues."""
        active_issues = [i for i in issues if not i.is_suppressed()]
        suppressed_issues = [i for i in issues if i.is_suppressed()]
        groups = _group_issues(active_issues)

        if format == "json":
            return json.dumps(
                {
                    "issues": [i.to_dict() for i in active_issues],
                    "suppressed": [i.to_dict() for i in suppressed_issues],
                    "groups": [
                        {
                            "file": file,
                            "function": func,
                            "kind": kind,
                            "count": len(group),
                            "lines": sorted(i.line for i in group),
                        }
                        for (file, func, kind), group in sorted(groups.items())
                        if len(group) >= 3
                    ],
                    "stats": dict(self.stats),
                },
                indent=2,
            )
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("pysymex Enhanced Scan Report v2.0")
        lines.append("=" * 60)
        lines.append("")
        by_file: dict[str, list[ScanIssue]] = defaultdict(list)
        for issue in issues:
            if not issue.is_suppressed() or self.config.show_suppressed:
                by_file[issue.file].append(issue)
        for file_path, file_issues in sorted(by_file.items()):
            lines.append(f"\n\U0001f4c4 {file_path }")
            lines.append("-" * 40)

            emitted_groups: set[tuple[str, str]] = set()
            for issue in sorted(file_issues, key=lambda i: i.line):
                group_key = (issue.function_name, issue.kind)
                group = groups.get((issue.file, issue.function_name, issue.kind), [])
                if len(group) >= 3 and group_key not in emitted_groups:

                    kind_label = issue.kind.replace("_", " ").lower()
                    func_label = f" in {issue .function_name }" if issue.function_name else ""
                    lines.append(f"  \U0001f4e6 {len (group )} {kind_label } findings{func_label }")
                    for gi in sorted(group, key=lambda i: i.line):
                        status = "\U0001f534" if gi.severity == "error" else "\U0001f7e1"
                        suppressed = " (SUPPRESSED)" if gi.is_suppressed() else ""
                        lines.append(
                            f"     {status } Line {gi .line }: {gi .message }"
                            f" (confidence: {gi .confidence :.0%}){suppressed }"
                        )
                        if gi.suggestion:
                            lines.append(f"        \U0001f4a1 {gi .suggestion }")
                    emitted_groups.add(group_key)
                elif len(group) < 3:
                    status = "\U0001f534" if issue.severity == "error" else "\U0001f7e1"
                    suppressed = " (SUPPRESSED)" if issue.is_suppressed() else ""
                    lines.append(
                        f"  {status } Line {issue .line }: [{issue .kind }] {issue .message }"
                        f" (confidence: {issue .confidence :.0%}){suppressed }"
                    )
                    if issue.suggestion:
                        lines.append(f"     \U0001f4a1 {issue .suggestion }")

        total = len(active_issues)
        suppressed_count = len(suppressed_issues)
        lines.append("")
        lines.append("=" * 60)
        lines.append("Summary")
        lines.append("=" * 60)
        lines.append(f"Total issues: {total }")
        lines.append(f"Suppressed (likely false positives): {suppressed_count }")
        lines.append(f"Files scanned: {self .stats .get ('files_scanned',0 )}")
        return "\n".join(lines)


def main() -> int:
    """Command-line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description="pysymex Enhanced Scanner v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        help="File or directory to scan",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.7,
        help="Minimum confidence threshold (0.0-1.0)",
    )
    parser.add_argument(
        "--show-suppressed",
        action="store_true",
        help="Show suppressed issues",
    )
    parser.add_argument(
        "--no-suppress",
        action="store_true",
        help="Don't suppress likely false positives",
    )
    args = parser.parse_args()
    config = ScannerConfig(
        verbose=args.verbose,
        min_confidence=args.min_confidence,
        show_suppressed=args.show_suppressed,
        suppress_likely_false_positives=not args.no_suppress,
    )
    scanner = Scanner(config)
    path = Path(args.path)
    if path.is_file():
        issues = scanner.scan_file(str(path))
    elif path.is_dir():
        issues = scanner.scan_directory(str(path))
    else:
        print(f"Error: {args .path } not found")
        return 1
    report = scanner.generate_report(issues, args.format)
    print(report)
    errors = sum(1 for i in issues if i.severity == "error" and not i.is_suppressed())
    return 1 if errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
