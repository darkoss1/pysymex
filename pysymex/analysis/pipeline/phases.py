"""Analysis pipeline phases and suppression logic.

Contains all concrete AnalysisPhase implementations and the false-positive
suppression functions they share.

Phases (executed in order):
1. TypeInferencePhase — infer variable types
2. PatternRecognitionPhase — recognize safe code patterns
3. FlowAnalysisPhase — flow-sensitive data-flow analysis
4. BugDetectionPhase — bug detection with context
5. DeadCodePhase — dead code detection
6. ResourcePhase — resource leak detection
7. SecurityPhase — taint + string security analysis
8. ExceptionPhase — exception handling quality
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import cast

from ..dead_code import DeadCodeAnalyzer, find_dataclass_class_names, is_class_body
from ..detectors.static import StaticAnalyzer
from ..exceptions.analysis import ExceptionAnalyzer
from ..exceptions.handler import should_skip_issue_in_handler
from ..false_positive_filter import filter_issue
from ..flow_sensitive import FlowSensitiveAnalyzer
from ..none_check import is_none_check_in_message
from ..patterns import PatternAnalyzer, PatternKind
from ..resources.analysis import ResourceAnalyzer
from ..string_analysis import StringAnalyzer
from ..taint.checker import TaintChecker
from ..type_inference import TypeAnalyzer, TypeEnvironment
from .types import (
    AnalysisContext,
    AnalysisPhase,
    IssueCategory,
    ScanIssue,
    ScannerConfig,
)

logger = logging.getLogger(__name__)

__all__ = [
    "BugDetectionPhase",
    "DeadCodePhase",
    "ExceptionPhase",
    "FlowAnalysisPhase",
    "PatternRecognitionPhase",
    "ResourcePhase",
    "SecurityPhase",
    "TypeInferencePhase",
]


class TypeInferencePhase(AnalysisPhase):
    """Phase 1: Run type inference and populate ``ctx.types``."""

    name = "type_inference"

    def __init__(self) -> None:
        self.analyzer = TypeAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[ScanIssue]:
        """Run type inference."""
        if not config.enable_type_inference:
            return []
        type_env = self.analyzer.analyze_function(ctx.code)
        ctx.types = cast("dict[str, object]", type_env)
        return []


class PatternRecognitionPhase(AnalysisPhase):
    """Phase 2: Recognise safe code patterns to suppress false positives."""

    name = "pattern_recognition"

    def __init__(self) -> None:
        self.analyzer = PatternAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[ScanIssue]:
        """Recognize patterns."""
        if not config.enable_pattern_recognition:
            return []
        patterns = self.analyzer.analyze_function(ctx.code)
        ctx.patterns = patterns
        return []


class FlowAnalysisPhase(AnalysisPhase):
    """Phase 3: Build flow-sensitive analyser and populate ``ctx.flow_analyzer``."""

    name = "flow_analysis"

    def __init__(self) -> None:
        pass

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[ScanIssue]:
        """Run flow analysis."""
        if not config.enable_flow_analysis:
            return []
        try:
            ctx.flow_analyzer = FlowSensitiveAnalyzer(ctx.code)
        except (ValueError, TypeError):
            logger.debug("Flow analysis initialization failed", exc_info=True)
        return []


class BugDetectionPhase(AnalysisPhase):
    """Phase 4: Run static detectors with full type/flow/pattern context."""

    name = "bug_detection"

    def __init__(self) -> None:
        self.analyzer = StaticAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[ScanIssue]:
        """Detect bugs with enhanced precision."""
        issues: list[ScanIssue] = []
        raw_issues = self.analyzer.analyze_function(
            ctx.code,
            ctx.file_path,
            type_env=cast("TypeEnvironment | None", ctx.types),
            pattern_info=ctx.patterns,
            flow_analyzer=ctx.flow_analyzer,
        )
        for issue in raw_issues:
            enhanced = ScanIssue(
                category=IssueCategory.BUG,
                kind=issue.kind.name,
                severity=issue.severity.name,
                file=issue.file,
                line=issue.line,
                message=issue.message,
                confidence=issue.confidence,
                function_name=ctx.code.co_name,
                detected_by=["static_detectors"],
            )
            if config.suppress_likely_false_positives:
                self._check_suppression(enhanced, ctx)
            if enhanced.confidence >= config.min_confidence:
                issues.append(enhanced)
        return issues

    def _check_suppression(
        self,
        issue: ScanIssue,
        ctx: AnalysisContext,
    ) -> None:
        """Check if issue should be suppressed."""

        _apply_common_suppression(issue, ctx)

        line = issue.line
        if ctx.patterns and hasattr(ctx.patterns, "matcher"):

            all_patterns: list[object] = []
            for _start_pc, matches in ctx.patterns.matcher._cache.items():
                for match in matches:
                    if match.line is not None and match.line == line:
                        all_patterns.append(match)
            pattern_kinds = {p.kind for p in all_patterns}
            if issue.kind == "KEY_ERROR" and PatternKind.DEFAULTDICT_ACCESS in pattern_kinds:
                issue.suppression_reasons.append("defaultdict access is safe")
                issue.confidence *= 0.1
            if issue.kind == "KEY_ERROR" and PatternKind.DICT_GET in pattern_kinds:
                issue.suppression_reasons.append("dict.get() handles missing keys")
                issue.confidence *= 0.1
            if issue.kind == "INDEX_ERROR" and PatternKind.ENUMERATE_ITER in pattern_kinds:
                issue.suppression_reasons.append("enumerate provides valid indices")
                issue.confidence *= 0.1

        class MockIssue:
            def __init__(self, kind: str, line: int, message: str, function_name: str) -> None:
                from ..detectors.static import IssueKind

                try:
                    self.kind = IssueKind[kind]
                except (KeyError, AttributeError):
                    self.kind = IssueKind.UNKNOWN
                self.line_number = line
                self.message = message
                self.function_name = function_name
                self.model = None

        mock = MockIssue(issue.kind, issue.line, issue.message, issue.function_name)
        result = filter_issue(mock, ctx.source)
        if result.should_filter:
            issue.suppression_reasons.append(f"FP Filter: {result .reason }")
            issue.confidence *= 0.5


def _apply_common_suppression(issue: ScanIssue, ctx: AnalysisContext) -> None:
    """Apply common false positive suppression rules across all phases."""

    if ctx.exception_handlers and should_skip_issue_in_handler(
        issue.line, issue.kind, ctx.exception_handlers
    ):
        issue.confidence *= 0.1
        issue.suppression_reasons.append("inside exception handler")

    if ctx.none_check_analyzer and issue.kind in (
        "NONE_DEREFERENCE",
        "ATTRIBUTE_ERROR",
        "TYPE_ERROR",
    ):
        is_none_msg, var_name = is_none_check_in_message(issue.message)
        if is_none_msg and var_name and ctx.none_check_analyzer.is_none_safe(var_name):
            issue.confidence *= 0.1
            issue.suppression_reasons.append(f"'{var_name }' is None-checked")
    if issue.kind in ("UNUSED_VARIABLE", "DEAD_STORE"):
        msg = issue.message
        var_name = ""
        if "Variable '" in msg:
            parts = msg.split("Variable '", 1)
            var_name = parts[1].split("'")[0] if len(parts) > 1 else ""
        elif "Value of '" in msg:
            parts = msg.split("Value of '", 1)
            var_name = parts[1].split("'")[0] if len(parts) > 1 else ""

        if var_name == "annotations" and "annotations" in msg:
            issue.suppression_reasons.append("__future__ annotations import")
            issue.confidence *= 0.0
            return

        if var_name in ("i", "j", "k", "idx", "index", "_"):
            issue.suppression_reasons.append("Loop counter variable")
            issue.confidence *= 0.0
            return

        if ctx.code.co_name == "<module>" and var_name in (
            "ast",
            "re",
            "os",
            "sys",
            "json",
            "dis",
            "math",
            "auto",
            "inspect",
            "typing",
            "collections",
            "functools",
            "pathlib",
            "dataclasses",
            "enum",
            "abc",
            "io",
            "textwrap",
            "copy",
        ):
            issue.suppression_reasons.append("Standard library import (cross-function usage)")
            issue.confidence *= 0.0
            return

        if var_name.startswith("_") and not var_name.startswith("__"):
            issue.suppression_reasons.append("Underscore-prefixed variable (unused by convention)")
            issue.confidence *= 0.3

        if ctx.file_path.endswith("__init__.py"):
            issue.suppression_reasons.append("Likely re-export in __init__.py")
            issue.confidence *= 0.2

        if var_name in (
            "__all__",
            "__version__",
            "__author__",
            "__doc__",
            "__slots__",
            "__annotations__",
        ):
            issue.suppression_reasons.append("Dunder variable used implicitly")
            issue.confidence *= 0.0
            return

        if is_class_body(ctx.code):

            if ctx.source and "dataclass" in ctx.source:
                dc_names = find_dataclass_class_names(ctx.source)
                if ctx.code.co_name in dc_names:
                    issue.suppression_reasons.append("Dataclass field default")
                    issue.confidence *= 0.0
                    return

            for const in ctx.code.co_consts:
                if hasattr(const, "co_code") and getattr(const, "co_name", None) == var_name:
                    issue.suppression_reasons.append("Class method/function definition")
                    issue.confidence *= 0.0
                    return

            if var_name and var_name.isupper():
                issue.suppression_reasons.append("Class-level constant")
                issue.confidence *= 0.3

            if var_name and not var_name.startswith("_") and not var_name.isupper():
                issue.suppression_reasons.append("Class attribute (accessible via instances)")
                issue.confidence *= 0.3

        if ctx.code.co_name == "<module>" and var_name and var_name.isupper():
            issue.suppression_reasons.append("Module-level constant (likely exported)")
            issue.confidence *= 0.3

        if ctx.code.co_name == "<module>" and var_name and not var_name.startswith("_"):

            if var_name.startswith(("on_", "test_", "setup", "teardown")):
                issue.suppression_reasons.append("Likely decorator-assigned callback")
                issue.confidence *= 0.3

        if (
            issue.kind == "UNUSED_VARIABLE"
            and ctx.code.co_name == "<module>"
            and var_name
            and ctx.source
        ):
            if _is_used_in_annotations(var_name, ctx.source):
                issue.suppression_reasons.append(
                    "Used in type annotations (PEP 563 postponed evaluation)"
                )
                issue.confidence *= 0.0
                return

        if (
            issue.kind == "UNUSED_VARIABLE"
            and ctx.code.co_name == "<module>"
            and var_name
            and not var_name.startswith("_")
            and ctx.source
        ):

            if _is_function_or_class_def(var_name, ctx.source):
                issue.suppression_reasons.append("Module-level function/class (likely exported)")
                issue.confidence *= 0.3

    if issue.kind == "UNREACHABLE_CODE" and ctx.code.co_name == "<module>":
        line = issue.line
        if line <= 50:
            issue.suppression_reasons.append("Likely try/except import pattern")
            issue.confidence *= 0.0
            return

    if issue.kind == "UNREACHABLE_CODE" and "at end of function" in issue.message:
        issue.suppression_reasons.append("Implicit return None (end-of-function FP)")
        issue.confidence *= 0.0
        return

    if issue.kind == "UNUSED_PARAMETER":
        param_name = ""
        if "Parameter '" in issue.message:
            parts = issue.message.split("Parameter '", 1)
            param_name = parts[1].split("'")[0] if len(parts) > 1 else ""

        func_name = issue.function_name or ctx.code.co_name
        if func_name.startswith("_op_") or func_name.startswith("_handle_"):
            issue.suppression_reasons.append("Dispatcher method with fixed interface")
            issue.confidence *= 0.0
            return

        if param_name.startswith("_"):
            issue.suppression_reasons.append("Underscore-prefixed parameter (unused by convention)")
            issue.confidence *= 0.0
            return

        if param_name in ("self", "cls"):
            issue.suppression_reasons.append("Required method parameter (self/cls)")
            issue.confidence *= 0.0
            return

        if func_name.startswith("visit_"):
            issue.suppression_reasons.append("Visitor pattern method (fixed interface)")
            issue.confidence *= 0.0
            return

        if func_name in (
            "analyze",
            "check",
            "detect",
            "run",
            "process",
            "analyze_function",
            "analyze_source",
            "analyze_module",
            "check_function",
            "build",
            "scan",
            "join",
            "meet",
            "widen",
            "narrow",
            "leq",
            "add",
            "sub",
            "mul",
            "div",
            "neg",
            "transfer",
            "match",
            "from_concrete",
            "add_state",
            "can_raise_error",
            "check_implies",
            "infer_call_result",
            "to_z3_constraint",
            "check_shift_safety",
            "analyze_source_context",
        ):
            issue.suppression_reasons.append("Interface method with standard signature")
            issue.confidence *= 0.3

        if func_name.startswith("__") and func_name.endswith("__"):
            issue.suppression_reasons.append("Dunder method with protocol-mandated signature")
            issue.confidence *= 0.0
            return

        if func_name.startswith(
            (
                "_check_",
                "_parse_",
                "_has_",
                "_transfer_",
                "_build_",
                "_analyze_",
                "_detect_",
                "_identify_",
                "_infer_",
                "_is_",
                "_key_",
                "_in_",
            )
        ):
            issue.suppression_reasons.append("Internal method with fixed interface")
            issue.confidence *= 0.0
            return

        if func_name.startswith(
            (
                "check_",
                "add_",
                "compose_",
                "get_",
                "is_",
                "resolve_",
                "should_",
                "verify_",
            )
        ) or func_name in ("apply",):
            issue.suppression_reasons.append("Analysis interface method with standard signature")
            issue.confidence *= 0.0
            return

    if issue.kind == "UNUSED_VARIABLE" and ctx.code.co_name == "<module>" and ctx.source:
        if "from " in ctx.source and " import " in ctx.source:
            lines = ctx.source.strip().splitlines()
            non_empty = [ln for ln in lines if ln.strip() and not ln.strip().startswith("#")]

            if len(non_empty) <= 5:
                issue.suppression_reasons.append("Likely re-export shim module")
                issue.confidence *= 0.0
                return

            if "__all__" in ctx.source:
                issue.suppression_reasons.append("Re-export module with __all__")
                issue.confidence *= 0.0
                return

        var_name = _extract_var_name_from_message(issue.message)
        if var_name and var_name[0].isupper() and not var_name.startswith("__"):
            issue.suppression_reasons.append("Imported type/class (likely used cross-module)")
            issue.confidence *= 0.3


def _apply_exception_suppression(issue: ScanIssue, _ctx: AnalysisContext) -> None:
    """Apply suppression rules for exception analysis findings."""

    if issue.kind == "TOO_BROAD_EXCEPT" and issue.severity == "info":
        issue.suppression_reasons.append("Handler has safety net or logging (info severity)")
        issue.confidence *= 0.0
        return

    if issue.kind in ("EXCEPTION_SWALLOWED", "EXCEPTION_NOT_LOGGED"):
        issue.suppression_reasons.append("Likely intentional resilience pattern")
        issue.confidence *= 0.5

    if issue.kind == "TOO_BROAD_EXCEPT" and issue.severity == "warning":
        issue.suppression_reasons.append("Defensive except pattern")
        issue.confidence *= 0.5


def _is_used_in_annotations(var_name: str, source: str) -> bool:
    """Check if a name is used in type annotations in the source."""
    import ast as _ast

    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return False

    annotation_names: set[str] = set()

    class _AnnotationVisitor(_ast.NodeVisitor):
        def _scan_annotation(self, node: _ast.expr | None) -> None:
            if node is None:
                return
            for child in _ast.walk(node):
                if isinstance(child, _ast.Name):
                    annotation_names.add(child.id)
                elif isinstance(child, _ast.Attribute) and isinstance(child.value, _ast.Name):
                    annotation_names.add(child.value.id)

                elif isinstance(child, _ast.Constant) and isinstance(child.value, str):
                    if var_name in child.value:
                        annotation_names.add(var_name)

        def visit_FunctionDef(self, node: _ast.FunctionDef) -> None:
            if node.returns:
                self._scan_annotation(node.returns)
            for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                self._scan_annotation(arg.annotation)
            if node.args.vararg and node.args.vararg.annotation:
                self._scan_annotation(node.args.vararg.annotation)
            if node.args.kwarg and node.args.kwarg.annotation:
                self._scan_annotation(node.args.kwarg.annotation)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: _ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(cast("_ast.FunctionDef", node))

        def visit_AnnAssign(self, node: _ast.AnnAssign) -> None:
            self._scan_annotation(node.annotation)
            self.generic_visit(node)

    _AnnotationVisitor().visit(tree)
    return var_name in annotation_names


def _is_function_or_class_def(var_name: str, source: str) -> bool:
    """Check if a name is defined as a function or class in the source."""
    import ast as _ast

    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return False
    for node in _ast.iter_child_nodes(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            if node.name == var_name:
                return True
    return False


def _extract_var_name_from_message(message: str) -> str:
    """Extract variable/parameter name from issue message.

    Handles patterns like ``Variable 'x' is ...``, ``Value of 'x' is ...``,
    ``Parameter 'x' is ...``, ``Import 'x' is ...``, etc.
    """
    if "'" in message:
        parts = message.split("'")
        if len(parts) >= 2:
            return parts[1]
    return ""


def _group_issues(
    issues: list[ScanIssue],
) -> dict[tuple[str, str, str], list[ScanIssue]]:
    """Group issues by (file, function_name, kind) for report grouping."""
    groups: dict[tuple[str, str, str], list[ScanIssue]] = defaultdict(list)
    for issue in issues:
        key = (issue.file, issue.function_name, issue.kind)
        groups[key].append(issue)
    return dict(groups)


class DeadCodePhase(AnalysisPhase):
    """Phase 5: Dead code detection.

    Delegates to :class:`DeadCodeAnalyzer` and applies common FP suppression.
    """

    name = "dead_code"

    def __init__(self) -> None:
        self.analyzer = DeadCodeAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[ScanIssue]:
        """Detect dead code."""
        if not config.enable_dead_code:
            return []
        issues: list[ScanIssue] = []
        dead_code = self.analyzer.analyze_function(ctx.code, ctx.file_path)
        for dc in dead_code:
            enhanced = ScanIssue(
                category=IssueCategory.DEAD_CODE,
                kind=dc.kind.name,
                severity="warning",
                file=dc.file,
                line=dc.line,
                message=dc.message,
                confidence=dc.confidence,
                function_name=ctx.code.co_name,
                detected_by=["dead_code_analyzer"],
            )
            if config.suppress_likely_false_positives:
                _apply_common_suppression(enhanced, ctx)
            if enhanced.confidence >= config.min_confidence:
                issues.append(enhanced)
        return issues


class ResourcePhase(AnalysisPhase):
    """Phase 6: Resource leak detection.

    Delegates to :class:`ResourceAnalyzer` for unclosed file/socket warnings.
    """

    name = "resource_analysis"

    def __init__(self) -> None:
        self.analyzer = ResourceAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[ScanIssue]:
        """Detect resource leaks."""
        if not config.enable_resource_analysis:
            return []
        issues: list[ScanIssue] = []
        warnings = self.analyzer.analyze_function(ctx.code, ctx.file_path)
        for warn in warnings:
            issues.append(
                ScanIssue(
                    category=IssueCategory.RESOURCE,
                    kind=warn.kind,
                    severity=warn.severity,
                    file=warn.file,
                    line=warn.line,
                    message=warn.message,
                    confidence=0.8,
                    function_name=ctx.code.co_name,
                    detected_by=["resource_analyzer"],
                )
            )
        return issues


class SecurityPhase(AnalysisPhase):
    """Phase 7: Security analysis (taint + string).

    Combines :class:`TaintChecker` and :class:`StringAnalyzer` to detect
    injection, XSS, path-traversal, and related vulnerabilities.
    """

    name = "security"

    def __init__(self) -> None:
        self.taint_checker = TaintChecker()
        self.string_analyzer = StringAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[ScanIssue]:
        """Run security analysis."""
        issues: list[ScanIssue] = []
        if config.enable_taint_analysis:
            taint_issues = self.taint_checker.check_function(ctx.code)
            for ti in taint_issues:

                taint_line = getattr(ti, "sink_line", None) or getattr(ti, "line", 0)
                taint_kind = "TAINT"
                if hasattr(ti, "sink") and hasattr(ti.sink, "kind"):
                    taint_kind = ti.sink.kind.name
                elif hasattr(ti, "kind"):
                    taint_kind = ti.kind.name if hasattr(ti.kind, "name") else str(ti.kind)

                taint_severity = "error"
                if hasattr(ti, "sink") and hasattr(ti.sink, "severity"):
                    taint_severity = ti.sink.severity
                issues.append(
                    ScanIssue(
                        category=IssueCategory.SECURITY,
                        kind=taint_kind,
                        severity=taint_severity,
                        file=ctx.file_path,
                        line=taint_line,
                        message=str(ti),
                        confidence=0.9,
                        function_name=ctx.code.co_name,
                        detected_by=["taint_analysis"],
                    )
                )
        if config.enable_string_analysis:
            string_issues = self.string_analyzer.analyze_source(ctx.source, ctx.file_path)
            for si in string_issues:
                issues.append(
                    ScanIssue(
                        category=IssueCategory.SECURITY,
                        kind=si.kind.name,
                        severity=si.severity,
                        file=si.file,
                        line=si.line,
                        message=si.message,
                        confidence=0.85,
                        detected_by=["string_analysis"],
                    )
                )
        return issues


class ExceptionPhase(AnalysisPhase):
    """Phase 8: Exception handling analysis.

    Flags overly broad except clauses, swallowed exceptions, and
    missing logging via :class:`ExceptionAnalyzer`.
    """

    name = "exception"

    def __init__(self) -> None:
        self.analyzer = ExceptionAnalyzer()

    def analyze(
        self,
        ctx: AnalysisContext,
        config: ScannerConfig,
    ) -> list[ScanIssue]:
        """Analyze exception handling."""
        if not config.enable_exception_analysis:
            return []
        issues: list[ScanIssue] = []
        warnings = self.analyzer.analyze_source(ctx.source, ctx.file_path)
        for warn in warnings:
            enhanced = ScanIssue(
                category=IssueCategory.STYLE,
                kind=warn.kind.name,
                severity=warn.severity,
                file=warn.file,
                line=warn.line,
                message=warn.message,
                confidence=0.8,
                detected_by=["exception_analysis"],
            )
            if config.suppress_likely_false_positives:
                _apply_exception_suppression(enhanced, ctx)
            if enhanced.confidence >= config.min_confidence:
                issues.append(enhanced)
        return issues
