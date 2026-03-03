"""Static bytecode-based detectors for pysymex.

This module provides static bug detectors that integrate with:
- Type inference system
- Flow-sensitive analysis
- Pattern recognition

These detectors are designed to minimize false positives while
catching real bugs.

Implementation spread across three sub-modules:
- ``static_types``: Enums, dataclasses, and the ``StaticDetector`` ABC
- ``static_detectors``: All concrete detector classes
- This file: ``DetectorRegistry``, ``StaticAnalyzer``, and re-exports
"""

from __future__ import annotations


import dis

from typing import (
    Any,
)


from pysymex.analysis.flow_sensitive import (
    FlowContext,
    FlowSensitiveAnalyzer,
)

from pysymex.analysis.patterns import (
    FunctionPatternInfo,
    PatternAnalyzer,
)

from pysymex.analysis.type_inference import (
    TypeAnalyzer,
    TypeEnvironment,
)


from .static_types import (
    DetectionContext,
    StaticDetector,
    Issue,
    IssueKind,
    Severity,
)


from .static_detectors import (
    DeadCodeDetector,
    StaticAssertionErrorDetector,
    StaticAttributeErrorDetector,
    StaticDivisionByZeroDetector,
    StaticIndexErrorDetector,
    StaticKeyErrorDetector,
    StaticTypeErrorDetector,
)

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions


class DetectorRegistry:
    """Registry of all enhanced detectors."""

    def __init__(self) -> None:
        self.detectors: list[StaticDetector] = []

        self._register_default_detectors()

    def _register_default_detectors(self) -> None:
        """Register all default detectors."""

        self.register(StaticDivisionByZeroDetector())

        self.register(StaticKeyErrorDetector())

        self.register(StaticIndexErrorDetector())

        self.register(StaticTypeErrorDetector())

        self.register(StaticAttributeErrorDetector())

        self.register(StaticAssertionErrorDetector())

        self.register(DeadCodeDetector())

    def register(self, detector: StaticDetector) -> None:
        """Register a detector."""

        self.detectors.append(detector)

    def get_all(self) -> list[StaticDetector]:
        """Get all registered detectors."""

        return list(self.detectors)


class StaticAnalyzer:
    """
    Enhanced analyzer that integrates all detection systems.
    """

    def __init__(self) -> None:
        self.registry = DetectorRegistry()

        self.type_analyzer = TypeAnalyzer()

        self.pattern_analyzer = PatternAnalyzer()

        self.CAUGHT_BY_HANDLER = "Caught by exception handler"

    def analyze_function(
        self,
        code: Any,
        file_path: str = "<unknown>",
        type_env: TypeEnvironment | dict[int, TypeEnvironment] | None = None,
        pattern_info: FunctionPatternInfo | None = None,
        flow_analyzer: FlowSensitiveAnalyzer | None = None,
    ) -> list[Issue]:
        """Analyze a function for issues."""

        issues: list[Issue] = []

        instructions = _cached_get_instructions(code)

        if not instructions:
            return issues

        type_data = type_env if type_env is not None else self.type_analyzer.analyze_function(code)

        def get_env_at(pc: int) -> TypeEnvironment:
            if isinstance(type_data, dict):
                return type_data.get(pc, TypeEnvironment())

            return type_data

        if pattern_info is None:
            pattern_info = self.pattern_analyzer.analyze_function(code, get_env_at(0))

        if flow_analyzer is None:
            try:
                flow_analyzer = FlowSensitiveAnalyzer(code)

            except Exception:
                pass

        for instr in instructions:
            line_no = self._extract_line_number(instr, code)

            if line_no is None:
                continue

            ctx = self._create_detection_context(
                code,
                instructions,
                instr,
                line_no,
                get_env_at(instr.offset),
                flow_analyzer,
                pattern_info,
                file_path,
            )

            issues.extend(self._run_detectors(ctx))

        return issues

    def _extract_line_number(self, instr: dis.Instruction, code: Any) -> int | None:
        """Extract line number from instruction."""

        is_start = instr.starts_line

        if is_start is None or is_start is False:
            return None

        if type(is_start) is int:
            return is_start

        if hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
            return instr.positions.lineno

        return code.co_firstlineno

    def _create_detection_context(
        self,
        code: Any,
        instructions: list[dis.Instruction],
        instr: dis.Instruction,
        line_no: int,
        env: TypeEnvironment,
        flow_analyzer: FlowSensitiveAnalyzer | None,
        pattern_info: FunctionPatternInfo,
        file_path: str,
    ) -> DetectionContext:
        """Create detection context for an instruction."""

        flow_context = FlowContext.create(flow_analyzer, instr.offset) if flow_analyzer else None

        return DetectionContext(
            code=code,
            instructions=instructions,
            pc=instr.offset,
            instruction=instr,
            line=line_no,
            type_env=env,
            flow_context=flow_context,
            pattern_info=pattern_info,
            file_path=file_path,
            function_name=code.co_name,
        )

    def _run_detectors(self, ctx: DetectionContext) -> list[Issue]:
        """Run all registered detectors for a context."""

        issues: list[Issue] = []

        for detector in self.registry.get_all():
            if detector.should_check(ctx):
                issue = detector.check(ctx)

                if issue and not issue.is_suppressed():
                    issues.append(issue)

        return issues
