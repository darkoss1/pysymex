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

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import dis
import types
from collections.abc import Sequence

from pysymex.analysis.specialized.flow import FlowContext, FlowSensitiveAnalyzer
from pysymex.analysis.patterns import FunctionPatternInfo, PatternAnalyzer
from pysymex.analysis.type_inference import TypeAnalyzer, TypeEnvironment
from pysymex.core.cache import get_instructions as _cached_get_instructions

from pysymex.analysis.detectors.types import DetectionContext, Issue, StaticDetector

from .division_by_zero import StaticDivisionByZeroDetector
from .key_error import StaticKeyErrorDetector
from .index_error import StaticIndexErrorDetector
from .type_error import StaticTypeErrorDetector
from .attribute_error import StaticAttributeErrorDetector
from .assertion_error import StaticAssertionErrorDetector
from .dead_code import DeadCodeDetector


class DetectorRegistry:
    """Registry of all static-analysis detectors.

    On construction the default set of detectors is registered automatically.
    """

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
    """Enhanced analyzer integrating type inference, patterns, and static detectors.

    Orchestrates ``DetectorRegistry``, ``TypeAnalyzer``, ``PatternAnalyzer``,
    and ``FlowSensitiveAnalyzer`` to analyse function bytecode.

    Attributes:
        registry: Registered static detectors.
        type_analyzer: Type inference engine.
        pattern_analyzer: Safe-pattern recognizer.
        CAUGHT_BY_HANDLER: Sentinel message for filtered issues.
    """

    def __init__(self) -> None:
        self.registry = DetectorRegistry()
        self.type_analyzer = TypeAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()
        self.CAUGHT_BY_HANDLER = "Caught by exception handler"

    def analyze_function(
        self,
        code: types.CodeType,
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
            """Get env at."""
            if isinstance(type_data, dict):
                return type_data.get(pc, TypeEnvironment())
            return type_data

        if pattern_info is None:
            pattern_info = self.pattern_analyzer.analyze_function(code, get_env_at(0))

        if flow_analyzer is None:
            try:
                flow_analyzer = FlowSensitiveAnalyzer(code)
            except (ValueError, TypeError):
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

    def _extract_line_number(self, instr: dis.Instruction, code: types.CodeType) -> int | None:
        """Extract line number from instruction."""
        is_start = instr.starts_line
        if not is_start:
            return None

        if type(is_start) is int:
            return is_start
        if hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
            return instr.positions.lineno
        return code.co_firstlineno

    def _create_detection_context(
        self,
        code: types.CodeType,
        instructions: Sequence[dis.Instruction],
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
