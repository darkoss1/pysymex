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

"""Orchestrate resource leak, lock safety, and lifecycle analysis passes."""

from __future__ import annotations

from pysymex.logger import get_logger
from types import CodeType

from pysymex.analysis.domains.exceptions.analyzer.core import analyze_nested_code_objects
from pysymex.analysis.domains.resources.usage import ResourceKind, ResourceWarning
from pysymex.analysis.domains.resources.context_managers import ContextManagerAnalyzer
from pysymex.analysis.domains.resources.generator_cleanup import GeneratorCleanupAnalyzer
from pysymex.analysis.domains.resources.leak_detection import ResourceLeakAnalyzer
from pysymex.analysis.domains.resources.lock_safety import LockSafetyAnalyzer
from pysymex.analysis.domains.resources.reference_cycles import ReferenceCycleDetector

logger = get_logger(__name__)


class ResourceAnalyzer:
    """Facade that runs leak, context-manager, cycle, lock, and generator analysers.

    Owns five sub-analyzers as long-lived components.  Call
    :meth:`analyze_function` for a single code object or
    :meth:`analyze_module` / :meth:`analyze_file` for recursive analysis.
    """

    def __init__(self) -> None:
        self.leak_detector = ResourceLeakAnalyzer()
        self.context_analyzer = ContextManagerAnalyzer()
        self.cycle_detector = ReferenceCycleDetector()
        self.lock_analyzer = LockSafetyAnalyzer()
        self.generator_analyzer = GeneratorCleanupAnalyzer()

    def analyze_function(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Run all resource sub-analyzers on *code*.

        Args:
            code: The function's code object.
            file_path: Source file path for diagnostic messages.

        Returns:
            Combined list of :class:`ResourceWarning` findings.
        """
        warnings: list[ResourceWarning] = []
        warnings.extend(self.leak_detector.detect(code, file_path))
        warnings.extend(self.context_analyzer.analyze(code, file_path))
        warnings.extend(self.cycle_detector.detect(code, file_path))
        warnings.extend(self.lock_analyzer.analyze(code, file_path))
        warnings.extend(self.generator_analyzer.analyze(code, file_path))
        return warnings

    def analyze_module(
        self,
        module_code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Analyse *module_code* and all nested code objects.

        Args:
            module_code: Top-level module code object.
            file_path: Source file path for diagnostic messages.

        Returns:
            Combined list of :class:`ResourceWarning` findings.
        """
        warnings: list[ResourceWarning] = []
        warnings.extend(self.analyze_function(module_code, file_path))
        analyze_nested_code_objects(module_code, file_path, warnings, self.analyze_function)
        return warnings

    def analyze_file(self, file_path: str) -> list[ResourceWarning]:
        """Read, compile, and analyse *file_path* for resource issues.

        Returns an ``ANALYSIS_ERROR`` warning on syntax or I/O failure.
        """
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            code = compile(source, file_path, "exec")
            return self.analyze_module(code, file_path)
        except (OSError, SyntaxError) as exc:
            logger.debug("Resource analysis failed for file %s", file_path, exc_info=True)
            return [
                ResourceWarning(
                    kind="ANALYSIS_ERROR",
                    file=file_path,
                    line=getattr(exc, "lineno", 0) or 0,
                    resource_kind=ResourceKind.CONTEXT_MANAGER,
                    resource_name="<analysis>",
                    message=f"Resource analysis failed: {type(exc).__name__}: {exc}",
                    severity="error",
                )
            ]


__all__ = ["ResourceAnalyzer"]
