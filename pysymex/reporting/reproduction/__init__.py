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

"""Auto-Reproduction Generator."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from pysymex.analysis.detectors import Issue
from pysymex.logger import get_logger
from pysymex.reporting.reproduction.args import (
    ReproductionArgsMixin,
    TYPE_DEFAULTS,
)
from pysymex.reporting.reproduction.output import ReproductionOutputMixin

logger = get_logger(__name__)


@dataclass(frozen=True)
class ReproductionModuleContext:
    """Import context for loading the target module in a generated script."""

    module_name: str
    source_file: str
    import_root: str


class ReproductionGenerator(ReproductionArgsMixin, ReproductionOutputMixin):
    """Generate concrete-input scripts for replaying detected issues.

    Limitations:
        A generated script is runtime replay evidence for one counterexample.
        It is not a proof that every reported path is feasible.
    """

    def __init__(self, output_dir: str | None = None) -> None:
        """Initialize the reproduction script generator.

        Args:
            output_dir: Target directory path to write generated regression scripts.
                If not specified, defaults to '.pysymex/reproduction' in the current
                working directory.
        """
        if output_dir is None:
            # Default to .pysymex/reproduction in the current working directory
            output_dir = os.path.join(".pysymex", "reproduction")

        self.output_dir = output_dir
        self._ensure_output_dir()

    def generate_script(self, issue: Issue) -> str | None:
        """
        Convenience wrapper for generate() using metadata from an Issue object.

        Args:
            issue: The detected issue.

        Returns:
            Path to the generated script, or None if generation failed.
        """
        if not issue.function_name or not issue.filename:
            logger.warning("Skipping reproduction script; issue lacks function or filename")
            return None
        return self.generate(
            issue=issue,
            func_name=issue.function_name,
            source_file=issue.filename,
            class_name=issue.class_name,
        )

    def generate(
        self, issue: Issue, func_name: str, source_file: str, class_name: str | None = None
    ) -> str | None:
        """
        Generate a reproduction script for a specific issue.

        Args:
            issue: The detected issue containing the counterexample.
            func_name: Name of the function where the issue occurred.
            source_file: Path to the source file containing the function.
            class_name: Optional name of the class if the function is a method.

        Returns:
            Path to the generated script, or None if generation failed.
        """
        counterexample = issue.get_counterexample()
        if not counterexample:
            logger.warning("Skipping reproduction script for %s; missing counterexample", func_name)
            return None
        module_context = self._module_context_for_source(source_file)
        if module_context is None:
            logger.warning(
                "Skipping reproduction script for %s; module name unresolved", source_file
            )
            return None
        args_list = self._build_args_list(counterexample, source_file, func_name, class_name)
        args_code = ",\n            ".join(args_list)
        clean_args = [arg.split("#")[0].strip() for arg in args_list]
        args_display = ", ".join(clean_args)
        script_content = self._create_script_content(
            module_name=module_context.module_name,
            source_file=module_context.source_file,
            import_root=module_context.import_root,
            func_name=func_name,
            class_name=class_name,
            args_code=args_code,
            args_display=args_display,
            issue_kind=issue.kind.name,
            message=issue.message,
        )
        filename = self._script_filename(issue.kind.name, func_name, class_name)
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(script_content)
            logger.verbose("Generated reproduction script %s", filepath)
            return filepath
        except OSError:
            logger.warning("Failed to write reproduction script %s", filepath, exc_info=True)
            return None

    def _module_context_for_source(self, source_file: str) -> ReproductionModuleContext | None:
        abs_source = os.path.abspath(source_file)
        package_parts: list[str] = []
        current_dir = os.path.dirname(abs_source)
        while os.path.isfile(os.path.join(current_dir, "__init__.py")):
            package_parts.append(os.path.basename(current_dir))
            parent_dir = os.path.dirname(current_dir)
            if parent_dir == current_dir:
                break
            current_dir = parent_dir

        source_name = os.path.splitext(os.path.basename(abs_source))[0]
        if package_parts:
            module_name = ".".join([*reversed(package_parts), source_name])
            return ReproductionModuleContext(
                module_name=module_name,
                source_file=abs_source,
                import_root=current_dir,
            )

        safe_name = self._safe_identifier(source_name)
        if not safe_name:
            return None
        return ReproductionModuleContext(
            module_name=f"_pysymex_repro_{safe_name}",
            source_file=abs_source,
            import_root=os.path.dirname(abs_source),
        )

    def _script_filename(
        self, issue_kind: str, func_name: str, class_name: str | None = None
    ) -> str:
        kind_tag = issue_kind.lower().replace("_error", "")
        target = f"{class_name}_{func_name}" if class_name else func_name
        return f"repro_{self._safe_filename(kind_tag)}_{self._safe_filename(target)}.py"

    def _safe_identifier(self, value: str) -> str:
        safe = re.sub(r"\W+", "_", value).strip("_")
        if not safe:
            return ""
        if safe[0].isdigit():
            safe = f"mod_{safe}"
        return safe

    def _safe_filename(self, value: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
        return safe or "issue"


__all__ = ["ReproductionGenerator", "TYPE_DEFAULTS"]
