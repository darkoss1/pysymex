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

"""Top-level pysymex configuration model."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.resources.models import ResourceLimits

from pysymex.guards import is_list_of_objects as is_object_list
from pysymex.config.sections import (
    AnalysisConfig,
    AnalysisLimits,
    ConcurrencyConfig,
    DetectorConfig,
    OutputConfig,
    SolverConfig,
)


@dataclass
class PysymexConfig:
    """Top-level configuration container for pysymex."""

    detectors: DetectorConfig = field(default_factory=DetectorConfig)
    limits: AnalysisLimits = field(default_factory=AnalysisLimits)
    output: OutputConfig = field(default_factory=OutputConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    solver: SolverConfig = field(default_factory=SolverConfig)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    project_root: Path | None = None
    config_file: Path | None = None

    def engine_resource_limits(self) -> ResourceLimits:
        """Return host engine limits for symbolic execution."""
        return self.limits.to_resource_limits()

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for serialization."""
        return {
            "detectors": self.detectors.to_dict(),
            "limits": self.limits.to_dict(),
            "output": self.output.to_dict(),
            "analysis": self.analysis.to_dict(),
            "solver": self.solver.to_dict(),
            "concurrency": self.concurrency.to_dict(),
        }

    def to_toml(self) -> str:
        """Generate TOML configuration string."""
        lines = ["[tool.pysymex]", ""]
        lines.append("[tool.pysymex.detectors]")
        for key, value in self.detectors.to_dict().items():
            if isinstance(value, bool):
                lines.append(f"{key} = {str(value).lower()}")
            elif is_object_list(value):
                normalized_values: list[str] = []
                for raw_val in value:
                    normalized_values.append(str(raw_val))
                items = ", ".join(f'"{v}"' for v in normalized_values)
                lines.append(f"{key} = [{items}]")
            else:
                lines.append(f"{key} = {value}")
        lines.append("")
        lines.append("[tool.pysymex.limits]")
        for key, value in self.limits.to_dict().items():
            lines.append(f"{key} = {value}")
        lines.append("")
        lines.append("[tool.pysymex.output]")
        for key, value in self.output.to_dict().items():
            if isinstance(value, bool):
                lines.append(f"{key} = {str(value).lower()}")
            elif value is None:
                continue
            elif isinstance(value, str):
                lines.append(f'{key} = "{value}"')
            else:
                lines.append(f"{key} = {value}")
        lines.append("")
        lines.append("[tool.pysymex.analysis]")
        for key, value in self.analysis.to_dict().items():
            if isinstance(value, bool):
                lines.append(f"{key} = {str(value).lower()}")
            elif is_object_list(value):
                normalized_values: list[str] = []
                for raw_val in value:
                    normalized_values.append(str(raw_val))
                items = ", ".join(f'"{v}"' for v in normalized_values)
                lines.append(f"{key} = [{items}]")
            elif isinstance(value, str):
                lines.append(f'{key} = "{value}"')
            else:
                lines.append(f"{key} = {value}")
        return "\n".join(lines)
