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

"""Classify profiler frames by ownership origin and subsystem phase."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

ProfileFrameOrigin = Literal["engine", "target", "project", "dependency", "runtime"]
ProfilePhase = Literal[
    "formula_and_evidence",
    "solver_engine",
    "detectors",
    "execution",
    "scanner",
    "models",
    "tracing",
    "sandbox",
    "cli_and_reporting",
    "target",
    "z3_runtime",
    "dependency",
    "python_runtime",
    "other_engine",
    "other_project",
]


class ProfileFramePolicy:
    """Policy owner for profiler frame origin and phase classification."""

    @staticmethod
    def classify(
        file_path: str,
        function_name: str,
        *,
        project_root: Path,
        target_path: Path,
    ) -> tuple[ProfileFrameOrigin, str, ProfilePhase]:
        """Return origin, display path, and phase for one raw cProfile frame."""
        origin = _frame_origin(file_path, project_root=project_root, target_path=target_path)
        display_path = _display_path(file_path, project_root, origin)
        return origin, display_path, _profile_phase(display_path, function_name, origin)


def resolve_profile_path(path: Path) -> Path:
    """Resolve a path without failing profile finalization on filesystem races."""
    try:
        return path.resolve()
    except (OSError, RuntimeError, ValueError):
        return path.absolute()


def _frame_origin(
    file_path: str,
    *,
    project_root: Path,
    target_path: Path,
) -> ProfileFrameOrigin:
    """Classify a profiler frame without treating pseudo paths as project files."""
    if file_path == "~" or file_path.startswith("<"):
        return "runtime"
    resolved = resolve_profile_path(Path(file_path))
    if _is_relative_to(resolved, project_root / "pysymex"):
        return "engine"
    if resolved == target_path or (target_path.is_dir() and _is_relative_to(resolved, target_path)):
        return "target"
    if _is_relative_to(resolved, project_root):
        if ".venv" in resolved.parts or "site-packages" in resolved.parts:
            return "dependency"
        return "project"
    if "site-packages" in resolved.parts or "dist-packages" in resolved.parts:
        return "dependency"
    return "runtime"


def _profile_phase(
    file_path: str,
    function_name: str,
    origin: ProfileFrameOrigin,
) -> ProfilePhase:
    """Return the stable subsystem phase for one classified frame."""
    normalized = file_path.replace("\\", "/").lower()
    function = function_name.lower()
    if origin == "target":
        return "target"
    if origin == "dependency":
        return "z3_runtime" if "/z3/" in normalized or "z3" in function else "dependency"
    if origin == "runtime":
        return "python_runtime"
    if origin == "project":
        return "other_project"
    if (
        "pysymex/_internal/analysis/evidence/" in normalized
        or "pysymex/_internal/core/solver/constraints/" in normalized
        or any(token in function for token in ("witness", "simplif", "substitut", "literal"))
    ):
        return "formula_and_evidence"
    if "pysymex/_internal/core/solver/" in normalized or "pysymex/_internal/core/z3/" in normalized:
        return "solver_engine"
    if (
        "pysymex/_internal/analysis/detectors/" in normalized
        or "pysymex/_internal/execution/detectors/" in normalized
    ):
        return "detectors"
    if "pysymex/_internal/execution/" in normalized:
        return "execution"
    if (
        "pysymex/_internal/scanner/" in normalized
        or "pysymex/_internal/analysis/scan/" in normalized
    ):
        return "scanner"
    if "pysymex/_internal/models/" in normalized:
        return "models"
    if "pysymex/_internal/tracing/" in normalized:
        return "tracing"
    if "pysymex/_internal/sandbox/" in normalized:
        return "sandbox"
    if "pysymex/_internal/cli/" in normalized or "pysymex/_internal/reporting/" in normalized:
        return "cli_and_reporting"
    return "other_engine"


def _display_path(file_path: str, project_root: Path, origin: ProfileFrameOrigin) -> str:
    """Return a bounded stable path for profiler output."""
    if origin == "runtime" and (file_path == "~" or file_path.startswith("<")):
        return "<python-runtime>"
    resolved = resolve_profile_path(Path(file_path))
    try:
        return resolved.relative_to(project_root).as_posix()
    except ValueError:
        return resolved.as_posix()


def _is_relative_to(path: Path, parent: Path) -> bool:
    """Return whether ``path`` is within ``parent``."""
    try:
        return path.is_relative_to(parent)
    except (OSError, RuntimeError, ValueError):
        return False
