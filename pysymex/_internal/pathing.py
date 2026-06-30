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

"""Path normalization helpers for CLI and public APIs."""

from __future__ import annotations

import contextlib
from pathlib import Path


def normalize_input_path(path_value: str | Path) -> Path:
    r"""Normalize user-provided paths across slash conventions.

    This accepts paths like ``.\\examples\\file.py`` and normalizes them so they
    resolve correctly on both Windows and POSIX hosts.
    """
    if isinstance(path_value, Path):
        return path_value

    raw_path = path_value.strip()
    candidates: list[str] = [raw_path]

    if "\\" in raw_path:
        candidates.append(raw_path.replace("\\", "/"))

    for candidate in candidates:
        normalized = Path(candidate).expanduser()
        if normalized.exists():
            return normalized

    return Path(candidates[-1]).expanduser()


def ensure_pysymex_gitignore(path: Path | str) -> None:
    """Ensure that a .gitignore containing '*' exists inside the .pysymex directory.

    Traverses up the hierarchy of the given path to find the directory named '.pysymex',
    and generates a '.gitignore' file containing '*' to ignore its content safely.
    """
    try:
        p = Path(path).resolve()
    except (OSError, RuntimeError):
        p = Path(path)

    for current_dir in [p, *p.parents]:
        if current_dir.name == ".pysymex" and current_dir.is_dir():
            gitignore_path = current_dir / ".gitignore"

            with contextlib.suppress(OSError):
                if not gitignore_path.exists():
                    gitignore_path.write_text("*\n", encoding="utf-8")
            break
