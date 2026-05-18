"""Path normalization helpers for CLI and public APIs."""

from __future__ import annotations

import contextlib
from pathlib import Path


def normalize_input_path(path_value: str | Path) -> Path:
    """Normalize user-provided paths across slash conventions.

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
