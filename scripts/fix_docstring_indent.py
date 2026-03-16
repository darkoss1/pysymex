"""Fix unindented docstrings that immediately follow def/class blocks."""

from __future__ import annotations

import argparse
from pathlib import Path


SKIP_DIRS = {
    ".git",
    ".idea",
    ".pytest_cache",
    ".ruff_cache",
    ".hypothesis",
    ".venv",
    "__pycache__",
    ".agent",
    ".vs",
}


def _indent_unit(leading_ws: str) -> str:
    if "\t" in leading_ws and leading_ws.replace("\t", "") == "":
        return "\t"
    return "    "


def _is_def_or_class(line: str) -> bool:
    stripped = line.lstrip()
    return (
        stripped.startswith("def ")
        or stripped.startswith("class ")
        or stripped.startswith("async def ")
    )


def _fix_docstring_block(
    lines: list[str],
    start_idx: int,
    indent: str,
    indent_unit: str,
    quote: str,
) -> int:
    """Indent a docstring block starting at start_idx. Returns lines changed."""
    changes = 0
    line = lines[start_idx]
    stripped = line.lstrip("\t ")
    lines[start_idx] = f"{indent}{indent_unit}{stripped}"
    changes += 1

    if quote in stripped[3:]:
        return changes

    idx = start_idx + 1
    while idx < len(lines):
        lines[idx] = f"{indent}{indent_unit}{lines[idx]}"
        changes += 1
        if quote in lines[idx][len(indent) + len(indent_unit) :]:
            break
        idx += 1
    return changes


def fix_file(path: Path, check_only: bool = False) -> tuple[int, bool]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    changes = 0
    modified = False

    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if not _is_def_or_class(line):
            idx += 1
            continue

        indent = line[: len(line) - len(line.lstrip())]
        indent_unit = _indent_unit(indent)
        header_idx = idx
        paren_depth = 0

        while header_idx < len(lines):
            header_line = lines[header_idx]
            paren_depth += header_line.count("(") - header_line.count(")")
            paren_depth += header_line.count("[") - header_line.count("]")
            paren_depth += header_line.count("{") - header_line.count("}")
            if paren_depth <= 0 and header_line.rstrip().endswith(":"):
                break
            header_idx += 1

        doc_idx = header_idx + 1
        while doc_idx < len(lines) and lines[doc_idx].strip() == "":
            doc_idx += 1

        if doc_idx < len(lines):
            doc_line = lines[doc_idx]
            stripped = doc_line.lstrip("\t ")
            if stripped.startswith('"""') or stripped.startswith("'''"):
                if not doc_line.startswith(f"{indent}{indent_unit}"):
                    quote = '"""' if stripped.startswith('"""') else "'''"
                    changes += _fix_docstring_block(
                        lines,
                        doc_idx,
                        indent,
                        indent_unit,
                        quote,
                    )
                    modified = True
        idx = header_idx + 1

    if modified and not check_only:
        path.write_text("".join(lines), encoding="utf-8")
    return changes, modified


def iter_python_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description="Fix unindented docstrings.")
    parser.add_argument(
        "root",
        nargs="?",
        default="pysymex_release/pysymex",
        help="Root directory to scan (default: pysymex_release/pysymex)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report changes without modifying files.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print each modified file.",
    )
    args = parser.parse_args()

    root = Path(args.root)
    files = iter_python_files(root)
    total_changes = 0
    modified_files = 0

    for path in files:
        changes, modified = fix_file(path, check_only=args.check)
        if modified:
            modified_files += 1
            total_changes += changes
            if args.verbose:
                print(f"{path}: {changes} line(s) adjusted")

    action = "Would update" if args.check else "Updated"
    print(f"{action} {modified_files} file(s), {total_changes} line(s) adjusted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
