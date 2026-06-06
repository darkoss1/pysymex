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

"""Dead-code data types and helper utilities."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum, auto
from types import CodeType

from pysymex.core.cache import get_instructions as cached_get_instructions
from pysymex.logger import get_logger

logger = get_logger(__name__)


def find_dataclass_class_names(source: str) -> set[str]:
    """Find class names decorated with ``@dataclass`` via AST parsing."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        logger.debug("Dead-code helper could not parse source for dataclass names", exc_info=True)
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for dec in node.decorator_list:
                dec_name: str | None = None
                if isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr
                elif isinstance(dec, ast.Call):
                    func = dec.func
                    if isinstance(func, ast.Name):
                        dec_name = func.id
                    elif isinstance(func, ast.Attribute):
                        dec_name = func.attr
                if dec_name == "dataclass":
                    names.add(node.name)
    return names


def is_class_body(code: CodeType) -> bool:
    """Check if a code object is a class body (not a function/method).

    CPython class bodies always store ``__module__`` and ``__qualname__``
    at the top.  Regular functions do not.
    """
    for instr in cached_get_instructions(code):
        if instr.opname == "STORE_NAME" and instr.argval == "__module__":
            return True
    return False


def get_class_method_names(class_code: CodeType) -> set[str]:
    """Get the names of methods/functions defined in a class body."""
    names: set[str] = set()
    for const in class_code.co_consts:
        if hasattr(const, "co_code") and hasattr(const, "co_name"):
            names.add(const.co_name)
    return names


class DeadCodeKind(Enum):
    """Categories of dead code findings.

    Each member represents a distinct class of unused or unreachable code.
    """

    UNREACHABLE_CODE = auto()
    UNREACHABLE_BRANCH = auto()
    UNUSED_VARIABLE = auto()
    UNUSED_FUNCTION = auto()
    UNUSED_IMPORT = auto()
    UNUSED_PARAMETER = auto()
    REDUNDANT_ASSIGNMENT = auto()
    DEAD_STORE = auto()
    UNREACHABLE_HANDLER = auto()
    REDUNDANT_CONDITION = auto()
    ANALYSIS_ERROR = auto()


@dataclass
class DeadCode:
    """A single dead-code finding.

    Attributes:
        kind: The category of dead code.
        file: Source file path.
        line: Start line number.
        end_line: End line number (may equal ``line``).
        name: Variable/function/import name.
        message: Human-readable description.
        confidence: Detection confidence in ``[0, 1]``.
        pc: Bytecode offset, if applicable.
    """

    kind: DeadCodeKind
    file: str
    line: int
    end_line: int | None = None
    name: str = ""
    message: str = ""
    confidence: float = 1.0
    pc: int | None = None

    def format(self) -> str:
        """Format for display."""
        location = f"{self.file}:{self.line}"
        if self.end_line and self.end_line != self.line:
            location += f"-{self.end_line}"
        return f"[{self.kind.name}] {location}: {self.message}"
