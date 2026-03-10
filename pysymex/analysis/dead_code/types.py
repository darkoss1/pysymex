"""Dead code types, enums, and helper utilities.

Provides:
- DeadCodeKind: Enum of dead code categories
- DeadCode: Data class representing a single dead code finding
- Helper functions for class body/dataclass detection (used by dead_code.py, pipeline_phases.py)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum, auto

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions


def find_dataclass_class_names(source: str) -> set[str]:
    """Find class names decorated with ``@dataclass`` via AST parsing."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
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


def is_class_body(code: object) -> bool:
    """Check if a code object is a class body (not a function/method).

    CPython class bodies always store ``__module__`` and ``__qualname__``
    at the top.  Regular functions do not.
    """
    for instr in _cached_get_instructions(code):
        if instr.opname == "STORE_NAME" and instr.argval == "__module__":
            return True
    return False


def collect_class_attrs_used(class_code: object) -> set[str]:
    """Collect all attribute names loaded via LOAD_ATTR across methods of a class.

    Note: This data is currently collected but not consumed by DeadStoreDetector
    because STORE_ATTR dead store detection is not yet implemented.  When
    STORE_ATTR detection is added (future work), this data should be passed
    through analyze_function() to suppress ``__init__`` attribute assignments
    that are read by other methods.
    """
    attrs_used: set[str] = set()
    for const in class_code.co_consts:
        if hasattr(const, "co_code"):
            for instr in _cached_get_instructions(const):
                if instr.opname == "LOAD_ATTR":
                    attrs_used.add(instr.argval)

            for inner in const.co_consts:
                if hasattr(inner, "co_code"):
                    for instr in _cached_get_instructions(inner):
                        if instr.opname == "LOAD_ATTR":
                            attrs_used.add(instr.argval)
    return attrs_used


def get_class_method_names(class_code: object) -> set[str]:
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
        location = f"{self .file }:{self .line }"
        if self.end_line and self.end_line != self.line:
            location += f"-{self .end_line }"
        return f"[{self .kind .name }] {location }: {self .message }"
