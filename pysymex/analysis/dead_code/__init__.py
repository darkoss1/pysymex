"""
Dead Code Detection for pysymex.

This module identifies unreachable and unused code including:
- Unreachable statements after return/raise/break/continue
- Unused variables (assigned but never read)
- Unused functions (defined but never called)
- Unused imports
- Unreachable branches (conditions always true/false)
- Dead exception handlers

Implementation split across:
- dead_code_types.py: DeadCodeKind enum, DeadCode dataclass, helper utilities
- dead_code_detectors.py: All concrete detector classes
- dead_code.py: DeadCodeAnalyzer orchestrator + re-exports
"""

from __future__ import annotations

from ..cross_function import CallGraphBuilder
from .core import (
    DeadStoreDetector,
    RedundantConditionDetector,
    UnreachableCodeDetector,
    UnusedFunctionDetector,
    UnusedImportDetector,
    UnusedParameterDetector,
    UnusedVariableDetector,
)
from .types import (
    DeadCode,
    DeadCodeKind,
    collect_class_attrs_used,
    find_dataclass_class_names,
    get_class_method_names,
    is_class_body,
)

__all__ = [
    "DeadCode",
    "DeadCodeAnalyzer",
    "DeadCodeKind",
    "DeadStoreDetector",
    "RedundantConditionDetector",
    "UnreachableCodeDetector",
    "UnusedFunctionDetector",
    "UnusedImportDetector",
    "UnusedParameterDetector",
    "UnusedVariableDetector",
]


class DeadCodeAnalyzer:
    """
    High-level interface for dead code detection.
    """

    def __init__(self) -> None:
        """Init."""
        """Initialize the class instance."""
        self.unreachable_detector = UnreachableCodeDetector()
        self.unused_var_detector = UnusedVariableDetector()
        self.dead_store_detector = DeadStoreDetector()
        self.unused_func_detector = UnusedFunctionDetector()
        self.unused_param_detector = UnusedParameterDetector()
        self.unused_import_detector = UnusedImportDetector()
        self.redundant_cond_detector = RedundantConditionDetector()

    def analyze_function(
        self,
        code: object,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Analyze a function for dead code."""
        results: list[DeadCode] = []
        results.extend(self.unreachable_detector.detect(code, file_path))
        results.extend(self.unused_var_detector.detect(code, file_path))
        results.extend(self.dead_store_detector.detect(code, file_path))
        results.extend(self.unused_param_detector.detect(code, file_path))
        results.extend(self.redundant_cond_detector.detect(code, file_path))
        return results

    def analyze_module(
        self,
        module_code: object,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Analyze a module for dead code."""
        results: list[DeadCode] = []
        results.extend(self.unused_import_detector.detect_from_source(source, file_path))
        results.extend(self.analyze_function(module_code, file_path))
        builder = CallGraphBuilder()
        call_graph = builder.build_from_module(module_code)
        results.extend(self.unused_func_detector.detect(call_graph, file_path))
        self._analyze_nested_functions(
            module_code,
            file_path,
            results,
            dataclass_names=find_dataclass_class_names(source),
        )
        return results

    def _analyze_nested_functions(
        self,
        code: object,
        file_path: str,
        results: list[DeadCode],
        *,
        dataclass_names: set[str] | None = None,
        class_attrs_used: set[str] | None = None,
    ) -> None:
        """Recursively analyze nested functions.

        Parameters
        ----------
        dataclass_names:
            Set of class names decorated with ``@dataclass`` in the module.
        class_attrs_used:
            Set of attribute names loaded (LOAD_ATTR) across sibling methods
            of the enclosing class.  Used to suppress false positives for
            instance attributes stored in ``__init__``.
        """
        for const in code.co_consts:
            if not hasattr(const, "co_code"):
                continue

            if is_class_body(const):

                is_dc = bool(dataclass_names and const.co_name in dataclass_names)

                if is_dc:

                    results.extend(self.unreachable_detector.detect(const, file_path))
                    results.extend(self.redundant_cond_detector.detect(const, file_path))
                else:

                    func_results = self.analyze_function(const, file_path)
                    method_names = get_class_method_names(const)
                    for dc in func_results:
                        if dc.kind == DeadCodeKind.UNUSED_VARIABLE and dc.name in method_names:
                            continue
                        results.append(dc)

                attrs_used = collect_class_attrs_used(const)
                self._analyze_nested_functions(
                    const,
                    file_path,
                    results,
                    dataclass_names=dataclass_names,
                    class_attrs_used=attrs_used,
                )
            else:

                results.extend(self.analyze_function(const, file_path))
                self._analyze_nested_functions(
                    const,
                    file_path,
                    results,
                    dataclass_names=dataclass_names,
                    class_attrs_used=class_attrs_used,
                )

    def analyze_file(self, file_path: str) -> list[DeadCode]:
        """Analyze a file for dead code."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            code = compile(source, file_path, "exec")
            return self.analyze_module(code, source, file_path)
        except SyntaxError as e:
            return [
                DeadCode(
                    kind=DeadCodeKind.UNREACHABLE_CODE,
                    file=file_path,
                    line=e.lineno or 0,
                    message=f"Syntax error prevents analysis: {e .msg }",
                )
            ]
        except Exception as exc:
            import logging

            logging.getLogger(__name__).debug(
                "Dead code analysis failed for %s: %s", file_path, exc
            )
            return []
