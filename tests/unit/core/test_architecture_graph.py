"""Architecture guards for the core package graph."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path


_CORE_ROOT_EXPORT = Path("pysymex/core/__init__.py")
_REMOVED_INTERNAL_ROUTES = {
    "pysymex.core.memory.addressing",
    "pysymex.core.memory.cow.chains",
    "pysymex.core.types.floats.analysis",
}
_FORBIDDEN_CORE_UPPER_LAYER_IMPORTS = {
    "pysymex.analysis",
    "pysymex.api",
    "pysymex.cli",
    "pysymex.contracts",
    "pysymex.execution",
    "pysymex.models",
    "pysymex.reporting",
    "pysymex.sandbox",
    "pysymex.scanner",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _module_name(root: Path, path: Path) -> str:
    relative = path.relative_to(root).with_suffix("")
    return ".".join(relative.parts)


def _is_type_checking_guard(test: ast.expr) -> bool:
    return (
        isinstance(test, ast.Name)
        and test.id == "TYPE_CHECKING"
        or isinstance(test, ast.Attribute)
        and isinstance(test.value, ast.Name)
        and test.value.id == "typing"
        and test.attr == "TYPE_CHECKING"
    )


def _runtime_imports(tree: ast.AST) -> Iterable[ast.Import | ast.ImportFrom]:
    def visit(node: ast.AST, *, type_checking: bool) -> Iterable[ast.Import | ast.ImportFrom]:
        if isinstance(node, ast.If) and _is_type_checking_guard(node.test):
            for child in node.orelse:
                yield from visit(child, type_checking=type_checking)
            return
        if isinstance(node, ast.Import | ast.ImportFrom):
            if not type_checking:
                yield node
            return
        for child in ast.iter_child_nodes(node):
            yield from visit(child, type_checking=type_checking)

    yield from visit(tree, type_checking=False)


def _all_imports(tree: ast.AST) -> Iterable[ast.Import | ast.ImportFrom]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            yield node


def _import_targets(import_node: ast.Import | ast.ImportFrom, importer: str) -> Iterable[str]:
    if isinstance(import_node, ast.Import):
        for alias in import_node.names:
            yield alias.name
        return

    if import_node.module == "__future__":
        return
    if import_node.level == 0:
        if import_node.module is not None:
            yield import_node.module
        return

    importer_parts = importer.split(".")
    base_parts = importer_parts[: -import_node.level]
    if import_node.module:
        yield ".".join([*base_parts, *import_node.module.split(".")])
    else:
        yield ".".join(base_parts)


def _core_python_files() -> list[Path]:
    return sorted((_repo_root() / "pysymex" / "core").rglob("*.py"))


def _core_top_level_runtime_edges() -> set[tuple[str, str]]:
    root = _repo_root()
    edges: set[tuple[str, str]] = set()
    for path in _core_python_files():
        importer = _module_name(root, path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for import_node in _runtime_imports(tree):
            for target in _import_targets(import_node, importer):
                if not target.startswith("pysymex.core."):
                    continue
                importer_parts = importer.split(".")
                target_parts = target.split(".")
                if len(importer_parts) < 3 or len(target_parts) < 3:
                    continue
                source = importer_parts[2]
                destination = target_parts[2]
                if source != destination and source != "__init__":
                    edges.add((source, destination))
    return edges


def _assert_acyclic(edges: set[tuple[str, str]]) -> None:
    graph: dict[str, set[str]] = {}
    for source, destination in edges:
        graph.setdefault(source, set()).add(destination)
        graph.setdefault(destination, set())

    visiting: set[str] = set()
    visited: set[str] = set()
    path: list[str] = []

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            cycle_start = path.index(node)
            cycle = [*path[cycle_start:], node]
            raise AssertionError(f"Core package runtime import cycle: {' -> '.join(cycle)}")

        visiting.add(node)
        path.append(node)
        for child in sorted(graph[node]):
            visit(child)
        path.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(graph):
        visit(node)


def test_core_top_level_runtime_package_graph_is_acyclic() -> None:
    _assert_acyclic(_core_top_level_runtime_edges())


def test_core_package_initializers_do_not_own_runtime_imports() -> None:
    root = _repo_root()
    offenders: list[str] = []
    for path in _core_python_files():
        relative = path.relative_to(root)
        if path.name != "__init__.py" or relative == _CORE_ROOT_EXPORT:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = [
            import_node
            for import_node in _runtime_imports(tree)
            if not (isinstance(import_node, ast.ImportFrom) and import_node.module == "__future__")
        ]
        if imports:
            offenders.append(str(relative))

    assert offenders == []


def test_core_source_does_not_import_upper_layers_even_for_typing() -> None:
    root = _repo_root()
    offenders: list[str] = []
    for path in _core_python_files():
        importer = _module_name(root, path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for import_node in _all_imports(tree):
            for target in _import_targets(import_node, importer):
                if any(
                    target == forbidden or target.startswith(f"{forbidden}.")
                    for forbidden in _FORBIDDEN_CORE_UPPER_LAYER_IMPORTS
                ):
                    offenders.append(f"{path.relative_to(root)} imports {target}")

    assert offenders == []


def test_removed_internal_routes_are_not_imported_by_source_or_tests() -> None:
    root = _repo_root()
    offenders: list[str] = []
    for base in (root / "pysymex", root / "tests"):
        for path in sorted(base.rglob("*.py")):
            importer = _module_name(root, path)
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for import_node in _runtime_imports(tree):
                for target in _import_targets(import_node, importer):
                    if target in _REMOVED_INTERNAL_ROUTES:
                        offenders.append(f"{path.relative_to(root)} imports {target}")

    assert offenders == []
