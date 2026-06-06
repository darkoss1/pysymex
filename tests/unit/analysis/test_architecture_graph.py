"""Architecture guards for the analysis package graph."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ImportReference:
    """Runtime import discovered in a Python source file."""

    module: str
    names: tuple[str, ...]
    importer: str
    path: Path


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


def _import_reference(
    import_node: ast.Import | ast.ImportFrom, importer: str, path: Path
) -> Iterable[ImportReference]:
    if isinstance(import_node, ast.Import):
        for alias in import_node.names:
            yield ImportReference(alias.name, (), importer, path)
        return

    if import_node.module == "__future__":
        return

    names = tuple(alias.name for alias in import_node.names)
    if import_node.level == 0:
        if import_node.module is not None:
            yield ImportReference(import_node.module, names, importer, path)
        return

    importer_parts = importer.split(".")
    base_parts = importer_parts[: -import_node.level]
    if import_node.module:
        module = ".".join([*base_parts, *import_node.module.split(".")])
    else:
        module = ".".join(base_parts)
    yield ImportReference(module, names, importer, path)


def _analysis_python_files() -> list[Path]:
    return sorted((_repo_root() / "pysymex" / "analysis").rglob("*.py"))


def _source_and_analysis_test_files() -> list[Path]:
    root = _repo_root()
    files = [*sorted((root / "pysymex" / "analysis").rglob("*.py"))]
    files.extend(sorted((root / "tests" / "unit" / "analysis").rglob("*.py")))
    return files


def _analysis_runtime_imports(paths: Iterable[Path]) -> Iterable[ImportReference]:
    root = _repo_root()
    for path in paths:
        importer = _module_name(root, path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for import_node in _runtime_imports(tree):
            yield from _import_reference(import_node, importer, path)


def _analysis_top_level_package(module: str) -> str | None:
    parts = module.split(".")
    if len(parts) < 3 or parts[0] != "pysymex" or parts[1] != "analysis":
        return None
    return parts[2]


def _analysis_top_level_runtime_edges() -> set[tuple[str, str]]:
    edges: set[tuple[str, str]] = set()
    for reference in _analysis_runtime_imports(_analysis_python_files()):
        source = _analysis_top_level_package(reference.importer)
        destination = _analysis_top_level_package(reference.module)
        if source is None or destination is None or source == destination or source == "__init__":
            continue
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
            raise AssertionError(f"Analysis package runtime import cycle: {' -> '.join(cycle)}")

        visiting.add(node)
        path.append(node)
        for child in sorted(graph[node]):
            visit(child)
        path.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(graph):
        visit(node)


def test_analysis_top_level_runtime_package_graph_is_acyclic() -> None:
    _assert_acyclic(_analysis_top_level_runtime_edges())


def test_analysis_runtime_does_not_import_execution_runtime() -> None:
    offenders = [
        f"{reference.path.relative_to(_repo_root())} imports {reference.module}"
        for reference in _analysis_runtime_imports(_analysis_python_files())
        if reference.module.startswith("pysymex.execution")
    ]

    assert offenders == []


def test_type_stub_records_do_not_import_type_inference_runtime() -> None:
    stubs_root = _repo_root() / "pysymex" / "analysis" / "static" / "stubs"
    offenders = [
        str(reference.path.relative_to(_repo_root()))
        for reference in _analysis_runtime_imports(stubs_root.rglob("*.py"))
        if reference.module.startswith("pysymex.analysis.static.types")
    ]

    assert offenders == []


def test_static_lifecycle_does_not_import_scan_runtime() -> None:
    static_root = _repo_root() / "pysymex" / "analysis" / "static"
    offenders = [
        str(reference.path.relative_to(_repo_root()))
        for reference in _analysis_runtime_imports(static_root.rglob("*.py"))
        if reference.module.startswith("pysymex.analysis.scan")
    ]

    assert offenders == []


def test_stub_records_do_not_convert_themselves_to_pytype() -> None:
    offenders: list[str] = []
    root = _repo_root()
    for path in _source_and_analysis_test_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "to_pytype":
                offenders.append(str(path.relative_to(root)))
                break

    assert offenders == []


def test_scan_lifecycle_sources_live_under_scan_package() -> None:
    analysis_root = _repo_root() / "pysymex" / "analysis"
    stale_sources = [
        "complexity.py",
        "records.py",
        "loading/__init__.py",
        "preflight/__init__.py",
    ]

    offenders = [
        stale_source for stale_source in stale_sources if (analysis_root / stale_source).exists()
    ]

    assert offenders == []


def test_static_lifecycle_sources_live_under_static_package() -> None:
    analysis_root = _repo_root() / "pysymex" / "analysis"
    stale_sources = [
        "control/__init__.py",
        "dataflow/__init__.py",
        "dead_code/types.py",
        "patterns/__init__.py",
        "properties/__init__.py",
        "type_inference/__init__.py",
        "type_stubs/__init__.py",
    ]

    offenders = [
        stale_source for stale_source in stale_sources if (analysis_root / stale_source).exists()
    ]

    assert offenders == []


def test_runtime_lifecycle_sources_live_under_runtime_package() -> None:
    analysis_root = _repo_root() / "pysymex" / "analysis"
    stale_sources = [
        "cache/__init__.py",
        "summaries/__init__.py",
    ]

    offenders = [
        stale_source for stale_source in stale_sources if (analysis_root / stale_source).exists()
    ]

    assert offenders == []


def test_domain_lifecycle_sources_live_under_domains_package() -> None:
    analysis_root = _repo_root() / "pysymex" / "analysis"
    stale_sources = [
        "concurrency/__init__.py",
        "exceptions/__init__.py",
        "resources/__init__.py",
        "specialized/__init__.py",
        "specialized/escape.py",
        "specialized/flow/analyzer.py",
        "specialized/ranges/analyzer.py",
        "specialized/string/analyzer.py",
    ]

    offenders = [
        stale_source for stale_source in stale_sources if (analysis_root / stale_source).exists()
    ]

    assert offenders == []
