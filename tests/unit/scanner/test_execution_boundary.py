"""Architecture guards for scanner execution-pass orchestration."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _scanner_execution_files() -> list[Path]:
    return sorted((_repo_root() / "pysymex" / "_internal" / "scanner" / "execution").rglob("*.py"))


def _scanner_files() -> list[Path]:
    return sorted((_repo_root() / "pysymex" / "_internal" / "scanner").rglob("*.py"))


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


def _is_type_checking_guard(test: ast.expr) -> bool:
    return (
        isinstance(test, ast.Name)
        and test.id == "TYPE_CHECKING"
        or isinstance(test, ast.Attribute)
        and isinstance(test.value, ast.Name)
        and test.value.id == "typing"
        and test.attr == "TYPE_CHECKING"
    )


def _imported_modules(import_node: ast.Import | ast.ImportFrom) -> Iterable[str]:
    if isinstance(import_node, ast.Import):
        for alias in import_node.names:
            yield alias.name
        return
    if import_node.module is not None:
        yield import_node.module


def _imported_names(import_node: ast.Import | ast.ImportFrom) -> Iterable[str]:
    for alias in import_node.names:
        yield alias.name


def test_scanner_execution_does_not_import_semantic_runtime_owners() -> None:
    forbidden_prefixes = (
        "pysymex._internal.analysis.detectors",
        "pysymex.contracts",
        "pysymex._internal.core.solver",
        "pysymex._internal.execution.calls",
        "pysymex._internal.execution.detectors",
        "pysymex._internal.execution.dispatch",
        "pysymex._internal.execution.initial.state",
        "pysymex._internal.execution.opcodes",
        "pysymex._internal.models",
        "z3",
    )
    offenders: list[str] = []
    root = _repo_root()
    for path in _scanner_execution_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for import_node in _runtime_imports(tree):
            for module in _imported_modules(import_node):
                if module.startswith(forbidden_prefixes):
                    offenders.append(f"{path.relative_to(root)} imports {module}")

    assert offenders == []


def test_scanner_execution_compatibility_package_has_no_source_files() -> None:
    assert _scanner_execution_files() == []


def test_scanner_package_has_no_legacy_cli_entrypoint() -> None:
    root = _repo_root()
    legacy_files = (
        root / "pysymex" / "_internal" / "scanner" / "async_scanner.py",
        root / "pysymex" / "_internal" / "scanner" / "__main__.py",
        root / "pysymex" / "_internal" / "scanner" / "cli.py",
        root / "pysymex" / "_internal" / "cli" / "scanner.py",
    )

    assert [path for path in legacy_files if path.exists()] == []


def test_scanner_package_does_not_own_console_printing() -> None:
    offenders: list[str] = []
    root = _repo_root()
    for path in _scanner_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "print":
                    offenders.append(f"{path.relative_to(root)} calls print()")

    assert offenders == []


def test_scanner_execution_does_not_encode_symbolic_or_default_semantics() -> None:
    forbidden_tokens = (
        "CallFrame",
        "IssueKind",
        "OpcodeResult",
        "SymbolicValue",
        "VMState",
        "__defaults__",
        "__kwdefaults__",
        "check_sat",
    )
    offenders: list[str] = []
    root = _repo_root()
    for path in _scanner_execution_files():
        source = path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if token in source:
                offenders.append(f"{path.relative_to(root)} contains {token}")

    assert offenders == []


class TypeHintStripper(ast.NodeTransformer):
    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.returns = None
        for arg in node.args.args + node.args.kwonlyargs:
            arg.annotation = None
        if node.args.vararg:
            node.args.vararg.annotation = None
        if node.args.kwarg:
            node.args.kwarg.annotation = None
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.returns = None
        for arg in node.args.args + node.args.kwonlyargs:
            arg.annotation = None
        if node.args.vararg:
            node.args.vararg.annotation = None
        if node.args.kwarg:
            node.args.kwarg.annotation = None
        return self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST:
        if node.value is None:
            return ast.copy_location(ast.Pass(), node)
        new_node = ast.Assign(targets=[node.target], value=node.value)
        return ast.copy_location(new_node, node)

    def visit_If(self, node: ast.If) -> ast.AST | None:
        if _is_type_checking_guard(node.test):
            return ast.copy_location(ast.Pass(), node)
        return self.generic_visit(node)


def test_scanner_file_does_not_construct_execution_owner_objects() -> None:
    root = _repo_root()
    path = root / "pysymex" / "_internal" / "scanner" / "file.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    forbidden_modules = {
        "pysymex._internal.config.execution",
        "pysymex._internal.execution.executors",
        "pysymex._internal.execution.opcodes",
    }
    forbidden_tokens = (
        "ExecutionConfig",
        "SymbolicExecutor",
        "load_opcode_handlers",
        "scanner_solver_timeout_ms",
    )
    offenders: list[str] = []

    for import_node in _runtime_imports(tree):
        for module in _imported_modules(import_node):
            if module in forbidden_modules:
                offenders.append(f"{path.relative_to(root)} imports {module}")

    stripped_tree = TypeHintStripper().visit(tree)
    source = ast.unparse(stripped_tree)
    for token in forbidden_tokens:
        if token in source:
            offenders.append(f"{path.relative_to(root)} contains {token}")

    assert offenders == []


def test_scanner_file_uses_preflight_facade_instead_of_detector_family_collectors() -> None:
    root = _repo_root()
    path = root / "pysymex" / "_internal" / "scanner" / "file.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders: list[str] = []
    allowed_preflight_import = "collect_scan_preflight_diagnostics"

    for import_node in _runtime_imports(tree):
        for module in _imported_modules(import_node):
            if module != "pysymex._internal.analysis.scan.preflight":
                continue
            for name in _imported_names(import_node):
                if name != allowed_preflight_import:
                    offenders.append(f"{path.relative_to(root)} imports preflight collector {name}")

    assert offenders == []


def test_scanner_package_does_not_import_semantic_runtime_internals() -> None:
    forbidden_prefixes = (
        "pysymex.contracts",
        "pysymex._internal.core.solver",
        "pysymex._internal.execution.calls",
        "pysymex._internal.config.execution",
        "pysymex._internal.execution.detectors",
        "pysymex._internal.execution.dispatch",
        "pysymex._internal.execution.executors",
        "pysymex._internal.execution.initial.state",
        "pysymex._internal.execution.opcodes",
        "pysymex._internal.models",
        "z3",
    )
    offenders: list[str] = []
    root = _repo_root()
    for path in _scanner_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for import_node in _runtime_imports(tree):
            for module in _imported_modules(import_node):
                if _is_allowed_opcode_registration(path, import_node, module):
                    continue
                if module.startswith(forbidden_prefixes):
                    offenders.append(f"{path.relative_to(root)} imports {module}")

    assert offenders == []


def _is_allowed_opcode_registration(
    path: Path,
    import_node: ast.Import | ast.ImportFrom,
    module: str,
) -> bool:
    _ = path
    _ = import_node
    _ = module
    return False
