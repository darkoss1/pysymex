"""
Auto-Reproduction Generator.

This module is responsible for synthesizing executable Python scripts ("Exploits")
that reproduce bugs detected by pysymex. It bridges the gap between
abstract symbolic execution results and concrete, runnable code.
"""

import ast
import os
from typing import cast

from pysymex.analysis.detectors import Issue

TYPE_DEFAULTS = {
    "int": "0",
    "float": "0.0",
    "str": '""',
    "bool": "False",
    "list": "[]",
    "dict": "{}",
    "tuple": "()",
    "set": "set()",
    "bytes": 'b""',
    "NoneType": "None",
}


class ReproductionGenerator:
    """Generates Python scripts to reproduce detected issues."""

    def __init__(self, output_dir: str = "."):
        """Init."""
        """Initialize the class instance."""
        self.output_dir = output_dir

    def generate(
        self, issue: Issue, func_name: str, source_file: str, class_name: str | None = None
    ) -> str | None:
        """
        Generate a reproduction script for a specific issue.

        Args:
            issue: The detected issue containing the counterexample.
            func_name: Name of the function where the issue occurred.
            source_file: Path to the source file containing the function.
            class_name: Optional name of the class if the function is a method.

        Returns:
            Path to the generated script, or None if generation failed.
        """
        if not issue.counterexample:
            return None
        module_name = self._resolve_module_name(source_file)
        if not module_name:
            return None
        args_list = self._build_args_list(issue.counterexample, source_file, func_name, class_name)
        args_code = ",\n        ".join(args_list)
        clean_args = [arg.split("#")[0].strip() for arg in args_list]
        args_display = ", ".join(clean_args)
        script_content = self._create_script_content(
            module_name=module_name,
            func_name=func_name,
            class_name=class_name,
            args_code=args_code,
            args_display=args_display,
            issue_kind=issue.kind.name,
            message=issue.message,
        )
        filename = f"reproduce_{issue .kind .name .lower ()}_{func_name }.py"
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, "w") as f:
                f.write(script_content)
            return filepath
        except OSError:
            return None

    def _resolve_module_name(self, source_file: str) -> str | None:
        """Convert file path to importable module name."""
        try:
            rel_path = os.path.relpath(source_file)
            name, _ = os.path.splitext(rel_path)
            return name.replace(os.path.sep, ".")
        except ValueError:
            return None

    def _get_all_function_args(
        self, source_file: str, func_name: str, class_name: str | None = None
    ) -> list[tuple[str, str | None]]:
        """
        Parse source file via AST to get ALL function arguments and their type hints.

        Returns:
            List of tuples: (arg_name, type_hint_or_None)
        """
        try:
            with open(source_file, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=source_file)
        except (OSError, SyntaxError):
            return []
        all_args: list[tuple[str, str | None]] = []

        class FunctionFinder(ast.NodeVisitor):
            """Visitor for locating function and method definitions in source code."""
            def __init__(self, target_func: str, target_class: str | None = None) -> None:
                """Init."""
                """Initialize the class instance."""
                self.target_func: str = target_func
                self.target_class: str | None = target_class
                self.found_args: ast.arguments | None = None

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                """Visit functiondef."""
                if self.found_args:
                    return
                if node.name == self.target_func:
                    self.found_args = node.args
                self.generic_visit(node)

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                """Visit classdef."""
                if self.target_class and node.name == self.target_class:
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef) and item.name == self.target_func:
                            self.found_args = item.args
                            return
                elif not self.target_class:
                    self.generic_visit(node)

        finder = FunctionFinder(
            func_name, class_name if class_name and "." not in class_name else None
        )
        if class_name and "." in class_name:
            finder = FunctionFinder(func_name)
        finder.visit(tree)
        if finder.found_args:
            for arg in finder.found_args.args:
                type_hint = None
                if arg.annotation:
                    if isinstance(arg.annotation, ast.Name):
                        type_hint = arg.annotation.id
                    elif isinstance(arg.annotation, ast.Attribute):
                        type_hint = arg.annotation.attr
                    elif isinstance(arg.annotation, ast.Constant):
                        type_hint = str(arg.annotation.value)
                all_args.append((arg.arg, type_hint))
        return all_args

    def _build_args_list(
        self,
        counterexample: dict[str, object],
        source_file: str | None = None,
        func_name: str | None = None,
        class_name: str | None = None,
    ) -> list[str]:
        """Convert counterexample dict to list of function argument strings."""
        all_args: list[tuple[str, str | None]] = []
        if source_file and func_name:
            all_args = self._get_all_function_args(source_file, func_name, class_name)
        args: list[str] = []
        if all_args:
            for arg_name, type_hint in all_args:
                if arg_name == "self":
                    continue
                if arg_name in counterexample:
                    value = counterexample[arg_name]
                    is_complex = False
                    if (
                        type_hint
                        and type_hint not in TYPE_DEFAULTS
                        and type_hint not in ("Any", "Optional")
                    ):
                        is_complex = True
                    if is_complex:
                        args.append(f"{arg_name }=None")
                    elif isinstance(value, bool) or isinstance(value, (int, float)):
                        args.append(f"{arg_name }={value }")
                    elif isinstance(value, str):
                        args.append(f"{arg_name }='{value }'")
                    elif value is None:
                        args.append(f"{arg_name }=None")
                    elif isinstance(value, (list, dict, tuple, set)):
                        args.append(f"{arg_name }={cast ('object' ,value )!r}")
                    else:
                        args.append(f"{arg_name }=None")
                else:
                    if type_hint:
                        if type_hint in TYPE_DEFAULTS:
                            args.append(f"{arg_name }={TYPE_DEFAULTS [type_hint ]}")
                        else:
                            args.append(f"{arg_name }=None")
                    else:
                        args.append(f"{arg_name }=None")
        else:
            for name, value in counterexample.items():
                if name == "self":
                    continue
                if isinstance(value, bool) or isinstance(value, (int, float)):
                    args.append(f"{name }={value }")
                elif isinstance(value, str):
                    args.append(f"{name }='{value }'")
                elif value is None:
                    args.append(f"{name }=None")
                elif isinstance(value, (list, dict, tuple, set)):
                    args.append(f"{name }={cast ('object' ,value )!r}")
                else:
                    args.append(f"{name }=None")
        return args

    def _generate_init_args_code(self, class_name: str) -> str:
        """Emit helper code that inspects ``__init__`` at runtime.

        The generated code is embedded in the reproduction script and
        builds default arguments based on type-hint introspection.

        Args:
            class_name: Fully-qualified class name.

        Returns:
            Python source snippet to embed in the script.
        """
        return '''
def _build_init_args(cls):
    """Generate default arguments for __init__ based on signature."""
    import inspect
    try:
        sig = inspect.signature(cls.__init__)
    except (ValueError, TypeError):
        return {}

    defaults = {
        "int": 0, "float": 0.0, "str": "", "bool": False,
        "list": [], "dict": {}, "tuple": (), "set": set(),
        "bytes": b"", "NoneType": None,
    }

    args = {}
    for name, param in sig.parameters.items():
        if name == "self":
            continue
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if param.default is not inspect.Parameter.empty:
            continue

        # Try to get type hint
        type_name = None
        if param.annotation is not inspect.Parameter.empty:
            type_name = getattr(param.annotation, "__name__", str(param.annotation))

        if type_name and type_name in defaults:
            args[name] = defaults[type_name]
        else:
            args[name] = None  # Fallback
            print(f"    [!] Warning: Unknown type for {name}, using None")

    return args
'''

    def _create_script_content(
        self,
        module_name: str,
        func_name: str,
        class_name: str | None,
        args_code: str,
        args_display: str,
        issue_kind: str,
        message: str,
    ) -> str:
        """Assemble the full reproduction-script source.

        Args:
            module_name: Importable module path.
            func_name: Target function name.
            class_name: Owning class, or ``None`` for top-level functions.
            args_code: Formatted argument assignment lines.
            args_display: Human-readable argument summary.
            issue_kind: Issue category string.
            message: Issue description.

        Returns:
            Complete Python source for the reproduction script.
        """
        if class_name:
            parts = class_name.split(".")
            root_class = parts[0]
            import_stmt = f"from {module_name } import {root_class }"
            import_msg = f"Importing {root_class } from {module_name }..."
            init_helper = self._generate_init_args_code(class_name)
            class_ref = class_name
            setup_code = f"""
    # Build constructor arguments dynamically
    init_args = _build_init_args({class_ref })

    # Instantiate Class
    print("[*] Instantiating {class_name }...")
    if init_args:
        print(f"    Using init args: {{init_args}}")
        instance = {class_ref }(**init_args)
    else:
        instance = {class_ref }()

    target_name = "{class_name }.{func_name }"

    # Method Call
    print(f"[*] Invoking {{target_name}} with payload...")
    instance.{func_name }({args_code })
"""
        else:
            import_stmt = f"from {module_name } import {func_name }"
            import_msg = f"Importing {func_name } from {module_name }..."
            init_helper = ""
            setup_code = f"""
    target_name = "{func_name }"

    # Function Call
    print(f"[*] Invoking {{target_name}} with payload...")
    {func_name }({args_code })
"""
        return f'''"""
pysymex Reproduction Script
Auto-generated proof-of-concept for issue: {issue_kind }

Run this script to reproduce the crash:
    python {os .path .basename (module_name )}.py
"""
import sys
import os
sys.path.insert(0, os.getcwd())
{init_helper }
try:
    {import_stmt }
    print(f"[*] {import_msg }")
except ImportError as e:
    print(f"[!] Failed to import target: {{e}}")
    print("    Check your PYTHONPATH or run from the project root.")
    sys.exit(1)
print("-" * 50)
print(f"[*] Target: {class_name +"."+func_name if class_name else func_name }")
print(f"[*] Injection Payload: {args_display }")
print(f"[*] Expected Issue:  {issue_kind }")
print("-" * 50)
print("\\n[*] Attempting to trigger crash...")
try:
    {setup_code }

    print("\\n[?] Execution finished without crashing.")
    print("    This might be a false positive or handled exception.")

except Exception as e:
    print(f"\\n[+] Crash Reproduced! SUCCESS")
    print(f"    Caught expected exception: {{type(e).__name__}}")
    print(f"    Message: {{e}}")
'''
