# pysymex: Python Symbolic Execution & Formal Verification
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

"""
Auto-Reproduction Generator.

This module is responsible for synthesizing executable Python scripts ("Exploits")
that reproduce bugs detected by pysymex. It bridges the gap between
abstract symbolic execution results and concrete, runnable code.
"""

import ast
import os
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

    def __init__(self, output_dir: str | None = None) -> None:
        if output_dir is None:
            # Default to .pysymex/reproduction in the current working directory
            output_dir = os.path.join(".pysymex", "reproduction")

        self.output_dir = output_dir
        self._ensure_output_dir()

    def _ensure_output_dir(self) -> None:
        """Create the output directory if it doesn't exist."""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            # Create __init__.py to make it a package
            init_file = os.path.join(self.output_dir, "__init__.py")
            if not os.path.exists(init_file):
                with open(init_file, "w") as f:
                    f.write("# pysymex reproductions package\n")
            from pysymex.pathing import ensure_pysymex_gitignore

            ensure_pysymex_gitignore(self.output_dir)
        except OSError:
            pass

    def generate_script(self, issue: Issue) -> str | None:
        """
        Convenience wrapper for generate() using metadata from an Issue object.

        Args:
            issue: The detected issue.

        Returns:
            Path to the generated script, or None if generation failed.
        """
        if not issue.function_name or not issue.filename:
            return None
        return self.generate(
            issue=issue,
            func_name=issue.function_name,
            source_file=issue.filename,
            class_name=issue.class_name,
        )

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
        args_code = ",\n            ".join(args_list)
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
        # Cleaner filename: [kind]_[func].py
        kind_tag = issue.kind.name.lower().replace("_error", "")
        filename = f"repro_{kind_tag}_{func_name}.py"
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
        except ValueError:
            # On Windows, ValueError is raised when paths are on different drives
            basename = os.path.basename(source_file)
            name, _ = os.path.splitext(basename)
            return name
        name, _ = os.path.splitext(rel_path)
        return name.replace(os.path.sep, ".")

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
                self.target_func: str = target_func
                self.target_class: str | None = target_class
                self.found_args: ast.arguments | None = None

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                if self.found_args:
                    return
                if node.name == self.target_func:
                    self.found_args = node.args
                self.generic_visit(node)

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
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
                        args.append(f"{arg_name}=None")
                    elif isinstance(value, bool) or isinstance(value, (int, float)):
                        args.append(f"{arg_name}={value}")
                    elif isinstance(value, str):
                        args.append(f"{arg_name}='{value}'")
                    elif value is None:
                        args.append(f"{arg_name}=None")
                    elif isinstance(value, (list, dict, tuple, set)):
                        args.append(f"{arg_name}={value!r}")
                    else:
                        args.append(f"{arg_name}=None")
                else:
                    if type_hint:
                        if type_hint in TYPE_DEFAULTS:
                            args.append(f"{arg_name}={TYPE_DEFAULTS[type_hint]}")
                        else:
                            args.append(f"{arg_name}=None")
                    else:
                        args.append(f"{arg_name}=None")
        else:
            for name, value in counterexample.items():
                if name == "self":
                    continue
                if isinstance(value, bool) or isinstance(value, (int, float)):
                    args.append(f"{name}={value}")
                elif isinstance(value, str):
                    args.append(f"{name}='{value}'")
                elif value is None:
                    args.append(f"{name}=None")
                elif isinstance(value, (list, dict, tuple, set)):
                    args.append(f"{name}={value!r}")
                else:
                    args.append(f"{name}=None")
        return args

    def _generate_init_args_code(self) -> str:
        """Emit helper code that inspects ``__init__`` at runtime.

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
        """Assemble the full reproduction-script source."""
        if class_name:
            import_stmt = f"from {module_name} import {class_name.split('.')[0]}"
            init_helper = self._generate_init_args_code().strip()
            setup_code = f"""# Instantiate {class_name}
        init_args = _build_init_args({class_name})
        instance = {class_name}(**init_args)
        
        # Invoke target method
        print(f"[*] Calling {class_name}.{func_name}({args_display})...")
        instance.{func_name}(
                {args_code}
            )"""
        else:
            import_stmt = f"from {module_name} import {func_name}"
            init_helper = ""
            setup_code = f"""# Invoke target function
        print(f"[*] Calling {func_name}({args_display})...")
        {func_name}(
                {args_code}
            )"""

        return f'''"""
pysymex Automated Reproduction Script
Issue: {issue_kind}
Message: {message}

This script was automatically generated to reproduce a defect detected by pysymex.
"""
import sys
import os
import traceback

# Ensure the project root is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

{init_helper}

def reproduce():
    print("=" * 60)
    print(f"pysymex REPRODUCTION: {issue_kind}")
    print(f"Message: {message}")
    print("-" * 60)
    
    try:
        {import_stmt}
    except ImportError as e:
        print(f"[!] Import Error: {{e}}")
        print("    Ensure you are running this script from a correctly configured environment.")
        return

    try:
        {setup_code.strip()}
        print("-" * 60)
        print("[?] Result: No exception raised. Execution finished normally.")
        print("    This could indicate a false positive or a handled exception.")
        
    except Exception as e:
        print("-" * 60)
        print(f"[+] CRASH REPRODUCED: {{type(e).__name__}}")
        print(f"    Message: {{e}}")
        print("\\nDetailed Traceback:")
        traceback.print_exc()
        print("=" * 60)

if __name__ == "__main__":
    reproduce()
'''
