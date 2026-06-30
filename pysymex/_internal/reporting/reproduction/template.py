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

"""Template assembly for generated reproduction scripts."""

from __future__ import annotations


def generate_init_args_code() -> str:
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
        return (), {}

    defaults = {
        "int": 0, "float": 0.0, "str": "", "bool": False,
        "list": [], "dict": {}, "tuple": (), "set": set(),
        "bytes": b"", "NoneType": None,
    }

    positional_args = []
    keyword_args = {}
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
            value = defaults[type_name]
        else:
            value = None

        if param.kind is inspect.Parameter.POSITIONAL_ONLY:
            positional_args.append(value)
        else:
            keyword_args[name] = value
    return tuple(positional_args), keyword_args
'''


def create_script_content(
    module_name: str,
    source_file: str,
    import_root: str,
    func_name: str,
    class_name: str | None,
    args_code: str,
    args_display: str,
    issue_kind: str,
    message: str,
) -> str:
    """Assemble the full reproduction-script source."""
    source_file_literal = repr(source_file)
    import_root_literal = repr(import_root)
    module_name_literal = repr(module_name)
    target_name_literal = repr(func_name)
    args_display_literal = repr(args_display)
    issue_kind_literal = repr(issue_kind)
    message_literal = repr(message)
    if class_name:
        class_name_literal = repr(class_name)
        init_helper = generate_init_args_code().strip()
        setup_code = f"""# Instantiate {class_name}
        cls = _resolve_qualname(module, {class_name_literal})
        init_posargs, init_kwargs = _build_init_args(cls)
        instance = cls(*init_posargs, **init_kwargs)

        # Invoke target method
        print("[*] Calling {class_name}.{func_name}(" + {args_display_literal} + ")...")
        target = getattr(instance, {target_name_literal})
        result = target(
            {args_code}
        )"""
    else:
        init_helper = ""
        setup_code = f"""# Invoke target function
        print("[*] Calling {func_name}(" + {args_display_literal} + ")...")
        target = getattr(module, {target_name_literal})
        result = target(
            {args_code}
        )"""

    return f'''"""
pysymex Automated Reproduction Script

This script was automatically generated to replay concrete inputs reported by pysymex.
It confirms runtime behavior only for this input and is not a formal proof.
"""
import sys
import os
import asyncio
import importlib.util
import inspect
import traceback


SOURCE_FILE = {source_file_literal}
IMPORT_ROOT = {import_root_literal}
MODULE_NAME = {module_name_literal}
ISSUE_KIND = {issue_kind_literal}
ISSUE_MESSAGE = {message_literal}


def _load_target_module():
    source_file = os.path.abspath(SOURCE_FILE)
    import_root = os.path.abspath(IMPORT_ROOT)
    if import_root not in sys.path:
        sys.path.insert(0, import_root)

    spec = importlib.util.spec_from_file_location(MODULE_NAME, source_file)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module {{MODULE_NAME!r}} from {{source_file!r}}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


def _resolve_qualname(root, qualname):
    current = root
    for part in qualname.split("."):
        current = getattr(current, part)
    return current

{init_helper}

def reproduce():
    print("=" * 60)
    print(f"pysymex REPRODUCTION: {{ISSUE_KIND}}")
    print(f"Message: {{ISSUE_MESSAGE}}")
    print("-" * 60)

    try:
        module = _load_target_module()
    except ImportError as e:
        print(f"[!] Import Error: {{e}}")
        print("    Ensure you are running this script from a correctly configured environment.")
        return

    try:
        {setup_code.strip()}
        if inspect.isawaitable(result):
            asyncio.run(result)
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
