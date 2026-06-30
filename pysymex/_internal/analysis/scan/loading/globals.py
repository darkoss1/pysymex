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

"""Module global namespace assembly for compile-only symbolic scans.

Builds globals with default environment entries, literal top-level bindings,
statically bound functions, and class definitions without executing target module code.
"""

from __future__ import annotations

import types
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.loading.classes.binding import TopLevelClasses
from pysymex._internal.analysis.scan.loading.environment import ModuleGlobals
from pysymex._internal.analysis.scan.loading.literal.bindings import TopLevelLiterals
from pysymex._internal.analysis.scan.loading.source.paths import SourceScanPaths
from pysymex._internal.analysis.scan.loading.stdlib.imports import StdlibImports

if TYPE_CHECKING:
    from pathlib import Path


def build_module_globals(
    *,
    content: str,
    file_path: Path,
    full_module_name: str,
    package_name: str,
    all_code_with_context: list[tuple[types.CodeType, str | None, str | None]],
) -> dict[str, object]:
    """Build globals used when scanning a source module and its functions.

    Initializes module-level constants (``__file__``, ``__name__``, ``__package__``),
    constructs bound ``FunctionType`` and
    ``ClassDef`` mocks statically so the symbolic execution VM can reference them.

    Args:
        content: The raw source code string of the module.
        file_path: The file path to the module.
        full_module_name: Fully qualified name of the module.
        package_name: Enclosing package name.
        all_code_with_context: List of code objects with enclosing class and path.

    Returns:
        A dictionary containing the populated global namespace for scanning.

    Side Effects:
        Binds static class/function definitions in-place.

    """
    module_globals = ModuleGlobals.default()
    StdlibImports.populate_concrete(content, module_globals)
    module_globals["__file__"] = str(file_path)
    module_globals["__name__"] = full_module_name
    module_globals["__package__"] = package_name
    literal_bindings = TopLevelLiterals.bindings(content)
    module_globals.update(literal_bindings)
    top_level_function_names = SourceScanPaths.top_level_functions(content, file_path)
    default_bindings = {**module_globals, **literal_bindings}
    literal_defaults = TopLevelLiterals.defaults(content, default_bindings)
    for code, _class_name, full_path in all_code_with_context:
        if not _is_top_level_function_code(code, top_level_function_names, full_path):
            continue
        defaults, kwdefaults = literal_defaults.get(code.co_name, (None, None))
        bound_function = types.FunctionType(
            code,
            module_globals,
            code.co_name,
            defaults or None,
        )
        if kwdefaults:
            bound_function.__kwdefaults__ = kwdefaults
        module_globals[code.co_name] = bound_function
    TopLevelClasses.bind_definitions(content, all_code_with_context, module_globals)

    return module_globals


def _is_top_level_function_code(
    code: types.CodeType,
    top_level_function_names: set[str],
    full_path: str | None,
) -> bool:
    """Return whether *code* is the callable body for a top-level source function."""
    if code.co_name not in top_level_function_names or full_path is None or code.co_freevars:
        return False
    if "." not in full_path:
        return full_path == code.co_name
    generic_path = f"<generic parameters of {code.co_name}>.{code.co_name}"
    return full_path == generic_path
