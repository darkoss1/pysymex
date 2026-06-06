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

"""Compile-only module loading for symbolic scans.

Owns source scan-path discovery, static class binding, default scan globals,
and package import-path scoping without executing target module code.
"""

from __future__ import annotations

from pysymex.analysis.scan.loading.discovery import (
    bind_top_level_class_definitions,
    collect_source_scan_paths,
    collect_top_level_class_names,
    collect_top_level_function_names,
    detect_package_name,
    find_package_root,
    is_test_file,
    should_scan_source_function,
)
from pysymex.analysis.scan.loading.environment import get_default_module_globals
from pysymex.analysis.scan.loading.globals import build_module_globals, scoped_package_import_path
from pysymex.analysis.scan.loading.stdlib.imports import (
    is_safe_stdlib_import,
    populate_concrete_stdlib_imports,
    stdlib_root,
)

__all__ = [
    "bind_top_level_class_definitions",
    "build_module_globals",
    "collect_source_scan_paths",
    "collect_top_level_class_names",
    "collect_top_level_function_names",
    "detect_package_name",
    "find_package_root",
    "get_default_module_globals",
    "is_safe_stdlib_import",
    "is_test_file",
    "populate_concrete_stdlib_imports",
    "scoped_package_import_path",
    "should_scan_source_function",
    "stdlib_root",
]
