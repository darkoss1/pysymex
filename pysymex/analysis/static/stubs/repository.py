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

"""Load, cache, and organise type stub files by module path."""

from __future__ import annotations

from importlib.util import find_spec
import sys
from pathlib import Path

from pysymex.analysis.static.stubs.parser import StubParser
from pysymex.analysis.static.stubs.types import ClassStub, FunctionStub, ModuleStub
from pysymex.logger import get_logger

logger = get_logger(__name__)


def _mypy_typeshed_path() -> Path | None:
    """Locate mypy's bundled typeshed without importing the optional package."""
    spec = find_spec("mypy")
    if spec is None:
        return None

    package_dir: Path | None = None
    if spec.origin not in (None, "built-in", "frozen"):
        package_dir = Path(spec.origin).parent
    elif spec.submodule_search_locations:
        package_dir = Path(next(iter(spec.submodule_search_locations)))

    if package_dir is None:
        return None

    typeshed_path = package_dir / "typeshed"
    return typeshed_path if typeshed_path.exists() and typeshed_path.is_dir() else None


class StubRepository:
    """
    Repository for loading and caching type stubs.
    """

    def __init__(self) -> None:
        self.cache: dict[str, ModuleStub] = {}
        self._parser = StubParser()
        self.search_paths: list[Path] = []
        self._setup_search_paths()

    def _setup_search_paths(self) -> None:
        """Set up default search paths for stubs."""
        possible_paths = [
            Path(__file__).parent / "typeshed",
            Path(sys.prefix) / "lib" / "python3" / "typeshed",
            Path.home() / ".typeshed",
        ]
        mypy_path = _mypy_typeshed_path()
        if mypy_path is not None:
            possible_paths.append(mypy_path)
        else:
            logger.debug("mypy typeshed package is unavailable for stub search")
        for path in possible_paths:
            if path.exists() and path.is_dir():
                self.search_paths.append(path)
        for site_path in sys.path:
            p = Path(site_path)
            if p.exists() and p.is_dir():
                self.search_paths.append(p)

    def add_search_path(self, path: str) -> None:
        """Add a search path for stubs."""
        p = Path(path)
        if p.exists() and p.is_dir():
            self.search_paths.insert(0, p)

    def get_stub(self, module_name: str) -> ModuleStub | None:
        """Get stub for a module, loading if necessary."""
        if module_name in self.cache:
            return self.cache[module_name]
        stub = self.load_stub(module_name)
        if stub:
            self.cache[module_name] = stub
        return stub

    def load_stub(self, module_name: str) -> ModuleStub | None:
        """Load a stub file for a module."""
        parts = module_name.split(".")
        for search_path in self.search_paths:
            stub_path = search_path
            for part in parts:
                stub_path = stub_path / part
            init_stub = stub_path / "__init__.pyi"
            if init_stub.exists():
                return self._parser.parse_file(str(init_stub))
            module_stub = stub_path.with_suffix(".pyi")
            if module_stub.exists():
                return self._parser.parse_file(str(module_stub))
            stubs_dir = search_path / "stubs"
            if stubs_dir.exists():
                stub_path = stubs_dir / module_name.replace(".", "-")
                init_stub = stub_path / "__init__.pyi"
                if init_stub.exists():
                    return self._parser.parse_file(str(init_stub))
        return None

    def get_function_type(
        self,
        module_name: str,
        function_name: str,
    ) -> FunctionStub | None:
        """Get the stub for a function."""
        stub = self.get_stub(module_name)
        if not stub:
            return None
        return stub.functions.get(function_name)

    def get_class_type(
        self,
        module_name: str,
        class_name: str,
    ) -> ClassStub | None:
        """Get the stub for a class."""
        stub = self.get_stub(module_name)
        if not stub:
            return None
        return stub.classes.get(class_name)

    def get_method_type(
        self,
        module_name: str,
        class_name: str,
        method_name: str,
    ) -> FunctionStub | None:
        """Get the stub for a method."""
        class_stub = self.get_class_type(module_name, class_name)
        if not class_stub:
            return None
        return class_stub.methods.get(method_name)


__all__ = ["StubRepository"]
