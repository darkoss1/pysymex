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

"""Registry for symbolic-execution bug detectors.

Maps detector names to :class:`~pysymex.analysis.detectors.detector.contract.Detector`
classes, plain :data:`DetectorFn` functions, and their singleton instances.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.types import (
    DetectorFn,
    DetectorInfo,
    IsSatFn,
    Issue,
    IssueKind,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


class FunctionDetectorAdapter(Detector):
    """Adapt a plain :data:`DetectorFn` to the :class:`Detector` ABC interface.

    Allows function-based detectors registered via
    :meth:`DetectorRegistry.register_fn` to be used anywhere a
    :class:`Detector` instance is expected.
    """

    def __init__(self, fn: DetectorFn, info: DetectorInfo) -> None:
        """Wrap *fn* with its *info* metadata."""
        self._fn = fn
        self._info = info
        self.name = info.name
        self.description = info.description
        self.issue_kind = info.issue_kind
        self.relevant_opcodes = info.relevant_opcodes

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Invoke the wrapped detector function and return the result."""
        return self._fn(state, instruction, _solver_check)

    def to_info(self) -> DetectorInfo:
        """Return immutable metadata for the wrapped function."""
        return self._info

    def as_fn(self) -> DetectorFn:
        """Return the wrapped function unchanged."""
        return self._fn


class DetectorRegistry:
    """Registry mapping detector names to classes, functions, and cached instances.

    Two registration tracks are supported:

    * **Class-based** (via :meth:`register`): subclasses of :class:`Detector`
      are instantiated lazily on first access.
    * **Function-based** (via :meth:`register_fn`): plain :data:`DetectorFn`
      callables wrapped in :class:`FunctionDetectorAdapter` on first access.
    """

    def __init__(self) -> None:
        """Initialize an empty DetectorRegistry instance."""
        self.detectors: dict[str, type[Detector]] = {}
        self._instances: dict[str, Detector] = {}
        self.fn_detectors: dict[str, tuple[DetectorFn, DetectorInfo]] = {}
        self._fn_instances: dict[str, FunctionDetectorAdapter] = {}

    def register(self, detector_class: type[Detector]) -> None:
        """Register a detector class by its ``name`` attribute."""
        self.detectors[detector_class.name] = detector_class
        self._instances.pop(detector_class.name, None)

    def register_fn(self, fn: DetectorFn, info: DetectorInfo) -> None:
        """Register a plain detector function."""
        self.fn_detectors[info.name] = (fn, info)
        self._fn_instances.pop(info.name, None)

    def get(self, name: str) -> Detector | None:
        """Return a lazily-instantiated detector by *name*, or ``None`` if unknown."""
        if name in self.detectors:
            if name not in self._instances:
                self._instances[name] = self.detectors[name]()
            return self._instances[name]
        if name in self.fn_detectors:
            if name not in self._fn_instances:
                fn, info = self.fn_detectors[name]
                self._fn_instances[name] = FunctionDetectorAdapter(fn, info)
            return self._fn_instances[name]
        return None

    def get_all(self) -> list[Detector]:
        """Return all detector instances (class- and function-based)."""
        result: list[Detector] = []
        for name in self.detectors:
            detector = self.get(name)
            if detector is not None:
                result.append(detector)
        for name in self.fn_detectors:
            detector = self.get(name)
            if detector is not None:
                result.append(detector)
        return result

    def get_all_fns(self) -> list[tuple[DetectorFn, DetectorInfo]]:
        """Return every detector as a ``(DetectorFn, DetectorInfo)`` pair."""
        result: list[tuple[DetectorFn, DetectorInfo]] = []
        for name in self.detectors:
            inst = self.get(name)
            if inst is not None:
                result.append((inst.as_fn(), inst.to_info()))
        for fn, info in self.fn_detectors.values():
            result.append((fn, info))
        return result

    def get_by_kind(self, kind: IssueKind) -> list[Detector]:
        """Return all detectors whose ``issue_kind`` matches *kind*."""
        return [detector for detector in self.get_all() if detector.issue_kind == kind]

    def list_available(self) -> list[str]:
        """Return all registered detector names."""
        return list(self.detectors.keys()) + list(self.fn_detectors.keys())


__all__ = ["DetectorRegistry", "FunctionDetectorAdapter"]
