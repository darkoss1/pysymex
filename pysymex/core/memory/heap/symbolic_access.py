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

"""Symbolic address helpers for heap storage."""

from __future__ import annotations

from pysymex.logger import get_logger

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.identity.addressing import next_address
from pysymex.core.memory.heap.alias_policy import SymbolicHeapAliasPolicyMixin
from pysymex.core.memory.types import MemoryRegion, SymbolicAddress
from pysymex.core.types.scalars.values import SymbolicValue

logger = get_logger(__name__)


class SymbolicHeapAccessMixin(SymbolicHeapAliasPolicyMixin):
    """Implement Z3-backed reads and writes for symbolic addresses.

    Symbolic fields are represented by per-region Z3 arrays. Heap-level alias
    policy lives in :class:`~pysymex.core.memory.heap.alias_policy.SymbolicHeapAliasPolicyMixin`.
    """

    _z3_memory: dict[tuple[MemoryRegion, str], z3.ArrayRef]

    def _get_memory_array(self, region: MemoryRegion, field: str) -> z3.ArrayRef:
        """Return or allocate the Z3 array storing one region/field pair."""
        key = (region, field)
        if key not in self._z3_memory:
            arr = z3.Array(
                f"mem_{region.name}_{field}_{next_address()}", z3.BitVecSort(64), z3.IntSort()
            )
            self._z3_memory[key] = arr
        return self._z3_memory[key]

    def _get_concrete_address(self, address: SymbolicAddress) -> int | None:
        """Return a wrapped 64-bit concrete address when both terms are literals."""
        try:
            if z3.is_bv_value(address.base) and z3.is_bv_value(address.offset):
                base = address.base.as_long()
                offset = address.offset.as_long()
                return (base + offset) & ((1 << 64) - 1)
        except z3.Z3Exception:
            logger.debug("Failed to resolve concrete address", exc_info=True)
        return None

    def _as_symbolic_value(self, value: object, hint: str) -> SymbolicValue:
        """Convert supported concrete values to storage values, widening others."""
        if isinstance(value, SymbolicValue):
            return value
        if value is None:
            return SymbolicValue.from_const(None)
        if isinstance(value, bool | int | float | str):
            return SymbolicValue.from_const(value)
        sym, _ = SymbolicValue.symbolic(hint)
        return sym

    def _read_symbolic(self, address: SymbolicAddress, field: str) -> SymbolicValue:
        """Construct an integer symbolic value by selecting from a memory array."""
        arr = self._get_memory_array(address.region, field)
        merged_expr = z3.Select(arr, address.effective_address)
        if not isinstance(merged_expr, z3.ArithRef):
            raise TypeError("Symbolic heap read expected arithmetic Z3 value")

        return SymbolicValue(
            _name=f"mem_read_{field}_{next_address()}",
            z3_int=merged_expr,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )

    def _write_symbolic(self, address: SymbolicAddress, value: object, field: str) -> None:
        """Write a converted value into the Z3 array for a symbolic address."""
        value_sv = self._as_symbolic_value(value, f"mem_write_{field}")
        arr = self._get_memory_array(address.region, field)
        self._z3_memory[(address.region, field)] = z3.Store(
            arr, address.effective_address, value_sv.z3_int
        )
