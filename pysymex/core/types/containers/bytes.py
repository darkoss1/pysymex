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

"""Z3 sequence-backed bytes carrier with a bounded concrete-value cache."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
import z3

from pysymex.core.cache.control import register_process_cache_clearer
from pysymex.core.solver.constraints.hashing import get_bitvec_val
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.containers.helpers import known_length_truthiness
from pysymex.core.types.scalars.values import fresh_name

BYTES_CONST_CACHE: dict[bytes, SymbolicBytes] = {}
BYTES_CONST_CACHE_LOCK = threading.Lock()
BYTES_CONST_CACHE_LIMIT: int = 1024


def _clear_symbolic_bytes_cache() -> None:
    """Clear process-local concrete bytes construction cache."""
    with BYTES_CONST_CACHE_LOCK:
        BYTES_CONST_CACHE.clear()


register_process_cache_clearer("core.symbolic_bytes_cache", _clear_symbolic_bytes_cache)


@dataclass
class SymbolicBytes(SymbolicType):
    """Bytes value represented as a sequence of 8-bit bit-vectors.

    Concrete construction consults and conditionally fills a bounded module
    cache. Symbolic construction creates an unconstrained sequence expression.
    """

    z3_bytes: z3.SeqRef
    _name: str = ""
    _concrete_value: bytes | None = None
    _z3_len: z3.ArithRef | None = field(default=None, init=False, repr=False, compare=False)
    _truthy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)
    _falsy_cache: z3.BoolRef | None = field(default=None, init=False, repr=False, compare=False)
    _hash_cache: int | None = field(default=None, init=False, repr=False, compare=False)

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        """Return the diagnostic name for this byte-sequence value."""
        return self._name or "bytes"

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 sequence expression representing these bytes."""
        return self.z3_bytes

    @property
    def z3_len(self) -> z3.ArithRef:
        """Return the cached Z3 length expression for the byte sequence."""
        cached = self._z3_len
        if cached is None:
            if self._concrete_value is not None:
                cached = get_int_val(len(self._concrete_value))
            else:
                cached = z3.Length(self.z3_bytes)
            self._z3_len = cached
        return cached

    @z3_len.setter
    def z3_len(self, value: z3.ArithRef) -> None:
        """Override byte length metadata and invalidate length-derived caches."""
        self._z3_len = value
        self._truthy_cache = None
        self._falsy_cache = None

    def hash_value(self) -> int:
        """Return a structural hash of the byte-sequence expression."""
        cached = self._hash_cache
        if cached is None:
            cached = self.z3_bytes.hash()
            self._hash_cache = cached
        return cached

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the predicate that the represented byte sequence is non-empty."""
        cached = self._truthy_cache
        if cached is None:
            length = self._z3_len
            if length is not None:
                cached = known_length_truthiness(length, truthy=True)
            elif self._concrete_value is not None:
                cached = known_length_truthiness(
                    get_int_val(len(self._concrete_value)), truthy=True
                )
            else:
                cached = self.z3_len > 0
            self._truthy_cache = cached
        return cached

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the predicate that the represented byte sequence is empty."""
        cached = self._falsy_cache
        if cached is None:
            length = self._z3_len
            if length is not None:
                cached = known_length_truthiness(length, truthy=False)
            elif self._concrete_value is not None:
                cached = known_length_truthiness(
                    get_int_val(len(self._concrete_value)), truthy=False
                )
            else:
                cached = self.z3_len == 0
            self._falsy_cache = cached
        return cached

    @property
    def concrete_value(self) -> bytes | None:
        """Return the retained concrete bytes payload when available."""
        return self._concrete_value

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicBytes:
        """Create an unconstrained byte-sequence value."""
        bytes_name = name or fresh_name("bytes")
        byte_sort = z3.BitVecSort(8)
        return SymbolicBytes(z3.Const(bytes_name, z3.SeqSort(byte_sort)), bytes_name)

    @staticmethod
    def concrete(value: bytes) -> SymbolicBytes:
        """Create or reuse the cached Z3 sequence for concrete bytes."""
        cached = BYTES_CONST_CACHE.get(value)
        if cached is not None:
            return cached

        byte_sort = z3.BitVecSort(8)
        if not value:
            sv = SymbolicBytes(z3.Empty(z3.SeqSort(byte_sort)), "b''", value)
        else:
            result = z3.Unit(get_bitvec_val(value[0], 8))
            for b in value[1:]:
                result = z3.Concat(result, z3.Unit(get_bitvec_val(b, 8)))
            sv = SymbolicBytes(result, repr(value), value)

        with BYTES_CONST_CACHE_LOCK:
            if len(BYTES_CONST_CACHE) < BYTES_CONST_CACHE_LIMIT:
                BYTES_CONST_CACHE[value] = sv
        return sv
