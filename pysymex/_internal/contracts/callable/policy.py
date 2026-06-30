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

"""Opcode and call-target policy for callable contract predicate safety."""

from __future__ import annotations

from pysymex._internal.contracts.combinators import And_, Implies_, Not_, Or_
from pysymex._internal.core.bytecode import CALL_OPCODES

HOST_STATE_MUTATION_OPCODES = frozenset(
    (
        "DELETE_ATTR",
        "DELETE_DEREF",
        "DELETE_GLOBAL",
        "DELETE_NAME",
        "DELETE_SUBSCR",
        "STORE_ATTR",
        "STORE_DEREF",
        "STORE_GLOBAL",
        "STORE_NAME",
        "STORE_SUBSCR",
    ),
)

HOST_RUNTIME_EFFECT_OPCODES = CALL_OPCODES | frozenset(
    (
        "CALL_INTRINSIC_1",
        "CALL_INTRINSIC_2",
        "IMPORT_FROM",
        "IMPORT_NAME",
        "IMPORT_STAR",
    ),
)

HOST_SUBSCRIPT_OPCODES = frozenset(("BINARY_SLICE", "BINARY_SUBSCR"))
HOST_ITERATION_OPCODES = frozenset(("FOR_ITER", "GET_ITER", "UNPACK_EX", "UNPACK_SEQUENCE"))
HOST_MEMBERSHIP_OPCODES = frozenset(("CONTAINS_OP",))
TRUTHINESS_OPCODES = frozenset(("TO_BOOL", "UNARY_NOT"))
HOST_FORMAT_OPCODES = frozenset(
    ("CONVERT_VALUE", "FORMAT_SIMPLE", "FORMAT_WITH_SPEC", "FORMAT_VALUE"),
)

APPROVED_CALL_TARGETS = frozenset((And_, Or_, Not_, Implies_))
