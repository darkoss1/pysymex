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

"""Numeric degraded-pass labels shared by opcode helpers and fallback events."""

SYMBOLIC_POWER_ABSTRACTION = "symbolic_power_abstraction"
SYMBOLIC_SHIFT_ABSTRACTION = "symbolic_shift_abstraction"
SYMBOLIC_BITWISE_ABSTRACTION = "symbolic_bitwise_abstraction"
UNSUPPORTED_NUMERIC_ABSTRACTION = "unsupported_numeric_abstraction"
UNSUPPORTED_NUMERIC_REFLECTION = "unsupported_numeric_reflection"
UNARY_POSITIVE_TYPE_UNCERTAIN = "unary_positive_type_uncertain"
NUMERIC_TYPE_ERROR_FEASIBILITY_UNKNOWN = "numeric_type_error_feasibility_unknown"
