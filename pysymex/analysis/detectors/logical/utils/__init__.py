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

"""Public exports for logical-detector utility helpers."""

from __future__ import annotations

from pysymex.analysis.detectors.logical.utils.comparisons import (
    bounds_are_inconsistent,
)
from pysymex.analysis.detectors.logical.utils.comparisons import (
    extract_bool_assignments,
)
from pysymex.analysis.detectors.logical.utils.comparisons import extract_bounds
from pysymex.analysis.detectors.logical.utils.comparisons import (
    extract_modulo_equalities,
)
from pysymex.analysis.detectors.logical.utils.comparisons import (
    extract_product_const_comparisons,
)
from pysymex.analysis.detectors.logical.utils.comparisons import (
    extract_sum_const_comparisons,
)
from pysymex.analysis.detectors.logical.utils.comparisons import (
    extract_var_const_comparisons,
)
from pysymex.analysis.detectors.logical.utils.comparisons import (
    extract_var_const_disequalities,
)
from pysymex.analysis.detectors.logical.utils.comparisons import (
    extract_var_const_equalities,
)
from pysymex.analysis.detectors.logical.utils.comparisons import (
    extract_var_var_comparisons,
)
from pysymex.analysis.detectors.logical.utils.comparisons import (
    select_lower_bound,
)
from pysymex.analysis.detectors.logical.utils.comparisons import (
    select_upper_bound,
)
from pysymex.analysis.detectors.logical.utils.operators import (
    check_sat_over_reals_result,
)
from pysymex.analysis.detectors.logical.utils.operators import (
    core_count_operator,
)
from pysymex.analysis.detectors.logical.utils.operators import (
    core_has_operator,
)
from pysymex.analysis.detectors.logical.utils.operators import count_operator
from pysymex.analysis.detectors.logical.utils.operators import has_operator
from pysymex.analysis.detectors.logical.utils.operators import (
    is_sat_over_reals,
)
from pysymex.analysis.detectors.logical.utils.operators import relax_to_real
from pysymex.analysis.detectors.logical.utils.walk import count_variables
from pysymex.analysis.detectors.logical.utils.walk import (
    expr_contains_variable,
)
from pysymex.analysis.detectors.logical.utils.walk import extract_constants
from pysymex.analysis.detectors.logical.utils.walk import (
    get_variable_names,
)
from pysymex.analysis.detectors.logical.utils.walk import (
    get_variable_names_all,
)
from pysymex.analysis.detectors.logical.utils.walk import get_variables
from pysymex.analysis.detectors.logical.utils.walk import (
    get_variables_for_core,
)
from pysymex.analysis.detectors.logical.utils.walk import (
    iter_subexpressions,
)

__all__ = [
    "bounds_are_inconsistent",
    "check_sat_over_reals_result",
    "core_count_operator",
    "core_has_operator",
    "count_operator",
    "count_variables",
    "expr_contains_variable",
    "extract_bool_assignments",
    "extract_bounds",
    "extract_constants",
    "extract_modulo_equalities",
    "extract_product_const_comparisons",
    "extract_sum_const_comparisons",
    "extract_var_const_comparisons",
    "extract_var_const_disequalities",
    "extract_var_const_equalities",
    "extract_var_var_comparisons",
    "get_variable_names",
    "get_variable_names_all",
    "get_variables",
    "get_variables_for_core",
    "has_operator",
    "is_sat_over_reals",
    "iter_subexpressions",
    "relax_to_real",
    "select_lower_bound",
    "select_upper_bound",
]
