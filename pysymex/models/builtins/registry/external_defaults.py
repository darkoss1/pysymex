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

"""External default model assembly for the builtin model registry."""

from __future__ import annotations

from pysymex.models.builtins.base import FunctionModel


def external_default_models() -> list[FunctionModel]:
    """Build deferred stdlib, container, and numeric model lists."""
    from pysymex.models.builtins.extended.registry import EXTENDED_MODELS
    from pysymex.models.containers.bytes.registry import BYTES_MODELS
    from pysymex.models.containers.dicts.registry import DICT_MODELS
    from pysymex.models.containers.frozensets.registry import FROZENSET_MODELS
    from pysymex.models.containers.lists.registry import LIST_MODELS
    from pysymex.models.containers.sets.registry import SET_MODELS
    from pysymex.models.containers.strings.registry import STRING_MODELS
    from pysymex.models.containers.tuples.registry import TUPLE_MODELS
    from pysymex.models.numeric import INT_FLOAT_MODELS
    from pysymex.models.stdlib import (
        collections_models,
        datetime_models,
        json_models,
        math_models,
        os_models,
        ospath_models,
        random_models,
        re_models,
        types_models,
    )

    return [
        *math_models,
        *collections_models,
        *os_models,
        *ospath_models,
        *json_models,
        *re_models,
        *random_models,
        *datetime_models,
        *types_models,
        *DICT_MODELS,
        *LIST_MODELS,
        *STRING_MODELS,
        *EXTENDED_MODELS,
        *SET_MODELS,
        *TUPLE_MODELS,
        *BYTES_MODELS,
        *FROZENSET_MODELS,
        *INT_FLOAT_MODELS,
    ]
