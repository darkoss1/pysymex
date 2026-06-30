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

"""SMT2 path-constraint decoding for spilled frontier checkpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.execution.frontier.checkpoints import FrontierReconstructionStatus
from pysymex._internal.execution.frontier.entries import FrontierMaterializationError
from pysymex._internal.execution.frontier.spill.fields.decode import optional_str

if TYPE_CHECKING:
    from collections.abc import Mapping


def path_constraints(payload: Mapping[str, object], capsule_id: str) -> list[z3.BoolRef]:
    """Return Z3 path constraints decoded from an optional SMT2 payload."""
    smt2_payload = optional_str(payload, "path_constraints_smt2")
    if smt2_payload is None:
        return []
    try:
        parsed_constraints = z3.parse_smt2_string(smt2_payload)
    except z3.Z3Exception as exc:
        raise FrontierMaterializationError(
            capsule_id=capsule_id,
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        ) from exc
    constraints = list(parsed_constraints)
    if not all(isinstance(constraint, z3.BoolRef) for constraint in constraints):
        raise FrontierMaterializationError(
            capsule_id=capsule_id,
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        )
    return [cast("z3.BoolRef", constraint) for constraint in constraints]
