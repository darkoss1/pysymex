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

"""Oracle differential validation for detector formal checks."""

from __future__ import annotations

import dis
import random

import z3

from pysymex.analysis.detectors.formal.oracles import (
    oracle_division_risk,
    oracle_index_risk,
    oracle_key_risk,
    oracle_none_risk,
)
from pysymex.analysis.detectors.formal.types import OracleResult
from pysymex.analysis.detectors.runtime import KeyErrorDetector
from pysymex.analysis.detectors.runtime.division_by_zero import pure_check_division_by_zero
from pysymex.analysis.detectors.runtime.index_error.bounds import pure_check_index_bounds
from pysymex.analysis.detectors.runtime.none_dereference import pure_check_none_deref
from pysymex.analysis.static.arithmetic.conditions import symbolic_numeric_zero_condition
from pysymex.core.solver.constraints.hashing import get_string_val
from pysymex.core.solver.engine.queries import check_sat_result
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.utils.math import wilson_upper_95


def _sat_status(constraints: list[z3.BoolRef]) -> SolverResult:
    """Return structured solver evidence for oracle validation cases."""
    return check_sat_result(constraints)


def _oracle_result(
    detector: str,
    samples: int,
    mismatches: int,
    inconclusive: int,
) -> OracleResult:
    """Build an oracle result whose rates use only classified samples."""
    conclusive = max(samples - inconclusive, 0)
    mismatch_rate = mismatches / conclusive if conclusive > 0 else 0.0
    return OracleResult(
        detector=detector,
        samples=samples,
        mismatches=mismatches,
        mismatch_rate=mismatch_rate,
        mismatch_upper_95=wilson_upper_95(mismatches, conclusive),
        inconclusive_samples=inconclusive,
    )


def run_oracle_differential_validation(samples: int = 300, seed: int = 11) -> list[OracleResult]:
    """Compare detector decisions to independent concrete Python exception oracles."""
    rng = random.Random(seed)
    results: list[OracleResult] = []

    div_mismatch = 0
    div_inconclusive = 0
    div_candidates: list[object] = [-2, -1, 0, 1, 2, 0.0, 1.5]
    for _ in range(samples):
        value = rng.choice(div_candidates)
        d, d_tc = SymbolicValue.symbolic("od")
        constraints: list[z3.BoolRef] = [d_tc]
        if isinstance(value, int) and not isinstance(value, bool):
            constraints.extend([d.is_int, z3.Not(d.is_float), d.z3_int == value])
            detected = (
                pure_check_division_by_zero(d, SymbolicValue.from_const(1), constraints, pc=0)
                is not None
            )
        elif isinstance(value, float):
            constraints.extend(
                [z3.Not(d.is_int), d.is_float, d.z3_float == z3.FPVal(value, z3.Float64())]
            )
        else:
            continue
        risk_status = _sat_status(
            [
                *constraints,
                symbolic_numeric_zero_condition(
                    d.is_int,
                    d.z3_int,
                    d.is_float,
                    d.z3_float,
                    include_float=True,
                ),
            ]
        )
        if risk_status.is_unknown:
            div_inconclusive += 1
            continue
        detected = (
            pure_check_division_by_zero(d, SymbolicValue.from_const(1), constraints, pc=0)
            is not None
        )
        oracle = oracle_division_risk(value)
        if detected != oracle:
            div_mismatch += 1
    results.append(_oracle_result("division-by-zero", samples, div_mismatch, div_inconclusive))

    idx_mismatch = 0
    idx_inconclusive = 0
    for _ in range(samples):
        length = rng.randint(0, 5)
        idx_value: object = rng.choice([rng.randint(-7, 7), "x", None])
        seq = [0] * length

        lst, lst_tc = SymbolicList.symbolic("olst")
        idx, idx_tc = SymbolicValue.symbolic("oidx")
        constraints = [lst_tc, idx_tc, lst.z3_len == length, lst.z3_len >= 0]
        if isinstance(idx_value, int):
            constraints.extend([idx.is_int, idx.z3_int == idx_value])
        else:
            constraints.append(z3.Not(idx.is_int))

        risk_status = _sat_status(
            [
                *constraints,
                idx.is_int,
                z3.Or(idx.z3_int < -lst.z3_len, idx.z3_int >= lst.z3_len),
            ]
        )
        if risk_status.is_unknown:
            idx_inconclusive += 1
            continue
        detected = pure_check_index_bounds(lst, idx, constraints, pc=0) is not None
        oracle = oracle_index_risk(seq, idx_value)
        if detected != oracle:
            idx_mismatch += 1
    results.append(_oracle_result("index-error", samples, idx_mismatch, idx_inconclusive))

    none_mismatch = 0
    none_inconclusive = 0
    names = ["x", "self", "self.attr", "cls.ctx", "args_value", "obj"]
    skip_names = frozenset({"self", "cls", "module", "builtins", "__builtins__"})
    skip_prefixes = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_")
    for _ in range(samples):
        name = rng.choice(names)
        is_none = rng.choice([True, False])
        obj, obj_tc = SymbolicValue.symbolic(name)
        constraints = [obj_tc, obj.is_none if is_none else z3.Not(obj.is_none)]
        oracle = oracle_none_risk(is_none, name)
        if oracle:
            risk_status = _sat_status([*constraints, obj.is_none])
            if risk_status.is_unknown:
                none_inconclusive += 1
                continue
        detected = (
            pure_check_none_deref(
                obj,
                "attr",
                constraints,
                pc=0,
                skip_names=skip_names,
                skip_prefixes=skip_prefixes,
            )
            is not None
        )
        if detected != oracle:
            none_mismatch += 1
    results.append(_oracle_result("none-dereference", samples, none_mismatch, none_inconclusive))

    key_mismatch = 0
    key_inconclusive = 0
    for _ in range(samples):
        key = rng.choice(["present", "missing", "k"])
        include = rng.choice([True, False])
        concrete_map = {"present": 1}
        if include:
            concrete_map[key] = 2

        state = VMState()
        detector = KeyErrorDetector()
        d = SymbolicDict.empty("od")
        for k, v in concrete_map.items():
            d = d.__setitem__(SymbolicString.from_const(k), SymbolicValue.from_const(v))

        key_obj: object = key if rng.choice([True, False]) else SymbolicString.from_const(key)
        state.push(d)
        state.push(key_obj)

        def _dummy() -> None:
            return None

        template = next(dis.get_instructions(_dummy))
        instr = template._replace(
            opname="BINARY_SUBSCR",
            opcode=dis.opmap.get("BINARY_SUBSCR", 0),
            arg=0,
            argval=None,
            argrepr="",
        )

        oracle = oracle_key_risk(concrete_map, key)
        if oracle:
            risk_status = _sat_status([z3.Not(z3.Select(d.known_keys, get_string_val(str(key))))])
            if risk_status.is_unknown:
                key_inconclusive += 1
                continue
        detected = detector.check(state, instr, lambda _c: True) is not None
        if detected != oracle:
            key_mismatch += 1
    results.append(_oracle_result("key-error", samples, key_mismatch, key_inconclusive))

    return results


__all__ = ["run_oracle_differential_validation"]
