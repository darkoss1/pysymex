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

"""Statistical property validation for formal runtime detector checks."""

from __future__ import annotations

import dis
import random
from collections.abc import Iterable

import z3

from pysymex.analysis.detectors.formal.types import StatisticalResult
from pysymex.analysis.detectors.runtime import KeyErrorDetector
from pysymex.analysis.detectors.runtime.division_by_zero import pure_check_division_by_zero
from pysymex.analysis.detectors.runtime.index_error.bounds import pure_check_index_bounds
from pysymex.analysis.detectors.runtime.none_dereference import pure_check_none_deref
from pysymex.core.solver.engine.queries import check_sat_result
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.utils.math import wilson_upper_95


def run_property_validation(samples: int = 400, seed: int = 7) -> list[StatisticalResult]:
    """Run statistical property validation over multiple randomized test cases.

    Validates false positive and false negative rates against targets for various
    detectors (division-by-zero, index-error, none-dereference, key-error).

    Args:
        samples: The number of randomized samples to generate per detector.
        seed: Random seed for reproducibility.

    Returns:
        A list of StatisticalResult objects summarizing the validation results.
    """
    rng = random.Random(seed)
    out: list[StatisticalResult] = []

    for name, case_fn in (
        ("division-by-zero", _division_case),
        ("index-error", _index_case),
        ("none-dereference", _none_case),
        ("key-error", _key_case),
    ):
        fp = 0
        fn = 0
        inconclusive = 0
        for _ in range(samples):
            detected, risk, is_inconclusive = case_fn(rng)
            if is_inconclusive:
                inconclusive += 1
                continue
            if detected and not risk:
                fp += 1
            if (not detected) and risk:
                fn += 1

        conclusive = _conclusive_samples(samples, inconclusive)
        out.append(
            StatisticalResult(
                detector=name,
                samples=samples,
                false_positives=fp,
                false_negatives=fn,
                fp_rate=_rate(fp, conclusive),
                fn_rate=_rate(fn, conclusive),
                fp_upper_95=wilson_upper_95(fp, conclusive),
                fn_upper_95=wilson_upper_95(fn, conclusive),
                inconclusive_samples=inconclusive,
            )
        )

    return out


def _division_case(rng: random.Random) -> tuple[bool, bool, bool]:
    """Generate a randomized division case and compare detector output to risk evidence."""
    d, _ = SymbolicValue.symbolic("d")
    constraints: list[z3.BoolRef] = []

    force_int = rng.choice([True, False])
    force_float = rng.choice([True, False])
    int_val = rng.randint(-2, 2)
    float_val = rng.choice([-1.0, -0.0, 0.0, 1.0, 2.0])

    constraints.extend([d.is_int if force_int else z3.Not(d.is_int)])
    constraints.extend([d.is_float if force_float else z3.Not(d.is_float)])
    constraints.append(d.z3_int == int_val)
    constraints.append(d.z3_float == z3.FPVal(float_val, z3.Float64()))

    risk_status = _sat_status(
        [
            *constraints,
            z3.Or(
                z3.And(d.is_int, d.z3_int == 0),
                z3.And(d.is_float, z3.fpIsZero(d.z3_float)),
            ),
        ]
    )
    detected = (
        pure_check_division_by_zero(d, SymbolicValue.from_const(1), constraints, pc=0) is not None
    )
    return detected, risk_status.is_sat, risk_status.is_unknown


def _index_case(rng: random.Random) -> tuple[bool, bool, bool]:
    """Generate a randomized index-bounds case and compare detector output to risk evidence."""
    lst, lst_tc = SymbolicList.symbolic("lst")
    idx, idx_tc = SymbolicValue.symbolic("idx")

    length = rng.randint(0, 5)
    index_value = rng.randint(-7, 7)
    force_int = rng.choice([True, False])

    constraints = [
        lst_tc,
        idx_tc,
        lst.z3_len == length,
        lst.z3_len >= 0,
        idx.z3_int == index_value,
        idx.is_int if force_int else z3.Not(idx.is_int),
    ]

    risk_status = _sat_status(
        [
            *constraints,
            idx.is_int,
            z3.Or(idx.z3_int >= lst.z3_len, idx.z3_int < -lst.z3_len),
        ]
    )
    detected = pure_check_index_bounds(lst, idx, constraints, pc=0) is not None
    return detected, risk_status.is_sat, risk_status.is_unknown


def _none_case(rng: random.Random) -> tuple[bool, bool, bool]:
    """Generate a randomized None-dereference case and compare detector output to risk evidence."""
    names = ["x", "self", "self.attr", "cls.ctx", "args_value", "obj"]
    name = rng.choice(names)
    obj, _ = SymbolicValue.symbolic(name)

    is_none = rng.choice([True, False])
    constraints = [obj.is_none if is_none else z3.Not(obj.is_none)]

    skip_names = frozenset({"self", "cls", "module", "builtins", "__builtins__"})
    skip_prefixes = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_")

    risk_status = _sat_status([*constraints, obj.is_none])
    skipped = name in skip_names or any(name.startswith(p) for p in skip_prefixes)
    risk = risk_status.is_sat and not skipped
    inconclusive = risk_status.is_unknown and not skipped

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
    return detected, risk, inconclusive


def _key_case(rng: random.Random) -> tuple[bool, bool, bool]:
    """Generate a randomized dict-subscript case and compare detector output to risk evidence."""
    state = VMState()
    detector = KeyErrorDetector()
    d = SymbolicDict.empty("d")
    key_str = rng.choice(["k", "missing", "present"])

    if rng.choice([True, False]):
        d = d.__setitem__(SymbolicString.from_const(key_str), SymbolicValue.from_const(1))

    if rng.choice([True, False]):
        key_obj: object = key_str
    else:
        key_obj = SymbolicString.from_const(key_str)

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

    detected = detector.check(state, instr, lambda _c: True) is not None
    contains_status = _sat_status([d.contains_key(SymbolicString.from_const(key_str)).z3_bool])
    risk = contains_status.is_unsat
    return detected, risk, contains_status.is_unknown


def _conclusive_samples(samples: int, inconclusive: int) -> int:
    """Return the number of samples that contributed classified evidence."""
    return max(samples - inconclusive, 0)


def _rate(count: int, conclusive_samples: int) -> float:
    """Return a metric rate over classified samples only."""
    if conclusive_samples <= 0:
        return 0.0
    return count / conclusive_samples


def _sat_status(constraints: Iterable[z3.BoolRef]) -> SolverResult:
    """Return structured SAT/UNSAT/UNKNOWN evidence for formal validation cases."""
    return check_sat_result(constraints)


__all__ = ["run_property_validation"]
