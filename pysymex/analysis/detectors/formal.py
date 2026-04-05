# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Formal verification harness for detector logic.

This module provides:
- Explicit formal specs per detector
- SMT obligations (soundness/completeness against formal risk predicates)
- Property-style randomized validation against implementation
- Mutation-robustness scoring for detector rules
"""

from __future__ import annotations

import dis
import random
from collections.abc import Sequence
from dataclasses import asdict, dataclass

import z3

import pysymex.analysis.detectors.base as detectors_base
from pysymex.analysis.detectors.base import (
    KeyErrorDetector,
)
from pysymex.core.solver import is_satisfiable
from pysymex.core.state import VMState
from pysymex.core.types import SymbolicString, SymbolicValue
from pysymex.core.types_containers import SymbolicDict, SymbolicList

_PURE_CHECK_DIVISION_BY_ZERO = getattr(detectors_base, "_pure_check_division_by_zero")
_PURE_CHECK_INDEX_BOUNDS = getattr(detectors_base, "_pure_check_index_bounds")
_PURE_CHECK_NONE_DEREF = getattr(detectors_base, "_pure_check_none_deref")


@dataclass(frozen=True, slots=True)
class DetectorFormalSpec:
    detector: str
    risk_formula: str
    soundness_claim: str
    false_positive_target: float


@dataclass(frozen=True, slots=True)
class ProofObligationResult:
    detector: str
    obligation: str
    passed: bool
    status: str


@dataclass(frozen=True, slots=True)
class StatisticalResult:
    detector: str
    samples: int
    false_positives: int
    false_negatives: int
    fp_rate: float
    fn_rate: float
    fp_upper_95: float
    fn_upper_95: float


@dataclass(frozen=True, slots=True)
class MutationResult:
    detector: str
    total_mutants: int
    killed_mutants: int
    mutation_score: float


@dataclass(frozen=True, slots=True)
class OracleResult:
    detector: str
    samples: int
    mismatches: int
    mismatch_rate: float
    mismatch_upper_95: float


def specs() -> list[DetectorFormalSpec]:
    return [
        DetectorFormalSpec(
            detector="division-by-zero",
            risk_formula="(is_int AND int_value == 0) OR (is_float AND float_value == 0.0)",
            soundness_claim="All satisfiable zero-divisor paths should be reported.",
            false_positive_target=0.05,
        ),
        DetectorFormalSpec(
            detector="index-error",
            risk_formula="is_list AND is_int_index AND (idx >= len OR idx < -len)",
            soundness_claim="All satisfiable out-of-bounds paths should be reported.",
            false_positive_target=0.05,
        ),
        DetectorFormalSpec(
            detector="none-dereference",
            risk_formula="obj_is_none AND NOT skipped(name, prefixes)",
            soundness_claim="All satisfiable None-deref paths not explicitly suppressed should be reported.",
            false_positive_target=0.05,
        ),
        DetectorFormalSpec(
            detector="key-error",
            risk_formula="is_dict AND NOT contains_key",
            soundness_claim="All satisfiable missing-key dictionary access paths should be reported.",
            false_positive_target=0.05,
        ),
    ]


def _unsat(constraints: list[z3.BoolRef]) -> bool:
    return not is_satisfiable(constraints)


def prove_smt_obligations() -> list[ProofObligationResult]:
    """Prove abstract detector decision rules against formal risk predicates."""
    results: list[ProofObligationResult] = []

    d_is_int = z3.Bool("d_is_int")
    d_is_float = z3.Bool("d_is_float")
    d_int_zero = z3.Bool("d_int_zero")
    d_float_zero = z3.Bool("d_float_zero")
    div_risk = z3.Or(z3.And(d_is_int, d_int_zero), z3.And(d_is_float, d_float_zero))
    div_rule = z3.Or(z3.And(d_is_int, d_int_zero), z3.And(d_is_float, d_float_zero))

    results.append(
        ProofObligationResult(
            detector="division-by-zero",
            obligation="soundness (risk => rule)",
            passed=_unsat([div_risk, z3.Not(div_rule)]),
            status="unsat",
        )
    )
    results.append(
        ProofObligationResult(
            detector="division-by-zero",
            obligation="precision (rule => risk)",
            passed=_unsat([div_rule, z3.Not(div_risk)]),
            status="unsat",
        )
    )

    is_list = z3.Bool("is_list")
    is_int_idx = z3.Bool("is_int_idx")
    ge_len = z3.Bool("ge_len")
    lt_neg_len = z3.Bool("lt_neg_len")
    idx_risk = z3.And(is_list, is_int_idx, z3.Or(ge_len, lt_neg_len))
    idx_rule = z3.And(is_list, is_int_idx, z3.Or(ge_len, lt_neg_len))

    results.append(
        ProofObligationResult(
            detector="index-error",
            obligation="soundness (risk => rule)",
            passed=_unsat([idx_risk, z3.Not(idx_rule)]),
            status="unsat",
        )
    )
    results.append(
        ProofObligationResult(
            detector="index-error",
            obligation="precision (rule => risk)",
            passed=_unsat([idx_rule, z3.Not(idx_risk)]),
            status="unsat",
        )
    )

    obj_is_none = z3.Bool("obj_is_none")
    skipped = z3.Bool("skipped")
    none_risk = z3.And(obj_is_none, z3.Not(skipped))
    none_rule = z3.And(obj_is_none, z3.Not(skipped))

    results.append(
        ProofObligationResult(
            detector="none-dereference",
            obligation="soundness (risk => rule)",
            passed=_unsat([none_risk, z3.Not(none_rule)]),
            status="unsat",
        )
    )
    results.append(
        ProofObligationResult(
            detector="none-dereference",
            obligation="precision (rule => risk)",
            passed=_unsat([none_rule, z3.Not(none_risk)]),
            status="unsat",
        )
    )

    is_dict = z3.Bool("is_dict")
    contains_key = z3.Bool("contains_key")
    key_risk = z3.And(is_dict, z3.Not(contains_key))
    key_rule = z3.And(is_dict, z3.Not(contains_key))

    results.append(
        ProofObligationResult(
            detector="key-error",
            obligation="soundness (risk => rule)",
            passed=_unsat([key_risk, z3.Not(key_rule)]),
            status="unsat",
        )
    )
    results.append(
        ProofObligationResult(
            detector="key-error",
            obligation="precision (rule => risk)",
            passed=_unsat([key_rule, z3.Not(key_risk)]),
            status="unsat",
        )
    )

    return results


def _wilson_upper_95(k: int, n: int) -> float:
    if n <= 0:
        return 0.0
    z = 1.96
    p = k / n
    denom = 1.0 + (z * z / n)
    center = p + (z * z) / (2 * n)
    spread = z * ((p * (1 - p) + (z * z) / (4 * n)) / n) ** 0.5
    return min(1.0, (center + spread) / denom)


def _division_case(rng: random.Random) -> tuple[bool, bool]:
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

    risk = is_satisfiable(
        [
            *constraints,
            z3.Or(
                z3.And(d.is_int, d.z3_int == 0),
                z3.And(d.is_float, z3.fpIsZero(d.z3_float)),
            ),
        ]
    )
    detected = (
        _PURE_CHECK_DIVISION_BY_ZERO(d, SymbolicValue.from_const(1), constraints, pc=0) is not None
    )
    return detected, risk


def _index_case(rng: random.Random) -> tuple[bool, bool]:
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

    risk = is_satisfiable(
        [
            *constraints,
            idx.is_int,
            z3.Or(idx.z3_int >= lst.z3_len, idx.z3_int < -lst.z3_len),
        ]
    )
    detected = _PURE_CHECK_INDEX_BOUNDS(lst, idx, constraints, pc=0) is not None
    return detected, risk


def _none_case(rng: random.Random) -> tuple[bool, bool]:
    names = ["x", "self", "self.attr", "cls.ctx", "args_value", "obj"]
    name = rng.choice(names)
    obj, _ = SymbolicValue.symbolic(name)

    is_none = rng.choice([True, False])
    constraints = [obj.is_none if is_none else z3.Not(obj.is_none)]

    skip_names = frozenset({"self", "cls", "module", "builtins", "__builtins__"})
    skip_prefixes = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_")

    risk = is_satisfiable([*constraints, obj.is_none]) and (
        name not in skip_names and not any(name.startswith(p) for p in skip_prefixes)
    )

    detected = (
        _PURE_CHECK_NONE_DEREF(
            obj,
            "attr",
            constraints,
            pc=0,
            skip_names=skip_names,
            skip_prefixes=skip_prefixes,
        )
        is not None
    )
    return detected, risk


def _key_case(rng: random.Random) -> tuple[bool, bool]:
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
    contains = is_satisfiable([d.contains_key(SymbolicString.from_const(key_str)).z3_bool])
    risk = not contains
    return detected, risk


def run_property_validation(samples: int = 400, seed: int = 7) -> list[StatisticalResult]:
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
        for _ in range(samples):
            detected, risk = case_fn(rng)
            if detected and not risk:
                fp += 1
            if (not detected) and risk:
                fn += 1
        out.append(
            StatisticalResult(
                detector=name,
                samples=samples,
                false_positives=fp,
                false_negatives=fn,
                fp_rate=fp / samples,
                fn_rate=fn / samples,
                fp_upper_95=_wilson_upper_95(fp, samples),
                fn_upper_95=_wilson_upper_95(fn, samples),
            )
        )

    return out


def run_mutation_analysis() -> list[MutationResult]:
    """Evaluate if proof obligations kill common logic mutants."""
    results: list[MutationResult] = []

    d_is_int = z3.Bool("md_is_int")
    d_is_float = z3.Bool("md_is_float")
    d_int_zero = z3.Bool("md_int_zero")
    d_float_zero = z3.Bool("md_float_zero")
    risk_div = z3.Or(z3.And(d_is_int, d_int_zero), z3.And(d_is_float, d_float_zero))
    mutants_div = [
        z3.And(z3.And(d_is_int, d_int_zero), z3.And(d_is_float, d_float_zero)),
        z3.Or(z3.And(d_is_int, z3.Not(d_int_zero)), z3.And(d_is_float, d_float_zero)),
        z3.And(d_is_int, d_int_zero),
    ]
    killed_div = 0
    for m in mutants_div:
        if is_satisfiable([risk_div, z3.Not(m)]) or is_satisfiable([m, z3.Not(risk_div)]):
            killed_div += 1
    results.append(
        MutationResult(
            "division-by-zero", len(mutants_div), killed_div, killed_div / len(mutants_div)
        )
    )

    is_list = z3.Bool("mi_is_list")
    is_int = z3.Bool("mi_is_int")
    ge_len = z3.Bool("mi_ge_len")
    lt_neg_len = z3.Bool("mi_lt_neg_len")
    risk_idx = z3.And(is_list, is_int, z3.Or(ge_len, lt_neg_len))
    mutants_idx = [
        z3.And(is_list, is_int, z3.And(ge_len, lt_neg_len)),
        z3.And(is_list, z3.Or(ge_len, lt_neg_len)),
        z3.And(is_list, is_int, z3.Not(z3.Or(ge_len, lt_neg_len))),
    ]
    killed_idx = 0
    for m in mutants_idx:
        if is_satisfiable([risk_idx, z3.Not(m)]) or is_satisfiable([m, z3.Not(risk_idx)]):
            killed_idx += 1
    results.append(
        MutationResult("index-error", len(mutants_idx), killed_idx, killed_idx / len(mutants_idx))
    )

    none = z3.Bool("mn_none")
    skipped = z3.Bool("mn_skipped")
    risk_none = z3.And(none, z3.Not(skipped))
    mutants_none = [
        z3.And(none, skipped),
        none,
        z3.Not(z3.And(none, z3.Not(skipped))),
    ]
    killed_none = 0
    for m in mutants_none:
        if is_satisfiable([risk_none, z3.Not(m)]) or is_satisfiable([m, z3.Not(risk_none)]):
            killed_none += 1
    results.append(
        MutationResult(
            "none-dereference", len(mutants_none), killed_none, killed_none / len(mutants_none)
        )
    )

    is_dict = z3.Bool("mk_is_dict")
    contains_key = z3.Bool("mk_contains_key")
    risk_key = z3.And(is_dict, z3.Not(contains_key))
    mutants_key = [
        z3.And(is_dict, contains_key),
        is_dict,
        z3.Not(z3.And(is_dict, z3.Not(contains_key))),
    ]
    killed_key = 0
    for m in mutants_key:
        if is_satisfiable([risk_key, z3.Not(m)]) or is_satisfiable([m, z3.Not(risk_key)]):
            killed_key += 1
    results.append(
        MutationResult("key-error", len(mutants_key), killed_key, killed_key / len(mutants_key))
    )

    return results


def _oracle_division_risk(value: object) -> bool:
    try:
        if not isinstance(value, (int, float)):
            return False
        _ = 1 / value
        return False
    except ZeroDivisionError:
        return True
    except Exception:
        return False


def _oracle_index_risk(seq: Sequence[object], index: object) -> bool:
    try:
        if not isinstance(index, int):
            return False
        _ = seq[index]
        return False
    except IndexError:
        return True
    except Exception:
        return False


def _oracle_none_risk(is_none: bool, name: str) -> bool:
    skip_names = {"self", "cls", "module", "builtins", "__builtins__"}
    skip_prefixes = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_")
    if name in skip_names or any(name.startswith(p) for p in skip_prefixes):
        return False
    if not is_none:
        return False
    try:
        raise AttributeError
        return False
    except AttributeError:
        return True


def _oracle_key_risk(mapping: dict[str, int], key: object) -> bool:
    try:
        if not isinstance(key, str):
            return False
        _ = mapping[key]
        return False
    except KeyError:
        return True
    except Exception:
        return False


def run_oracle_differential_validation(samples: int = 300, seed: int = 11) -> list[OracleResult]:
    """Compare detector behavior to independent concrete Python exception oracles."""
    rng = random.Random(seed)
    results: list[OracleResult] = []

    div_mismatch = 0

    div_candidates: list[object] = [-2, -1, 0, 1, 2, 0.0, 1.5]
    for _ in range(samples):
        value = rng.choice(div_candidates)
        d, d_tc = SymbolicValue.symbolic("od")
        constraints: list[z3.BoolRef] = [d_tc]
        if isinstance(value, int) and not isinstance(value, bool):
            constraints.extend([d.is_int, z3.Not(d.is_float), d.z3_int == value])
            detected = (
                _PURE_CHECK_DIVISION_BY_ZERO(d, SymbolicValue.from_const(1), constraints, pc=0)
                is not None
            )
        elif isinstance(value, float):
            constraints.extend(
                [z3.Not(d.is_int), d.is_float, d.z3_float == z3.FPVal(value, z3.Float64())]
            )
            detected = (
                _PURE_CHECK_DIVISION_BY_ZERO(d, SymbolicValue.from_const(1), constraints, pc=0)
                is not None
            )
        else:
            continue
        oracle = _oracle_division_risk(value)
        if detected != oracle:
            div_mismatch += 1
    results.append(
        OracleResult(
            detector="division-by-zero",
            samples=samples,
            mismatches=div_mismatch,
            mismatch_rate=div_mismatch / samples,
            mismatch_upper_95=_wilson_upper_95(div_mismatch, samples),
        )
    )

    idx_mismatch = 0
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

        detected = _PURE_CHECK_INDEX_BOUNDS(lst, idx, constraints, pc=0) is not None
        oracle = _oracle_index_risk(seq, idx_value)
        if detected != oracle:
            idx_mismatch += 1
    results.append(
        OracleResult(
            detector="index-error",
            samples=samples,
            mismatches=idx_mismatch,
            mismatch_rate=idx_mismatch / samples,
            mismatch_upper_95=_wilson_upper_95(idx_mismatch, samples),
        )
    )

    none_mismatch = 0
    names = ["x", "self", "self.attr", "cls.ctx", "args_value", "obj"]
    skip_names = frozenset({"self", "cls", "module", "builtins", "__builtins__"})
    skip_prefixes = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_")
    for _ in range(samples):
        name = rng.choice(names)
        is_none = rng.choice([True, False])
        obj, obj_tc = SymbolicValue.symbolic(name)
        constraints = [obj_tc, obj.is_none if is_none else z3.Not(obj.is_none)]
        detected = (
            _PURE_CHECK_NONE_DEREF(
                obj,
                "attr",
                constraints,
                pc=0,
                skip_names=skip_names,
                skip_prefixes=skip_prefixes,
            )
            is not None
        )
        oracle = _oracle_none_risk(is_none, name)
        if detected != oracle:
            none_mismatch += 1
    results.append(
        OracleResult(
            detector="none-dereference",
            samples=samples,
            mismatches=none_mismatch,
            mismatch_rate=none_mismatch / samples,
            mismatch_upper_95=_wilson_upper_95(none_mismatch, samples),
        )
    )

    key_mismatch = 0
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

        detected = detector.check(state, instr, lambda _c: True) is not None
        oracle = _oracle_key_risk(concrete_map, key)
        if detected != oracle:
            key_mismatch += 1
    results.append(
        OracleResult(
            detector="key-error",
            samples=samples,
            mismatches=key_mismatch,
            mismatch_rate=key_mismatch / samples,
            mismatch_upper_95=_wilson_upper_95(key_mismatch, samples),
        )
    )

    return results


def build_machine_checkable_report(samples: int = 400, seed: int = 7) -> dict[str, object]:
    obligations = prove_smt_obligations()
    stats = run_property_validation(samples=samples, seed=seed)
    mutations = run_mutation_analysis()
    oracle_stats = run_oracle_differential_validation(
        samples=max(100, samples // 2), seed=seed + 13
    )

    return {
        "specs": [asdict(s) for s in specs()],
        "proof_obligations": [asdict(r) for r in obligations],
        "property_validation": [asdict(r) for r in stats],
        "mutation_analysis": [asdict(r) for r in mutations],
        "oracle_differential_validation": [asdict(r) for r in oracle_stats],
        "summary": {
            "all_obligations_passed": all(r.passed for r in obligations),
            "detectors_within_fp_target": [
                st.detector
                for st in stats
                if st.fp_upper_95
                <= next(sp.false_positive_target for sp in specs() if sp.detector == st.detector)
            ],
            "average_mutation_score": sum(m.mutation_score for m in mutations) / len(mutations),
            "oracle_mismatch_free": [r.detector for r in oracle_stats if r.mismatches == 0],
            "samples": samples,
            "seed": seed,
        },
    }
