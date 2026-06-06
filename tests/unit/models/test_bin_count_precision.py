from __future__ import annotations

import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import BinModel, HexModel, OctModel
from pysymex.models.containers.strings.search.counts import StrCountModel


def test_symbolic_bin_count_one_zero_implies_zero_integer() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("value")

    bin_result = BinModel().apply([value], {}, VMState(pc=10))
    assert isinstance(bin_result.value, SymbolicString)
    count_result = StrCountModel().apply([bin_result.value, "1"], {}, VMState(pc=20))
    assert isinstance(count_result.value, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, *bin_result.constraints, *count_result.constraints)
    solver.add(value.z3_int != 0, count_result.value.z3_int == 0)

    assert solver.check() == z3.unsat


def test_symbolic_bin_count_one_zero_path_remains_satisfiable() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("value")

    bin_result = BinModel().apply([value], {}, VMState(pc=10))
    assert isinstance(bin_result.value, SymbolicString)
    count_result = StrCountModel().apply([bin_result.value, "1"], {}, VMState(pc=20))
    assert isinstance(count_result.value, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, *bin_result.constraints, *count_result.constraints)
    solver.add(value.z3_int == 0, count_result.value.z3_int == 0)

    assert solver.check() == z3.sat


def test_sliced_symbolic_bin_count_one_does_not_inherit_whole_string_zero_fact() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("value")

    bin_result = BinModel().apply([value], {}, VMState(pc=10))
    assert isinstance(bin_result.value, SymbolicString)
    count_result = StrCountModel().apply([bin_result.value, "1", 0, 1], {}, VMState(pc=20))
    assert isinstance(count_result.value, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, *bin_result.constraints, *count_result.constraints)
    solver.add(value.z3_int != 0, count_result.value.z3_int == 0)

    assert solver.check() == z3.sat


def test_bounded_symbolic_hex_count_digit_uses_digit_count_upper_bound() -> None:
    value = SymbolicValue(
        _name="value",
        z3_int=z3.Int("value"),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        affinity_type="int",
        min_val=0,
        max_val=15,
    )

    hex_result = HexModel().apply([value], {}, VMState(pc=30))
    assert isinstance(hex_result.value, SymbolicString)
    count_result = StrCountModel().apply([hex_result.value, "f"], {}, VMState(pc=40))
    assert isinstance(count_result.value, SymbolicValue)

    solver = z3.Solver()
    solver.add(*hex_result.constraints, *count_result.constraints)
    solver.add(count_result.value.z3_int > 1)

    assert solver.check() == z3.unsat


def test_bounded_symbolic_hex_count_keeps_prefix_zero_unbounded_by_digit_metadata() -> None:
    value = SymbolicValue(
        _name="value",
        z3_int=z3.Int("value"),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        affinity_type="int",
        min_val=0,
        max_val=15,
    )

    hex_result = HexModel().apply([value], {}, VMState(pc=30))
    assert isinstance(hex_result.value, SymbolicString)
    count_result = StrCountModel().apply([hex_result.value, "0"], {}, VMState(pc=40))
    assert isinstance(count_result.value, SymbolicValue)

    solver = z3.Solver()
    solver.add(*hex_result.constraints, *count_result.constraints)
    solver.add(count_result.value.z3_int == 2)

    assert solver.check() == z3.sat


def test_bounded_symbolic_oct_count_digit_uses_digit_count_upper_bound() -> None:
    value = SymbolicValue(
        _name="value",
        z3_int=z3.Int("value"),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        affinity_type="int",
        min_val=0,
        max_val=7,
    )

    oct_result = OctModel().apply([value], {}, VMState(pc=50))
    assert isinstance(oct_result.value, SymbolicString)
    count_result = StrCountModel().apply([oct_result.value, "7"], {}, VMState(pc=60))
    assert isinstance(count_result.value, SymbolicValue)

    solver = z3.Solver()
    solver.add(*oct_result.constraints, *count_result.constraints)
    solver.add(count_result.value.z3_int > 1)

    assert solver.check() == z3.unsat


def test_bounded_symbolic_oct_count_keeps_prefix_zero_unbounded_by_digit_metadata() -> None:
    value = SymbolicValue(
        _name="value",
        z3_int=z3.Int("value"),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        affinity_type="int",
        min_val=0,
        max_val=7,
    )

    oct_result = OctModel().apply([value], {}, VMState(pc=50))
    assert isinstance(oct_result.value, SymbolicString)
    count_result = StrCountModel().apply([oct_result.value, "0"], {}, VMState(pc=60))
    assert isinstance(count_result.value, SymbolicValue)

    solver = z3.Solver()
    solver.add(*oct_result.constraints, *count_result.constraints)
    solver.add(count_result.value.z3_int == 2)

    assert solver.check() == z3.sat
