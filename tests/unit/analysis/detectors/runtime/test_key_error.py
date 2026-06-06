"""Tests for pysymex/analysis/detectors/runtime/key_error.py."""

from __future__ import annotations

import dis
import time

import z3

from pysymex.analysis.detectors.runtime.errors.key import KeyErrorDetector
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.containers.dicts import SymbolicDict


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    """Create a deterministic instruction for detector unit tests."""

    def _dummy() -> None:
        """Provide bytecode for a template instruction."""
        return None

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


def _is_sat(constraints: list[z3.BoolRef]) -> bool:
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check() == z3.sat


class TestKeyErrorDetector:
    """Test suite for pysymex.analysis.detectors.detector.KeyErrorDetector."""

    def test_relevant_opcodes_include_normal_subscript_reads(self) -> None:
        """Runtime dispatch must invoke the detector for ordinary ``dict[key]`` reads."""
        assert "BINARY_SUBSCR" in KeyErrorDetector.relevant_opcodes

    def test_check_reports_missing_key_for_concrete_dict(self) -> None:
        """Report KEY_ERROR for concrete dictionaries missing the requested key."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        state = VMState(stack=[{"present": 1}, "missing"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_existing_key_for_concrete_dict(self) -> None:
        """Return None when concrete dictionary key exists."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        state = VMState(stack=[{"present": 1}, "present"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_missing_key_for_symbolic_dict_string_key(self) -> None:
        """Report KEY_ERROR for symbolic dictionaries when string key may be absent."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.empty("sym_dict")
        state = VMState(
            stack=[symbolic_dict, SymbolicString.from_const("missing")],
            path_constraints=[],
            pc=1,
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_missing_key_for_symbolic_value_string_key(self) -> None:
        """Report KEY_ERROR when key is represented as SymbolicValue constrained to string."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.empty("sym_dict")
        symbolic_key = SymbolicValue.from_const("missing")
        state = VMState(stack=[symbolic_dict, symbolic_key], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_defaultdict_subscript_missing_key(self) -> None:
        """A default-producing dictionary supplies missing values on subscription."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.empty("defaultdict")
        setattr(symbolic_dict, "_has_default_factory", True)
        state = VMState(stack=[symbolic_dict, "missing"], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_reports_defaultdict_delete_missing_key(self) -> None:
        """Default factories do not make deletion of missing keys safe."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("DELETE_SUBSCR")
        symbolic_dict = SymbolicDict.empty("defaultdict")
        setattr(symbolic_dict, "_has_default_factory", True)
        state = VMState(stack=[symbolic_dict, "missing"], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is not None

    def test_check_ignores_non_dict_container(self) -> None:
        """Return None when container is not a dictionary."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        state = VMState(stack=[[1, 2, 3], "missing"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_symbolic_dict_concrete_items_present_key_no_issue(self) -> None:
        """Do not report KEY_ERROR when symbolic dict has concrete backing and key exists."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.from_const({"present": 1})
        state = VMState(stack=[symbolic_dict, "present"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_symbolic_dict_concrete_items_missing_key_reports(self) -> None:
        """Report KEY_ERROR when symbolic dict has concrete backing and key is missing."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.from_const({"present": 1})
        state = VMState(stack=[symbolic_dict, "missing"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_symbolic_dict_symbolic_int_key_guard_suppresses_issue(self) -> None:
        """Do not report KEY_ERROR when an int-key membership guard proves presence."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.from_const({1: "one", 2: "two"})
        symbolic_key, type_constraint = SymbolicValue.symbolic_int("k")
        presence = symbolic_dict.concrete_key_presence_condition(symbolic_key)
        assert presence is not None
        state = VMState(
            stack=[symbolic_dict, symbolic_key],
            path_constraints=[type_constraint, presence],
            pc=1,
        )

        issue = detector.check(state, instruction, _is_sat)

        assert issue is None

    def test_check_symbolic_int_key_guard_suppresses_inconclusive_prefix_issue(self) -> None:
        """An inconclusive prefix must not report a locally contradicted missing-key query."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.from_const({1: "one", 2: "two"})
        symbolic_key, type_constraint = SymbolicValue.symbolic_int("guarded_present_key")
        presence = symbolic_dict.concrete_key_presence_condition(symbolic_key)
        assert presence is not None
        path_constraints = [type_constraint, presence]
        state = VMState(
            stack=[symbolic_dict, symbolic_key],
            path_constraints=path_constraints,
            last_inconclusive_feasibility_len=len(path_constraints),
            pc=1,
        )

        issue = detector.check(state, instruction, lambda _constraints: False)

        assert issue is None

    def test_check_symbolic_dict_symbolic_int_key_missing_path_reports(self) -> None:
        """Report KEY_ERROR when an int-key membership guard proves absence."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.from_const({1: "one", 2: "two"})
        symbolic_key, type_constraint = SymbolicValue.symbolic_int("k")
        presence = symbolic_dict.concrete_key_presence_condition(symbolic_key)
        assert presence is not None
        state = VMState(
            stack=[symbolic_dict, symbolic_key],
            path_constraints=[type_constraint, z3.Not(presence)],
            pc=1,
        )

        issue = detector.check(state, instruction, _is_sat)

        assert issue is not None

    def test_check_symbolic_dict_concrete_items_symbolic_key_reports(self) -> None:
        """Report KEY_ERROR when concrete-backed SymbolicDict is indexed by symbolic key."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.from_const({"present": 1})
        symbolic_key, _symbolic_constraint = SymbolicString.symbolic("k")
        state = VMState(stack=[symbolic_dict, symbolic_key], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_missing_key_for_delete_subscr(self) -> None:
        """Report KEY_ERROR for DELETE_SUBSCR when key can be absent."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("DELETE_SUBSCR")
        state = VMState(stack=[{"present": 1}, "missing"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_missing_key_for_dict_pop_call(self) -> None:
        """Report KEY_ERROR for dict.pop call when key can be absent."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)

        class _PopCallable:
            __name__ = "mapping.pop"

            def __call__(self) -> None:
                return None

        state = VMState(
            stack=[_PopCallable(), {"present": 1}, "missing"], path_constraints=[], pc=1
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_concrete_dict_pop_call_with_default(self) -> None:
        """Do not report KEY_ERROR for dict.pop(key, default)."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("CALL", arg=2, argval=2)

        class _PopCallable:
            __name__ = "mapping.pop"

            def __call__(self) -> None:
                return None

        state = VMState(
            stack=[_PopCallable(), {"present": 1}, "missing", None],
            path_constraints=[],
            pc=1,
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_symbolic_dict_pop_call_with_default(self) -> None:
        """Do not report KEY_ERROR for SymbolicDict.pop(key, default)."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("CALL", arg=2, argval=2)

        class _PopCallable:
            __name__ = "mapping.pop"

            def __call__(self) -> None:
                return None

        state = VMState(
            stack=[_PopCallable(), SymbolicDict.empty("pop_default_dict"), "missing", None],
            path_constraints=[],
            pc=1,
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_inconclusive_concrete_dict_key_error_on_solver_unknown(self) -> None:
        """Solver UNKNOWN may surface only as a model-less low-confidence KeyError."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        x = z3.Int("unknown_key_error_path")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            issue = detector.check(
                VMState(stack=[{"present": 1}, "missing"], path_constraints=[x > 0], pc=1),
                instruction,
                lambda _constraints: True,
            )
        finally:
            active_incremental_solver.reset(token)

        assert issue is not None
        assert "Path feasibility inconclusive" in issue.message
        assert issue.model is None
        assert issue.get_counterexample() == {}
        assert issue.confidence == 0.5
        assert issue.likelihood == 0.5

    def test_check_reports_inconclusive_symbolic_dict_key_error_on_solver_unknown(self) -> None:
        """Symbolic missing-key reports keep solver uncertainty visible."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.empty("unknown_sym_dict")
        key, key_constraint = SymbolicString.symbolic("unknown_key")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = active_incremental_solver.set(solver)
        try:
            issue = detector.check(
                VMState(
                    stack=[symbolic_dict, key],
                    path_constraints=[key_constraint],
                    pc=1,
                ),
                instruction,
                lambda _constraints: True,
            )
        finally:
            active_incremental_solver.reset(token)

        assert issue is not None
        assert "Path feasibility inconclusive" in issue.message
        assert issue.model is None
        assert issue.get_counterexample() == {}
        assert issue.confidence == 0.5
        assert issue.likelihood == 0.5
