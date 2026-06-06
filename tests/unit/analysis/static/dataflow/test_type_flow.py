"""Tests for type-flow analysis."""

from __future__ import annotations

from pysymex.analysis.static.dataflow.type_flow import TypeFlowAnalysis
from pysymex.analysis.static.types import PyType, TypeAnalyzer, TypeEnvironment, TypeKind
from tests.unit.analysis.static.dataflow.helpers import MockCFG, MockInstr, make_block


class TestTypeFlowAnalysis:
    """Test suite for pysymex.analysis.static.dataflow.type_flow.TypeFlowAnalysis."""

    def test_initial_value(self) -> None:
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer())
        assert isinstance(tfa.initial_value(), TypeEnvironment)

    def test_boundary_value(self) -> None:
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer())
        assert isinstance(tfa.boundary_value(), TypeEnvironment)

    def test_transfer(self) -> None:
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer())
        bb = make_block(0, [MockInstr("LOAD_CONST", 10, 42), MockInstr("STORE_NAME", 12, "x")])
        out_env = tfa.transfer(bb, TypeEnvironment())
        assert out_env.get_type("x").is_numeric()

    def test_transfer_infers_binary_operation_result(self) -> None:
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer())
        bb = make_block(
            0,
            [
                MockInstr("LOAD_CONST", 10, 1),
                MockInstr("LOAD_CONST", 12, 2.5),
                MockInstr("BINARY_OP", 14, "+", "+"),
                MockInstr("STORE_NAME", 16, "x"),
            ],
        )

        out_env = tfa.transfer(bb, TypeEnvironment())

        assert out_env.get_type("x").kind == TypeKind.FLOAT

    def test_transfer_decodes_binary_op_numeric_arg_when_argrepr_missing(self) -> None:
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer())
        bb = make_block(
            0,
            [
                MockInstr("LOAD_CONST", 10, 4),
                MockInstr("LOAD_CONST", 12, 2),
                MockInstr("BINARY_OP", 14, 11, ""),
                MockInstr("STORE_NAME", 16, "x"),
            ],
        )

        out_env = tfa.transfer(bb, TypeEnvironment())

        assert out_env.get_type("x").kind == TypeKind.FLOAT

    def test_transfer_infers_compare_operation_result(self) -> None:
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer())
        bb = make_block(
            0,
            [
                MockInstr("LOAD_CONST", 10, 1),
                MockInstr("LOAD_CONST", 12, 2),
                MockInstr("COMPARE_OP", 14, "<", "<"),
                MockInstr("STORE_NAME", 16, "x"),
            ],
        )

        out_env = tfa.transfer(bb, TypeEnvironment())

        assert out_env.get_type("x").kind == TypeKind.BOOL

    def test_transfer_decodes_compare_op_numeric_arg_when_argrepr_missing(self) -> None:
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer())
        bb = make_block(
            0,
            [
                MockInstr("LOAD_CONST", 10, 1),
                MockInstr("LOAD_CONST", 12, 2),
                MockInstr("COMPARE_OP", 14, 2, ""),
                MockInstr("STORE_NAME", 16, "x"),
            ],
        )

        out_env = tfa.transfer(bb, TypeEnvironment())

        assert out_env.get_type("x").kind == TypeKind.BOOL

    def test_transfer_infers_subscript_operation_result(self) -> None:
        initial_env = TypeEnvironment()
        initial_env.set_type("items", PyType.list_(PyType.str_()))
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer(), initial_env)
        bb = make_block(
            0,
            [
                MockInstr("LOAD_NAME", 10, "items"),
                MockInstr("LOAD_CONST", 12, 0),
                MockInstr("BINARY_SUBSCR", 14),
                MockInstr("STORE_NAME", 16, "x"),
            ],
        )

        out_env = tfa.transfer(bb, initial_env)

        assert out_env.get_type("x").kind == TypeKind.STR

    def test_transfer_infers_unary_operation_result(self) -> None:
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer())
        bb = make_block(
            0,
            [
                MockInstr("LOAD_CONST", 10, True),
                MockInstr("UNARY_NEGATIVE", 12),
                MockInstr("STORE_NAME", 14, "x"),
            ],
        )

        out_env = tfa.transfer(bb, TypeEnvironment())

        assert out_env.get_type("x").kind == TypeKind.INT

    def test_transfer_delete_clears_type_fact(self) -> None:
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer())
        bb = make_block(
            0,
            [
                MockInstr("LOAD_CONST", 10, 42),
                MockInstr("STORE_NAME", 12, "x"),
                MockInstr("DELETE_NAME", 14, "x"),
            ],
        )
        out_env = tfa.transfer(bb, TypeEnvironment())

        assert out_env.get_type("x").kind == TypeKind.UNKNOWN
        assert "x" not in out_env.definitely_assigned
        assert "x" not in out_env.maybe_assigned

    def test_meet(self) -> None:
        tfa = TypeFlowAnalysis(MockCFG(), TypeAnalyzer())
        e1 = TypeEnvironment()
        e1.set_type("x", PyType.int_type())
        e2 = TypeEnvironment()
        e2.set_type("x", PyType.str_type())
        met = tfa.meet([e1, e2])
        assert met.get_type("x").name == "Union"

    def test_get_type_at(self) -> None:
        cfg = MockCFG()
        cfg.blocks = {
            0: make_block(0, [MockInstr("LOAD_CONST", 10, 42), MockInstr("STORE_NAME", 12, "x")])
        }
        tfa = TypeFlowAnalysis(cfg, TypeAnalyzer())
        tfa.in_facts[0] = TypeEnvironment()
        assert tfa.get_type_at(14, "x").is_numeric()
