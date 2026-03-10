import z3
from types import SimpleNamespace

from pysymex.analysis.dead_code.core import UnreachableCodeDetector
from pysymex.analysis.detectors import IssueKind
from pysymex.analysis.detectors.base import _create_default_registry
from pysymex.analysis.detectors.specialized import CommandInjectionDetector
from pysymex.analysis.solver import FunctionAnalyzer, SymType, SymValue, SymbolicState
from pysymex.analysis.summaries.core import SummaryRegistry
from pysymex.analysis.summaries.types import FunctionSummary
from pysymex.analysis.type_inference import (
    ConfidenceScore,
    TypeAnalyzer,
    TypeEnvironment,
    TypeState,
)


class TestSolverAuditFixes:
    def test_visit_key_uses_full_constraint_history(self):
        analyzer = FunctionAnalyzer(SimpleNamespace(max_depth=50))
        x = z3.Int("x")
        y = z3.Int("y")

        state_a = SymbolicState()
        state_b = SymbolicState()
        for constraint in [x > 0, y > 0, x < 10, y < 10, x != 5, y != 7]:
            state_a.add_constraint(constraint)
        for constraint in [x > 1, y > 0, x < 10, y < 10, x != 5, y != 7]:
            state_b.add_constraint(constraint)

        assert analyzer._make_visit_key(1, state_a) != analyzer._make_visit_key(1, state_b)

    def test_symbolic_params_follow_function_annotations(self):
        analyzer = FunctionAnalyzer(SimpleNamespace(max_depth=50))
        captured = {}

        def sample(flag: bool, name: str, count: int):
            return name if flag else str(count)

        def capture_state(cfg, block_id, state, crashes, call_sites, visited, depth):
            captured["flag"] = state.get_var("flag")
            captured["name"] = state.get_var("name")
            captured["count"] = state.get_var("count")

        analyzer._explore_paths = capture_state  # type: ignore[method-assign]
        analyzer.analyze(sample)

        assert captured["flag"] is not None
        assert captured["flag"].sym_type == SymType.BOOL
        assert z3.is_bool(captured["flag"].expr)
        assert captured["name"] is not None
        assert captured["name"].sym_type == SymType.STRING
        assert captured["count"] is not None
        assert captured["count"].sym_type == SymType.INT

    def test_is_op_resolves_obvious_identity(self):
        analyzer = FunctionAnalyzer(SimpleNamespace(max_depth=50))
        state = SymbolicState()
        shared_expr = z3.Int("shared")
        state.push(SymValue(shared_expr, name="left", sym_type=SymType.INT))
        state.push(SymValue(shared_expr, name="right", sym_type=SymType.INT))

        result = analyzer._op_IS_OP(0, state, [], [])

        assert result is not None
        assert z3.is_true(result.expr)

    def test_is_op_resolves_none_vs_non_none(self):
        analyzer = FunctionAnalyzer(SimpleNamespace(max_depth=50))
        state = SymbolicState()
        state.push(SymValue(z3.IntVal(0), name="none", sym_type=SymType.NONE, is_none=True))
        state.push(SymValue(z3.Int("value"), name="value", sym_type=SymType.INT))

        result = analyzer._op_IS_OP(0, state, [], [])

        assert result is not None
        assert z3.is_false(result.expr)


class TestTypeInferenceAuditFixes:
    def test_analyze_function_resets_run_state(self):
        analyzer = TypeAnalyzer()
        analyzer.state_machine.set_state(99, TypeState(env=TypeEnvironment(), pc=99))
        analyzer.confidence_scores[(99, "ghost")] = ConfidenceScore.from_literal()

        def sample(value):
            return value

        result = analyzer.analyze_function(sample)

        assert 99 not in result
        assert 99 not in analyzer.state_machine.states
        assert analyzer.get_confidence_at(99, "ghost").source == "unknown"


class TestSummaryRegistryAuditFixes:
    def test_register_deduplicates_module_membership(self):
        registry = SummaryRegistry()
        summary = FunctionSummary(name="target", module="pkg.module")

        registry.register(summary)
        registry.register(summary)

        summaries = registry.get_for_module("pkg.module")
        assert len(summaries) == 1
        assert summaries[0].name == "target"


class TestDetectorAuditFixes:
    def test_default_registry_keeps_base_resource_leak_detector(self):
        registry = _create_default_registry()

        detector = registry.get("resource-leak")

        assert detector is not None
        assert detector.issue_kind == IssueKind.RESOURCE_LEAK
        assert detector.__class__.__module__.endswith("detectors.base")

    def test_command_injection_requires_dangerous_target(self):
        detector = CommandInjectionDetector()
        state = SimpleNamespace(
            stack=[SimpleNamespace(name="safe.call"), SimpleNamespace(taint_labels={"user_input"})],
            pc=7,
        )
        instruction = SimpleNamespace(opname="CALL", argval=1, arg=1)

        issue = detector.check(state, instruction, lambda constraints: True)

        assert issue is None

    def test_command_injection_reports_dangerous_target(self):
        detector = CommandInjectionDetector()
        state = SimpleNamespace(
            stack=[SimpleNamespace(name="os.system"), SimpleNamespace(taint_labels={"user_input"})],
            pc=11,
        )
        instruction = SimpleNamespace(opname="CALL", argval=1, arg=1)

        issue = detector.check(state, instruction, lambda constraints: True)

        assert issue is not None
        assert "os.system" in issue.message


class TestDeadCodeAuditFixes:
    def test_region_has_user_code_without_terminator_line(self):
        instructions = [
            SimpleNamespace(starts_line=None, positions=None),
            SimpleNamespace(starts_line=42, positions=None),
        ]

        assert UnreachableCodeDetector._region_has_user_code(instructions, 0, 2, None) is True
