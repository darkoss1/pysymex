import pytest
import z3

from pysymex.analysis.summaries.core import (
    SummaryBuilder,
    compose_summaries,
    instantiate_summary,
    SummaryAnalyzer,
    SummaryRegistry
)
from pysymex.analysis.summaries.types import CallSite

def test_stage2_composition_drops_constraints():
    """
    Adversarial test demonstrating that compose_summaries silently drops
    the preconditions and postconditions of the inner function.
    """
    inner_summary = (
        SummaryBuilder("inner")
        .add_parameter("x", "int")
        .set_return_type("int")
        .build()
    )
    x = inner_summary.parameters[0].to_z3()
    inner_summary.add_precondition(x > 10)
    inner_summary.add_postcondition(inner_summary.return_var > 0)
    
    outer_summary = (
        SummaryBuilder("outer")
        .add_parameter("y", "int")
        .set_return_type("int")
        .build()
    )
    y = outer_summary.parameters[0].to_z3()
    
    composed = compose_summaries(
        outer_summary,
        CallSite(callee="inner", args=[y]),
        inner_summary
    )
    
    assert len(composed.preconditions) > 0, "Vulnerability exists: Preconditions were dropped!"
    assert len(composed.postconditions) > 0, "Vulnerability exists: Postconditions were dropped!"

def test_stage3_unbound_variable_trap():
    """
    Adversarial test demonstrating that instantiate_summary and check_preconditions
    now correctly enforce argument binding and accept kwargs.
    """
    summary = (
        SummaryBuilder("target")
        .add_parameter("a", "int")
        .add_parameter("b", "int")
        .build()
    )
    a = summary.parameters[0].to_z3()
    b = summary.parameters[1].to_z3()
    summary.add_precondition(a > b)
    
    registry = SummaryRegistry()
    registry.register(summary)
    analyzer = SummaryAnalyzer(registry)
    
    arg_a = z3.IntVal(10)
    
    with pytest.raises(TypeError, match="Missing required argument: 'b'"):
        instantiate_summary(summary, args=[arg_a], kwargs={})
    
    arg_b_unsafe = z3.IntVal(15)
    is_safe, cex = analyzer.check_preconditions(
        "target", args=[arg_a], path_constraints=[], kwargs={"b": arg_b_unsafe}
    )
    assert is_safe is False, "10 > 15 is False, so precondition is violated"
    
    arg_b_safe = z3.IntVal(5)
    is_safe2, cex2 = analyzer.check_preconditions(
        "target", args=[arg_a], path_constraints=[], kwargs={"b": arg_b_safe}
    )
    assert is_safe2 is True, "10 > 5 is True, so precondition is satisfied"

if __name__ == "__main__":
    pytest.main(["-v", __file__])
