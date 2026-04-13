from pysymex.analysis.detectors.logical.base import LogicalContradictionDetector
from pysymex.analysis.detectors.logical.t1_local import *
from pysymex.analysis.detectors.logical.t2_multivar import *
from pysymex.analysis.detectors.logical.t3_path import *
from pysymex.analysis.detectors.logical.t4_interprocedural import *
from pysymex.analysis.detectors.logical.t5_temporal import *

def create_logic_detector() -> LogicalContradictionDetector:
    detector = LogicalContradictionDetector()
    
    # Tier 1
    detector.register_rule(RangeContradictionRule())
    detector.register_rule(ParityContradictionRule())
    detector.register_rule(ModularContradictionRule())
    detector.register_rule(SelfContradictionRule())
    detector.register_rule(ArithmeticImpossibilityRule())
    detector.register_rule(EqualityContradictionRule())
    detector.register_rule(ComplementContradictionRule())
    
    # Tier 2
    detector.register_rule(AntisymmetryRule())
    detector.register_rule(TriangleImpossibilityRule())
    detector.register_rule(SumImpossibilityRule())
    detector.register_rule(ProductSignContradictionRule())
    detector.register_rule(GcdImpossibilityRule())
    
    # Tier 3
    detector.register_rule(SequentialModularRule())
    detector.register_rule(PostAssignmentContradictionRule())
    detector.register_rule(LoopInvariantViolationRule())
    detector.register_rule(NarrowingContradictionRule())
    detector.register_rule(ReturnTypeContradictionRule())
    
    # Tier 4
    detector.register_rule(PostconditionContradictionRule())
    detector.register_rule(PreconditionImpossibilityRule())
    detector.register_rule(ApiContractViolationRule())
    detector.register_rule(TaintConstraintContradictionRule())
    detector.register_rule(NumericRangePropagationRule())
    
    # Tier 5
    detector.register_rule(StateImpossibilityRule())
    detector.register_rule(ResourceStateContradictionRule())
    detector.register_rule(ConcurrencyContradictionRule())
    
    return detector

__all__ = ["LogicalContradictionDetector", "create_logic_detector"]
