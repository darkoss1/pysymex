import pytest

from pysymex.core.graph.cig import ConstraintInteractionGraph
from pysymex.execution.strategies.tts import AdaptivePathManagerV2, TopologicalThompsonSampling

def test_y_topo_calculation():
    cig = ConstraintInteractionGraph()
    # Branch 100 shares var 'x' with 104
    cig.add_branch(100, frozenset(['x']))
    cig.add_branch(104, frozenset(['x', 'y']))
    cig.add_branch(108, frozenset(['y', 'z']))
    
    # Degrees: 100: 1, 104: 2, 108: 1
    tts = TopologicalThompsonSampling(rho=0.1, lam=1.0, tau=1.5)
    
    # C_MUS = [100, 104]
    # sum_deg = 1 + 2 = 3
    # |C_MUS| = 2, 2^1.5 = 2.828
    # y_topo = -0.1 + 1.0 * (3 / 2.828) = 0.9606
    
    y_topo = tts.calculate_y_topo([100, 104], cig)
    assert round(y_topo, 4) == 0.9607

def test_tts_arm_selection():
    tts = TopologicalThompsonSampling()
    arm = tts.select_arm()
    assert arm in ["topological", "coverage", "random"]
    assert tts.last_arm == arm

def test_tts_update_reward():
    tts = TopologicalThompsonSampling(gamma=0.5)
    
    initial_alpha = tts.arms["topological"][0]
    initial_beta = tts.arms["topological"][1]
    
    # Give a strong reward
    tts.update_reward("topological", 1.0)
    
    # Expect alpha to increase and beta to decay towards 1
    new_alpha = tts.arms["topological"][0]
    new_beta = tts.arms["topological"][1]
    
    assert new_alpha > initial_alpha
    assert new_beta <= initial_beta

def test_adaptive_path_manager_v2():
    cig = ConstraintInteractionGraph()
    manager = AdaptivePathManagerV2(cig)
    
    assert manager.is_empty() is True
    assert manager.size() == 0
    
    # Add a fake state
    manager.add_state("state_1", state_id=1, pc=100, depth=1)
    manager.add_state("state_2", state_id=2, pc=104, depth=2)
    
    assert manager.size() == 2
    assert manager.is_empty() is False
    
    state = manager.get_next_state()
    assert state in ["state_1", "state_2"]
    
    state2 = manager.get_next_state()
    assert state2 in ["state_1", "state_2"]
    assert state != state2
    
    assert manager.is_empty() is True

def test_feedback_mus():
    cig = ConstraintInteractionGraph()
    cig.add_branch(100, frozenset(['x']))
    cig.add_branch(104, frozenset(['x']))
    
    manager = AdaptivePathManagerV2(cig)
    manager.tts.last_arm = "topological"
    initial_alpha = manager.tts.arms["topological"][0]
    
    manager.feedback_mus([100, 104])
    
    assert manager.tts.arms["topological"][0] > initial_alpha
