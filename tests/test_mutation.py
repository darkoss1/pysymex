from pysymex.core.types_containers import SymbolicDict
from pysymex.core.state import VMState
from pysymex.models.dicts import DictPopModel
from pysymex.core.types import SymbolicString
import z3

def test_mutation():
    d, c = SymbolicDict.symbolic("my_dict")
    d.z3_len = z3.IntVal(5)
    
    state1 = VMState()
    # Add dict to memory to test proper side effect mutation
    state1.memory[100] = d
    
    state2 = state1.fork()
    
    model = DictPopModel()
    
    key, _ = SymbolicString.symbolic("k")
    
    # Run the model in state2
    res = model.apply([d, key], {}, state2)
    
    # Process side_effects like _apply_model does
    if "dict_mutation" in res.side_effects:
        mut = res.side_effects["dict_mutation"]
        state2.memory[100] = mut["updated_dict"]
        
    d_in_state1 = state1.memory[100]
    print(f"State 1 length: {d_in_state1.z3_len}")
    
    d_in_state2 = state2.memory[100]
    print(f"State 2 length: {d_in_state2.z3_len}")

if __name__ == "__main__":
    test_mutation()