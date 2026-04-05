from pysymex.core.iterators_combinators import SymbolicFilter
from pysymex.core.iterators_base import SymbolicSequenceIterator
from pysymex.core.symbolic_types import SymbolicInt
import z3

def test_symbolic_filter():
    seq = [SymbolicInt.concrete(5), SymbolicInt.concrete(10)]
    iterator = SymbolicSequenceIterator(seq)
    
    def my_pred(x):
        return x.z3_int > 7
        
    filtered = SymbolicFilter(my_pred, iterator)
    
    res1 = next(filtered)
    assert not res1.exhausted
    assert z3.is_true(z3.simplify(res1.value.z3_int == z3.IntVal(10)))

    res2 = next(res1.iterator)
    assert res2.exhausted
    assert res2.value is None

if __name__ == "__main__":
    test_symbolic_filter()