from pysymex.core.exceptions_types import ExceptionState, TryBlock, FinallyHandler, SymbolicException

def test_finally_handling():
    state = ExceptionState()
    
    # TryBlock with ONLY a finally handler (no except blocks)
    block = TryBlock(
        try_start=0,
        try_end=10,
        handlers=[],
        finally_handler=FinallyHandler(target_pc=15, exit_pc=20)
    )
    
    state.push_try(block)
    
    exc = SymbolicException.concrete(ValueError, "test")
    handler, target_pc = state.handle_exception(exc)
    
    print(f"Handler found: {handler is not None}")
    print(f"Target PC: {target_pc}")

if __name__ == "__main__":
    test_finally_handling()