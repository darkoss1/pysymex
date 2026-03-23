"""PySyMex GPU Acceleration Module.

This module provides hardware-accelerated evaluation of Boolean constraints
for the CHTD (Constraint Hypergraph Treewidth Decomposition) algorithm.

Architecture:
    - bytecode: GPU-executable instruction set and Z3-to-bytecode compiler
    - dispatcher: Automatic backend selection (CUDA > CPU > Reference)
    - backends/: Backend implementations (cuda, cpu, reference)
    - memory: Device memory management utilities
    - thompson_sampling: GPU-accelerated Thompson Sampling for path scheduling

Note: async_executor module provides ThreadPoolExecutor-based concurrent evaluation.
It is available for direct import but not re-exported from the main package.

Example:
    >>> import z3
    >>> from pysymex.h_acceleration import compile_constraint, evaluate_bag
    >>>
    >>> a, b, c = z3.Bools('a b c')
    >>> constraint = z3.And(z3.Or(a, b), z3.Not(z3.And(b, c)))
    >>>
    >>> compiled = compile_constraint(constraint, ['a', 'b', 'c'])
    >>> result = evaluate_bag(compiled)
    >>>
    >>> print(f"Backend: {result.backend_used.name}")
    >>> print(f"Satisfying: {result.count_satisfying()}/{2**3}")
"""

from __future__ import annotations

__version__ = "0.1.0a2"

__all__ = [
    "INSTRUCTION_DTYPE",
    "BackendType",
    "BytecodeCompiler",
    "CompiledConstraint",
    "DispatchResult",
    "GPUBagEvaluator",
    "Instruction",
    "MemoryBudget",
    "Opcode",
    "ThompsonSampler",
    "__version__",
    "calculate_memory_budget",
    "compile_constraint",
    "count_satisfying",
    "create_sampler",
    "disassemble",
    "evaluate_bag",
    "get_backend_info",
    "get_bag_evaluator",
    "get_dispatcher",
    "iter_satisfying",
    "warmup",
]

_lazy_loaded: dict[str, object] = {}

def __getattr__(name: str) -> object:
    if name in _lazy_loaded:
        return _lazy_loaded[name]

    if name in ("Opcode", "Instruction", "CompiledConstraint", "INSTRUCTION_DTYPE",
                "compile_constraint", "BytecodeCompiler", "disassemble"):
        from pysymex.h_acceleration import bytecode
        _lazy_loaded.update({
            "Opcode": bytecode.Opcode,
            "Instruction": bytecode.Instruction,
            "CompiledConstraint": bytecode.CompiledConstraint,
            "INSTRUCTION_DTYPE": bytecode.INSTRUCTION_DTYPE,
            "compile_constraint": bytecode.compile_constraint,
            "BytecodeCompiler": bytecode.BytecodeCompiler,
            "disassemble": bytecode.disassemble,
        })
        return _lazy_loaded[name]

    if name in ("evaluate_bag", "get_dispatcher", "BackendType", "DispatchResult",
                "count_satisfying", "iter_satisfying", "get_backend_info", "warmup"):
        from pysymex.h_acceleration import dispatcher
        _lazy_loaded.update({
            "evaluate_bag": dispatcher.evaluate_bag,
            "get_dispatcher": dispatcher.get_dispatcher,
            "BackendType": dispatcher.BackendType,
            "DispatchResult": dispatcher.DispatchResult,
            "count_satisfying": dispatcher.count_satisfying,
            "iter_satisfying": dispatcher.iter_satisfying,
            "get_backend_info": dispatcher.get_backend_info,
            "warmup": dispatcher.warmup,
        })
        return _lazy_loaded[name]

    if name in ("MemoryBudget", "calculate_memory_budget"):
        from pysymex.h_acceleration import memory
        _lazy_loaded.update({
            "MemoryBudget": memory.MemoryBudget,
            "calculate_memory_budget": memory.calculate_memory_budget,
        })
        return _lazy_loaded[name]

    if name in ("GPUBagEvaluator", "get_bag_evaluator"):
        from pysymex.h_acceleration import chtd_integration
        _lazy_loaded.update({
            "GPUBagEvaluator": chtd_integration.GPUBagEvaluator,
            "get_bag_evaluator": chtd_integration.get_bag_evaluator,
        })
        return _lazy_loaded[name]

    if name in ("ThompsonSampler", "create_sampler"):
        from pysymex.h_acceleration import thompson_sampling
        _lazy_loaded.update({
            "ThompsonSampler": thompson_sampling.ThompsonSampler,
            "create_sampler": thompson_sampling.create_sampler,
        })
        return _lazy_loaded[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
