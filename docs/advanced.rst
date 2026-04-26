Advanced Features
=================

This section covers advanced features of pysymex.


Hardware Acceleration
---------------------

PySyMex includes a custom-built, high-performance Tiered CPU Dispatcher and local SAT solver for resolving Constraint Hypergraph Treewidth Decomposition (CHTD) queries at scale. 

To learn more about the Tiered CPU Dispatcher, thread-local SAT integration, and how to manage state explosion efficiently without PCIe latency, see the dedicated architecture documentation:
* `docs/arch/ACCELERATION.md`


Sandbox Architecture and Hardening
----------------------------------

PySyMex includes a hardened sandbox subsystem for containment-sensitive execution scenarios.
For architecture and threat-model details, see:
* `docs/arch/SANDBOX_SECURITY.md`


Inter-Procedural Analysis
-------------------------

Analyze multiple functions and their interactions:

.. code-block:: python

   from pysymex.analysis.interprocedural import InterproceduralAnalyzer

   analyzer = InterproceduralAnalyzer(
       max_inline_depth=3,
       use_summaries=True,
   )

   # Analyze entire module
   import mymodule
   results = analyzer.analyze_module(mymodule)

   # Get call graph
   dot_graph = analyzer.get_call_graph_dot()


Call Graph Visualization
~~~~~~~~~~~~~~~~~~~~~~~~

Export the call graph for visualization:

.. code-block:: python

   dot_output = analyzer.get_call_graph_dot()
   with open("callgraph.dot", "w") as f:
       f.write(dot_output)

   # Then use Graphviz: dot -Tpng callgraph.dot -o callgraph.png


Concolic Execution
------------------

Combine concrete and symbolic execution for better scalability:

.. code-block:: python

   from pysymex.analysis.concolic import ConcolicExecutor

   executor = ConcolicExecutor(
       max_iterations=100,
       strategy="coverage",
   )

   result = executor.execute(
       my_function,
       initial_inputs={"x": 0, "y": 1},
       symbolic_types={"x": "int", "y": "int"},
   )

   print(result.format_summary())


Path Exploration Strategies
---------------------------

Choose how paths are explored:

.. code-block:: python

   from pysymex.execution.executor import ExecutionConfig
   from pysymex.analysis.path_manager import ExplorationStrategy

    # CHTD-native (default)
    config = ExecutionConfig(strategy=ExplorationStrategy.CHTD_NATIVE)

    # Adaptive Thompson-sampling scheduler
    config = ExecutionConfig(strategy=ExplorationStrategy.ADAPTIVE)

   # Coverage-guided
   config = ExecutionConfig(strategy=ExplorationStrategy.COVERAGE_GUIDED)


Advanced Detectors
------------------

Enable additional bug detectors:

.. code-block:: python

   from pysymex.analysis.advanced_detectors import (
       NullDereferenceDetector,
       IntegerOverflowDetector,
       InfiniteLoopDetector,
   )
   from pysymex.analysis.detectors import DetectorRegistry

   registry = DetectorRegistry()
   registry.register(NullDereferenceDetector)
   registry.register(IntegerOverflowDetector)

   from pysymex.execution.executor import SymbolicExecutor
   executor = SymbolicExecutor(detector_registry=registry)


Custom Detectors
~~~~~~~~~~~~~~~~

Create your own bug detector:

.. code-block:: python

   from pysymex.analysis.detectors import Detector, Issue, IssueKind

   class MyDetector(Detector):
       name = "my-detector"
       description = "Detects my custom issue"
       issue_kind = IssueKind.INVALID_ARGUMENT

       def check(self, state, instruction, is_satisfiable_fn):
           # Your detection logic here
           if some_condition:
               return Issue(
                   kind=self.issue_kind,
                   message="Custom issue detected",
                   pc=state.pc,
               )
           return None


Function Summaries
------------------

Use function summaries for modular analysis:

.. code-block:: python

   from pysymex.analysis.interprocedural import FunctionSummary

   # Summaries capture function behavior without re-analysis
   summary = FunctionSummary(
       name="safe_divide",
       parameters=["x", "y"],
       preconditions=[y_not_zero],
       is_pure=True,
   )


Low-Level Access
----------------

Access the execution engine directly:

.. code-block:: python

   from pysymex.execution.executor import SymbolicExecutor, ExecutionConfig
   from pysymex.core.state import VMState
   from pysymex.core.types import SymbolicValue

   # Create executor
   config = ExecutionConfig(verbose=True)
   executor = SymbolicExecutor(config)

   # Execute function
   result = executor.execute_function(my_func, {"x": "int"})

   # Access internal state
   print(f"Coverage: {len(result.coverage)} instructions")


Constraint Solving
------------------

Work directly with Z3 constraints:

.. code-block:: python

   import z3
   from pysymex.core.solver import is_satisfiable, get_model

   x = z3.Int("x")
   constraints = [x > 0, x < 10, x != 5]

   if is_satisfiable(constraints):
       model = get_model(constraints)
       print(f"x = {model.eval(x)}")


Performance Tuning
------------------

Tips for analyzing complex functions:

.. code-block:: python

   result = analyze(
       complex_function,
       symbolic_args,
       max_paths=500,          # Limit exploration
       max_depth=20,           # Limit recursion
       timeout=60.0,           # Set timeout
       max_iterations=5000,    # Limit total iterations
   )
