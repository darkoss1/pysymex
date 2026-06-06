# Glossary

| Term | Meaning |
| --- | --- |
| Symbolic execution | Executing code with symbolic values so branches create path constraints instead of using only concrete inputs. |
| Symbolic VM | The PySyMex execution engine that interprets supported CPython bytecode over symbolic state. |
| `VMState` | The execution snapshot for one path: bytecode position, stack, locals/globals, constraints, path metadata, and exception state. |
| Path constraint | A Boolean condition accumulated along one symbolic path. |
| SMT | Satisfiability Modulo Theories, the logic style used by Z3 for encoded path constraints. |
| SMT slicing | Solver optimization that keeps dependency-linked constraints for a query while preserving SAT/UNSAT/UNKNOWN semantics. |
| SAT | The encoded constraints are satisfiable. A witness model may exist. |
| UNSAT | The encoded constraints are unsatisfiable. The path or proof obligation is infeasible under the encoding. |
| UNKNOWN | The solver or engine did not establish SAT or UNSAT. |
| Timeout | A resource or solver deadline was reached before a definite answer. |
| Unsupported | The target used semantics that PySyMex does not currently model precisely. |
| Inconclusive | The engine cannot justify a definite finding or proof result. UNKNOWN and timeout are common causes. |
| Blocked | Policy, sandbox, import, filesystem, or environment constraints prevented execution. |
| Degraded pass | An analysis pass completed partially, stopped early, or lost precision. |
| Path frontier | The pending set of path states waiting to be explored. |
| CIG | Constraint Interaction Graph. In source, `ConstraintInteractionGraph` tracks branch program counters and connects branches whose variable sets overlap. |
| CIGS | Not a separate PySyMex subsystem in the current repository. When this term appears in discussion, check whether the intended term is CIG or CEGIS. |
| Detector | A component that inspects symbolic state, bytecode, or scan facts and emits findings when evidence is sufficient. |
| Finding | A reported `Issue`, contract issue, arithmetic issue, or scan issue record. |
| Report | A formatted representation of results, such as text, JSON, Markdown, HTML, or SARIF. |
| Counterexample | Witness values extracted from a model or issue record showing one path to a finding. |
| POLAR | The current frontier/runtime architecture name used by the execution frontier package. Implemented pieces include frontier entries, work-store state, telemetry, checkpoints, spill helpers, and rollout modes. |
| CEGIS | Costed Evidence-Guided Indexed Scheduler. In this repository it ranks frontier evidence actions and routes work-removing actions through exact owner certificates; it is not a broad public synthesis API. |
