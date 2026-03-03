PySyMex Documentation
========================

.. warning::

   **v0.1.0a0 — Academic Research Prototype**

   PySyMex is an early-stage research tool for studying symbolic execution
   and formal verification concepts. It is **not** intended for production
   security auditing or critical systems. Use at your own risk.

**PySyMex** (Python Symbolic Execution) is a **static source-code analysis tool**
that scans Python files and projects for bugs and vulnerabilities — without
ever executing the code. It works by disassembling Python bytecode, symbolically
exploring every reachable execution path, and using the Z3 SMT Theorem Prover
to mathematically prove whether a bug can occur.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   userguide
   api
   advanced


Quick Example
-------------

.. code-block:: bash

   # Scan a Python file from the command line
   pysymex scan mycode.py

   # Scan an entire project recursively
   pysymex scan src/ -r

   # Export a SARIF report for CI/CD integration
   pysymex scan src/ --format sarif -o report.sarif

.. code-block:: python

   from pysymex.analysis.solver import verify_function

   def binary_search(arr, target):
       lo, hi = 0, len(arr)
       while lo <= hi:
           mid = (lo + hi) // 2  # 64-bit overflow on large inputs
           if arr[mid] == target:
               return mid
           elif arr[mid] < target:
               lo = mid + 1
           else:
               hi = mid - 1
       return -1

   results = verify_function(binary_search)
   for r in results:
       if r.can_crash:
           print(f"Bug: {r.crash.description}")
           print(f"Counterexample: {r.counterexample}")


What It Detects
---------------

+---------------------------+----------------------------------------------+
| Bug Type                  | Description                                  |
+===========================+==============================================+
| Division / Modulo by Zero | Denominator proven to be zero by Z3          |
+---------------------------+----------------------------------------------+
| Integer Overflow          | 64-bit arithmetic overflow (e.g. mid index)  |
+---------------------------+----------------------------------------------+
| None Dereference          | Attribute access on a provably-None object   |
+---------------------------+----------------------------------------------+
| Index Out of Bounds       | Array/list access beyond valid range         |
+---------------------------+----------------------------------------------+
| Assertion Failure         | ``assert`` that Z3 proves can fail           |
+---------------------------+----------------------------------------------+
| Type Error                | Type mismatch in operations                  |
+---------------------------+----------------------------------------------+
| Key Error                 | Dict key that Z3 proves does not exist       |
+---------------------------+----------------------------------------------+
| Taint Violation           | Untrusted data reaching a dangerous sink     |
+---------------------------+----------------------------------------------+
| Unreachable Code          | Dead code paths identified statically        |
+---------------------------+----------------------------------------------+


Features
--------

- **Bytecode-level analysis** — directly reads CPython 3.11–3.13 bytecode
- **Z3 SMT integration** — formal constraint solving, not heuristics
- **Interprocedural analysis** — tracks bugs across function call boundaries
- **Taint tracking** — follows untrusted data to dangerous sinks
- **Abstract interpretation** — interval, sign, and parity domains for loops
- **Multiple output formats** — text, JSON, HTML, SARIF 2.1.0 (GitHub Security tab)
- **Watch mode** — auto-rescans on file change during development
- **Parallel scanning** — multi-process analysis for large codebases
- **Plugin system** — custom detectors via a simple API


Installation
------------

.. code-block:: bash

   pip install z3-solver
   pip install pysymex


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
