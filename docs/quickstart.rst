Quick Start Guide
=================

Get up and running with PySyMex in under 5 minutes.


Installation
------------

.. code-block:: bash

   # Step 1 — Install the Z3 SMT solver (required dependency)
   pip install z3-solver

   # Step 2 — Install PySyMex
   pip install pysymex

   # Or install from source
   git clone https://github.com/darkoss1/pysymex.git
   cd pysymex
   pip install -e .


Scanning a File
---------------

The primary way to use PySyMex is to point it at a Python file or directory:

.. code-block:: bash

   # Scan a single file
   pysymex scan mycode.py

   # Scan a directory recursively
   pysymex scan src/ -r

   # Generate a JSON report
   pysymex scan src/ --format json -o report.json

   # Generate a SARIF report (GitHub Security tab compatible)
   pysymex scan src/ --format sarif -o report.sarif


Your First Analysis (Python API)
---------------------------------

.. code-block:: python

   from pysymex.analysis.solver import verify_function

   def unsafe_divide(x: int, y: int) -> int:
       return x // y

   results = verify_function(unsafe_divide)
   for r in results:
       if r.can_crash:
           print(f"Bug: {r.crash.description}")
           print(f"Counterexample: {r.counterexample}")

PySyMex will output:

.. code-block:: text

   🔴 CRASHES PROVEN POSSIBLE (Z3 found counterexamples):
   ──────────────────────────────────────────────────────
     ➗ [DIVISION BY ZERO]
        unsafe_divide() at line 2
        Division by zero: y can be 0 in //
        💡 Crash when: y=0


Detecting a Real Historical Bug
--------------------------------

PySyMex can catch the famous 64-bit integer overflow bug in Binary Search,
which went undetected for 20 years in Java's standard library:

.. code-block:: python

   from pysymex.analysis.solver import verify_function

   def binary_search(arr: list, target: int) -> int:
       lo, hi = 0, len(arr)
       while lo <= hi:
           mid = (lo + hi) // 2  # Bug: overflows on very large arrays
           if arr[mid] == target:
               return mid
           elif arr[mid] < target:
               lo = mid + 1
           else:
               hi = mid - 1
       return -1

   results = verify_function(binary_search)

PySyMex detects the overflow path and reports the exact counterexample inputs.


Understanding the Output
------------------------

Every detected issue includes:

- **Bug type** — what kind of crash was found (division, overflow, null, etc.)
- **Location** — file name, function name, and line number
- **Counterexample** — the exact input values that trigger the bug
- **Proof** — Z3 solver confirmation that the crash is mathematically possible

A result of ``✅ Proven safe`` means Z3 exhaustively checked all paths and
found **no** inputs that can cause a crash.


CLI Reference
-------------

.. code-block:: text

   pysymex scan <path> [options]

   Positional:
     path                  Python file or directory to scan

   Options:
     -r, --recursive       Recursively scan directories
     --format              Output format: text (default), json, sarif
     -o OUTPUT             Output file (default: stdout)
     --max-paths N         Max paths per function (default: 1000)
     --timeout SECONDS     Timeout per function (default: 60)
     -v, --verbose         Verbose output
     --workers N           Parallel worker processes (default: CPU count)
     --watch               Watch for file changes and re-scan automatically


Next Steps
----------

- Read the :doc:`userguide` for detailed Python API usage
- Explore the :doc:`advanced` features (taint tracking, interprocedural analysis)
- See the :doc:`api` reference for all public classes and functions
- Learn how to write :doc:`contributing` custom detectors
