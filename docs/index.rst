pysymex Documentation
========================

**pysymex** is a symbolic execution engine for Python bytecode using Z3.
It analyzes Python functions to find potential runtime errors like division
by zero, assertion failures, and index errors.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   userguide
   api
   advanced
   contributing


Quick Example
-------------

.. code-block:: python

   from pysymex import analyze

   def divide(x, y):
       return x / y

   result = analyze(divide, {"x": "int", "y": "int"})

   for issue in result.issues:
       print(issue.format())

This will detect that ``y`` could be zero, causing a division by zero error.


Features
--------

- **Symbolic Execution**: Explores all possible execution paths
- **Z3 Integration**: Uses SMT solving for constraint reasoning
- **Bug Detection**: Division by zero, assertions, index errors, and more
- **Path Strategies**: DFS, BFS, coverage-guided exploration
- **Multiple Outputs**: Text, JSON, HTML, Markdown, SARIF formatters
- **CLI Tool**: Command-line interface for easy integration
- **Type-Safe**: Full type annotations with py.typed marker


Installation
------------

.. code-block:: bash

   pip install pysymex


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
