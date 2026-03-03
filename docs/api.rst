API Reference
=============

This section documents the public API of pysymex.


Main Functions
--------------

.. autofunction:: pysymex.analyze

.. autofunction:: pysymex.analyze_file

.. autofunction:: pysymex.quick_check

.. autofunction:: pysymex.check_division_by_zero

.. autofunction:: pysymex.check_assertions

.. autofunction:: pysymex.format_result


Core Classes
------------

ExecutionResult
~~~~~~~~~~~~~~~

.. autoclass:: pysymex.ExecutionResult
   :members:
   :undoc-members:

Issue
~~~~~

.. autoclass:: pysymex.Issue
   :members:
   :undoc-members:

IssueKind
~~~~~~~~~

.. autoclass:: pysymex.IssueKind
   :members:
   :undoc-members:


Execution
---------

SymbolicExecutor
~~~~~~~~~~~~~~~~

.. autoclass:: pysymex.execution.executor.SymbolicExecutor
   :members:
   :undoc-members:

ExecutionConfig
~~~~~~~~~~~~~~~

.. autoclass:: pysymex.execution.executor.ExecutionConfig
   :members:
   :undoc-members:


Types
-----

SymbolicValue
~~~~~~~~~~~~~

.. autoclass:: pysymex.core.types.SymbolicValue
   :members:
   :undoc-members:

SymbolicString
~~~~~~~~~~~~~~

.. autoclass:: pysymex.core.types.SymbolicString
   :members:
   :undoc-members:

SymbolicList
~~~~~~~~~~~~

.. autoclass:: pysymex.core.types.SymbolicList
   :members:
   :undoc-members:


Analysis
--------

DetectorRegistry
~~~~~~~~~~~~~~~~

.. autoclass:: pysymex.analysis.detectors.DetectorRegistry
   :members:
   :undoc-members:

PathManager
~~~~~~~~~~~

.. autoclass:: pysymex.analysis.path_manager.PathManager
   :members:
   :undoc-members:


Formatters
----------

.. autofunction:: pysymex.reporting.formatters.format_result

.. autoclass:: pysymex.reporting.formatters.TextFormatter
   :members:

.. autoclass:: pysymex.reporting.formatters.JSONFormatter
   :members:

.. autoclass:: pysymex.reporting.formatters.HTMLFormatter
   :members:

.. autoclass:: pysymex.reporting.formatters.MarkdownFormatter
   :members:
