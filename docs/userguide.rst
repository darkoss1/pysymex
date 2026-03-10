User Guide
==========

This guide covers all features of pysymex in detail.


Basic Usage
-----------

Analyzing Functions
~~~~~~~~~~~~~~~~~~~

The main entry point is the ``analyze()`` function:

.. code-block:: python

   from pysymex import analyze

   def my_function(x, y):
       # function code
       pass

   result = analyze(my_function, {"x": "int", "y": "int"})


Parameter Types
~~~~~~~~~~~~~~~

Specify symbolic parameter types using a dictionary:

.. code-block:: python

   result = analyze(func, {
       "x": "int",      # Integer
       "y": "str",      # String
       "z": "bool",     # Boolean
       "arr": "list",   # List
   })


Configuration Options
~~~~~~~~~~~~~~~~~~~~~

Customize analysis behavior:

.. code-block:: python

   result = analyze(
       func,
       {"x": "int"},
       max_paths=500,               # Limit path exploration
       max_depth=50,                # Max recursion depth
       timeout=30.0,                # Timeout in seconds
       detect_division_by_zero=True,
       detect_assertion_errors=True,
       detect_index_errors=True,
   )


Working with Results
--------------------

ExecutionResult
~~~~~~~~~~~~~~~

The ``ExecutionResult`` object contains:

.. code-block:: python

   result.issues            # List of Issue objects
   result.paths_explored    # Number of paths explored
   result.paths_completed   # Paths that reached a return
   result.coverage          # Set of covered bytecode offsets
   result.total_time_seconds

   result.has_issues()      # Quick check for any issues
   result.format_summary()  # Human-readable summary
   result.to_dict()         # Serialize to dictionary


Issue Details
~~~~~~~~~~~~~

Each ``Issue`` contains:

.. code-block:: python

   issue.kind              # IssueKind enum
   issue.message           # Human-readable description
   issue.line_number       # Source line (if available)
   issue.get_counterexample()  # Dict of triggering inputs

   issue.format()          # Formatted string
   issue.to_dict()         # Serialize to dictionary


Filtering Issues
~~~~~~~~~~~~~~~~

Filter by issue type:

.. code-block:: python

   from pysymex import IssueKind

   div_issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)
   assert_issues = result.get_issues_by_kind(IssueKind.ASSERTION_ERROR)


Output Formats
--------------

Text Format (Default)
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from pysymex import format_result

   text_output = format_result(result, format="text")
   print(text_output)


JSON Format
~~~~~~~~~~~

.. code-block:: python

   json_output = format_result(result, format="json")


HTML Format
~~~~~~~~~~~

.. code-block:: python

   html_output = format_result(result, format="html")
   with open("report.html", "w") as f:
       f.write(html_output)


Markdown Format
~~~~~~~~~~~~~~~

.. code-block:: python

   md_output = format_result(result, format="markdown")


Convenience Functions
---------------------

pysymex provides specialized analysis functions:

.. code-block:: python

   from pysymex import (
       quick_check,
       check_division_by_zero,
       check_assertions,
   )

   # Quick check with default settings
   issues = quick_check(my_function)

   # Check only for division by zero
   div_issues = check_division_by_zero(my_function)

   # Check only for assertion errors
   assert_issues = check_assertions(my_function)


Analyzing Code Strings
----------------------

Analyze code directly as a string:

.. code-block:: python

   from pysymex import analyze_code

   code = '''
   def foo(x):
       return 100 / x
   '''

   result = analyze_code(code, {"x": "int"})


Command-Line Interface
----------------------

Basic Usage
~~~~~~~~~~~

.. code-block:: bash

   pysymex <file.py> -f <function_name>


Options
~~~~~~~

.. code-block:: text

   -f, --function    Function to analyze (required)
   --format          Output format: text, json, html, markdown, sarif
   --args            Parameter types: name=type
   --max-paths       Maximum paths to explore
   --timeout         Timeout in seconds
   --no-div          Disable division by zero detection
   --no-assert       Disable assertion error detection
   --no-index        Disable index error detection
   -v, --verbose     Verbose output
   -o, --output      Output file


Examples
~~~~~~~~

.. code-block:: bash

   # Basic analysis
   pysymex myfile.py -f calculate

   # With JSON output
   pysymex myfile.py -f calculate --format json

   # Save to file
   pysymex myfile.py -f calculate -o report.json --format json

   # Specify types
   pysymex myfile.py -f process --args x=int y=str

   # Increase path limit
   pysymex myfile.py -f complex_func --max-paths 5000
