Contributing to pysymex
=========================

Thank you for your interest in contributing to pysymex!


Development Setup
-----------------

1. Clone the repository:

   .. code-block:: bash

      git clone https://github.com/darkoss1/pysymex.git
      cd pysymex

2. Create a virtual environment:

   .. code-block:: bash

      python -m venv .venv
      source .venv/bin/activate  # On Windows: .venv\Scripts\activate

3. Install development dependencies:

   .. code-block:: bash

      pip install -e ".[dev]"


Running Tests
-------------

Run the test suite:

.. code-block:: bash

   pytest tests/ -v

With coverage:

.. code-block:: bash

   pytest tests/ -v --cov=pysymex --cov-report=html

Test architecture:

- Unit tests follow a shadow tree under ``tests/unit/...`` mirroring ``pysymex/...``.
- Integration scenarios live in ``tests/integration/...``.
- Historical regressions live in ``tests/repro/...``.
- Archived legacy tests are under ``tests_backup/`` and excluded from default discovery.


Code Style
----------

We use Ruff for formatting:

.. code-block:: bash

   # Format code
   ruff format pysymex/ tests/


Type Checking
-------------

Run Pyright for strict type checking:

.. code-block:: bash

   pyright pysymex/


Adding New Opcodes
------------------

To add support for a new Python opcode:

1. Find the appropriate module in ``pysymex/execution/opcodes/``
2. Add a handler function:

   .. code-block:: python

      @opcode_handler("NEW_OPCODE")
      def handle_new_opcode(instr, state, ctx):
          # Implementation
          state.pc += 1
          return OpcodeResult.continue_with(state)

3. Add tests in ``tests/``


Adding New Detectors
--------------------

To add a new bug detector:

1. Create a class inheriting from ``Detector``
2. Implement the ``check()`` method
3. Register with the ``DetectorRegistry``

See ``pysymex/analysis/detectors/`` for examples.


Pull Request Guidelines
-----------------------

- Write tests for new functionality
- Update documentation if needed
- Follow the existing code style
- Add type hints to new code
- Keep commits focused and atomic


Reporting Issues
----------------

When reporting bugs, please include:

- Python version
- pysymex version
- Minimal reproduction example
- Full error message/traceback


Contact
-------

- GitHub Issues: https://github.com/darkoss1/pysymex/issues
- Discussions: https://github.com/darkoss1/pysymex/discussions
