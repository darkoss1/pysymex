Contributing to PySpectre
=========================

Thank you for your interest in contributing to PySpectre!


Development Setup
-----------------

1. Clone the repository:

   .. code-block:: bash

      git clone https://github.com/darkoss1/pyspecter.git
      cd pyspecter

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

   pytest tests/ -v --cov=pyspectre --cov-report=html


Code Style
----------

We use Black for formatting and Ruff for linting:

.. code-block:: bash

   # Format code
   black pyspectre/ tests/

   # Lint code
   ruff check pyspectre/ tests/


Type Checking
-------------

Run MyPy for type checking:

.. code-block:: bash

   mypy pyspectre/


Adding New Opcodes
------------------

To add support for a new Python opcode:

1. Find the appropriate module in ``pyspectre/execution/opcodes/``
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

See ``pyspectre/analysis/advanced_detectors.py`` for examples.


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
- PySpectre version
- Minimal reproduction example
- Full error message/traceback


Contact
-------

- GitHub Issues: https://github.com/darkoss1/pyspecter/issues
- Discussions: https://github.com/darkoss1/pyspecter/discussions
