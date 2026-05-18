"""
08: Symbolic Exception Paths

This example demonstrates how pysymex models exception handling and control flow propagation
across try-except-finally structures, tracing both happy paths and exception-raising paths.

To scan this example:
    pysymex scan examples/08_exception_handling.py
"""


def exception_propagation_bug(value: int) -> int:
    """
    Traces control flow through try-except blocks.
    pysymex tracks raised exceptions to ensure all paths are verified.
    """
    result = 100
    try:
        if value < 0:
            raise ValueError("Negative inputs not allowed")
        result = result // value
    except ValueError:
        # Graceful handling of negative values
        result = -1
    except ZeroDivisionError:
        # If value is 0, division raises ZeroDivisionError, which propagates out
        # and triggers an UNHANDLED_EXCEPTION issue.
        pass

    return result
