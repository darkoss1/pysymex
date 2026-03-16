import dis
import sys

# Ensure all handlers are loaded
import pysymex.execution.opcodes.arithmetic
import pysymex.execution.opcodes.async_ops
import pysymex.execution.opcodes.collections
import pysymex.execution.opcodes.compare
import pysymex.execution.opcodes.control
import pysymex.execution.opcodes.exceptions
import pysymex.execution.opcodes.functions
import pysymex.execution.opcodes.locals
import pysymex.execution.opcodes.stack

from pysymex.execution.dispatcher import OpcodeDispatcher

handled = set(OpcodeDispatcher._global_handlers.keys())
all_ops = set(dis.opmap.keys())

missing = all_ops - handled

print(f"Total Opcodes Handled: {len(handled)}")
print(f"Total Python Opcodes: {len(all_ops)}")
print("Unhandled Opcodes:")
for op in sorted(missing):
    print(op)
