def foo(a=1, b=2): pass

print("Function dir:")
print([a for a in dir(foo) if 'default' in a])

print("Code dir:")
print([a for a in dir(foo.__code__) if 'default' in a])