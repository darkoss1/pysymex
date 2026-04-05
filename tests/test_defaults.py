def foo(a=1): pass

if __name__ == "__main__":
    print("Has co_defaults on code?", hasattr(foo.__code__, 'co_defaults'))
    print("Has __defaults__ on func?", hasattr(foo, '__defaults__'))