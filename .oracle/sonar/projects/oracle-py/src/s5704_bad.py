def f():
    try:
        work()
    finally:
        cleanup()
        raise
