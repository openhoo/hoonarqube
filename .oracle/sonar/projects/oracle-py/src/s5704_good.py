def f():
    try:
        work()
    except ValueError:
        raise
    finally:
        cleanup()
