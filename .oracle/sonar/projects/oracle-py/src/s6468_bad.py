try:
    collect()
except* ExceptionGroup:
    drain()
