try:
    risky()
except ValueError:
    assertEqual(1, 2)
