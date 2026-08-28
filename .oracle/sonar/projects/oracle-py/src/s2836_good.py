for item in items:
    if rejected(item):
        break
else:
    close()

while pending():
    if exhausted:
        break
    drain()
else:
    close()
