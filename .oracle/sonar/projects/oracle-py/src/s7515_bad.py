async def load():
    with open("data.txt") as handle:
        data = handle.read()
    return data
