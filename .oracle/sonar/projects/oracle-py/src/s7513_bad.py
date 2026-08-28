import trio

async def work():
    return 1

async def one():
    async with trio.open_nursery() as nursery:
        nursery.start_soon(work)
