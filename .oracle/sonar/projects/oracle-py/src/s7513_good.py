import trio

async def first_job():
    return 1

async def second_job():
    return 2

async def many():
    async with trio.open_nursery() as nursery:
        nursery.start_soon(first_job)
        nursery.start_soon(second_job)
