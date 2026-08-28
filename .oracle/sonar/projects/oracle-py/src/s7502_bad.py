import asyncio

async def worker():
    return 1

asyncio.create_task(worker())
