import asyncio

async def worker():
    return 1

handle = asyncio.create_task(worker())
