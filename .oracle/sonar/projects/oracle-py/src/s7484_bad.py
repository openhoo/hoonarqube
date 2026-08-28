import asyncio

async def poll(client):
    while True:
        await asyncio.sleep(1)
