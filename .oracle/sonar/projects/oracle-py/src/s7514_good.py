async def supervise():
    async with anyio.create_task_group() as tg:
        tg.start_soon(worker)
