async def guarded():
    with anyio.fail_after(5):
        await anyio.sleep(0.1)
