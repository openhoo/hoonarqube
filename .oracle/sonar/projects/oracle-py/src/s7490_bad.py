async def guarded():
    with anyio.fail_after(5):
        prepare()
