from asyncio import CancelledError

def cleanup():
    return 1

async def worker(job):
    try:
        await job()
    except CancelledError:
        cleanup()
