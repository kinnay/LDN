
import contextlib
import trio


@contextlib.asynccontextmanager
async def background_task(task, *args):
	async with trio.open_nursery() as nursery:
		nursery.start_soon(task, *args)
		yield
		nursery.cancel_scope.cancel()
