
import math
import trio


class Queue:
	def __init__(self, sender, receiver):
		self.sender = sender
		self.receiver = receiver
	
	async def __aenter__(self): return self
	async def __aexit__(self, typ, val, tb):
		await self.close()
	
	async def put(self, value):
		await self.sender.send(value)
	
	async def get(self):
		return await self.receiver.receive()
	
	async def close(self):
		await self.sender.aclose()
		await self.receiver.aclose()


def create(size=math.inf):
	send, recv = trio.open_memory_channel(size)
	return Queue(send, recv)
