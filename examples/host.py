
# This script creates a network for Super Mario Maker 2.

import ldn
import trio
import struct
import random


NICKNAME = "Hello!"


class Stream:
	def __init__(self):
		self.data = b""
	
	def pad(self, size): self.data += bytes(size)
	
	def u8(self, value): self.data += bytes([value])
	def u16(self, value): self.data += struct.pack("<H", value)
	def u32(self, value): self.data += struct.pack("<I", value)
	def u64(self, value): self.data += struct.pack("<Q", value)
	
	def wchars(self, text):
		for char in text:
			self.u16(ord(char))


def make_application_data():
	# Build the pia header
	stream = Stream()
	stream.u32(random.randint(0, 0xFFFFFFFF)) # Session id
	stream.u32(0) # CRC-32
	stream.u8(5) # System communication version
	stream.u8(24) # Header size
	stream.pad(2)
	stream.u32(random.randint(0, 0xFFFFFFFF)) # Session param
	stream.pad(8)
	
	# SMM2 header
	stream.u64(random.randint(0, 0xFFFFFFFFFFFFFFFF)) # Network service account id
	stream.wchars(NICKNAME + "\0" * (11 - len(NICKNAME)))
	stream.pad(2)
	
	# Mii info
	stream.pad(88) # Simply set everything to 0 for now
	
	# Unknown
	stream.pad(24)
	return stream.data


async def main():
	print("Creating network.")
	param = ldn.CreateNetworkParam()
	param.local_communication_id = 0x01009B90006DC000
	param.game_mode = 1
	param.max_participants = 4
	param.application_data = make_application_data()
	param.name = NICKNAME
	param.app_version = 7
	param.password = "LunchPack2DefaultPhrase"
	async with ldn.create_network(param) as network:
		print("Listening for events.")
		while True:
			event = await network.next_event()
			if isinstance(event, ldn.JoinEvent):
				participant = event.participant
				print("%s joined the network (%s / %s)" %(participant.name, participant.mac_address, participant.ip_address))
			elif isinstance(event, ldn.LeaveEvent):
				participant = event.participant
				print("%s left the network (%s / %s)" %(participant.name, participant.mac_address, participant.ip_address))
trio.run(main)
