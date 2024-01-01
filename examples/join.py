
# This script joins a Super Mario Maker 2 network and listens for packets.

import ldn
import trio
import socket


LOCAL_COMMUNICATION_ID = 0x01009B90006DC000
GAME_MODE = 1

PASSWORD = "LunchPack2DefaultPhrase"
APPLICATION_VERSION = 6

NICKNAME = "Hello!"


async def scan():
	# This function tries to find a nearby network
	print("Scanning for networks.")
	print()
	
	networks = await ldn.scan()
	print("Found %i network(s)." %len(networks))
	
	# Check if one the networks is suitable
	for i, network in enumerate(networks):
		if network.local_communication_id != LOCAL_COMMUNICATION_ID:
			print("\t%i: Skipping (different game)" %i)
		elif network.game_mode != GAME_MODE:
			print("\t%i: Skipping (different game mode)" %i)
		elif network.accept_policy == ldn.ACCEPT_NONE:
			print("\t%i: Skipping (participation is closed)" %i)
		elif network.num_participants == network.max_participants:
			print("\t%i: Skipping (network is full)" %i)
		else:
			print("\t%i: OK" %i)
			print()
			return network
	
	print()
	print("No suitable network found.")
	return None

async def receive_packets():
	# This function prints packets that
	# we receive through the network
	
	s = trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	await s.bind(("", 12345)) # LDN uses port 12345 for broadcast
	while True:
		data, addr = await s.recvfrom(4096)
		print("Received %i bytes from %s" %(len(data), addr))

async def main():
	# First try to find a suitable network
	info = await scan()
	if info is None:
		return
	
	# Print information about the network
	print("Found network:")
	print("\tMaximum number of participants:", info.max_participants)
	print("\tCurrent number of participants:", info.num_participants)
	print("\tApplication data: <%i bytes>" %len(info.application_data))
	print("\tSSID:", info.ssid.hex())
	print("\tWLAN channel:", info.channel)
	print()
	
	# Now try to join the network
	print("Trying to connect.")
	param = ldn.ConnectNetworkParam()
	param.network = info
	param.password = PASSWORD
	param.name = NICKNAME
	param.app_version = APPLICATION_VERSION
	async with ldn.connect(param) as network:
		# If this part is reached, we have successfully joined the network
		print("Connection ok.")
		
		async with trio.open_nursery() as nursery:
			# Start a task that receives packets from the network
			nursery.start_soon(receive_packets)
			
			# At the same time, listen for network events
			while True:
				event = await network.next_event()
				if isinstance(event, ldn.JoinEvent):
					print("%s joined the network (%s)" %(event.participant.name, event.participant.ip_address))
				elif isinstance(event, ldn.LeaveEvent):
					print("%s left the network (%s)" %(event.participant.name, event.participant.ip_address))
				elif isinstance(event, ldn.DisconnectEvent):
					print("Network was disconnected.")
					break
			
			# Stop the packet receiver task
			nursery.cancel_scope.cancel()
	
trio.run(main)
