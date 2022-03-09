
# This script scans for nearby LDN networks and prints information about them.

import ldn
import trio

AcceptPolicies = {
	ldn.ACCEPT_ALL: "ALL",
	ldn.ACCEPT_NONE: "NONE",
	ldn.ACCEPT_BLACKLIST: "BLACKLIST",
	ldn.ACCEPT_WHITELIST: "WHITELIST"
}

async def main():
	networks = await ldn.scan()
	
	print("Found %i network(s)" %len(networks))
	for i, network in enumerate(networks):
		print()
		print("Network %i:" %i)
		print("\tLocal communication id: %016x" %network.local_communication_id)
		print("\tGame mode: %i" %network.game_mode)
		print()
		print("\tStation accept policy: %s" %AcceptPolicies[network.accept_policy])
		print("\tMaximum number of participants: %i" %network.max_participants)
		print("\tApplication data: <%i bytes>" %len(network.application_data))
		print()
		print("\tHost address: %s" %network.address)
		print("\tWLAN channel: %i" %network.channel)
		print("\tSSID: %s" %network.ssid.hex())
		print()
		print("\tLDN version: %i" %network.version)
		print("\tSecurity level: %i" %network.security_level)
		print()
		print("\tParticipants:")
		for i, participant in enumerate(network.participants):
			if i != 0:
				print("\t\t---")
			print("\t\tName: %s" %participant.name)
			print("\t\tIP address: %s" %participant.ip_address)
			print("\t\tMAC address: %s" %participant.mac_address)
			print("\t\tApplication version: %i" %participant.app_version)
			print("\t\tConnected: %s" %participant.connected)
		
trio.run(main)
