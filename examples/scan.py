
# This script scans for nearby LDN networks and prints information about them.

import ldn
import trio

AcceptPolicies = {
    ldn.ACCEPT_ALL: "ALL",
    ldn.ACCEPT_NONE: "NONE",
    ldn.ACCEPT_BLACKLIST: "BLACKLIST",
    ldn.ACCEPT_WHITELIST: "WHITELIST"
}

BandNames ={
    2: "2.4 GHz",
    5: "5 GHz"
}

Platforms = {
    ldn.PLATFORM_NX: "Switch",
    ldn.PLATFORM_OUNCE: "Switch 2"
}

async def main():
    keys = ldn.load_keys("~/.switch/prod.keys")
    networks = await ldn.scan(keys)
    
    print(f"Found {len(networks)} network(s)")
    for i, network in enumerate(networks):
        print()
        print(f"Network {i}:")
        print(f"\tLocal communication id: {network.local_communication_id:016x}")
        print(f"\tScene id: {network.scene_id}")
        print()
        print(f"\tStation accept policy: {AcceptPolicies[network.accept_policy]}")
        print(f"\tMaximum number of participants: {network.max_participants}")
        print(f"\tApplication data: {network.application_data.hex()} ({len(network.application_data)} bytes)")
        print()
        print(f"\tHost address: {network.address}")
        print(f"\tWLAN band: {BandNames[network.band]}")
        print(f"\tWLAN channel: {network.channel}")
        print(f"\tSSID: {network.ssid.hex()}")
        print()
        print(f"\tLDN version: {network.version}")
        print(f"\tSecurity mode: {network.security_mode}")
        print()
        print("\tParticipants:")
        for i, participant in enumerate(network.participants):
            if participant.connected:
                print(f"\t\tName: {participant.name.decode()}")
                print(f"\t\tIP address: {participant.ip_address}")
                print(f"\t\tMAC address: {participant.mac_address}")
                print(f"\t\tApplication version: {participant.app_version}")
                print(f"\t\tPlatform: {Platforms[participant.platform]}")
                print(f"\t\tConnected: {participant.connected}")
                print("\t\t---")
        
trio.run(main)
