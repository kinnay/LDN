
from Crypto.Cipher import AES
from ldn import streams, wlan
import hashlib
import socket
import struct
import trio


MACAddress = wlan.MACAddress


# Station accept policy
ACCEPT_ALL = 0
ACCEPT_NONE = 1
ACCEPT_BLACKLIST = 2
ACCEPT_WHITELIST = 3


AES_KEK_GENERATION_SOURCE = bytes.fromhex("4d870986c45d20722fba1053da92e8a9")
AES_KEY_GENERATION_SOURCE = bytes.fromhex("89615ee05c31b6805fe58f3da24f7aa8")
MASTER_KEY = bytes.fromhex("c2caaff089b9aed55694876055271c7d")

def decrypt_key(key, kek):
	aes = AES.new(kek, AES.MODE_ECB)
	return aes.decrypt(key)

def derive_key(inp, source):
	key = decrypt_key(AES_KEK_GENERATION_SOURCE, MASTER_KEY)
	key = decrypt_key(source, key)
	key = decrypt_key(AES_KEY_GENERATION_SOURCE, key)
	return decrypt_key(hashlib.sha256(inp).digest()[:16], key)


class SessionInfo:
	def __init__(self):
		self.local_communication_id = None
		self.game_mode = None
		self.ssid = None
	
	def encode(self, endianness):
		stream = streams.StreamOut(endianness)
		stream.u64(self.local_communication_id)
		stream.pad(2)
		stream.u16(self.game_mode)
		stream.pad(4)
		stream.write(self.ssid)
		return stream.get()
	
	def decode(self, data, endianness):
		stream = streams.StreamIn(data, endianness)
		self.local_communication_id = stream.u64()
		stream.pad(2)
		self.game_mode = stream.u16()
		stream.pad(4)
		self.ssid = stream.read(16)


class ParticipantInfo:
	def __init__(self):
		self.reset()
	
	def reset(self):
		self.ip_address = "0.0.0.0"
		self.mac_address = MACAddress()
		self.connected = False
		self.name = ""
		self.app_version = 0
	
	def encode(self):
		name = self.name.encode()
		stream = streams.StreamOut(">")
		stream.write(socket.inet_aton(self.ip_address))
		stream.write(self.mac_address.encode())
		stream.bool(self.connected)
		stream.pad(1)
		stream.write(name + b"\0" * (32 - len(name)))
		stream.u16(self.app_version)
		stream.pad(10)
		return stream.get()
	
	def decode(self, data):
		stream = streams.StreamIn(data, ">")
		self.ip_address = socket.inet_ntoa(stream.read(4))
		self.mac_address = MACAddress(stream.read(6))
		self.connected = stream.bool()
		stream.pad(1)
		self.name = stream.read(32).rstrip(b"\0").decode()
		self.app_version = stream.u16()
		stream.pad(10)


class AdvertisementInfo:
	def __init__(self):
		self.key = None
		self.security_level = None
		self.station_accept_policy = None
		self.max_participants = None
		self.num_participants = None
		self.participants = None
		self.application_data = None
		self.challenge = None
	
	def encode(self):
		stream = streams.StreamOut(">")
		stream.write(self.key)
		stream.u16(self.security_level)
		stream.u8(self.station_accept_policy)
		stream.pad(3)
		stream.u8(self.max_participants)
		stream.u8(self.num_participants)
		for participant in self.participants:
			stream.write(participant.encode())
		stream.pad(2)
		stream.u16(len(self.application_data))
		stream.write(self.application_data + b"\0" * (384 - len(self.application_data)))
		stream.pad(412)
		stream.u64(self.challenge)
		return stream.get()
	
	def decode(self, data):
		stream = streams.StreamIn(data, ">")
		
		self.key = stream.read(16)
		self.security_level = stream.u16()
		self.station_accept_policy = stream.u8()
		stream.pad(3)
		self.max_participants = stream.u8()
		self.num_participants = stream.u8()
		
		self.participants = []
		for i in range(8):
			participant = ParticipantInfo()
			participant.decode(stream.read(56))
			self.participants.append(participant)
		
		stream.pad(2)
		
		beacon_size = stream.u16()
		beacon_data = stream.read(384)
		self.application_data = beacon_data[:beacon_size]
		
		stream.pad(412)
		
		self.challenge = stream.u64()


class AdvertisementFrame:
	def __init__(self):
		self.header = None
		self.version = None
		self.encryption = None
		self.nonce = None
		self.info = None
	
	def encrypt(self, data):
		if self.encryption == 1:
			return data
		
		source = bytes.fromhex("191884743e24c77d87c69e4207d0c438")
		key = derive_key(self.header.encode(">"), source)
		aes = AES.new(key, AES.MODE_CTR, nonce=self.nonce)
		return aes.encrypt(data)
	
	def decrypt(self, data):
		if self.encryption == 1:
			return data
		
		source = bytes.fromhex("191884743e24c77d87c69e4207d0c438")
		key = derive_key(self.header.encode(">"), source)
		aes = AES.new(key, AES.MODE_CTR, nonce=self.nonce)
		return aes.decrypt(data)
	
	def encode(self):
		stream = streams.StreamOut(">")
		stream.u8(0x7F) # Vendor-specific
		stream.u24(0x0022AA) # Nintendo
		stream.u8(4) # LDN
		stream.pad(1)
		stream.u16(0x101) # Advertisement frame
		stream.pad(4)
		
		substream = streams.StreamOut(">")
		substream.write(self.header.encode(">"))
		substream.u8(self.version)
		substream.u8(self.encryption)
		substream.u16(0x500)
		substream.write(self.nonce)
		header = substream.get()
		
		info = self.info.encode()
		message = header + bytes(32) + info
		sha = hashlib.sha256(message).digest()
		
		stream.write(header)
		stream.write(self.encrypt(sha + info))
		return stream.get()
	
	def decode(self, data):
		stream = streams.StreamIn(data, ">")
		if stream.u8() != 0x7F:
			raise ValueError("Action frame is not vendor-specific")
		if stream.u24() != 0x0022AA:
			raise ValueError("Action frame has wrong OUI")
		
		if stream.u8() != 4:
			raise ValueError("Action frame is not for LDN")
		
		stream.pad(1)
		if stream.u16() != 0x101:
			raise ValueError("Action frame is not an advertisement frame")
		stream.pad(4)
		
		header = stream.peek(0x28)
		
		self.header = SessionInfo()
		self.header.decode(stream.read(32), ">")
		
		self.version = stream.u8()
		if self.version not in [2, 3]:
			raise ValueError("Advertisement frame has unsupported version number")
		
		self.encryption = stream.u8()
		if self.encryption not in [1, 2]:
			raise ValueError("Advertisement frame has invalid encryption algorithm")
		
		size = stream.u16()
		if size != 0x500:
			raise ValueError("Advertisement frame has unexpected size field")
		
		self.nonce = stream.read(4)
		
		body = self.decrypt(stream.read(32 + size))
		sha = body[:32]
		info = body[32:]
		
		message = header + bytes(32) + info
		if hashlib.sha256(message).digest() != sha:
			raise ValueError("Advertisement frame has wrong SHA-256 hash")
		
		self.info = AdvertisementInfo()
		self.info.decode(info)

		
class NetworkInfo:
	def __init__(self):
		self.address = None
		self.channel = None
		
		self.local_communication_id = None
		self.game_mode = None
		self.ssid = None
		self.version = None
		self.key = None
		self.security_level = None
		self.accept_policy = None
		self.max_participants = None
		self.num_participants = None
		self.participants = None
		self.application_data = None
		self.challenge = None
	
	def parse(self, frame):
		self.local_communication_id = frame.header.local_communication_id
		self.game_mode = frame.header.game_mode
		self.ssid = frame.header.ssid
		self.version = frame.version
		self.key = frame.info.key
		self.security_level = frame.info.security_level
		self.accept_policy = frame.info.station_accept_policy
		self.max_participants = frame.info.max_participants
		self.participants = frame.info.participants[:frame.info.num_participants]
		self.application_data = frame.info.application_data
		self.challenge = frame.info.challenge


class Scanner:
	def __init__(self, monitor):
		self.monitor = monitor
	
	async def receive_advertisement(self):
		# Vendor-specific, Nintendo OUI, LDN, Advertisement
		header = bytes([0x7F, 0x00, 0x22, 0xAA, 0x04, 0x00, 0x01, 0x01])
		while True:
			# Receive a single frame
			radiotap = await self.monitor.recv()
			
			# Check if we received an action frame
			if len(radiotap.data) < 2 or struct.unpack_from(">H", radiotap.data)[0] != 0xD000:
				continue
			
			action = wlan.ActionFrame()
			try: action.decode(radiotap.data)
			except Exception:
				continue # Skip invalid frames
			
			# Check if we received an advertisement frame from LDN
			if not action.action.startswith(header):
				continue
			
			# Decode the frame itself
			frame = AdvertisementFrame()
			try: frame.decode(action.action)
			except Exception:
				continue # Skip invalid frames
			
			channel = wlan.map_frequency(radiotap.frequency)
			return frame, action.source, channel

	async def scan(self, channels, dwell_time):
		networks = []
		async def scan_frames():
			while True:
				frame, address, channel = await self.receive_advertisement()
				
				info = NetworkInfo()
				info.address = address
				info.channel = channel
				info.parse(frame)
				networks.append(info)
		
		async with util.background_task(scan_frames):
			for channel in channels:
				await self.monitor.set_channel(channel)
				await trio.sleep(dwell_time)
		return networks


async def scan(ifname="ldn", phyname="phy0", channels=[1, 6, 11], dwell_time=.110):
	if not channels: return []

	# Check if all channels are valid
	for channel in channels:
		if not wlan.is_valid_channel(channel):
			raise ValueError("Invalid channel: %i" %channel)
	
	async with wlan.create() as factory:
		async with factory.create_monitor(phyname, ifname) as monitor:
			scanner = Scanner(monitor)
			return await scanner.scan(channels, dwell_time)
