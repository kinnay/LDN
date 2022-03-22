
from Crypto.Cipher import AES
from ldn import streams, wlan, queue
from netlink import route
import contextlib
import secrets
import hashlib
import socket
import random
import struct
import math
import hmac
import copy
import trio


MACAddress = wlan.MACAddress


# Station accept policy
ACCEPT_ALL = 0
ACCEPT_NONE = 1
ACCEPT_BLACKLIST = 2
ACCEPT_WHITELIST = 3

# Authentication status code
AUTH_SUCCESS = 0
AUTH_DENIED_BY_POLICY = 1
AUTH_MALFORMED_REQUEST = 2
AUTH_INVALID_VERSION = 4
AUTH_UNEXPECTED = 5
AUTH_CHALLENGE_FAILURE = 6

# Disconnect reason
DISCONNECT_NETWORK_DESTROYED = 3
DISCONNECT_NETWORK_DESTROYED_FORCEFULLY = 4
DISCONNECT_STATION_REJECTED_BY_HOST = 5
DISCONNECT_CONNECTION_LOST = 6


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

def generate_data_key(key, password):
	source = bytes.fromhex("f1e7018419a84f711da714c2cf919c9c")
	return derive_key(key + password.encode(), source)


class AuthenticationError(Exception):
	def __init__(self, status_code):
		self.status_code = status_code
	
	def __str__(self):
		return "Authentication failed with status %i" %self.status_code


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
		
		
class ChallengeRequest:
	def __init__(self):
		self.token = None
		self.nonce = None
		self.device_id = None
		self.params1 = []
		self.params2 = []
	
	def encode(self):
		stream = streams.StreamOut("<")
		stream.u8(0) # Always 0
		stream.u8(0) # Always 0
		stream.u8(len(self.params1))
		stream.u8(len(self.params2))
		stream.u8(0) # Debug check
		stream.pad(3)
		
		stream.u64(self.token)
		stream.u64(self.nonce)
		stream.u64(self.device_id)
		
		stream.pad(0x70)
		
		stream.repeat(self.params1, stream.u64)
		stream.pad(8 * (8 - len(self.params1)))
		
		stream.repeat(self.params2, stream.u64)
		stream.pad(8 * (64 - len(self.params2)))
		
		body = stream.get()
		
		key = bytes.fromhex("f84b487fb37251c263bf11609036589266af70ca79b44c93c7370c5769c0f602")
		mac = hmac.digest(key, body, "sha256")
		
		stream = streams.StreamOut("<")
		stream.u32(0)
		stream.write(mac)
		stream.pad(12)
		stream.write(body)
		
		return stream.get()
	
	def decode(self, data):
		if len(data) != 0x300:
			raise ValueError("Challenge request has wrong size")
		
		stream = streams.StreamIn(data, "<")
		stream.pad(4)
		mac = stream.read(32)
		stream.pad(12)
		body = stream.read(0x2D0)
		
		key = bytes.fromhex("f84b487fb37251c263bf11609036589266af70ca79b44c93c7370c5769c0f602")
		if mac != hmac.digest(key, body, "sha256"):
			raise ValueError("Challenge request has wrong HMAC")
		
		stream = streams.StreamIn(body, "<")
		stream.pad(2)
		n1 = stream.u8()
		n2 = stream.u8()
		stream.pad(4)
		
		self.token = stream.u64()
		self.nonce = stream.u64()
		self.device_id = stream.u64()
		
		stream.pad(0x70)
		
		self.params1 = stream.repeat(stream.u64, 8)[:n1]
		self.params2 = stream.repeat(stream.u64, 8)[:n2]


class ChallengeResponse:
	def __init__(self):
		self.nonce = None
		self.device_id = None
		self.device_id_host = None
	
	def encode(self):
		stream = streams.StreamOut("<")
		stream.u8(0) # Always 0
		stream.u8(0) # Always 0
		stream.pad(6)
		stream.u64(self.nonce)
		stream.u64(self.device_id)
		stream.u64(self.device_id_host)
		stream.pad(0xB0)
		
		body = stream.get()
	
		key = bytes.fromhex("f84b487fb37251c263bf11609036589266af70ca79b44c93c7370c5769c0f602")
		mac = hmac.digest(key, body, "sha256")
		
		stream = streams.StreamOut("<")
		stream.u32(0)
		stream.write(mac)
		stream.pad(12)
		stream.write(body)
		return stream.get()
	
	def decode(self, data):
		if len(data) != 0x100:
			raise ValueError("Challenge response has wrong size")
		
		stream = streams.StreamIn(data, "<")
		stream.pad(4)
		mac = stream.read(32)
		stream.pad(12)
		body = stream.read(0xD0)
		
		key = bytes.fromhex("f84b487fb37251c263bf11609036589266af70ca79b44c93c7370c5769c0f602")
		if mac != hmac.digest(key, body, "sha256"):
			raise ValueError("Challenge response has wrong HMAC")
		
		stream = streams.StreamIn(body, "<")
		stream.pad(8)
		self.nonce = stream.u64()
		self.device_id = stream.u64()
		self.device_id_host = stream.u64()
		stream.pad(0xB0)


class AuthenticationRequest:
	def __init__(self):
		self.username = None
		self.app_version = None
		self.challenge = None
	
	def encode(self, version):
		stream = streams.StreamOut(">")
		
		name = self.username.encode()
		stream.write(name + b"\0" * (32 - len(name)))
		stream.u16(self.app_version)
		stream.pad(30)
		
		if version >= 3:
			stream.pad(0x24)
			if self.challenge is not None:
				stream.write(self.challenge)
		return stream.get()
	
	def decode(self, data, version):
		stream = streams.StreamIn(data, ">")
		
		self.username = stream.read(32).rstrip(b"\0").decode()
		self.app_version = stream.u16()
		stream.pad(30)
		
		if version >= 3:
			stream.pad(0x24)
			if not stream.eof():
				self.challenge = stream.read(0x300)


class AuthenticationResponse:
	def __init__(self):
		self.challenge = None
	
	def encode(self, version):
		stream = streams.StreamOut(">")
		if version >= 3:
			stream.pad(0x84)
			if self.challenge is not None:
				stream.write(self.challenge)
		return stream.get()
	
	def decode(self, data, version):
		stream = streams.StreamIn(data, ">")
		if version >= 3:
			stream.pad(0x84)
			if not stream.eof():
				self.challenge = stream.read(0x100)


class AuthenticationFrame:
	def __init__(self):
		self.version = None
		self.status_code = None
		self.header = None
		self.network_key = None
		self.authentication_key = None
		self.payload = None
	
	def encode(self):
		payload = self.payload.encode(self.version)
		
		stream = streams.StreamOut(">")
		stream.u24(0x0022AA) # Nintendo
		stream.u16(0x102) # Authentication frame
		stream.pad(1)
		
		stream.u8(self.version)
		stream.u8(len(payload) & 0xFF)
		stream.u8(self.status_code)
		stream.u8(isinstance(self.payload, AuthenticationResponse))
		stream.u8(len(payload) >> 8)
		stream.pad(3)
		
		stream.write(self.header.encode("<"))
		stream.write(self.network_key)
		stream.write(self.authentication_key)
		stream.write(payload)
		return stream.get()
	
	def decode(self, data):
		stream = streams.StreamIn(data, ">")
		if stream.u24() != 0x0022AA:
			raise ValueError("Data frame has wrong OUI")
		if stream.u16() != 0x102:
			raise ValueError("Data frame is not an authentication frame")
		stream.pad(1)
		
		self.version = stream.u8()
		size_lo = stream.u8()
		self.status_code = stream.u8()
		is_response = stream.u8()
		size_hi = stream.u8()
		stream.pad(3)
		
		self.header = SessionInfo()
		self.header.decode(stream.read(32), "<")
		self.network_key = stream.read(16)
		self.authentication_key = stream.read(16)
		
		size = (size_hi << 8) | size_lo
		if stream.available() != size:
			raise ValueError("Authentication frame has wrong size")
		
		if is_response:
			self.payload = AuthenticationResponse()
		else:
			self.payload = AuthenticationRequest()
		self.payload.decode(stream.read(size), self.version)


class DisconnectFrame:
	def __init__(self):
		self.reason = None
	
	def encode(self):
		stream = streams.StreamOut(">")
		stream.u24(0x0022AA) # Nintendo
		stream.u16(0x103) # Disconnect frame
		stream.pad(1)
		
		stream.u8(self.reason)
		stream.pad(31)
		return stream.get()
	
	def decode(self, data):
		stream = streams.StreamIn(data, ">")
		if stream.u24() != 0x0022AA:
			raise ValueError("Data frame has wrong OUI")
		if stream.u16() != 0x103:
			raise ValueError("Data frame is not a disconnect frame")
		stream.pad(1)
		
		self.reason = stream.u8()
		stream.pad(31)

		
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
		self.nonce = None
	
	def check(self, info):
		if info.local_communication_id != self.local_communication_id: return False
		if info.game_mode != self.game_mode: return False
		if info.ssid != self.ssid: return False
		if info.version != self.version: return False
		if info.security_level != self.security_level: return False
		return True
	
	def parse(self, frame):
		self.local_communication_id = frame.header.local_communication_id
		self.game_mode = frame.header.game_mode
		self.ssid = frame.header.ssid
		self.version = frame.version
		self.key = frame.info.key
		self.security_level = frame.info.security_level
		self.accept_policy = frame.info.station_accept_policy
		self.max_participants = frame.info.max_participants
		self.num_participants = frame.info.num_participants
		self.participants = frame.info.participants
		self.application_data = frame.info.application_data
		self.challenge = frame.info.challenge
		self.nonce = frame.nonce
	
	def build(self):
		header = SessionInfo()
		header.local_communication_id = self.local_communication_id
		header.game_mode = self.game_mode
		header.ssid = self.ssid
		
		info = AdvertisementInfo()
		info.key = self.key
		info.security_level = self.security_level
		info.station_accept_policy = self.accept_policy
		info.max_participants = self.max_participants
		info.num_participants = self.num_participants
		info.participants = self.participants
		info.application_data = self.application_data
		info.challenge = self.challenge
		
		frame = AdvertisementFrame()
		frame.header = header
		frame.version = self.version
		frame.encryption = 1 if self.security_level == 3 else 2
		frame.nonce = self.nonce
		frame.info = info
		return frame


class ConnectNetworkParam:
	def __init__(self):
		self.ifname = "ldn"
		self.ifname_monitor = "ldn-mon"
		self.phyname = "phy0"
		self.phyname_monitor = "phy0"
		
		self.network = None
		self.password = ""
		
		self.name = ""
		self.app_version = 0
		
		self.version = 3
		self.enable_challenge = True
		self.device_id = random.randint(0, 0xFFFFFFFFFFFFFFFF)

	def check(self):
		if self.network is None: raise ValueError("network is required")
		if self.network.version not in [2, 3]:
			raise ValueError("Network version not supported")


class CreateNetworkParam:
	def __init__(self):
		self.ifname = "ldn"
		self.ifname_monitor = "ldn-mon"
		self.phyname = "phy0"
		self.phyname_monitor = "phy0"
		
		self.local_communication_id = None
		self.game_mode = None
		
		self.max_participants = 8
		self.application_data = b""
		self.accept_policy = ACCEPT_ALL
		self.accept_filter = []
		self.security_level = 1
		self.ssid = None
		
		self.name = ""
		self.app_version = 0
		
		self.channel = None
		self.key = None
		self.password = ""
		
		self.version = 3
		self.enable_challenge = True
		self.device_id = random.randint(0, 0xFFFFFFFFFFFFFFFF)

	def check(self):
		if self.local_communication_id is None: raise ValueError("local_communication_id is required")
		if self.game_mode is None: raise ValueError("game_mode is required")
		if self.max_participants > 8: raise ValueError("max_participants is too high")
		if len(self.application_data) > 0x180: raise ValueError("application_data is too large")
		if self.ssid is not None and len(self.ssid) != 16:
			raise ValueError("ssid has wrong size")
		if self.channel is not None and not wlan.is_valid_channel(self.channel):
			raise ValueError("channel is invalid")
		if self.key is not None and len(self.key) != 16:
			raise ValueError("key has wrong size")
		if self.version not in [2, 3]:
			raise ValueError("version is invalid")


class DisconnectEvent:
	def __init__(self, reason):
		self.reason = reason

class JoinEvent:
	def __init__(self, index, participant):
		self.index = index
		self.participant = participant

class LeaveEvent:
	def __init__(self, index, participant):
		self.index = index
		self.participant = participant

class AcceptPolicyChanged:
	def __init__(self, old, new):
		self.old = old
		self.new = new

class ApplicationDataChanged:
	def __init__(self, old, new):
		self.old = old
		self.new = new


class AdvertisementMonitor:
	def __init__(self, monitor):
		self.monitor = monitor
	
	async def receive(self):
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
			
			info = NetworkInfo()
			info.address = action.source
			info.channel = wlan.map_frequency(radiotap.frequency)
			info.parse(frame)
			return info

	async def scan(self, channels, dwell_time):
		networks = []
		async def scan_frames():
			addresses = []
			while True:
				network = await self.receive()
				if network.address not in addresses:
					addresses.append(network.address)
					networks.append(network)
		
		async with util.background_task(scan_frames):
			for channel in channels:
				await self.monitor.set_channel(channel)
				await trio.sleep(dwell_time)
		return networks

		
class STANetwork:
	def __init__(self, interface, monitor, router, param):
		self.monitor = AdvertisementMonitor(monitor)
		self.interface = interface
		self.router = router
		
		self.network = param.network
		self.param = param
		
		self.authentication_key = secrets.token_bytes(16)
		
		self.network_id = None
		
		self.events = queue.create()
	
	def check_authentication_response(self, address, data):
		if address != self.network.address: return False
		
		frame = AuthenticationFrame()
		try:
			frame.decode(data)
		except Exception:
			return False # Ignore invalid frames
		
		if not isinstance(frame.payload, AuthenticationResponse): return False
		
		if frame.header.local_communication_id != self.network.local_communication_id: return False
		if frame.header.game_mode != self.network.game_mode: return False
		if frame.header.ssid != self.network.ssid: return False
		
		if frame.network_key != self.network.key: return False
		if frame.authentication_key != self.authentication_key: return False
		
		if frame.status_code != 0:
			raise AuthenticationError(frame.status_code)
		return True
	
	def info(self):
		return self.network
	
	async def next_event(self):
		return await self.events.get()
	
	@contextlib.asynccontextmanager
	async def start(self):
		await self.authenticate()
		await self.initialize_network()
		async with util.background_task(self.process_events):
			async with util.background_task(self.monitor_network):
				yield
	
	async def process_events(self):
		while True:
			event = await self.interface.next_event()
			if isinstance(event, wlan.FrameEvent):
				frame = DisconnectFrame()
				frame.decode(event.data)
				await self.events.put(DisconnectEvent(frame.reason))
			elif isinstance(event, wlan.DisassociationEvent):
				await self.events.put(DisconnectEvent(DISCONNECT_CONNECTION_LOST))
	
	async def authenticate(self):
		request = AuthenticationRequest()
		request.username = self.param.name
		request.app_version = self.param.app_version
		
		if self.param.enable_challenge:
			challenge = ChallengeRequest()
			challenge.token = self.network.challenge
			challenge.nonce = random.randint(0, 0xFFFFFFFFFFFFFFFF)
			challenge.device_id = self.param.device_id
			request.challenge = challenge.encode()
		
		header = SessionInfo()
		header.local_communication_id = self.network.local_communication_id
		header.game_mode = self.network.game_mode
		header.ssid = self.network.ssid
		
		frame = AuthenticationFrame()
		frame.version = self.network.version
		frame.status_code = 0
		frame.header = header
		frame.network_key = self.network.key
		frame.authentication_key = self.authentication_key
		frame.payload = request
		
		# Attempt authentication up to three times
		for i in range(3):
			await self.interface.send_frame(self.network.address, frame.encode())
			
			# Resend the authentication request if we do not
			# receive a response after 700 milliseconds
			with trio.move_on_after(.7):
				while True:
					event = await self.interface.next_event()
					if isinstance(event, wlan.FrameEvent):
						if self.check_authentication_response(event.address, event.data):
							return
					elif isinstance(event, wlan.DisassociationEvent):
						raise ConnectionError("Station was disassociated")
		raise ConnectionError("Authentication timeout (password may be wrong)")
	
	async def receive_network(self):
		# Receives the next advertisement frame
		while True:
			info = await self.monitor.receive()
			if info.address == self.network.address and info.channel == self.network.channel:
				if not self.network.check(info):
					raise ConnectionError("Received incompatible advertisement frame from host")
				return info
	
	async def initialize_network(self):
		await self.interface.set_authorized()
		
		# Wait until the host has updated the advertisement frame
		with trio.fail_after(1):
			while True:
				network = await self.receive_network()
				for index, participant in enumerate(network.participants):
					if participant.mac_address == self.interface.address:
						break
		
		# Initialize local state
		self.network = network
		self.network_id = int(network.participants[0].ip_address.split(".")[2])
		
		# Initialize interface address
		attrs = {
			route.IFA_LOCAL: socket.inet_aton(network.participants[index].ip_address),
			route.IFA_BROADCAST: socket.inet_aton("169.254.%i.255" %self.network_id)
		}
		await self.router.add_address(
			socket.AF_INET, 24, route.IFA_F_PERMANENT, route.RT_SCOPE_UNIVERSE,
			self.interface.index, attrs
		)
		
		# Create a static neighbor entry for each participant
		for participant in network.participants:
			if participant.connected:
				attrs = {
					route.NDA_DST: socket.inet_aton(participant.ip_address),
					route.NDA_LLADDR: participant.mac_address.encode()
				}
				await self.router.add_neighbor(socket.AF_INET, self.interface.index, route.NUD_PERMANENT, 0, 0, attrs)
	
	async def monitor_network(self):
		# Monitors advertisement frames to get
		# notified when the network changes
		while True:
			network = await self.receive_network()
			
			# Check if the accept policy has changed
			if network.accept_policy != self.network.accept_policy:
				await self.events.put(AcceptPolicyChanged(self.network.accept_policy, network.accept_policy))
			
			# Check if the application data has changed
			if network.application_data != self.network.application_data:
				await self.events.put(ApplicationDataChanged(self.network.application_data, network.application_data))
			
			# Remove participants that are gone
			for i in range(8):
				old = self.network.participants[i]
				new = network.participants[i]
				if old.connected and old.mac_address != new.mac_address:
					attrs = {
						route.NDA_DST: socket.inet_aton(old.ip_address),
						route.NDA_LLADDR: old.mac_address.encode()
					}
					await self.router.remove_neighbor(socket.AF_INET, self.interface.index, route.NUD_PERMANENT, 0, 0, attrs)
					await self.events.put(LeaveEvent(i, old))
			
			# Register new participants
			for i in range(8):
				old = self.network.participants[i]
				new = network.participants[i]
				if new.connected and old.mac_address != new.mac_address:
					attrs = {
						route.NDA_DST: socket.inet_aton(new.ip_address),
						route.NDA_LLADDR: new.mac_address.encode()
					}
					await self.router.add_neighbor(socket.AF_INET, self.interface.index, route.NUD_PERMANENT, 0, 0, attrs)
					await self.events.put(JoinEvent(i, new))
			
			# Update local state
			self.network = network


class APNetwork:
	def __init__(self, interface, monitor, router, param):
		self.interface = interface
		self.monitor = monitor
		self.router = router
		
		self.accept_filter = param.accept_filter
		self.enable_challenge = param.enable_challenge
		self.device_id = param.device_id
		
		self.nonce = random.randint(0, 0xFFFFFFFF)
		self.network_id = random.randint(1, 127)
		
		participant = ParticipantInfo()
		participant.ip_address = "169.254.%i.1" %self.network_id
		participant.mac_address = interface.address
		participant.connected = True
		participant.name = param.name
		participant.app_version = param.app_version
		
		participants = [participant]
		for i in range(7):
			participants.append(ParticipantInfo())
		
		self.network = NetworkInfo()
		self.network.address = interface.address
		self.network.channel = param.channel
		self.network.local_communication_id = param.local_communication_id
		self.network.game_mode = param.game_mode
		self.network.ssid = param.ssid
		self.network.version = param.version
		self.network.key = param.key
		self.network.security_level = param.security_level
		self.network.accept_policy = param.accept_policy
		self.network.max_participants = param.max_participants
		self.network.num_participants = 1
		self.network.participants = participants
		self.network.application_data = param.application_data
		self.network.challenge = random.randint(0, 0xFFFFFFFFFFFFFFFF)
		self.network.nonce = struct.pack(">I", self.nonce)
		
		self.events = queue.create()
	
	def make_authentication_response(self, status, version, key, challenge=b""):
		header = SessionInfo()
		header.local_communication_id = self.network.local_communication_id
		header.game_mode = self.network.game_mode
		header.ssid = self.network.ssid
		
		response = AuthenticationResponse()
		response.challenge = challenge
		
		frame = AuthenticationFrame()
		frame.version = version
		frame.status_code = status
		frame.header = header
		frame.network_key = self.network.key
		frame.authentication_key = key
		frame.payload = response
		return frame
	
	def check_accept_policy(self, address):
		if self.network.accept_policy == ACCEPT_ALL: return True
		if self.network.accept_policy == ACCEPT_NONE: return False
		if self.network.accept_policy == ACCEPT_BLACKLIST:
			return address not in self.accept_filter
		if self.network.accept_policy == ACCEPT_WHITELIST:
			return address in self.accept_filter
		return False
	
	def check_authentication_request(self, address, frame):
		if frame.version not in [2, 3]: return AUTH_INVALID_VERSION
		
		if frame.status_code != 0: return AUTH_MALFORMED_REQUEST
		if frame.header.local_communication_id != self.network.local_communication_id: return AUTH_MALFORMED_REQUEST
		if frame.header.game_mode != self.network.game_mode: return AUTH_MALFORMED_REQUEST
		if frame.header.ssid != self.network.ssid: return AUTH_MALFORMED_REQUEST
		if frame.network_key != self.network.key: return AUTH_MALFORMED_REQUEST
		if not isinstance(frame.payload, AuthenticationRequest): return AUTH_MALFORMED_REQUEST
		
		if not self.check_accept_policy(address):
			return AUTH_DENIED_BY_POLICY
	
	def process_authentication_challenge(self, challenge):
		if not self.enable_challenge: return b""
		
		request = ChallengeRequest()
		try:
			request.decode(challenge)
		except Exception:
			return None
		
		if request.token != self.network.challenge:
			return None
		
		response = ChallengeResponse()
		response.nonce = request.nonce
		response.device_id = request.device_id
		response.device_id_host = self.device_id
		return response.encode()
	
	def update_nonce(self):
		self.nonce = (self.nonce + 1) & 0xFFFFFFFF
		self.network.nonce = struct.pack(">I", self.nonce)
	
	def info(self):
		return self.network
	
	def set_application_data(self, data):
		self.network.application_data = data
		self.update_nonce()
	
	def set_accept_policy(self, policy):
		self.network.accept_policy = policy
		self.update_nonce()
	
	def set_accept_filter(self, filter):
		self.accept_filter = filter
		
	async def kick(self, index):
		participant = self.network.participants[index]
		if participant.connected:
			frame = DisconnectFrame()
			frame.reason = DISCONNECT_STATION_REJECTED_BY_HOST
			await self.interface.send_frame(participant.mac_address, frame.encode())
			await self.interface.remove_station(participant.mac_address)
			await self.process_disassociation(participant.mac_address)
	
	async def next_event(self):
		return await self.events.get()
	
	@contextlib.asynccontextmanager
	async def start(self):
		await self.initialize_network()
		async with util.background_task(self.process_events):
			async with util.background_task(self.send_advertisements):
				yield
				await self.destroy_network()
	
	async def process_events(self):
		while True:
			event = await self.interface.next_event()
			if isinstance(event, wlan.FrameEvent):
				response = await self.process_authentication_event(event)
				await self.interface.send_frame(event.address, response.encode())
			elif isinstance(event, wlan.DisassociationEvent):
				await self.process_disassociation(event)
	
	async def process_authentication_event(self, event):
		frame = AuthenticationFrame()
		
		try:
			frame.decode(event.data)
		except Exception:
			return self.make_authentication_response(AUTH_MALFORMED_REQUEST, self.network.version, bytes(16))
		
		error = self.check_authentication_request(event.address, frame)
		if error is not None:
			return self.make_authentication_response(error, self.network.version, frame.authentication_key)
		
		challenge = self.process_authentication_challenge(frame.payload.challenge)
		if challenge is None:
			return self.make_authentication_response(AUTH_CHALLENGE_FAILURE, self.network.version, frame.authentication_key)
		
		await self.register_participant(event.address, frame.payload.username, frame.payload.app_version)
		
		return self.make_authentication_response(AUTH_SUCCESS, self.network.version, frame.authentication_key, challenge)
	
	async def register_participant(self, address, name, app_version):
		# Allocate an ip address
		for index in range(8):
			if not self.network.participants[index].connected:
				break
		
		participant = ParticipantInfo()
		participant.ip_address = "169.254.%i.%i" %(self.network_id, (index + 1))
		participant.mac_address = address
		participant.connected = True
		participant.name = name
		participant.app_version = app_version
		
		self.network.participants[index] = participant
		self.update_nonce()
		
		# Add neighbor entry
		attrs = {
			route.NDA_DST: socket.inet_aton(participant.ip_address),
			route.NDA_LLADDR: participant.mac_address.encode()
		}
		await self.router.add_neighbor(socket.AF_INET, self.interface.index, route.NUD_PERMANENT, 0, 0, attrs)
		
		await self.events.put(JoinEvent(index, participant))
	
	async def process_disassociation(self, address):
		for index, participant in enumerate(self.network.participants):
			if participant.connected and participant.mac_address == address:
				break
		else: return
		
		participant.connected = False
		self.update_nonce()
		
		# Remove neighbor entry
		attrs = {
			route.NDA_DST: socket.inet_aton(participant.ip_address),
			route.NDA_LLADDR: participant.mac_address.encode()
		}
		await self.router.remove_neighbor(socket.AF_INET, self.interface.index, route.NUD_PERMANENT, 0, 0, attrs)
		
		await self.events.put(LeaveEvent(index, participant))
	
	async def send_advertisements(self):
		while True:
			await self.send_advertisement()
			await trio.sleep(.1)
	
	async def send_advertisement(self):
		frame = self.network.build()
		
		action = wlan.ActionFrame()
		action.source = self.interface.address
		action.action = frame.encode()
		
		radiotap = wlan.RadiotapFrame()
		radiotap.data = action.encode()
		await self.monitor.send(radiotap)
	
	async def initialize_network(self):
		host = self.network.participants[0]
		attrs = {
			route.NDA_DST: socket.inet_aton(host.ip_address),
			route.NDA_LLADDR: host.mac_address.encode()
		}
		await self.router.add_neighbor(socket.AF_INET, self.interface.index, route.NUD_PERMANENT, 0, 0, attrs)
	
	async def destroy_network(self):
		for participant in self.network.participants:
			if participant.connected:
				frame = DisconnectFrame()
				frame.reason = DISCONNECT_NETWORK_DESTROYED
				await self.interface.send_frame(participant.mac_address, frame.encode())


async def scan(ifname="ldn", phyname="phy0", channels=[1, 6, 11], dwell_time=.110):
	if not channels: return []

	# Check if all channels are valid
	for channel in channels:
		if not wlan.is_valid_channel(channel):
			raise ValueError("Invalid channel: %i" %channel)
	
	async with wlan.create() as factory:
		async with factory.create_monitor(phyname, ifname) as monitor:
			scanner = AdvertisementMonitor(monitor)
			return await scanner.scan(channels, dwell_time)

@contextlib.asynccontextmanager
async def connect(param, ifname="ldn", phyname="phy0"):
	param = copy.copy(param)
	param.check()
	
	network = param.network
	
	key = None
	if network.security_level == 1:
		key = generate_data_key(network.key, param.password)
	
	async with wlan.create() as factory:
		async with factory.create_monitor(param.phyname_monitor, param.ifname_monitor) as monitor:
			await monitor.set_channel(network.channel)
			async with factory.connect_network(param.phyname, param.ifname, network.ssid.hex(), network.channel, key) as interface:
				async with route.connect() as router:
					network = STANetwork(interface, monitor, router, param)
					async with network.start():
						yield network

@contextlib.asynccontextmanager
async def create_network(param, ifname="ldn", phyname="phy0"):
	param = copy.copy(param)
	if param.ssid is None: param.ssid = secrets.token_bytes(16)
	if param.channel is None: param.channel = random.choice([1, 6, 11])
	if param.key is None: param.key = secrets.token_bytes(16)
	param.check()
	
	key = None
	if param.security_level == 1:
		key = generate_data_key(param.key, param.password)
	
	async with wlan.create() as factory:
		async with factory.create_monitor(param.phyname_monitor, param.ifname_monitor) as monitor:
			await monitor.set_channel(param.channel)
			async with factory.create_network(param.phyname, param.ifname, param.ssid.hex(), param.channel, key, param.max_participants) as interface:
				async with route.connect() as router:
					network = APNetwork(interface, monitor, router, param)
					async with network.start():
						yield network
