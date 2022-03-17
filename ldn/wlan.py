
# This file implements WLAN functions using NL80211

from netlink import generic, nl80211
from ldn import streams, util, queue
import contextlib
import netlink
import string
import struct
import socket
import fcntl
import trio


SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

IFF_UP = 1

ETH_P_ALL = 3
ETH_P_OUI = 0x88B7


IEEE80211_FTYPE_MGMT = 0
IEEE80211_FTYPE_CTL = 4
IEEE80211_FTYPE_DATA = 8
IEEE80211_FTYPE_EXT = 0xC

IEEE80211_STYPE_ASSOC_REQ = 0
IEEE80211_STYPE_ASSOC_RESP = 0x10
IEEE80211_STYPE_REASSOC_REQ = 0x20
IEEE80211_STYPE_REASSOC_RESP = 0x30
IEEE80211_STYPE_PROBE_REQ = 0x40
IEEE80211_STYPE_PROBE_RESP = 0x50
IEEE80211_STYPE_BEACON = 0x80
IEEE80211_STYPE_ATIM = 0x90
IEEE80211_STYPE_DISASSOC = 0xA0
IEEE80211_STYPE_AUTH = 0xB0
IEEE80211_STYPE_DEAUTH = 0xC0
IEEE80211_STYPE_ACTION = 0xD0

WLAN_STATUS_SUCCESS = 0
WLAN_STATUS_UNSPECIFIED_FAILURE = 1
WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA = 17

WLAN_REASON_UNSPECIFIED = 1

def SUITE(oui, id):
	return (oui << 8) | id

WLAN_CIPHER_SUITE_CCMP = 0x000FAC04

WLAN_AKM_SUITE_PSK = SUITE(0x000FAC, 2)

WLAN_AUTH_OPEN = 0

WLAN_EID_SSID = 0
WLAN_EID_SUPP_RATES = 1
WLAN_EID_DS_PARAMS = 3
WLAN_EID_SUPPORTED_CHANNELS = 36
WLAN_EID_HT_CAPABILITY = 45
WLAN_EID_RSN = 48
WLAN_EID_EXT_CAPABILITY = 127


Channels = {
	1: 2412,
	6: 2437,
	11: 2462,
	36: 5180,
	40: 5200,
	44: 5220,
	48: 5240
}

Frequencies = {v: k for k, v in Channels.items()}

def map_frequency(freq):
	return Frequencies[freq]

def is_valid_channel(channel):
	return channel in Channels


def encode_elements(elements):
	stream = streams.StreamOut("<")
	for id in sorted(elements):
		stream.u8(id)
		stream.u8(len(elements[id]))
		stream.write(elements[id])
	return stream.get()

def decode_elements(data):
	elements = {}
	stream = streams.StreamIn(data, "<")
	while not stream.eof():
		id = stream.u8()
		length = stream.u8()
		elements[id] = stream.read(length)
	return elements


class MACAddress:
	def __init__(self, address=None):
		if address is None:
			self.fields = [0] * 6
		elif isinstance(address, str):
			self.parse(address)
		elif isinstance(address, bytes):
			if len(address) != 6:
				raise ValueError("Invalid MAC address: %s" %address.hex())
			self.fields = list(address)
		elif isinstance(address, int):
			if address < 0 or address > 0xFFFFFFFFFFFF:
				raise ValueError("Invalid MAC address: %#x" %address)
			self.fields = [(address >> (40 - i * 8)) & 0xFF for i in range(6)]
		else:
			raise ValueError("Invalid MAC address: %s" %address)
	
	def __eq__(self, other):
		return self.fields == other.fields
	def __hash__(self):
		return hash(str(self))
	
	def __str__(self):
		return ":".join("%02x" %value for value in self.fields)
	def __repr__(self):
		return "MACAddress('%s')" %self
	
	def encode(self): return bytes(self.fields)
	def decode(self, data): self.fields = list(data)
	
	def parse(self, text):
		fields = text.split(":")
		if len(fields) != 6:
			raise ValueError("Invalid MAC address: %s" %text)
		
		for field in fields:
			if len(field) != 2 or field[0] not in string.hexdigits or field[1] not in string.hexdigits:
				raise ValueError("Invalid MAC address: %s" %text)
		
		self.fields = [int(field, 16) for field in fields]


class SSIDElement:
	def __init__(self):
		self.ssid = None
	
	def encode(self):
		return self.ssid.encode()
	
	def decode(self, data):
		self.ssid = data.decode()


class SuppRatesElement:
	def __init__(self):
		self.supported_rates = None
	
	def encode(self):
		return bytes(self.supported_rates)
	
	def decode(self, data):
		self.supported_rates = list(data)


class DSParamsElement:
	def __init__(self):
		self.current_channel = None
	
	def encode(self):
		return bytes([self.current_channel])


class RSNElement:
	def __init__(self):
		self.group_cipher_suite = None
		self.pairwise_cipher_suites = None
		self.akm_suites = None
		self.capabilities = None
	
	def encode(self):
		stream = streams.StreamOut("<")
		stream.u16(1) # Version
		stream.u32_be(self.group_cipher_suite)
		stream.u16(len(self.pairwise_cipher_suites))
		stream.repeat(self.pairwise_cipher_suites, stream.u32_be)
		stream.u16(len(self.akm_suites))
		stream.repeat(self.akm_suites, stream.u32_be)
		stream.u16(self.capabilities)
		return stream.get()


class RadiotapFrame:
	def __init__(self):
		self.data = None
		
		self.mactime = None # Bit 0
		self.flags = None # Bit 1
		self.rate = None # Bit 2
		
		# Bit 3
		self.frequency = None
		self.channel_flags = None
	
	def encode(self):
		present = 0
		if self.mactime is not None: present |= 1
		if self.flags is not None: present |= 2
		if self.rate is not None: present |= 4
		if self.frequency is not None: present |= 8
		
		stream = streams.StreamOut("<")
		stream.u8(0) # Version
		stream.pad(1)
		stream.skip(2) # Length
		
		if present & 1:
			stream.align(8)
			stream.u64(self.mactime)
		if present & 2: stream.u8(self.flags)
		if present & 4: stream.u8(self.rate)
		if present & 8:
			stream.align(2)
			stream.u16(self.frequency)
			stream.u16(self.channel_flags)
		
		stream.align(8)
		
		length = stream.tell()
		stream.write(self.data)
		
		stream.seek(2)
		stream.u16(length)
		
		return stream.get()
	
	def decode(self, data):
		stream = streams.StreamIn(data, "<")
		
		version = stream.u8()
		if version != 0:
			raise ValueError("Radiotap header has invalid version number: %i" %version)
		
		stream.pad(1)
		
		length = stream.u16()
		
		shift = 0
		present = 0
		while True:
			value = stream.u32()
			present |= value << shift
			if not value & 0x80000000:
				break
			shift += 32
		
		if present & 1:
			stream.align(8)
			self.mactime = stream.u64()
		if present & 2: self.flags = stream.u8()
		if present & 4: self.rate = stream.u8()
		if present & 8:
			stream.align(2)
			self.frequency = stream.u16()
			self.channel_flags = stream.u16()
		
		if stream.tell() > length:
			raise ValueError("Radiotap header has wrong length field")
		
		stream.seek(length)
		self.data = stream.readall()


class MACHeader:
	def __init__(self):
		self.frame_control = 0
		self.duration = 0
		self.address1 = MACAddress()
		self.address2 = MACAddress()
		self.address3 = MACAddress()
		self.sequence_control = 0
	
	def encode(self):
		stream = streams.StreamOut("<")
		stream.u16(self.frame_control)
		stream.u16(self.duration)
		stream.write(self.address1.encode())
		stream.write(self.address2.encode())
		stream.write(self.address3.encode())
		stream.u16(self.sequence_control)
		return stream.get()
	
	def decode(self, data):
		stream = streams.StreamIn(data, "<")
		self.frame_control = stream.u16()
		self.duration = stream.u16()
		self.address1 = MACAddress(stream.read(6))
		self.address2 = MACAddress(stream.read(6))
		self.address3 = MACAddress(stream.read(6))
		self.sequence_control = stream.u16()


class AssociationRequest:
	def __init__(self):
		self.source = None
		self.target = None
		
		self.capability_information = None
		self.listen_interval = None
		self.elements = {}
	
	def decode(self, data):
		stream = streams.StreamIn(data, "<")
		
		header = MACHeader()
		header.decode(stream.read(24))
		if header.frame_control != IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ASSOC_REQ:
			raise ValueError("Frame is not an association request")
		
		self.target = header.address1
		self.source = header.address2
		
		self.capability_information = stream.u16()
		self.listen_interval = stream.u16()
		self.elements = decode_elements(stream.readall())


class AssociationResponse:
	def __init__(self):
		self.source = None
		self.target = None
		
		self.capability_information = None
		self.status_code = None
		self.aid = None
		
		self.elements = {}
		
	def encode(self):
		stream = streams.StreamOut("<")
		
		header = MACHeader()
		header.frame_control = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ASSOC_RESP
		header.address1 = self.target
		header.address2 = self.source
		header.address3 = self.source
		stream.write(header.encode())
		
		stream.u16(self.capability_information)
		stream.u16(self.status_code)
		stream.u16(self.aid)
		
		stream.write(encode_elements(self.elements))
		return stream.get()


class ProbeRequest:
	def __init__(self):
		self.source = None
		self.elements = {}
	
	def decode(self, data):
		stream = streams.StreamIn(data, "<")
		
		header = MACHeader()
		header.decode(stream.read(24))
		if header.frame_control != IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ:
			raise ValueError("Frame is not a probe request")
		
		self.source = header.address2
		self.elements = decode_elements(stream.readall())


class ProbeResponse:
	def __init__(self):
		self.source = None
		self.target = None
		
		self.timestamp = 0
		self.beacon_interval = 0
		self.capability_information = 0
		
		self.elements = {}
	
	def encode(self):
		stream = streams.StreamOut("<")
		
		header = MACHeader()
		header.frame_control = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_RESP
		header.address1 = self.target
		header.address2 = self.source
		header.address3 = self.source
		stream.write(header.encode())
		
		stream.u64(self.timestamp)
		stream.u16(self.beacon_interval)
		stream.u16(self.capability_information)
		stream.write(encode_elements(self.elements))
		return stream.get()


class BeaconFrame:
	def __init__(self):
		self.source = None
		
		self.timestamp = 0
		self.beacon_interval = 0
		self.capability_information = 0
		
		self.elements = {}
		
	def encode(self):
		stream = streams.StreamOut("<")
		
		header = MACHeader()
		header.frame_control = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_BEACON
		header.address1 = MACAddress("ff:ff:ff:ff:ff:ff")
		header.address2 = self.source
		header.address3 = self.source
		stream.write(header.encode())
		
		stream.u64(self.timestamp)
		stream.u16(self.beacon_interval)
		stream.u16(self.capability_information)
		stream.write(encode_elements(self.elements))
		return stream.get()


class DisassociationFrame:
	def __init__(self):
		self.source = None
		self.target = None
		self.reason = None
		self.elements = {}
	
	def decode(self, data):
		stream = streams.StreamIn(data, "<")
		
		header = MACHeader()
		header.decode(stream.read(24))
		if header.frame_control != IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_DISASSOC:
			raise ValueError("Frame is not a disassociation frame")
		
		self.target = header.address1
		self.source = header.address2
		self.reason = stream.u16()
		self.elements = decode_elements(stream.readall())


class AuthenticationFrame:
	def __init__(self):
		self.source = None
		self.target = None
		self.bssid = None
		
		self.algorithm = None
		self.sequence = None
		self.status_code = WLAN_STATUS_SUCCESS
		
		self.elements = {}
	
	def decode(self, data):
		stream = streams.StreamIn(data, "<")
		
		header = MACHeader()
		header.decode(stream.read(24))
		if header.frame_control != IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH:
			raise ValueError("Frame is not an authentication frame")
		
		self.target = header.address1
		self.source = header.address2
		self.bssid = header.address3
		
		self.algorithm = stream.u16()
		self.sequence = stream.u16()
		self.status_code = stream.u16()
		
		self.elements = decode_elements(stream.readall())
	
	def encode(self):
		stream = streams.StreamOut("<")
		
		header = MACHeader()
		header.frame_control = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH
		header.address1 = self.target
		header.address2 = self.source
		header.address3 = self.bssid
		stream.write(header.encode())
		
		stream.u16(self.algorithm)
		stream.u16(self.sequence)
		stream.u16(self.status_code)
		stream.write(encode_elements(self.elements))
		return stream.get()


class DeauthenticationFrame:
	def __init__(self):
		self.source = None
		self.target = None
		self.bssid = None
		self.reason = None
		self.elements = {}
	
	def encode(self):
		stream = streams.StreamOut("<")
		
		header = MACHeader()
		header.frame_control = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_DEAUTH
		header.address1 = self.target
		header.address2 = self.source
		header.address3 = self.bssid
		stream.write(header.encode())
		
		stream.u16(self.reason)
		stream.write(encode_elements(self.elements))
		return stream.get()


class ActionFrame:
	def __init__(self):
		self.source = None
		self.action = None
	
	def decode(self, data):
		stream = streams.StreamIn(data, "<")
		
		header = MACHeader()
		header.decode(stream.read(24))
		if header.frame_control != IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION:
			raise ValueError("Frame is not an action frame")
		
		self.source = header.address2
		
		self.action = stream.readall()
	
	def encode(self):
		header = MACHeader()
		header.frame_control = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION
		header.address1 = MACAddress("ff:ff:ff:ff:ff:ff")
		header.address2 = self.source
		header.address3 = MACAddress("ff:ff:ff:ff:ff:ff")
		
		stream = streams.StreamOut("<")
		stream.write(header.encode())
		stream.write(self.action)
		return stream.get()


class AssociationEvent:
	def __init__(self, address):
		self.address = address
		

class DisassociationEvent:
	def __init__(self, address):
		self.address = address
		

class FrameEvent:
	def __init__(self, address, data):
		self.address = address
		self.data = data


class Interface:
	def __init__(self, wlan, attributes):
		self.wlan = wlan
		
		self.phy = attributes[nl80211.NL80211_ATTR_WIPHY]
		self.index = attributes[nl80211.NL80211_ATTR_IFINDEX]
		self.name = attributes[nl80211.NL80211_ATTR_IFNAME]
		self.type = attributes[nl80211.NL80211_ATTR_IFTYPE]
		self.address = MACAddress(attributes[nl80211.NL80211_ATTR_MAC])
		
		self.socket = socket.socket()
	
	def getflags(self):
		req = struct.pack("16sH", self.name.encode(), 0)
		res = fcntl.ioctl(self.socket.fileno(), SIOCGIFFLAGS, req)
		return struct.unpack_from("H", res, 16)[0]
	
	def setflags(self, flags):
		# This is really slow, but there doesn't seem to be
		# an async implementation of fcntl.ioctl :(
		req = struct.pack("16sH", self.name.encode(), flags)
		fcntl.ioctl(self.socket.fileno(), SIOCSIFFLAGS, req)
	
	def disable_ipv6(self):
		with open("/proc/sys/net/ipv6/conf/%s/disable_ipv6" %self.name, "w") as f:
			f.write("1")
	
	def up(self):
		self.setflags(self.getflags() | IFF_UP)
		
	async def set_channel(self, channel):
		if channel not in Channels:
			raise ValueError("Invalid channel: %i" %channel)
		
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.index,
			nl80211.NL80211_ATTR_WIPHY_FREQ: Channels[channel]
		}
		await self.wlan.request(nl80211.NL80211_CMD_SET_CHANNEL, attrs)


class Monitor:
	# This class represents an interface in monitor mode
	
	def __init__(self, wlan, interface):
		self.wlan = wlan
		self.interface = interface
		
		self.socket = trio.socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
	
	async def bind(self):
		await self.socket.bind((self.interface.name, 0))
	
	async def recv(self):
		data = await self.socket.recv(4096)
		radiotap = RadiotapFrame()
		radiotap.decode(data)
		return radiotap
	
	async def send(self, frame):
		await self.socket.send(frame.encode())
	
	async def set_channel(self, channel):
		await self.interface.set_channel(channel)


class STAInterface:
	# This class represents an interface in station mode
	
	def __init__(self, wlan, interface, ssid, channel, key):
		self.wlan = wlan
		self.interface = interface
		self.ssid = ssid
		self.channel = channel
		self.key = key
		
		self.address = self.interface.address
		self.index = self.interface.index
		
		self.host_address = None
		
		self.events = queue.create()
	
	async def next_event(self):
		return await self.events.get()
	
	async def send_frame(self, addr, frame):
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
			nl80211.NL80211_ATTR_FRAME: frame,
			nl80211.NL80211_ATTR_MAC: addr.encode(),
			nl80211.NL80211_ATTR_CONTROL_PORT_ETHERTYPE: struct.pack("H", ETH_P_OUI)
		}
		await self.wlan.request(nl80211.NL80211_CMD_CONTROL_PORT_FRAME, attrs)
	
	@contextlib.asynccontextmanager
	async def connect_network(self):
		rsn = RSNElement()
		rsn.group_cipher_suite = WLAN_CIPHER_SUITE_CCMP
		rsn.pairwise_cipher_suites = [WLAN_CIPHER_SUITE_CCMP]
		rsn.akm_suites = [WLAN_AKM_SUITE_PSK]
		rsn.capabilities = 0xC
		
		elements = {
			WLAN_EID_RSN: rsn.encode()
		}
		
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
			nl80211.NL80211_ATTR_SSID: self.ssid.encode(),
			nl80211.NL80211_ATTR_WIPHY_FREQ: Channels[self.channel],
			nl80211.NL80211_ATTR_AUTH_TYPE: nl80211.NL80211_AUTHTYPE_OPEN_SYSTEM,
			nl80211.NL80211_ATTR_CIPHER_SUITES_PAIRWISE: struct.pack("I", WLAN_CIPHER_SUITE_CCMP),
			nl80211.NL80211_ATTR_CIPHER_SUITE_GROUP: WLAN_CIPHER_SUITE_CCMP,
			nl80211.NL80211_ATTR_AKM_SUITES: struct.pack("I", WLAN_AKM_SUITE_PSK),
			nl80211.NL80211_ATTR_IE: encode_elements(elements),
			nl80211.NL80211_ATTR_PRIVACY: True,
			
			nl80211.NL80211_ATTR_CONTROL_PORT: True,
			nl80211.NL80211_ATTR_CONTROL_PORT_ETHERTYPE: struct.pack("H", ETH_P_OUI),
			nl80211.NL80211_ATTR_CONTROL_PORT_OVER_NL80211: True,
			nl80211.NL80211_ATTR_SOCKET_OWNER: True
		}
		await self.wlan.request(nl80211.NL80211_CMD_CONNECT, attrs)
		
		while True:
			message = await self.wlan.receive()
			if message.type == nl80211.NL80211_CMD_CONNECT:
				status = message.attributes[nl80211.NL80211_ATTR_STATUS_CODE]
				if status != WLAN_STATUS_SUCCESS:
					raise ConnectionError("Connect failed with status code %i" %status)
				break
		
		try:
			self.host_address = message.attributes[nl80211.NL80211_ATTR_MAC]
			
			if self.key is not None:
				attrs = {
					nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
					nl80211.NL80211_ATTR_MAC: self.host_address,
					nl80211.NL80211_ATTR_KEY: {
						nl80211.NL80211_KEY_IDX: 0,
						nl80211.NL80211_KEY_DATA: self.key,
						nl80211.NL80211_KEY_CIPHER: WLAN_CIPHER_SUITE_CCMP,
						nl80211.NL80211_KEY_DEFAULT: True
					}
				}
				await self.wlan.request(nl80211.NL80211_CMD_NEW_KEY, attrs)
				
				attrs = {
					nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
					nl80211.NL80211_ATTR_KEY: {
						nl80211.NL80211_KEY_IDX: 1,
						nl80211.NL80211_KEY_DATA: self.key,
						nl80211.NL80211_KEY_CIPHER: WLAN_CIPHER_SUITE_CCMP,
						nl80211.NL80211_KEY_DEFAULT: True
					}
				}
				await self.wlan.request(nl80211.NL80211_CMD_NEW_KEY, attrs)
			
			yield
		finally:
			attrs = {nl80211.NL80211_ATTR_IFINDEX: self.interface.index}
			await self.wlan.request(nl80211.NL80211_CMD_DISCONNECT, attrs)
	
	@contextlib.asynccontextmanager
	async def connect(self):
		self.interface.disable_ipv6()
		async with self.connect_network() as addr:
			async with util.background_task(self.process_messages):
				attrs = {
					nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
					nl80211.NL80211_ATTR_FRAME_TYPE: IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION,
					nl80211.NL80211_ATTR_FRAME_MATCH: b""
				}
				await self.wlan.request(nl80211.NL80211_CMD_REGISTER_FRAME, attrs)
				yield
	
	async def process_messages(self):
		while True:
			message = await self.wlan.receive()
			if message.type == nl80211.NL80211_CMD_CONTROL_PORT_FRAME:
				address = MACAddress(message.attributes[nl80211.NL80211_ATTR_MAC])
				data = message.attributes[nl80211.NL80211_ATTR_FRAME]
				await self.events.put(FrameEvent(address, data))
			elif message.type == nl80211.NL80211_CMD_DEL_STATION:
				address = MACAddress(message.attributes[nl80211.NL80211_ATTR_MAC])
				await self.events.put(DisassociationEvent(None))
	
	async def set_authorized(self):
		flag = 1 << nl80211.NL80211_STA_FLAG_AUTHORIZED
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
			nl80211.NL80211_ATTR_MAC: self.host_address,
			nl80211.NL80211_ATTR_STA_FLAGS2: struct.pack("II", flag, flag)
		}
		await self.wlan.request(nl80211.NL80211_CMD_SET_STATION, attrs)


class APInterface:
	# This class represents an interface in access point mode
	
	def __init__(self, wlan, interface, ssid, channel, key, max_stations):
		self.wlan = wlan
		self.interface = interface
		self.ssid = ssid
		self.channel = channel
		self.key = key
		self.max_stations = max_stations
		
		self.address = self.interface.address
		self.index = self.interface.index
		
		self.stations_by_id = {}
		self.stations_by_address = {}
		
		self.events = queue.create()
	
	def create_beacon_head(self):
		frame = BeaconFrame()
		frame.source = self.interface.address
		frame.beacon_interval = 100
		frame.capability_information = 0x511
		return frame.encode()
	
	def create_beacon_tail(self):
		return b"" # No beacon tail for now
	
	def create_probe_response(self, address):
		ssid = SSIDElement()
		ssid.ssid = self.ssid
		
		rates = SuppRatesElement()
		rates.supported_rates = [0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C]
		
		dsparams = DSParamsElement()
		dsparams.current_channel = self.channel
		
		rsn = RSNElement()
		rsn.group_cipher_suite = WLAN_CIPHER_SUITE_CCMP
		rsn.pairwise_cipher_suites = [WLAN_CIPHER_SUITE_CCMP]
		rsn.akm_suites = [WLAN_AKM_SUITE_PSK]
		rsn.capabilities = 0xC
		
		response = ProbeResponse()
		response.source = self.interface.address
		response.target = address
		response.beacon_interval = 100
		response.capability_information = 0x511
		response.elements = {
			WLAN_EID_SSID: ssid.encode(),
			WLAN_EID_SUPP_RATES: rates.encode(),
			WLAN_EID_DS_PARAMS: dsparams.encode(),
			WLAN_EID_RSN: rsn.encode()
		}
		return response.encode()
	
	def create_association_response(self, address, aid):
		rates = SuppRatesElement()
		rates.supported_rates = [0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C]
		
		response = AssociationResponse()
		response.source = self.interface.address
		response.target = address
		response.capability_information = 0x411
		response.status_code = WLAN_STATUS_SUCCESS
		response.aid = aid | 0xC000
		response.elements = {
			WLAN_EID_SUPP_RATES: rates.encode()
		}
		return response.encode()
	
	def create_association_error(self, address, error):
		response = AssociationResponse()
		response.source = self.interface.address
		response.target = address
		response.capability_information = 0x411
		response.status_code = error
		response.aid = 0
		return response.encode()
	
	def parse_management_frame(self, data):
		header = MACHeader()
		header.decode(data)
		
		frame = {
			IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ASSOC_REQ: AssociationRequest,
			IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ: ProbeRequest,
			IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_DISASSOC: DisassociationFrame,
			IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH: AuthenticationFrame
		}[header.frame_control]()
		frame.decode(data)
		return frame
	
	async def next_event(self):
		return await self.events.get()
	
	@contextlib.asynccontextmanager
	async def start_ap(self):
		beacon_head = self.create_beacon_head()
		beacon_tail = self.create_beacon_tail()
		
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
			nl80211.NL80211_ATTR_SSID: self.ssid.encode(),
			nl80211.NL80211_ATTR_BEACON_HEAD: beacon_head,
			nl80211.NL80211_ATTR_BEACON_TAIL: beacon_tail,
			nl80211.NL80211_ATTR_BEACON_INTERVAL: 100,
			nl80211.NL80211_ATTR_DTIM_PERIOD: 3,
			nl80211.NL80211_ATTR_HIDDEN_SSID: nl80211.NL80211_HIDDEN_SSID_ZERO_CONTENTS,
			nl80211.NL80211_ATTR_WIPHY_FREQ: Channels[self.channel],
			nl80211.NL80211_ATTR_CONTROL_PORT: True,
			nl80211.NL80211_ATTR_CONTROL_PORT_ETHERTYPE: struct.pack("H", ETH_P_OUI),
			nl80211.NL80211_ATTR_CONTROL_PORT_OVER_NL80211: True,
			nl80211.NL80211_ATTR_SOCKET_OWNER: True
			
		}
		await self.wlan.request(nl80211.NL80211_CMD_START_AP, attrs)
		
		if self.key is not None:
			attrs = {
				nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
				nl80211.NL80211_ATTR_KEY: {
					nl80211.NL80211_KEY_IDX: 1,
					nl80211.NL80211_KEY_DATA: self.key,
					nl80211.NL80211_KEY_CIPHER: WLAN_CIPHER_SUITE_CCMP,
					nl80211.NL80211_KEY_DEFAULT: True
				}
			}
			await self.wlan.request(nl80211.NL80211_CMD_NEW_KEY, attrs)
		
		try:
			yield
		finally:
			attrs = {nl80211.NL80211_ATTR_IFINDEX: self.interface.index}
			await self.wlan.request(nl80211.NL80211_CMD_STOP_AP, attrs)
	
	async def register_frame(self, type, match=b""):
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
			nl80211.NL80211_ATTR_FRAME_TYPE: type,
			nl80211.NL80211_ATTR_FRAME_MATCH: match
		}
		await self.wlan.request(nl80211.NL80211_CMD_REGISTER_FRAME, attrs)
	
	@contextlib.asynccontextmanager
	async def start(self):
		self.interface.disable_ipv6()
		async with self.start_ap():
			await self.register_frame(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ASSOC_REQ)
			await self.register_frame(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ)
			await self.register_frame(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_DISASSOC)
			await self.register_frame(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH)
			
			async with util.background_task(self.process_messages):
				yield
	
	async def process_messages(self):
		while True:
			message = await self.wlan.receive()
			if message.type == nl80211.NL80211_CMD_FRAME:
				data = message.attributes[nl80211.NL80211_ATTR_FRAME]
				try:
					frame = self.parse_management_frame(data)
				except Exception as e:
					continue # Ignore invalid frames
				await self.process_frame(frame)
			elif message.type == nl80211.NL80211_CMD_CONTROL_PORT_FRAME:
				address = MACAddress(message.attributes[nl80211.NL80211_ATTR_MAC])
				data = message.attributes[nl80211.NL80211_ATTR_FRAME]
				await self.events.put(FrameEvent(address, data))
	
	async def process_frame(self, frame):
		if isinstance(frame, ProbeRequest):
			ssid = frame.elements.get(WLAN_EID_SSID)
			if ssid == self.ssid.encode():
				response = self.create_probe_response(frame.source)
				await self.send_management_frame(response)
		elif isinstance(frame, AuthenticationFrame):
			if frame.bssid == self.interface.address:
				if frame.algorithm == WLAN_AUTH_OPEN and frame.sequence == 1:
					response = AuthenticationFrame()
					response.source = self.interface.address
					response.target = frame.source
					response.bssid = self.interface.address
					response.algorithm = WLAN_AUTH_OPEN
					response.sequence = 2
					response.status_code = WLAN_STATUS_SUCCESS
					await self.send_management_frame(response.encode())
		elif isinstance(frame, AssociationRequest):
			ssid = frame.elements.get(WLAN_EID_SSID)
			if ssid == self.ssid.encode():
				response = await self.process_association_request(frame)
				await self.send_management_frame(response)
		elif isinstance(frame, DisassociationFrame):
			await self.process_disassociation(frame)
	
	async def process_association_request(self, frame):
		if frame.source in self.stations_by_address:
			aid = self.stations_by_address[frame.source]
			return self.create_association_response(frame.source, aid)
		
		if len(self.stations_by_id) >= self.max_stations:
			return self.create_association_error(frame.source, WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA)
		
		if WLAN_EID_SUPP_RATES not in frame.elements:
			return self.create_association_error(frame.source, WLAN_STATUS_ASSOC_DENIED_UNSPEC)
		
		aid = 1
		while aid in self.stations_by_id:
			aid += 1
		
		self.stations_by_id[aid] = frame.source
		self.stations_by_address[frame.source] = aid
		
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
			nl80211.NL80211_ATTR_MAC: frame.source.encode(),
			nl80211.NL80211_ATTR_STA_LISTEN_INTERVAL: frame.listen_interval,
			nl80211.NL80211_ATTR_STA_SUPPORTED_RATES: frame.elements[WLAN_EID_SUPP_RATES],
			nl80211.NL80211_ATTR_STA_CAPABILITY: frame.capability_information,
			nl80211.NL80211_ATTR_STA_AID: aid
		}
		if WLAN_EID_EXT_CAPABILITY in frame.elements:
			attrs[nl80211.NL80211_ATTR_STA_EXT_CAPABILITY] = frame.elements[WLAN_EID_EXT_CAPABILITY]
		if WLAN_EID_HT_CAPABILITY in frame.elements:
			attrs[nl80211.NL80211_ATTR_HT_CAPABILITY] = frame.elements[WLAN_EID_HT_CAPABILITY]
		if WLAN_EID_SUPPORTED_CHANNELS in frame.elements:
			attrs[nl80211.NL80211_ATTR_STA_SUPPORTED_CHANNELS] = frame.elements[WLAN_EID_SUPPORTED_CHANNELS]
		await self.wlan.request(nl80211.NL80211_CMD_NEW_STATION, attrs)
		
		if self.key is not None:
			attrs = {
				nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
				nl80211.NL80211_ATTR_MAC: frame.source.encode(),
				nl80211.NL80211_ATTR_KEY: {
					nl80211.NL80211_KEY_IDX: 0,
					nl80211.NL80211_KEY_DATA: self.key,
					nl80211.NL80211_KEY_CIPHER: WLAN_CIPHER_SUITE_CCMP,
					nl80211.NL80211_KEY_DEFAULT: True
				}
			}
			await self.wlan.request(nl80211.NL80211_CMD_NEW_KEY, attrs)
		
		await self.events.put(AssociationEvent(frame.source))
		return self.create_association_response(frame.source, aid)
	
	async def process_disassociation(self, frame):
		if frame.source not in self.stations_by_address: return
		
		aid = self.stations_by_address.pop(frame.source)
		del self.stations_by_id[aid]
		
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
			nl80211.NL80211_ATTR_MAC: frame.source.encode(),
			nl80211.NL80211_ATTR_MGMT_SUBTYPE: IEEE80211_STYPE_DISASSOC >> 4,
			nl80211.NL80211_ATTR_REASON_CODE: frame.reason
		}
		await self.wlan.request(nl80211.NL80211_CMD_DEL_STATION, attrs)
		
		await self.events.put(DisassociationEvent(frame.source))
	
	async def send_management_frame(self, data):
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
			nl80211.NL80211_ATTR_FRAME: data
		}
		await self.wlan.request(nl80211.NL80211_CMD_FRAME, attrs)
	
	async def send_frame(self, addr, frame):
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
			nl80211.NL80211_ATTR_FRAME: frame,
			nl80211.NL80211_ATTR_MAC: addr.encode(),
			nl80211.NL80211_ATTR_CONTROL_PORT_ETHERTYPE: struct.pack("H", ETH_P_OUI)
		}
		await self.wlan.request(nl80211.NL80211_CMD_CONTROL_PORT_FRAME, attrs)
	
	async def remove_station(self, addr):
		if addr not in self.stations_by_address: return
		
		aid = self.stations_by_address.pop(addr)
		del self.stations_by_id[aid]
		
		frame = DeauthenticationFrame()
		frame.source = self.interface.address
		frame.target = addr
		frame.bssid = self.interface.address
		frame.reason = WLAN_REASON_UNSPECIFIED
		await self.send_management_frame(frame.encode())
		
		attrs = {
			nl80211.NL80211_ATTR_IFINDEX: self.interface.index,
			nl80211.NL80211_ATTR_MAC: addr.encode(),
			nl80211.NL80211_ATTR_REASON_CODE: WLAN_REASON_UNSPECIFIED
		}
		await self.wlan.request(nl80211.NL80211_CMD_DEL_STATION, attrs)


class WLAN:
	# This class acts as a factory for WLAN interfaces
	
	def __init__(self, wlan):
		self.wlan = wlan
		self.wlan.add_membership("mlme")
		
	async def get_wiphy_index(self, name):
		messages = await self.wlan.request(nl80211.NL80211_CMD_GET_WIPHY, flags=netlink.NLM_F_DUMP)
		for message in messages:
			if message.attributes[nl80211.NL80211_ATTR_WIPHY_NAME] == name:
				return message.attributes[nl80211.NL80211_ATTR_WIPHY]
		raise ValueError("No wiphy found with name '%s'" %name)

	@contextlib.asynccontextmanager
	async def create_interface(self, phy, name, type, extra={}):
		index = await self.get_wiphy_index(phy)
		attrs = {
			nl80211.NL80211_ATTR_WIPHY: index,
			nl80211.NL80211_ATTR_IFNAME: name,
			nl80211.NL80211_ATTR_IFTYPE: type,
		}
		attrs.update(extra)
		
		messages = await self.wlan.request(nl80211.NL80211_CMD_NEW_INTERFACE, attrs)
		interface = Interface(self.wlan, messages[0].attributes)
		try:
			interface.up()
			yield interface
		finally:
			attrs = {nl80211.NL80211_ATTR_IFINDEX: interface.index}
			await self.wlan.request(nl80211.NL80211_CMD_DEL_INTERFACE, attrs)
	
	@contextlib.asynccontextmanager
	async def create_monitor(self, phy, name):
		attrs = {
			nl80211.NL80211_ATTR_MNTR_FLAGS: {
				nl80211.NL80211_MNTR_FLAG_OTHER_BSS: True
			}
		}
		async with self.create_interface(phy, name, nl80211.NL80211_IFTYPE_MONITOR, attrs) as interface:
			monitor = Monitor(self.wlan, interface)
			await monitor.bind()
			yield monitor
	
	@contextlib.asynccontextmanager
	async def connect_network(self, phy, name, ssid, channel, key):
		async with self.create_interface(phy, name, nl80211.NL80211_IFTYPE_STATION) as interface:
			interface = STAInterface(self.wlan, interface, ssid, channel, key)
			async with interface.connect():
				yield interface
	
	@contextlib.asynccontextmanager
	async def create_network(self, phy, name, ssid, channel, key, max_stations):
		async with self.create_interface(phy, name, nl80211.NL80211_IFTYPE_AP) as interface:
			interface = APInterface(self.wlan, interface, ssid, channel, key, max_stations)
			async with interface.start():
				yield interface


@contextlib.asynccontextmanager
async def create():
	async with nl80211.connect() as wlan:
		yield WLAN(wlan)
