
from netlink import nl80211
from ldn import streams, util
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


class WLAN:
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
	async def create_interface(self, phy, name, type):
		index = await self.get_wiphy_index(phy)
		attrs = {
			nl80211.NL80211_ATTR_WIPHY: index,
			nl80211.NL80211_ATTR_IFNAME: name,
			nl80211.NL80211_ATTR_IFTYPE: type
		}
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
		async with self.create_interface(phy, name, nl80211.NL80211_IFTYPE_MONITOR) as interface:
			monitor = Monitor(self.wlan, interface)
			await monitor.bind()
			yield monitor


@contextlib.asynccontextmanager
async def create():
	async with nl80211.connect() as wlan:
		yield WLAN(wlan)
