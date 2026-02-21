
"""
This module implements WLAN functions using NL80211.

This module is used internally by the main LDN module and is not meant to be
exposed to the user directly.
"""

from __future__ import annotations

from Crypto.Cipher import AES

from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from netlink import nl80211, route
from ldn import streams, util, queue

import contextlib
import fcntl
import netlink
import socket
import string
import struct
import trio
import typing

import logging
logger = logging.getLogger(__name__)


SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

TUNSETIFF = 0x400454CA

IFF_UP = 1

IFF_TUN = 1
IFF_TAP = 2
IFF_NO_PI = 0x1000

ETH_P_ALL = 3
ETH_P_IP = 0x800
ETH_P_ARP = 0x806
ETH_P_OUI = 0x88B7


IEEE80211_FTYPE_MGMT = 0
IEEE80211_FTYPE_CTL = 1
IEEE80211_FTYPE_DATA = 2
IEEE80211_FTYPE_EXT = 3

IEEE80211_STYPE_ASSOC_REQ = 0
IEEE80211_STYPE_ASSOC_RESP = 1
IEEE80211_STYPE_REASSOC_REQ = 2
IEEE80211_STYPE_REASSOC_RESP = 3
IEEE80211_STYPE_PROBE_REQ = 4
IEEE80211_STYPE_PROBE_RESP = 5
IEEE80211_STYPE_BEACON = 8
IEEE80211_STYPE_ATIM = 9
IEEE80211_STYPE_DISASSOC = 10
IEEE80211_STYPE_AUTH = 11
IEEE80211_STYPE_DEAUTH = 12
IEEE80211_STYPE_ACTION = 13

WLAN_STATUS_SUCCESS = 0
WLAN_STATUS_UNSPECIFIED_FAILURE = 1
WLAN_STATUS_ASSOC_DENIED_UNSPEC = 12
WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA = 17

WLAN_REASON_UNSPECIFIED = 1
WLAN_REASON_DISASSOC_STA_HAS_LEFT = 8

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
WLAN_EID_EXT_SUPP_RATES = 50
WLAN_EID_EXT_CAPABILITY = 127
WLAN_EID_VENDOR_SPECIFIC = 221


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

def map_frequency(freq: int) -> int:
    """Returns the channel number for a given frequency."""
    return Frequencies[freq]

def is_valid_channel(channel: int) -> bool:
    """Returns whether the given value is a valid channel number."""
    return channel in Channels


def encode_elements(elements: dict[int, bytes]) -> bytes:
    """Encodes the given information elements (TLVs)."""
    stream = streams.StreamOut("<")
    for id in sorted(elements):
        stream.u8(id)
        stream.u8(len(elements[id]))
        stream.write(elements[id])
    return stream.get()

def decode_elements(data: bytes) -> dict[int, bytes]:
    """Decodes the given data into information elements (TLVs)"""
    elements = {}
    stream = streams.StreamIn(data, "<")
    while not stream.eof():
        id = stream.u8()
        length = stream.u8()
        elements[id] = stream.read(length)
    return elements


class MACAddress:
    """Represents a MAC address."""

    _address: list[int]

    def __init__(self, address: str | bytes | int | None = None):
        """
        Creates a new MAC address. If an address is given, the MAC address is
        parsed from the given string, bytes or integer object.
        """

        if address is None:
            self._address = [0] * 6
        
        elif isinstance(address, str):
            self._address = self._parse(address)
        
        elif isinstance(address, bytes):
            if len(address) != 6:
                raise ValueError(f"Invalid MAC address: {address.hex()}")
            self._address = list(address)
        
        elif isinstance(address, int):
            if address < 0 or address > 0xFFFFFFFFFFFF:
                raise ValueError(f"Invalid MAC address: {address:#x}")
            self._address = [(address >> (40 - i * 8)) & 0xFF for i in range(6)]
        
        else:
            raise ValueError("Invalid MAC address: %s" %address)
    
    def __eq__(self, other: object) -> bool:
        """Checks whether two MAC addresses are equal."""
        if isinstance(other, MACAddress):
            return self._address == other._address
        return super().__eq__(other)
    
    def __hash__(self) -> int:
        """
        Returns a hash so that a MAC address can be used in sets and dictionary
        keys.
        """
        return hash(str(self))
    
    def __bytes__(self) -> bytes:
        """Returns a bytes representation of the MAC address."""
        return bytes(self._address)

    def __str__(self) -> str:
        """Returns a string representation of the MAC address."""
        return ":".join(f"{value:02X}" for value in self._address)
    
    def __repr__(self) -> str:
        """Returns a string representation of the MAC address."""
        return f"MACAddress('{self}')"
    
    def encode(self) -> bytes:
        """Returns a bytes representation of the MAC address."""
        return bytes(self._address)
    
    def _parse(self, text: str) -> list[int]:
        """Parses the given MAC address string."""

        fields = text.split(":")
        if len(fields) != 6:
            raise ValueError("Invalid MAC address: %s" %text)
        
        for field in fields:
            if len(field) != 2 or field[0] not in string.hexdigits or \
               field[1] not in string.hexdigits:
                raise ValueError("Invalid MAC address: %s" %text)
        
        return [int(field, 16) for field in fields]


@dataclass
class SSIDElement:
    ssid: str = ""

    def encode(self) -> bytes:
        return self.ssid.encode()
    
    def decode(self, data: bytes) -> None:
        self.ssid = data.decode()


@dataclass
class SuppRatesElement:
    supported_rates: list[int]
    
    def encode(self) -> bytes:
        return bytes(self.supported_rates)


@dataclass
class DSParamsElement:
    current_channel: int

    def encode(self) -> bytes:
        return bytes([self.current_channel])


@dataclass
class RSNElement:
    group_cipher_suite: int
    pairwise_cipher_suites: list[int]
    akm_suites: list[int]
    capabilities: int

    def encode(self) -> bytes:
        stream = streams.StreamOut("<")
        stream.u16(1) # Version
        stream.u32_be(self.group_cipher_suite)
        stream.u16(len(self.pairwise_cipher_suites))
        stream.repeat(self.pairwise_cipher_suites, stream.u32_be)
        stream.u16(len(self.akm_suites))
        stream.repeat(self.akm_suites, stream.u32_be)
        stream.u16(self.capabilities)
        return stream.get()


@dataclass
class RadiotapFrame:
    data: bytes = b""

    mactime: int | None = None
    flags: int | None = None
    rate: int | None = None

    frequency: int | None = None
    channel_flags: int | None = None
    
    def encode(self) -> bytes:
        present = 0
        if self.mactime is not None: present |= 1
        if self.flags is not None: present |= 2
        if self.rate is not None: present |= 4
        if self.frequency is not None: present |= 8
        
        stream = streams.StreamOut("<")
        stream.u8(0) # Version
        stream.pad(1)
        stream.skip(2) # Length

        stream.u32(present)
        
        if self.mactime is not None:
            stream.align(8)
            stream.u64(self.mactime)
        if self.flags is not None: stream.u8(self.flags)
        if self.rate is not None: stream.u8(self.rate)
        if self.frequency is not None and self.channel_flags is not None:
            stream.align(2)
            stream.u16(self.frequency)
            stream.u16(self.channel_flags)
        
        stream.align(8)
        
        length = stream.tell()
        stream.write(self.data)
        
        stream.seek(2)
        stream.u16(length)
        
        return stream.get()
    
    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        
        version = stream.u8()
        if version != 0:
            raise ValueError(
                f"Radiotap header has invalid version number: {version}"
            )
        
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


@dataclass
class MACHeader:
    type: int = 0
    subtype: int = 0
    flags: int = 0

    duration: int = 0
    address1: MACAddress = MACAddress()
    address2: MACAddress = MACAddress()
    address3: MACAddress = MACAddress()
    sequence_control: int = 0
    
    def encode(self) -> bytes:
        frame_control = (self.type << 2) | (self.subtype << 4) | \
            (self.flags << 8)
        stream = streams.StreamOut("<")
        stream.u16(frame_control)
        stream.u16(self.duration)
        stream.write(self.address1.encode())
        stream.write(self.address2.encode())
        stream.write(self.address3.encode())
        stream.u16(self.sequence_control)
        return stream.get()
    
    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")

        frame_control = stream.u16()
        if frame_control & 3:
            raise ValueError("Frame has unsupported MAC version number")
        
        self.type = (frame_control >> 2) & 3
        self.subtype = (frame_control >> 4) & 0xF
        self.flags = frame_control >> 8

        self.duration = stream.u16()
        self.address1 = MACAddress(stream.read(6))
        self.address2 = MACAddress(stream.read(6))
        self.address3 = MACAddress(stream.read(6))
        self.sequence_control = stream.u16()


class FrameType(typing.Protocol):
    def decode(self, data: bytes) -> None:
        ...
    
    def encode(self) -> bytes:
        ...


@dataclass
class AssociationRequest:
    target: MACAddress = MACAddress()
    source: MACAddress = MACAddress()

    capability_information: int = 0
    listen_interval: int = 0
    elements: dict[int, bytes] = field(default_factory=dict)

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        
        header = MACHeader()
        header.decode(stream.read(24))

        if header.type != IEEE80211_FTYPE_MGMT or \
           header.subtype != IEEE80211_STYPE_ASSOC_REQ:
            raise ValueError("Frame is not an association request")
        
        self.target = header.address1
        self.source = header.address2
        
        self.capability_information = stream.u16()
        self.listen_interval = stream.u16()
        self.elements = decode_elements(stream.readall())
    
    def encode(self) -> bytes:
        stream = streams.StreamOut("<")
        
        header = MACHeader()
        header.type = IEEE80211_FTYPE_MGMT
        header.subtype = IEEE80211_STYPE_ASSOC_REQ
        header.address1 = self.target
        header.address2 = self.source
        header.address3 = self.target
        stream.write(header.encode())
        
        stream.u16(self.capability_information)
        stream.u16(self.listen_interval)
        
        stream.write(encode_elements(self.elements))
        return stream.get()


@dataclass
class AssociationResponse:
    target: MACAddress = MACAddress()
    source: MACAddress = MACAddress()

    capability_information: int = 0
    status_code: int = 0
    aid: int = 0

    elements: dict[int, bytes] = field(default_factory=dict)

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        
        header = MACHeader()
        header.decode(stream.read(24))

        if header.type != IEEE80211_FTYPE_MGMT or \
           header.subtype != IEEE80211_STYPE_ASSOC_RESP:
            raise ValueError("Frame is not an association response")
        
        self.target = header.address1
        self.source = header.address2
        
        self.capability_information = stream.u16()
        self.status_code = stream.u16()
        self.aid = stream.u16()

        self.elements = decode_elements(stream.readall())
        
    def encode(self) -> bytes:
        stream = streams.StreamOut("<")
        
        header = MACHeader()
        header.type = IEEE80211_FTYPE_MGMT
        header.subtype = IEEE80211_STYPE_ASSOC_RESP
        header.address1 = self.target
        header.address2 = self.source
        header.address3 = self.source
        stream.write(header.encode())
        
        stream.u16(self.capability_information)
        stream.u16(self.status_code)
        stream.u16(self.aid)
        
        stream.write(encode_elements(self.elements))
        return stream.get()


@dataclass
class ProbeRequest:
    source: MACAddress = MACAddress()
    elements: dict[int, bytes] = field(default_factory=dict)
    
    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        
        header = MACHeader()
        header.decode(stream.read(24))

        if header.type != IEEE80211_FTYPE_MGMT or \
           header.subtype != IEEE80211_STYPE_PROBE_REQ:
            raise ValueError("Frame is not a probe request")
        
        self.source = header.address2
        self.elements = decode_elements(stream.readall())
    
    def encode(self) -> bytes:
        stream = streams.StreamOut("<")
        
        header = MACHeader()
        header.type = IEEE80211_FTYPE_MGMT
        header.subtype = IEEE80211_STYPE_PROBE_REQ
        header.address1 = MACAddress("ff:ff:ff:ff:ff:ff")
        header.address2 = self.source
        header.address3 = MACAddress("ff:ff:ff:ff:ff:ff")
        stream.write(header.encode())
        
        stream.write(encode_elements(self.elements))
        return stream.get()


@dataclass
class ProbeResponse:
    target: MACAddress = MACAddress()
    source: MACAddress = MACAddress()

    timestamp: int = 0
    beacon_interval: int = 0
    capability_information: int = 0

    elements: dict[int, bytes] = field(default_factory=dict)

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        
        header = MACHeader()
        header.decode(stream.read(24))

        if header.type != IEEE80211_FTYPE_MGMT or \
           header.subtype != IEEE80211_STYPE_PROBE_RESP:
            raise ValueError("Frame is not a probe response")
        
        self.target = header.address1
        self.source = header.address2
        self.timestamp = stream.u64()
        self.beacon_interval = stream.u16()
        self.capability_information = stream.u16()
        self.elements = decode_elements(stream.readall())
    
    def encode(self) -> bytes:
        stream = streams.StreamOut("<")
        
        header = MACHeader()
        header.type = IEEE80211_FTYPE_MGMT
        header.subtype = IEEE80211_STYPE_PROBE_RESP
        header.address1 = self.target
        header.address2 = self.source
        header.address3 = self.source
        stream.write(header.encode())
        
        stream.u64(self.timestamp)
        stream.u16(self.beacon_interval)
        stream.u16(self.capability_information)
        stream.write(encode_elements(self.elements))
        return stream.get()


@dataclass
class BeaconFrame:
    source: MACAddress = MACAddress()

    timestamp: int = 0
    beacon_interval: int = 0
    capability_information: int = 0

    elements: dict[int, bytes] = field(default_factory=dict)

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        
        header = MACHeader()
        header.decode(stream.read(24))

        if header.type != IEEE80211_FTYPE_MGMT or \
           header.subtype != IEEE80211_STYPE_BEACON:
            raise ValueError("Frame is not a beacon frame")
        
        self.source = header.address2
        self.timestamp = stream.u64()
        self.beacon_interval = stream.u16()
        self.capability_information = stream.u16()
        self.elements = decode_elements(stream.readall())
        
    def encode(self) -> bytes:
        stream = streams.StreamOut("<")
        
        header = MACHeader()
        header.type = IEEE80211_FTYPE_MGMT
        header.subtype = IEEE80211_STYPE_BEACON
        header.address1 = MACAddress("ff:ff:ff:ff:ff:ff")
        header.address2 = self.source
        header.address3 = self.source
        stream.write(header.encode())
        
        stream.u64(self.timestamp)
        stream.u16(self.beacon_interval)
        stream.u16(self.capability_information)
        stream.write(encode_elements(self.elements))
        return stream.get()


@dataclass
class DisassociationFrame:
    target: MACAddress = MACAddress()
    source: MACAddress = MACAddress()
    bssid: MACAddress = MACAddress()

    reason: int = 0
    elements: dict[int, bytes] = field(default_factory=dict)
    
    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        
        header = MACHeader()
        header.decode(stream.read(24))

        if header.type != IEEE80211_FTYPE_MGMT or \
           header.subtype != IEEE80211_STYPE_DISASSOC:
            raise ValueError("Frame is not a disassociation frame")
        
        self.target = header.address1
        self.source = header.address2
        self.bssid = header.address3

        self.reason = stream.u16()
        self.elements = decode_elements(stream.readall())
    
    def encode(self) -> bytes:
        stream = streams.StreamOut("<")
        
        header = MACHeader()
        header.type = IEEE80211_FTYPE_MGMT
        header.subtype = IEEE80211_STYPE_AUTH
        header.address1 = self.target
        header.address2 = self.source
        header.address3 = self.bssid
        stream.write(header.encode())
        
        stream.u16(self.reason)
        stream.write(encode_elements(self.elements))
        return stream.get()


@dataclass
class AuthenticationFrame:
    target: MACAddress = MACAddress()
    source: MACAddress = MACAddress()
    bssid: MACAddress = MACAddress()

    algorithm: int = 0 
    sequence: int = 0
    status_code: int = WLAN_STATUS_SUCCESS

    elements: dict[int, bytes] = field(default_factory=dict)

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        
        header = MACHeader()
        header.decode(stream.read(24))

        if header.type != IEEE80211_FTYPE_MGMT or \
           header.subtype != IEEE80211_STYPE_AUTH:
            raise ValueError("Frame is not an authentication frame")
        
        self.target = header.address1
        self.source = header.address2
        self.bssid = header.address3
        
        self.algorithm = stream.u16()
        self.sequence = stream.u16()
        self.status_code = stream.u16()
        
        self.elements = decode_elements(stream.readall())
    
    def encode(self) -> bytes:
        stream = streams.StreamOut("<")
        
        header = MACHeader()
        header.type = IEEE80211_FTYPE_MGMT
        header.subtype = IEEE80211_STYPE_AUTH
        header.address1 = self.target
        header.address2 = self.source
        header.address3 = self.bssid
        stream.write(header.encode())
        
        stream.u16(self.algorithm)
        stream.u16(self.sequence)
        stream.u16(self.status_code)
        stream.write(encode_elements(self.elements))
        return stream.get()


@dataclass
class DeauthenticationFrame:
    target: MACAddress = MACAddress()
    source: MACAddress = MACAddress()
    bssid: MACAddress = MACAddress()

    reason: int = 0

    elements: dict[int, bytes] = field(default_factory=dict)

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")

        header = MACHeader()
        header.decode(stream.read(24))

        if header.type != IEEE80211_FTYPE_MGMT or \
           header.subtype != IEEE80211_STYPE_DEAUTH:
            raise ValueError("Frame is not an deauthentication frame")

        self.target = header.address1
        self.source = header.address2
        self.bssid = header.address3

        self.reason = stream.u16()

        self.elements = decode_elements(stream.readall())

    def encode(self) -> bytes:
        stream = streams.StreamOut("<")
        
        header = MACHeader()
        header.type = IEEE80211_FTYPE_MGMT
        header.subtype = IEEE80211_STYPE_DEAUTH
        header.address1 = self.target
        header.address2 = self.source
        header.address3 = self.bssid
        stream.write(header.encode())
        
        stream.u16(self.reason)
        stream.write(encode_elements(self.elements))
        return stream.get()


@dataclass
class ActionFrame:
    source: MACAddress = MACAddress()
    action: bytes = b""

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        
        header = MACHeader()
        header.decode(stream.read(24))

        if header.type != IEEE80211_FTYPE_MGMT or \
           header.subtype != IEEE80211_STYPE_ACTION:
            raise ValueError("Frame is not an action frame")
        
        self.source = header.address2
        
        self.action = stream.readall()
    
    def encode(self) -> bytes:
        header = MACHeader()
        header.type = IEEE80211_FTYPE_MGMT
        header.subtype = IEEE80211_STYPE_ACTION
        header.address1 = MACAddress("ff:ff:ff:ff:ff:ff")
        header.address2 = self.source
        header.address3 = MACAddress("ff:ff:ff:ff:ff:ff")
        
        stream = streams.StreamOut("<")
        stream.write(header.encode())
        stream.write(self.action)
        return stream.get()


@dataclass
class DataFrame:
    target: MACAddress = MACAddress()
    source: MACAddress = MACAddress()
    bssid: MACAddress = MACAddress()

    fromds: bool = False
    tods: bool = False

    protected: bool = False

    nonce: int = 0
    keyid: int = 0

    payload: bytes = b""

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")

        header = MACHeader()
        header.decode(stream.read(24))

        if header.type != IEEE80211_FTYPE_DATA or header.subtype != 0:
            raise ValueError("Frame is not a data frame")
        
        self.tods = bool(header.flags & 1)
        self.fromds = bool(header.flags & 2)
        self.protected = bool(header.flags & 0x40)

        self.target = header.address1
        self.source = header.address2
        self.bssid = header.address3

        # This is a bit ugly, but apparently the driver may decrypt the frame
        # without clearing the protected bit?
        if stream.peek(3) == b"\xAA\xAA\x03":
            self.protected = False

        if self.protected:
            nonce = stream.u16()
            extra = stream.u16()
            nonce |= stream.u32() << 16

            self.nonce = nonce
            self.keyid = (extra >> 14) & 3
            if not extra & 0x2000:
                raise ValueError("Ext IV was expected in protected frame")

        self.payload = stream.readall()

    def encode(self) -> bytes:
        header = MACHeader()
        header.type = IEEE80211_FTYPE_DATA
        header.address1 = self.target
        header.address2 = self.source
        header.address3 = self.bssid
        header.flags = self.tods | (self.fromds << 1) | (self.protected << 6)
        
        stream = streams.StreamOut("<")
        stream.write(header.encode())

        if self.protected:
            extra = 0x2000 | (self.keyid) << 14
            stream.u16(self.nonce & 0xFFFF)
            stream.u16(extra)
            stream.u32(self.nonce >> 16)
        
        stream.write(self.payload)
        return stream.get()

    def decrypt(self, key: bytes) -> None:
        """Decrypts the frame if it is protected."""

        if not self.protected:
            return
        
        ciphertext = self.payload[:-8]
        mac = self.payload[-8:]
        
        aes = AES.new(key, AES.MODE_CCM, nonce=self._nonce(), mac_len=8)
        aes.update(self._aad())
        self.payload = aes.decrypt_and_verify(ciphertext, mac)

        self.protected = False
    
    def encrypt(self, key: bytes, packetno: int, keyid: int) -> None:
        if self.protected:
            raise ValueError("Data frame is already protected")
        
        self.protected = True
        self.nonce = packetno
        self.keyid = keyid
        
        aes = AES.new(key, AES.MODE_CCM, nonce=self._nonce(), mac_len=8)
        aes.update(self._aad())
        ciphertext, mac = aes.encrypt_and_digest(self.payload)
        
        self.payload = ciphertext + mac
    
    def _nonce(self) -> bytes:
        """Returns the nonce that is used for the AES-CCMP algorithm."""
        nonce = b"\0" # Priority
        nonce += self.source.encode()
        nonce += struct.pack(">Q", self.nonce)[2:]
        return nonce
    
    def _aad(self) -> bytes:
        """
        Returns the additional authenticated data for the AES-CCMP algorithm.
        """
        frame_control = IEEE80211_FTYPE_DATA << 2
        frame_control |= self.tods << 8
        frame_control |= self.fromds << 9
        frame_control |= self.protected << 14

        aad = struct.pack("<H", frame_control)
        aad += self.target.encode()
        aad += self.source.encode()
        aad += self.bssid.encode()
        aad += bytes(2) # Fragment number
        return aad


@dataclass
class SNAPHeader:
    oui: int = 0
    protocol: int = 0
    payload: bytes = b""

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, ">")
        if stream.read(3) != b"\xAA\xAA\x03":
            raise ValueError("SNAP extension is required")
        
        self.oui = stream.u24()
        self.protocol = stream.u16()
        self.payload = stream.readall()
    
    def encode(self) -> bytes:
        stream = streams.StreamOut(">")
        stream.write(b"\xAA\xAA\x03")
        stream.u24(self.oui)
        stream.u16(self.protocol)
        stream.write(self.payload)
        return stream.get()


@dataclass
class EthernetFrame:
    target: MACAddress = MACAddress()
    source: MACAddress = MACAddress()
    protocol: int = 0
    payload: bytes = b""

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, ">")
        self.target = MACAddress(stream.read(6))
        self.source = MACAddress(stream.read(6))
        self.protocol = stream.u16()
        self.payload = stream.readall()

    def encode(self) -> bytes:
        stream = streams.StreamOut(">")
        stream.write(self.target.encode())
        stream.write(self.source.encode())
        stream.u16(self.protocol)
        stream.write(self.payload)
        return stream.get()


FrameTypes: dict[int, type[FrameType]] = {
    IEEE80211_STYPE_ASSOC_REQ: AssociationRequest,
    IEEE80211_STYPE_ASSOC_RESP: AssociationResponse,
    IEEE80211_STYPE_PROBE_REQ: ProbeRequest,
    IEEE80211_STYPE_PROBE_RESP: ProbeResponse,
    IEEE80211_STYPE_BEACON: BeaconFrame,
    IEEE80211_STYPE_DISASSOC: DisassociationFrame,
    IEEE80211_STYPE_AUTH: AuthenticationFrame,
    IEEE80211_STYPE_DEAUTH: DeauthenticationFrame,
    IEEE80211_STYPE_ACTION: ActionFrame
}


@dataclass
class AssociationEvent:
    address: MACAddress
        

@dataclass
class DisassociationEvent:
    address: MACAddress


@dataclass
class ActionFrameEvent:
    frame: ActionFrame
    frequency: int


@dataclass
class CustomFrameEvent:
    address: MACAddress
    data: bytes


type EventType = AssociationEvent | DisassociationEvent | ActionFrameEvent | \
    CustomFrameEvent


class Interface:
    """Class that provides common operations for WLAN interfaces."""

    _wlan: nl80211.NL80211
    _router: route.RouteController

    _name: str
    _index: int
    _address: MACAddress | None

    _socket: trio.socket.SocketType

    def __init__(
        self, wlan: nl80211.NL80211, router: route.RouteController, name: str,
        index: int | None = None, address: MACAddress | None = None
    ):
        self._wlan = wlan
        self._router = router
        self._name = name

        if index is None:
            index = socket.if_nametoindex(name)
        self._index = index

        self._address = address

        self._socket = trio.socket.socket()
    
    def disable_ipv6(self) -> None:
        """Disables IPv6 on the interface."""
        filename = f"/proc/sys/net/ipv6/conf/{self._name}/disable_ipv6"
        with open(filename, "w") as f:
            f.write("1")
    
    def name(self) -> str:
        return self._name

    def index(self) -> int:
        return self._index
    
    def address(self) -> MACAddress:
        if self._address is None:
            raise ValueError("This interface does not have a MAC address")
        return self._address
    
    async def up(self) -> None:
        """Marks the interface as 'up', changing it to a running state."""
        await self._router.update_link(
            socket.AF_UNSPEC, 0, self._index, IFF_UP, IFF_UP, {}
        )
    
    async def update_link(self, address: MACAddress) -> None:
        attrs = {
            route.IFLA_ADDRESS: address.encode()
        }
        await self._router.update_link(
            socket.AF_UNSPEC, 0, self._index, 0, 0, attrs
        )
    
    async def add_address(
        self, local: str, broadcast: str, prefix: int = 24
    ) -> None:
        attrs = {
            route.IFA_LOCAL: socket.inet_aton(local),
            route.IFA_BROADCAST: socket.inet_aton(broadcast)
        }
        await self._router.add_address(
            socket.AF_INET, prefix, route.IFA_F_PERMANENT,
            route.RT_SCOPE_UNIVERSE, self._index, attrs
        )
    
    async def add_neighbor(self, ipaddr: str, macaddr: MACAddress) -> None:
        attrs = {
            route.NDA_DST: socket.inet_aton(ipaddr),
            route.NDA_LLADDR: macaddr.encode()
        }
        await self._router.add_neighbor(
            socket.AF_INET, self.index(), route.NUD_PERMANENT, 0, 0, attrs
        )
    
    async def remove_neighbor(self, ipaddr: str, macaddr: MACAddress) -> None:
        attrs = {
            route.NDA_DST: socket.inet_aton(ipaddr),
            route.NDA_LLADDR: macaddr.encode()
        }
        await self._router.remove_neighbor(
            socket.AF_INET, self.index(), route.NUD_PERMANENT, 0, 0, attrs
        )
    
    async def set_channel(self, channel: int) -> None:
        """Changes the channel on which the monitor is active."""

        if channel not in Channels:
            raise ValueError("Invalid channel: %i" %channel)
        
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_WIPHY_FREQ: Channels[channel]
        }
        await self._wlan.request(nl80211.NL80211_CMD_SET_CHANNEL, attrs)
    
    async def _register_frame(self, type: int, match: bytes = b"") -> None:
        """Tells the driver to start listening for a specific frame type."""
        type = (type << 4) | (IEEE80211_FTYPE_MGMT << 2)
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_FRAME_TYPE: type,
            nl80211.NL80211_ATTR_FRAME_MATCH: match
        }
        await self._wlan.request(nl80211.NL80211_CMD_REGISTER_FRAME, attrs)


class Monitor(Interface):
    """
    Represents an interface in monitor mode. This class can be used to send and
    receive raw IEEE 802.11 frames. It also provides utilities such as changing
    channels and filtering based on the BSSID.
    """

    _socket: trio.socket.SocketType

    _filter: MACAddress | None
    _lock: trio.Lock
    
    def __init__(
        self, wlan: nl80211.NL80211, router: route.RouteController, name: str,
        index: int, address: MACAddress
    ):
        super().__init__(wlan, router, name, index, address)

        self._socket = trio.socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
        )

        self._filter = None
        self._lock = trio.Lock()
    
    def set_filter(self, filter: MACAddress | str | None) -> None:
        """This method can be used to filter incoming frames on BSSID."""
        if isinstance(filter, str):
            filter = MACAddress(filter)
        
        self._filter = filter
    
    async def activate(self) -> None:
        """
        Ensures that the raw socket is bound to the underlying interface. This
        method must be called exactly once before radiotap frames can be
        received.
        """
        await self.up()
        await self._socket.bind((self.name(), 0))
    
    async def recv(self) -> RadiotapFrame:
        """
        Waits until a radiotap frame arrives and returns it.

        Note: these frames are not filtered on BSSID. Use recv_frame if you want
        to use filtering.
        """
        while True:
            data = await self._socket.recv(4096)
            radiotap = RadiotapFrame()
            try:
                radiotap.decode(data)
                return radiotap
            except Exception:
                logger.debug("Ignoring invalid radiotap frame")
    
    async def send(self, frame: RadiotapFrame) -> None:
        """Sends a radiotap frame through the underlying interface."""
        await self._socket.send(frame.encode())
    
    async def recv_frame(self) -> FrameType:
        """
        Waits until an IEEE 802.11 frame arrives, parses it and returns it.
        """
        while True:
            radiotap = await self.recv()
            try:
                frame = self._parse_frame(radiotap.data)
                if frame is not None:
                    return frame
            except Exception:
                logger.debug("Ignoring invalid frame")
    
    async def send_frame(self, frame: FrameType) -> None:
        """Sends an IEEE 802.11 through the underlying interface."""
        async with self._lock:
            radiotap = RadiotapFrame(frame.encode())
            await self.send(radiotap)
    
    def _parse_frame(self, data: bytes) -> FrameType | None:
        """
        Parses an IEEE 802.11 frame and returns it. Raises an exception if the
        frame cannot be parsed.
        """
        header = MACHeader()
        header.decode(data)

        # Check BSSID filter
        bssid = header.address3
        if bssid != MACAddress("ff:ff:ff:ff:ff:ff") and \
           self._filter is not None and bssid != self._filter:
            return None
        
        if header.type == IEEE80211_FTYPE_MGMT:
            frame = FrameTypes[header.subtype]()
            frame.decode(data)
            return frame
        elif header.type == IEEE80211_FTYPE_DATA:
            frame = DataFrame()
            frame.decode(data)
            return frame
        else:
            logger.debug("Ignoring unsupported frame type")
            return None


class Station(Interface):
    """Represents an interface in station mode."""

    _ssid: str
    _channel: int
    _key: bytes | None

    _host_address: MACAddress | None

    _events: queue.Queue[EventType]
    
    def __init__(
        self, wlan: nl80211.NL80211, router: route.RouteController, name: str,
        index: int, address: MACAddress, ssid: str, channel: int,
        key: bytes | None
    ):
        super().__init__(wlan, router, name, index, address)
        
        self._ssid = ssid
        self._channel = channel
        self._key = key
        
        self._host_address = None
        
        self._events = queue.create()
    
    async def next_event(self) -> EventType:
        """Blocks until an interesting event occurs and returns it."""
        return await self._events.get()
    
    async def send_custom_frame(self, addr: MACAddress, frame: bytes) -> None:
        """Sends a control port frame to the given address."""
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_FRAME: frame,
            nl80211.NL80211_ATTR_MAC: bytes(addr),
            nl80211.NL80211_ATTR_CONTROL_PORT_ETHERTYPE:
                struct.pack("H", ETH_P_OUI),
        }
        await self._wlan.request(nl80211.NL80211_CMD_CONTROL_PORT_FRAME, attrs)
    
    @contextlib.asynccontextmanager
    async def connect(self) -> AsyncIterator[None]:
        """
        Connects the interface to the network. Blocks until the connection is
        complete, or raises an exception if the connection fails. Disconnects
        from the network when the context manager exits.
        """
        await self.up()
        self.disable_ipv6()
        async with self._connect_network():
            async with util.background_task(self._process_messages):
                await self._register_frame(IEEE80211_STYPE_ACTION)
                yield
    
    async def _register_key(self, key: bytes) -> None:
        """
        Adds the encryption key to the underlying driver:
        * Key index 0 is used for direct frames
        * Key index 1 is used for broadcast frames

        TODO: figure out if direct frames are ever used by the Nintendo Switch,
        and if yes, should we create a new key for each station separately?
        """
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_MAC: self._host_address,
            nl80211.NL80211_ATTR_KEY: {
                nl80211.NL80211_KEY_IDX: 0,
                nl80211.NL80211_KEY_DATA: key,
                nl80211.NL80211_KEY_CIPHER: WLAN_CIPHER_SUITE_CCMP
            }
        }
        await self._wlan.request(nl80211.NL80211_CMD_NEW_KEY, attrs)
        
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_KEY: {
                nl80211.NL80211_KEY_IDX: 1,
                nl80211.NL80211_KEY_DATA: key,
                nl80211.NL80211_KEY_CIPHER: WLAN_CIPHER_SUITE_CCMP
            }
        }
        await self._wlan.request(nl80211.NL80211_CMD_NEW_KEY, attrs)
    
    @contextlib.asynccontextmanager
    async def _connect_network(self) -> AsyncIterator[None]:
        """
        Joins the network through the underlying driver. Blocks until the
        network has been joined. Raises an exception if the network could not be
        joined.

        The network is disconnected when the context manager exits.
        """

        rsn = RSNElement(
            group_cipher_suite = WLAN_CIPHER_SUITE_CCMP,
            pairwise_cipher_suites = [WLAN_CIPHER_SUITE_CCMP],
            akm_suites = [WLAN_AKM_SUITE_PSK],
            capabilities = 12
        )
        
        elements = {
            WLAN_EID_RSN: rsn.encode()
        }
        
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_SSID: self._ssid.encode(),
            nl80211.NL80211_ATTR_WIPHY_FREQ: Channels[self._channel],
            nl80211.NL80211_ATTR_AUTH_TYPE:
                nl80211.NL80211_AUTHTYPE_OPEN_SYSTEM,
            
            nl80211.NL80211_ATTR_CONTROL_PORT: True,
            nl80211.NL80211_ATTR_CONTROL_PORT_ETHERTYPE:
                struct.pack("H", ETH_P_OUI),
            nl80211.NL80211_ATTR_CONTROL_PORT_OVER_NL80211: True,
            nl80211.NL80211_ATTR_SOCKET_OWNER: True
        }

        if self._key is not None:
            attrs[nl80211.NL80211_ATTR_CIPHER_SUITES_PAIRWISE] = \
                struct.pack("I", WLAN_CIPHER_SUITE_CCMP)
            attrs[nl80211.NL80211_ATTR_CIPHER_SUITE_GROUP] = \
                WLAN_CIPHER_SUITE_CCMP
            attrs[nl80211.NL80211_ATTR_AKM_SUITES] = \
                struct.pack("I", WLAN_AKM_SUITE_PSK)
            attrs[nl80211.NL80211_ATTR_IE] = encode_elements(elements)
            attrs[nl80211.NL80211_ATTR_PRIVACY] = True
        else:
            # If no key is provided, the frames are not encrypted.
            attrs[nl80211.NL80211_ATTR_PRIVACY] = False

        await self._wlan.request(nl80211.NL80211_CMD_CONNECT, attrs)
        
        while True:
            message = await self._wlan.receive()
            if message.type == nl80211.NL80211_CMD_CONNECT:
                status = message.attributes[nl80211.NL80211_ATTR_STATUS_CODE]
                if status != WLAN_STATUS_SUCCESS:
                    error = f"Connect failed with status code {status}"
                    raise ConnectionError(error)
                break
        
        try:
            self._host_address = message.attributes[nl80211.NL80211_ATTR_MAC]
            if self._key is not None:
                await self._register_key(self._key)
            yield
        finally:
            attrs = {nl80211.NL80211_ATTR_IFINDEX: self.index()}
            await self._wlan.request(nl80211.NL80211_CMD_DISCONNECT, attrs)
    
    async def _process_messages(self) -> None:
        """
        Processes messages from the underlying driver and adds interesting
        events to the event queue.
        """
        while True:
            message = await self._wlan.receive()
            if message.type == nl80211.NL80211_CMD_FRAME:
                frame = ActionFrame()
                frame.decode(message.attributes[nl80211.NL80211_ATTR_FRAME])
                freq = message.attributes[nl80211.NL80211_ATTR_WIPHY_FREQ]
                await self._events.put(ActionFrameEvent(frame, freq))
            elif message.type == nl80211.NL80211_CMD_CONTROL_PORT_FRAME:
                mac = MACAddress(message.attributes[nl80211.NL80211_ATTR_MAC])
                data = message.attributes[nl80211.NL80211_ATTR_FRAME]
                await self._events.put(CustomFrameEvent(mac, data))
            elif message.type == nl80211.NL80211_CMD_DEL_STATION:
                mac = MACAddress(message.attributes[nl80211.NL80211_ATTR_MAC])
                await self._events.put(DisassociationEvent(mac))
    
    async def set_authorized(self) -> None:
        """
        Marks the interface as being authorized.

        TODO: when there are more participants in the network, should we mark
        them as authorized as well?
        """
        flag = 1 << nl80211.NL80211_STA_FLAG_AUTHORIZED
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_MAC: self._host_address,
            nl80211.NL80211_ATTR_STA_FLAGS2: struct.pack("II", flag, flag)
        }
        await self._wlan.request(nl80211.NL80211_CMD_SET_STATION, attrs)


class AccessPoint(Interface):
    """This class represents a access point interface."""

    _interface: Interface

    _ssid: str
    _channel: int
    _key: bytes | None
    _max_stations: int

    _stations_by_id: dict[int, MACAddress]
    _stations_by_address: dict[MACAddress, int]
    
    _events: queue.Queue[EventType]
    
    def __init__(
        self, wlan: nl80211.NL80211, router: route.RouteController, ifname: str,
        index: int, address: MACAddress, ssid: str, channel: int,
        key: bytes | None, max_stations: int
    ):
        super().__init__(wlan, router, ifname, index, address)

        self._ssid = ssid
        self._channel = channel
        self._key = key
        self._max_stations = max_stations
        
        self._stations_by_id = {}
        self._stations_by_address = {}
        
        self._events = queue.create()

    async def next_event(self):
        """Blocks until an interesting event occurs and returns it."""
        return await self._events.get()
    
    @contextlib.asynccontextmanager
    async def create(self) -> AsyncIterator[None]:
        """
        Starts an access point on the underlying interface. The access point is
        stopped when the context manager exits.
        """
        await self.up()
        self.disable_ipv6()
        for type in [
            IEEE80211_STYPE_ASSOC_REQ,
            IEEE80211_STYPE_PROBE_REQ,
            IEEE80211_STYPE_DISASSOC,
            IEEE80211_STYPE_AUTH,
            IEEE80211_STYPE_DEAUTH
        ]:
            await self._register_frame(type)
        async with self._start_ap():
            async with util.background_task(self._process_messages):
                yield
    
    async def send_custom_frame(self, addr: MACAddress, frame: bytes) -> None:
        """Transmits a control port frame through the underlying interface."""
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_FRAME: frame,
            nl80211.NL80211_ATTR_MAC: bytes(addr),
            nl80211.NL80211_ATTR_CONTROL_PORT_ETHERTYPE:
                struct.pack("H", ETH_P_OUI)
        }
        await self._wlan.request(nl80211.NL80211_CMD_CONTROL_PORT_FRAME, attrs)
    
    async def remove_station(self, addr: MACAddress) -> None:
        """Removes the station with the given address from the network."""

        if addr not in self._stations_by_address: return
        
        aid = self._stations_by_address.pop(addr)
        del self._stations_by_id[aid]
        
        frame = DeauthenticationFrame()
        frame.source = self.address()
        frame.target = addr
        frame.bssid = self.address()
        frame.reason = WLAN_REASON_UNSPECIFIED
        await self.send_frame(frame.encode())
        
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_MAC: addr.encode(),
            nl80211.NL80211_ATTR_REASON_CODE: WLAN_REASON_UNSPECIFIED
        }
        await self._wlan.request(nl80211.NL80211_CMD_DEL_STATION, attrs)
    
    def _create_beacon_head(self) -> bytes:
        """Creates and encodes a beacon frame for transmission."""
        frame = BeaconFrame()
        frame.source = self.address()
        frame.beacon_interval = 100
        frame.capability_information = 0x511
        return frame.encode()
    
    def _create_beacon_tail(self) -> bytes:
        """Returns the beacon tail."""
        return b"" # No beacon tail for now
    
    def _create_probe_response(self, address: MACAddress) -> bytes:
        """Creates and encodes a probe response frame for the given address."""

        supported_rates = [0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C]

        ssid = SSIDElement(self._ssid)
        rates = SuppRatesElement(supported_rates)
        dsparams = DSParamsElement(self._channel)

        rsn = RSNElement(
            group_cipher_suite = WLAN_CIPHER_SUITE_CCMP,
            pairwise_cipher_suites = [WLAN_CIPHER_SUITE_CCMP],
            akm_suites = [WLAN_AKM_SUITE_PSK],
            capabilities = 12
        )
        
        response = ProbeResponse()
        response.source = self.address()
        response.target = address
        response.beacon_interval = 100
        response.capability_information = 0x501
        response.elements = {
            WLAN_EID_SSID: ssid.encode(),
            WLAN_EID_SUPP_RATES: rates.encode(),
            WLAN_EID_DS_PARAMS: dsparams.encode(),
        }
        if self._key is not None:
            response.capability_information |= 0x10
            response.elements[WLAN_EID_RSN] = rsn.encode()
        return response.encode()
    
    def _create_association_response(
        self, address: MACAddress, aid: int
    ) -> bytes:
        """
        Creates and encodes an association response frame with the given address
        and association id. The association response indicates success.
        """

        supported_rates = [0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C]
        
        rates = SuppRatesElement(supported_rates)
        
        response = AssociationResponse()
        response.source = self.address()
        response.target = address
        response.capability_information = 0x411
        response.status_code = WLAN_STATUS_SUCCESS
        response.aid = aid | 0xC000
        response.elements = {
            WLAN_EID_SUPP_RATES: rates.encode()
        }
        return response.encode()
    
    def _create_association_error(
        self, address: MACAddress, error: int
    ) -> bytes:
        """
        Creates and encodes an association response frame with the given address
        for an error situation.
        """
        response = AssociationResponse()
        response.source = self.address()
        response.target = address
        response.capability_information = 0x411
        response.status_code = error
        response.aid = 0
        return response.encode()
    
    def _parse_management_frame(self, data: bytes) -> FrameType:
        header = MACHeader()
        header.decode(data)

        frame = FrameTypes[header.subtype]()
        frame.decode(data)
        return frame
    
    @contextlib.asynccontextmanager
    async def _start_ap(self) -> AsyncIterator[None]:
        """
        Sends the nl80211 messages that are required to create an IBSS.
        The IBSS is destroyed when the context manager exits.
        """
        beacon_head = self._create_beacon_head()
        beacon_tail = self._create_beacon_tail()
        
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_SSID: self._ssid.encode(),
            nl80211.NL80211_ATTR_MAC: self.address().encode(),
            nl80211.NL80211_ATTR_WIPHY_FREQ: Channels[self._channel],
            nl80211.NL80211_ATTR_BEACON_HEAD: beacon_head,
            nl80211.NL80211_ATTR_BEACON_TAIL: beacon_tail,
            nl80211.NL80211_ATTR_BEACON_INTERVAL: 100,
            nl80211.NL80211_ATTR_DTIM_PERIOD: 3,
            nl80211.NL80211_ATTR_HIDDEN_SSID:
                nl80211.NL80211_HIDDEN_SSID_ZERO_CONTENTS,
            nl80211.NL80211_ATTR_CONTROL_PORT: True,
            nl80211.NL80211_ATTR_CONTROL_PORT_ETHERTYPE:
                struct.pack("H", ETH_P_OUI),
            nl80211.NL80211_ATTR_CONTROL_PORT_OVER_NL80211: True,
            nl80211.NL80211_ATTR_SOCKET_OWNER: True
        }

        await self._wlan.request(nl80211.NL80211_CMD_START_AP, attrs)

        # Wait until the AP is ready
        while True:
            message = await self._wlan.receive()
            if message.type == nl80211.NL80211_CMD_START_AP:
                break

        if self._key is not None:
            attrs = {
                nl80211.NL80211_ATTR_IFINDEX: self.index(),
                nl80211.NL80211_ATTR_KEY: {
                    nl80211.NL80211_KEY_IDX: 1,
                    nl80211.NL80211_KEY_DATA: self._key,
                    nl80211.NL80211_KEY_CIPHER: WLAN_CIPHER_SUITE_CCMP
                }
            }
            await self._wlan.request(nl80211.NL80211_CMD_NEW_KEY, attrs)

            attrs = {
                nl80211.NL80211_ATTR_IFINDEX: self.index(),
                nl80211.NL80211_ATTR_KEY: {
                    nl80211.NL80211_KEY_IDX: 1,
                    nl80211.NL80211_KEY_DEFAULT: True,
                    nl80211.NL80211_KEY_DEFAULT_TYPES: {
                        nl80211.NL80211_KEY_DEFAULT_TYPE_MULTICAST: True
                    }
                }
            }
            await self._wlan.request(nl80211.NL80211_CMD_SET_KEY, attrs)
        
        try:
            yield
        finally:
            attrs = {nl80211.NL80211_ATTR_IFINDEX: self.index()}
            await self._wlan.request(nl80211.NL80211_CMD_STOP_AP, attrs)
    
    async def _process_messages(self):
        """
        Processes messages from the underlying driver and adds interesting
        events to the event queue.
        """
        while True:
            message = await self._wlan.receive()
            if message.type == nl80211.NL80211_CMD_FRAME:
                data = message.attributes[nl80211.NL80211_ATTR_FRAME]
                try:
                    frame = self._parse_management_frame(data)
                except Exception:
                    continue # Ignore invalid frames
                await self._process_frame(frame)
            elif message.type == nl80211.NL80211_CMD_CONTROL_PORT_FRAME:
                address = MACAddress(message.attributes[nl80211.NL80211_ATTR_MAC])
                data = message.attributes[nl80211.NL80211_ATTR_FRAME]
                await self._events.put(CustomFrameEvent(address, data))
    
    async def _process_frame(self, frame: FrameType) -> None:
        """
        Handles an incoming management frame.
        """
        if isinstance(frame, ProbeRequest):
            ssid = frame.elements.get(WLAN_EID_SSID)
            if ssid == self._ssid.encode():
                probe_response = self._create_probe_response(frame.source)
                await self.send_frame(probe_response)
        elif isinstance(frame, AuthenticationFrame):
            if frame.bssid == self.address():
                if frame.algorithm == WLAN_AUTH_OPEN and frame.sequence == 1:
                    auth_response = AuthenticationFrame()
                    auth_response.source = self.address()
                    auth_response.target = frame.source
                    auth_response.bssid = self.address()
                    auth_response.algorithm = WLAN_AUTH_OPEN
                    auth_response.sequence = 2
                    auth_response.status_code = WLAN_STATUS_SUCCESS
                    await self.send_frame(auth_response.encode())
        elif isinstance(frame, AssociationRequest):
            ssid = frame.elements.get(WLAN_EID_SSID)
            if ssid == self._ssid.encode():
                response = await self._process_association_request(frame)
                await self.send_frame(response)
        elif isinstance(frame, (DisassociationFrame, DeauthenticationFrame)):
            await self._process_disassociation(frame)
    
    async def _process_association_request(
        self, frame: AssociationRequest
    ) -> bytes:
        """
        Processes an incoming association request and returns the encoded
        response.
        """

        # If the station is already connected, we simply return the existing
        # association id.
        if frame.source in self._stations_by_address:
            aid = self._stations_by_address[frame.source]
            return self._create_association_response(frame.source, aid)
        
        # Send an error if the network is full.
        if len(self._stations_by_id) >= self._max_stations:
            return self._create_association_error(
                frame.source, WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA
            )
        
        if WLAN_EID_SUPP_RATES not in frame.elements:
            return self._create_association_error(
                frame.source, WLAN_STATUS_ASSOC_DENIED_UNSPEC
            )
        
        # Allocate an association id and add the station to our internal table.
        aid = 1
        while aid in self._stations_by_id:
            aid += 1
        
        self._stations_by_id[aid] = frame.source
        self._stations_by_address[frame.source] = aid
        
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_MAC: bytes(frame.source),
            nl80211.NL80211_ATTR_STA_LISTEN_INTERVAL: frame.listen_interval,
            nl80211.NL80211_ATTR_STA_SUPPORTED_RATES:
                frame.elements[WLAN_EID_SUPP_RATES],
            nl80211.NL80211_ATTR_STA_CAPABILITY: frame.capability_information,
            nl80211.NL80211_ATTR_STA_AID: aid
        }
        if WLAN_EID_EXT_CAPABILITY in frame.elements:
            attrs[nl80211.NL80211_ATTR_STA_EXT_CAPABILITY] = \
                frame.elements[WLAN_EID_EXT_CAPABILITY]
        if WLAN_EID_HT_CAPABILITY in frame.elements:
            attrs[nl80211.NL80211_ATTR_HT_CAPABILITY] = \
                frame.elements[WLAN_EID_HT_CAPABILITY]
        if WLAN_EID_SUPPORTED_CHANNELS in frame.elements:
            attrs[nl80211.NL80211_ATTR_STA_SUPPORTED_CHANNELS] = \
                frame.elements[WLAN_EID_SUPPORTED_CHANNELS]
        await self._wlan.request(nl80211.NL80211_CMD_NEW_STATION, attrs)
        
        if self._key is not None:
            attrs = {
                nl80211.NL80211_ATTR_IFINDEX: self.index(),
                nl80211.NL80211_ATTR_MAC: frame.source.encode(),
                nl80211.NL80211_ATTR_KEY: {
                    nl80211.NL80211_KEY_IDX: 0,
                    nl80211.NL80211_KEY_DATA: self._key,
                    nl80211.NL80211_KEY_CIPHER: WLAN_CIPHER_SUITE_CCMP
                }
            }
            await self._wlan.request(nl80211.NL80211_CMD_NEW_KEY, attrs)
        
        await self._events.put(AssociationEvent(frame.source))
        return self._create_association_response(frame.source, aid)
    
    async def _process_disassociation(
        self, frame: DisassociationFrame | DeauthenticationFrame
    ) -> None:
        """Processes an incoming disassociation or deauthentication frame."""

        if frame.source not in self._stations_by_address: return
        
        aid = self._stations_by_address.pop(frame.source)
        del self._stations_by_id[aid]

        subtype = IEEE80211_STYPE_DISASSOC
        if isinstance(frame, DeauthenticationFrame):
            subtype = IEEE80211_STYPE_DEAUTH

        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_MAC: frame.source.encode(),
            nl80211.NL80211_ATTR_MGMT_SUBTYPE: subtype,
            nl80211.NL80211_ATTR_REASON_CODE: frame.reason
        }
        await self._wlan.request(nl80211.NL80211_CMD_DEL_STATION, attrs)
        
        await self._events.put(DisassociationEvent(frame.source))
    
    async def send_frame(self, data: bytes) -> None:
        """Sends a management frame."""
        attrs = {
            nl80211.NL80211_ATTR_IFINDEX: self.index(),
            nl80211.NL80211_ATTR_FRAME: data
        }
        await self._wlan.request(nl80211.NL80211_CMD_FRAME, attrs)


class Tap(Interface):
    _file: trio._file_io.AsyncIOWrapper

    def __init__(
        self, wlan: nl80211.NL80211, router: route.RouteController, ifname: str,
        address: MACAddress, file: trio._file_io.AsyncIOWrapper
    ):
        super().__init__(wlan, router, ifname, address=address)
        self._file = file
    
    async def write(self, data: bytes) -> None:
        await self._file.write(data)
    
    async def read(self) -> bytes:
        return await self._file.read(4096)


class Factory:
    """Acts as a factory for WLAN Interfaces"""

    _wlan: nl80211.NL80211
    _router: route.RouteController
    
    def __init__(self, wlan: nl80211.NL80211, router: route.RouteController):
        self._wlan = wlan
        self._wlan.add_membership("mlme")

        self._router = router
    
    @contextlib.asynccontextmanager
    async def create_monitor(
        self, phyname: str, ifname: str, channel: int | None = None
    ) -> AsyncIterator[Monitor]:
        """
        Creates an interface in monitor mode on the given phy with the given
        name. If a channel is provided, the phy is immediately switched to the
        given channel.
        """
        flags = {
            nl80211.NL80211_ATTR_MNTR_FLAGS: {
                nl80211.NL80211_MNTR_FLAG_OTHER_BSS: True
            }
        }
        async with self._create_interface(
            phyname, ifname, nl80211.NL80211_IFTYPE_MONITOR, flags
        ) as attributes:
            index = attributes[nl80211.NL80211_ATTR_IFINDEX]
            address = MACAddress(attributes[nl80211.NL80211_ATTR_MAC])
            
            monitor = Monitor(self._wlan, self._router, ifname, index, address)
            await monitor.activate()
            yield monitor
    
    @contextlib.asynccontextmanager
    async def connect_network(
        self, phyname: str, ifname: str, ssid: str, channel: int,
        key: bytes | None
    ) -> AsyncIterator[Station]:
        """
        Creates an interface in station mode and connects it to the given SSID.
        """
        async with self._create_interface(
            phyname, ifname, nl80211.NL80211_IFTYPE_STATION
        ) as attributes:
            index = attributes[nl80211.NL80211_ATTR_IFINDEX]
            address = MACAddress(attributes[nl80211.NL80211_ATTR_MAC])

            sta = Station(
                self._wlan, self._router, ifname, index, address, ssid, channel,
                key
            )
            async with sta.connect():
                yield sta
    
    @contextlib.asynccontextmanager
    async def create_ap(
        self, phyname: str, ifname: str, ssid: str, channel: int,
        key: bytes | None, max_stations: int
    ) -> AsyncIterator[AccessPoint]:
        """
        Creates an interface in IBSS mode with the given SSID.
        """
        async with self._create_interface(
            phyname, ifname, nl80211.NL80211_IFTYPE_AP
        ) as attributes:
            index = attributes[nl80211.NL80211_ATTR_IFINDEX]
            address = MACAddress(attributes[nl80211.NL80211_ATTR_MAC])

            ibss = AccessPoint(
                self._wlan, self._router, ifname, index, address, ssid, channel,
                key, max_stations
            )
            async with ibss.create():
                yield ibss
    
    @contextlib.asynccontextmanager
    async def create_tap(
        self, ifname: str, address: MACAddress
    ) -> AsyncIterator[Tap]:
        file = await trio.open_file("/dev/net/tun", "rb+", buffering=0)
        async with file:
            request = struct.pack("16sH", ifname.encode(), IFF_TAP | IFF_NO_PI)
            fcntl.ioctl(file.fileno(), TUNSETIFF, request)

            tap = Tap(self._wlan, self._router, ifname, address, file)
            await tap.update_link(address)
            await tap.up()
            yield tap
    
    @contextlib.asynccontextmanager
    async def _create_interface(
        self, phyname: str, ifname: str, type: int,
        extra: dict[int, typing.Any] = {}
    ) -> AsyncIterator[dict[int, typing.Any]]:
        """
        Creates an interface on the given phy, with the given name, type and
        additional attributes.

        The interface is deleted when the context manager exits.

        Returns the attributes of the newly created interface.
        """
        wiphy = await self._get_wiphy_index(phyname)

        attrs = {
            nl80211.NL80211_ATTR_WIPHY: wiphy,
            nl80211.NL80211_ATTR_IFNAME: ifname,
            nl80211.NL80211_ATTR_IFTYPE: type,
        }
        attrs.update(extra)
        
        messages = await self._wlan.request(
            nl80211.NL80211_CMD_NEW_INTERFACE, attrs
        )
        attributes = messages[0].attributes
        index = attributes[nl80211.NL80211_ATTR_IFINDEX]
        try:
            yield attributes
        finally:
            attrs = {nl80211.NL80211_ATTR_IFINDEX: index}
            await self._wlan.request(nl80211.NL80211_CMD_DEL_INTERFACE, attrs)
    
    async def _get_wiphy_index(self, name: str) -> int:
        """Returns the PHY index with the given name."""
        messages = await self._wlan.request(
            nl80211.NL80211_CMD_GET_WIPHY, flags=netlink.NLM_F_DUMP
        )
        for message in messages:
            if message.attributes[nl80211.NL80211_ATTR_WIPHY_NAME] == name:
                return message.attributes[nl80211.NL80211_ATTR_WIPHY]
        raise ValueError(f"No wiphy found with name '{name}'")


@contextlib.asynccontextmanager
async def create_factory() -> AsyncIterator[Factory]:
    """
    Establishes an nl80211 connection with the kernel and returns a factory for
    wireless interfaces.
    """
    async with nl80211.connect() as wlan:
        async with route.connect() as router:
            yield Factory(wlan, router)
