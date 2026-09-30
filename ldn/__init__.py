
"""
Provides an implementation of the LDN protocol. This protocol facilitates local
wireless communication between Nintendo Switch consoles.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from Crypto.Cipher import AES

from ldn import streams, wlan, queue, util

from dataclasses import dataclass, field

import contextlib
import copy
import hashlib
import hmac
import os
import random
import secrets
import socket
import struct
import trio
import typing

import logging
logger = logging.getLogger(__name__)


MACAddress = wlan.MACAddress


# Station accept policy
ACCEPT_ALL = 0
ACCEPT_NONE = 1
ACCEPT_BLACKLIST = 2
ACCEPT_WHITELIST = 3

# Advertisement frame format
ADVERTISE_FORMAT_PLAIN = 1
ADVERTISE_FORMAT_AES_CTR = 2
ADVERTISE_FORMAT_AES_GCM = 3

# Authentication status code
AUTH_SUCCESS = 0
AUTH_DENIED_BY_POLICY = 1
AUTH_MALFORMED_REQUEST = 2
AUTH_TIMEOUT = 3
AUTH_INVALID_VERSION = 4
AUTH_UNEXPECTED = 5
AUTH_CHALLENGE_FAILURE = 6

# Authentication frame format
AUTH_FORMAT_PLAIN = 0
AUTH_FORMAT_AES_GCM = 1

# Disconnect reason
DISCONNECT_NETWORK_DESTROYED = 3
DISCONNECT_NETWORK_DESTROYED_FORCEFULLY = 4
DISCONNECT_STATION_REJECTED_BY_HOST = 5
DISCONNECT_CONNECTION_LOST = 6

# Platform type
PLATFORM_NX = 0
PLATFORM_OUNCE = 1

# Security mode
SECURITY_MODE_PROD = 1 # Everything is encrypted
SECURITY_MODE_DEBUG = 2 # Advertisement frames are encrypted, data frames not
SECURITY_MODE_SYSTEM_DEBUG = 3 # No advertisement or data frames are encrypted


# This key is used for the HMAC algorithm in the authentication challenge.
CHALLENGE_KEY = bytes.fromhex(
    "f84b487fb37251c263bf11609036589266af70ca79b44c93c7370c5769c0f602"
)
CHALLENGE_KEY_DEV = bytes.fromhex(
    "5a0fbfb5b5c5a2733439401b3d46938343f5d2f494224a7c007b61eaacbc1f20"
)


ChannelBands = {
    1: 2,
    6: 2,
    11: 2,
    36: 5,
    40: 5,
    44: 5,
    48: 5,
}


def load_keys(path: str) -> dict[str, bytes]:
    """Loads encryption keys from a prod.keys file."""
    path = os.path.expanduser(path)

    with open(path) as f:
        lines = f.readlines()

    keys = {}
    for line in lines:
        line = line.strip()
        if line:
            name, key = line.split("=")
            keys[name.strip()] = bytes.fromhex(key)
    return keys


class AuthenticationError(Exception):
    """Represents an error that occurred during authentication."""

    status_code: int

    def __init__(self, status_code: int):
        self.status_code = status_code
    
    def __str__(self):
        return f"Authentication failed with status {self.status_code}"


class KeyDerivation:
    """Implements key derivation for the LDN protocol."""

    _keys: dict[str, bytes]
    _protocol: int

    _override_advertise_key: bytes | None
    _override_data_key: bytes | None
    _override_challenge_key: bytes | None

    def __init__(
        self, keys: dict[str, bytes], protocol: int, *,
        override_advertise_key: bytes | None = None,
        override_data_key: bytes | None = None,
        override_challenge_key: bytes | None = None
    ):
        """
        Initializes key derivation with the given encryption keys and protocol
        version. It is also possible to supply pre-derived keys through the
        override_advertise_key and override_data_key arguments.
        """
        self._keys = keys
        self._protocol = protocol

        self._override_advertise_key = override_advertise_key
        self._override_data_key = override_data_key
        self._override_challenge_key = override_challenge_key
    
    def _decrypt_key(self, key: bytes, kek: bytes) -> bytes:
        """Decrypts a key with AES-ECB."""
        aes = AES.new(kek, AES.MODE_ECB)
        return aes.decrypt(key)
    
    def _select_master_key(self) -> bytes:
        """Returns the master key for the active protocol version."""
        if self._protocol == 1:
            return self._keys["master_key_00"]
        elif self._protocol == 3:
            return self._keys["master_key_12"]
    
        raise ValueError(
            f"Key derivation for protocol version {self._protocol} is not " \
            "supported"
        )
    
    def _derive_key(self, data: bytes, source: bytes) -> bytes:
        """Derives an encryption key from the provided data and source."""

        aes_kek_generation_source = self._keys["aes_kek_generation_source"]
        aes_key_generation_source = self._keys["aes_key_generation_source"]

        key = self._select_master_key()
        key = self._decrypt_key(aes_kek_generation_source, key)
        key = self._decrypt_key(source, key)
        key = self._decrypt_key(aes_key_generation_source, key)
        return self._decrypt_key(hashlib.sha256(data).digest()[:16], key)
    
    def derive_authentication_key(self, client_random: bytes) -> bytes:
        """Derives the key that is used for authentication frames."""
        source = bytes.fromhex("f1e7018419a84f711da714c2cf919c9c")
        return self._derive_key(client_random, source)
    
    def derive_data_key(self, server_random: bytes, password: bytes) -> bytes:
        """Derives the key that is used for data frames."""
        if self._override_data_key:
            return self._override_data_key
        
        source = bytes.fromhex("f1e7018419a84f711da714c2cf919c9c")
        return self._derive_key(server_random + password, source)
    
    def derive_advertise_key(self, data: bytes) -> bytes:
        """Derives the key that is used for advertisement frames."""
        if self._override_advertise_key:
            return self._override_advertise_key
        
        source = bytes.fromhex("191884743e24c77d87c69e4207d0c438")
        return self._derive_key(data, source)
    
    def challenge_key(self, dev: bool) -> bytes:
        """Returns the HMAC key for the authentication challenge."""
        if self._override_challenge_key:
            return self._override_challenge_key
        
        return CHALLENGE_KEY_DEV if dev else CHALLENGE_KEY


@dataclass
class NetworkId:
    """
    A 32-byte struct that contains the local communication id, game mode and
    SSID of the network.
    """

    local_communication_id: int = 0
    scene_id: int = 0
    ssid: bytes = bytes(16)
    
    def encode(self, endianness: str) -> bytes:
        """Encodes the network id with the given endianness."""
        stream = streams.StreamOut(endianness)
        stream.u64(self.local_communication_id)
        stream.pad(2)
        stream.u16(self.scene_id)
        stream.pad(4)
        stream.write(self.ssid)
        return stream.get()
    
    def decode(self, data: bytes, endianness: str) -> None:
        """Decodes the network id from the given data and endianness."""
        stream = streams.StreamIn(data, endianness)
        self.local_communication_id = stream.u64()
        stream.pad(2)
        self.scene_id = stream.u16()
        stream.pad(4)
        self.ssid = stream.read(16)


@dataclass
class ParticipantInfo:
    """Holds information about a node in the network."""

    ip_address: str = "0.0.0.0"
    mac_address: MACAddress = MACAddress()
    connected: bool = False
    name: bytes = b""
    app_version: int = 0
    platform: int = PLATFORM_NX


@dataclass
class AdvertisementInfo:
    server_random: bytes = bytes(16)
    security_mode: int = SECURITY_MODE_PROD
    station_accept_policy: int = ACCEPT_ALL

    app_version: int = 0

    # Band and channel were added in 20.0.0
    band: int = 0
    channel: int = 0

    max_participants: int = 0
    num_participants: int = 0
    participants: list[ParticipantInfo] = field(default_factory=list)
    application_data: bytes = b""

    # The challenge was added in 6.0.0
    challenge: int = 0


class AdvertisementInfoEncoder(typing.Protocol):
    def encode(self, info: AdvertisementInfo) -> bytes:
        ...
    
    def decode(self, data: bytes) -> AdvertisementInfo:
        ...


class AdvertisementInfoEncoderV1:
    """
    Advertisement encoder when AES-CTR or plaintext encryption is used
    """

    def encode(self, info: AdvertisementInfo) -> bytes:
        stream = streams.StreamOut(">")
        stream.write(info.server_random)
        stream.u16(info.security_mode)
        stream.u8(info.station_accept_policy)
        stream.pad(1)
        stream.u16((info.band << 10) | info.channel)
        stream.u8(info.max_participants)
        stream.u8(info.num_participants)

        for participant in info.participants:
            name = participant.name
            stream.write(socket.inet_aton(participant.ip_address))
            stream.write(bytes(participant.mac_address))
            stream.bool(participant.connected)
            stream.u8(participant.platform)
            stream.write(name + b"\0" * (32 - len(name)))
            stream.u16(participant.app_version)
            stream.pad(10)
        
        padding = b"\0" * (384 - len(info.application_data))
        
        stream.pad(2)
        stream.u16(len(info.application_data))
        stream.write(info.application_data + padding)
        stream.pad(412)
        stream.u64(info.challenge)
        return stream.get()
    
    def decode(self, data: bytes) -> AdvertisementInfo:
        stream = streams.StreamIn(data, ">")

        info = AdvertisementInfo()
        info.server_random = stream.read(16)
        info.security_mode = stream.u16()
        info.station_accept_policy = stream.u8()
        stream.pad(1)

        value = stream.u16()
        info.band = value >> 10
        info.channel = value & 0x3FF

        info.max_participants = stream.u8()
        info.num_participants = stream.u8()
        
        info.participants = []
        for i in range(8):
            participant = ParticipantInfo()
            participant.ip_address = socket.inet_ntoa(stream.read(4))
            participant.mac_address = MACAddress(stream.read(6))
            participant.connected = stream.bool()
            participant.platform = stream.u8()
            participant.name = stream.read(32).rstrip(b"\0")
            participant.app_version = stream.u16()
            stream.pad(10)
            info.participants.append(participant)
        
        info.app_version = info.participants[0].app_version
        
        stream.pad(2)
        
        beacon_size = stream.u16()
        beacon_data = stream.read(384)
        info.application_data = beacon_data[:beacon_size]
        
        stream.pad(412)
        
        info.challenge = stream.u64()
        return info


class AdvertisementInfoEncoderV2:
    """
    Advertisement encoder when AES-GCM encryption is used
    """

    def encode(self, info: AdvertisementInfo) -> bytes:
        stream = streams.StreamOut(">")
        stream.write(info.server_random)
        stream.u64(info.challenge)
        stream.u8(info.security_mode)
        stream.u8(info.station_accept_policy)
        stream.u16(info.app_version)
        stream.pad(8)
        stream.u16((info.band << 10) | info.channel)
        stream.u8(info.max_participants)
        stream.u8(info.num_participants)

        for index, participant in enumerate(info.participants):
            if participant.connected:
                name = participant.name
                stream.write(socket.inet_aton(participant.ip_address))
                stream.write(bytes(participant.mac_address))
                stream.u8(index)
                stream.u8(participant.platform)
                stream.write(name + b"\0" * (32 - len(name)))
                stream.pad(4)
        
        stream.u16(len(info.application_data))
        stream.write(info.application_data)
        return stream.get()
    
    def decode(self, data: bytes) -> AdvertisementInfo:
        stream = streams.StreamIn(data, ">")

        info = AdvertisementInfo()
        info.server_random = stream.read(16)
        info.challenge = stream.u64()
        info.security_mode = stream.u8()
        info.station_accept_policy = stream.u8()
        info.app_version = stream.u16()
        stream.pad(8)
        
        value = stream.u16()
        info.band = value >> 10
        info.channel = value & 0x3FF

        info.max_participants = stream.u8()
        info.num_participants = stream.u8()
        
        info.participants = [ParticipantInfo() for i in range(8)]
        for i in range(info.num_participants):
            participant = ParticipantInfo()
            participant.ip_address = socket.inet_ntoa(stream.read(4))
            participant.mac_address = MACAddress(stream.read(6))
            index = stream.u8()
            participant.platform = stream.u8()
            participant.name = stream.read(32).rstrip(b"\0")
            stream.pad(4)

            participant.connected = True
            participant.app_version = info.app_version

            if index < len(info.participants):
                info.participants[index] = participant
        
        info.application_data = stream.read(stream.u16())
        return info


class AdvertisementFrame:
    """Represents an advertisement frame."""

    _key_derivation: KeyDerivation
    _protocol: int

    network_id: NetworkId
    version: int
    format: int
    nonce: bytes
    payload: AdvertisementInfo

    def __init__(self, key_derivation: KeyDerivation, protocol: int):
        self._key_derivation = key_derivation
        self._protocol = protocol

        self.network_id = NetworkId()
        self.version = 0
        self.format = ADVERTISE_FORMAT_AES_GCM
        self.nonce = b""
        self.payload = AdvertisementInfo()

    def _derive_key(self) -> bytes:
        """Derives the key that is used to encrypt the advertisement frame."""
        data = self.network_id.encode(">")
        return self._key_derivation.derive_advertise_key(data)
    
    def _encrypt_aes_ctr(self, payload: bytes) -> bytes:
        key = self._derive_key()
        aes = AES.new(key, AES.MODE_CTR, nonce=self.nonce)
        return aes.encrypt(payload)
    
    def _encrypt_aes_gcm(self, header: bytes, payload: bytes) -> bytes:
        key = self._derive_key()
        nonce = self.nonce + bytes(8)
        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        aes.update(header)
        payload, mac = aes.encrypt_and_digest(payload)
        return mac + payload
    
    def _decrypt_aes_ctr(self, payload: bytes) -> bytes:
        key = self._derive_key()
        aes = AES.new(key, AES.MODE_CTR, nonce=self.nonce)
        return aes.decrypt(payload)
    
    def _decrypt_aes_gcm(self, header: bytes, payload: bytes) -> bytes:
        key = self._derive_key()
        nonce = self.nonce + bytes(8)
        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        aes.update(header)
        return aes.decrypt_and_verify(payload[16:], payload[:16])
    
    def _make_payload_encoder(self) -> AdvertisementInfoEncoder:
        if self.format == ADVERTISE_FORMAT_AES_GCM:
            return AdvertisementInfoEncoderV2()
        return AdvertisementInfoEncoderV1()
    
    def encode(self) -> bytes:
        stream = streams.StreamOut(">")
        stream.u8(0x7F) # Vendor-specific
        stream.u24(0x0022AA) # Nintendo
    
        stream.u8(4) # LDN
        stream.pad(1)
        stream.u16(0x101) # Advertisement frame
        stream.pad(4)

        encoder = self._make_payload_encoder()
        plaintext = encoder.encode(self.payload)
        plaintext_len = len(plaintext)

        substream = streams.StreamOut(">")
        substream.write(self.network_id.encode(">"))
        substream.u8(self.version)
        substream.u8(self.format)
        substream.u16(plaintext_len)
        substream.write(self.nonce)
        header = substream.get()

        # A SHA-256 is added before the payload in plain and AES-CTR mode
        if self.format in [ADVERTISE_FORMAT_PLAIN, ADVERTISE_FORMAT_AES_CTR]:
            data = header + bytes(32) + plaintext
            sha = hashlib.sha256(data).digest()
            plaintext = sha + plaintext
        
        if self.format == ADVERTISE_FORMAT_PLAIN:
            ciphertext = plaintext
        elif self.format == ADVERTISE_FORMAT_AES_CTR:
            ciphertext = self._encrypt_aes_ctr(plaintext)
        elif self.format == ADVERTISE_FORMAT_AES_GCM:
            ciphertext = self._encrypt_aes_gcm(header, plaintext)
        else:
            raise ValueError("An invalid advertisement format was specified")
        
        stream.write(header)
        stream.write(ciphertext)
        return stream.get()
    
    def decode(self, data: bytes) -> None:
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
        
        self.network_id = NetworkId()
        self.network_id.decode(stream.read(32), ">")
        
        self.version = stream.u8()
        if self.version not in [2, 3, 4]:
            raise ValueError("Advertisement frame has unsupported version number")
        
        self.format = stream.u8()

        expected_format = ADVERTISE_FORMAT_AES_CTR
        if self._protocol != 1:
            expected_format = ADVERTISE_FORMAT_AES_GCM
        
        if self.format not in [ADVERTISE_FORMAT_PLAIN, expected_format]:
            message = "Advertisement frame has invalid encryption algorithm " \
                "for the current protocol"
            raise ValueError(message)
        
        size = stream.u16()

        if self.format in [ADVERTISE_FORMAT_PLAIN, ADVERTISE_FORMAT_AES_CTR]:
            if size != 0x500:
                message = "Advertisement frame has unexpected size field"
                raise ValueError(message)
        
        self.nonce = stream.read(4)

        if self.format == ADVERTISE_FORMAT_PLAIN:
            plaintext = stream.read(32 + size)
        elif self.format == ADVERTISE_FORMAT_AES_CTR:
            plaintext = self._decrypt_aes_ctr(stream.read(32 + size))
        elif self.format == ADVERTISE_FORMAT_AES_GCM:
            plaintext = self._decrypt_aes_gcm(header, stream.read(16 + size))
        else:
            message = "Advertisement frame has invalid encryption algorithm"
            raise ValueError(message)
        
        if self.format in [ADVERTISE_FORMAT_PLAIN, ADVERTISE_FORMAT_AES_CTR]:
            sha = plaintext[:32]
            plaintext = plaintext[32:]
            data = header + bytes(32) + plaintext
            if hashlib.sha256(data).digest() != sha:
                raise ValueError("Advertisement frame has wrong SHA-256 hash")

        encoder = self._make_payload_encoder()
        self.payload = encoder.decode(plaintext)
        

@dataclass
class ChallengeRequest:
    flags: int = 0
    token: int = 0
    nonce: int = 0
    device_id: int = 0

    unk: bytes = bytes(16) # Only present on Switch 2
    params1: list[int] = field(default_factory=list)
    params2: list[int] = field(default_factory=list)
    
    def encode(self, key: bytes) -> bytes:
        stream = streams.StreamOut("<")
        stream.u8(0) # Always 0
        stream.u8(0) # Always 0
        stream.u8(len(self.params1))
        stream.u8(len(self.params2))
        stream.u8(self.flags)
        stream.pad(3)
        
        stream.u64(self.token)
        stream.u64(self.nonce)
        stream.u64(self.device_id)
        stream.write(self.unk)

        stream.pad(0x60)
        
        stream.repeat(self.params1, stream.u64)
        stream.pad(8 * (8 - len(self.params1)))
        
        stream.repeat(self.params2, stream.u64)
        stream.pad(8 * (64 - len(self.params2)))
        
        body = stream.get()
        
        mac = hmac.digest(key, body, "sha256")
        
        stream = streams.StreamOut("<")
        stream.u32(0)
        stream.write(mac)
        stream.pad(12)
        stream.write(body)
        
        return stream.get()
    
    def decode(self, data: bytes, key: bytes) -> None:
        if len(data) != 0x300:
            raise ValueError("Challenge request has wrong size")
        
        stream = streams.StreamIn(data, "<")
        stream.pad(4)
        mac = stream.read(32)
        stream.pad(12)
        body = stream.read(0x2D0)

        if mac != hmac.digest(key, body, "sha256"):
            raise ValueError("Challenge request has wrong HMAC")
        
        stream = streams.StreamIn(body, "<")
        stream.pad(2)
        n1 = stream.u8()
        n2 = stream.u8()
        self.flags = stream.u8()
        stream.pad(3)
        
        self.token = stream.u64()
        self.nonce = stream.u64()
        self.device_id = stream.u64()
        self.unk = stream.read(16)
        
        stream.pad(0x60)
        
        self.params1 = stream.repeat(stream.u64, 8)[:n1]
        self.params2 = stream.repeat(stream.u64, 8)[:n2]


@dataclass
class ChallengeResponse:
    flags: int = 0
    nonce: int = 0
    device_id: int = 0
    device_id_host: int = 0

    unk: bytes = bytes(16)
    unk_host: bytes = bytes(16)
    
    def encode(self, key: bytes) -> bytes:
        stream = streams.StreamOut("<")
        stream.u8(0) # Always 0
        stream.u8(0) # Always 0
        stream.pad(2)
        stream.u32(self.flags)
        stream.u64(self.nonce)
        stream.u64(self.device_id)
        stream.u64(self.device_id_host)
        stream.write(self.unk)
        stream.write(self.unk_host)
        stream.pad(0x90)
        
        body = stream.get()
    
        mac = hmac.digest(key, body, "sha256")
        
        stream = streams.StreamOut("<")
        stream.u32(0)
        stream.write(mac)
        stream.pad(12)
        stream.write(body)
        return stream.get()
    
    def decode(self, data: bytes, key: bytes) -> None:
        if len(data) != 0x100:
            raise ValueError("Challenge response has wrong size")
        
        stream = streams.StreamIn(data, "<")
        stream.pad(4)
        mac = stream.read(32)
        stream.pad(12)
        body = stream.read(0xD0)
        
        if mac != hmac.digest(key, body, "sha256"):
            raise ValueError("Challenge response has wrong HMAC")
        
        stream = streams.StreamIn(body, "<")
        stream.pad(4)
        self.flags = stream.u32()
        self.nonce = stream.u64()
        self.device_id = stream.u64()
        self.device_id_host = stream.u64()
        self.unk = stream.read(16)
        self.unk_host = stream.read(16)
        stream.pad(0x90)


@dataclass
class AuthenticationRequest:
    username: bytes = b""
    app_version: int = 0
    platform: int = PLATFORM_NX
    challenge: bytes = b""

    def encode(self, version: int) -> bytes:
        stream = streams.StreamOut(">")
        
        name = self.username
        stream.write(name + b"\0" * (32 - len(name)))
        stream.u16(self.app_version)
        stream.u8(self.platform)
        stream.pad(29)
        
        if version >= 3:
            stream.pad(0x24)
            if self.challenge is not None:
                stream.write(self.challenge)
        return stream.get()
    
    def decode(self, data: bytes, version: int) -> None:
        stream = streams.StreamIn(data, ">")
        
        self.username = stream.read(32).rstrip(b"\0")
        self.app_version = stream.u16()
        self.platform = stream.u8()
        stream.pad(29)
        
        if version >= 3:
            stream.pad(0x24)
            if not stream.eof():
                self.challenge = stream.read(0x300)


@dataclass
class AuthenticationResponse:
    platform: int = PLATFORM_NX
    challenge: bytes = b""

    def encode(self, version: int) -> bytes:
        stream = streams.StreamOut(">")
        if version >= 3:
            stream.u8(self.platform)
            stream.pad(0x83)
            if self.challenge is not None:
                stream.write(self.challenge)
        return stream.get()
    
    def decode(self, data: bytes, version: int) -> None:
        stream = streams.StreamIn(data, ">")
        if version >= 3:
            self.platform = stream.u8()
            stream.pad(0x83)
            if not stream.eof():
                self.challenge = stream.read(0x100)


class AuthenticationFrame:
    _key_derivation: KeyDerivation
    _protocol: int

    version: int
    status_code: int
    network_id: NetworkId
    server_random: bytes
    client_random: bytes
    payload: AuthenticationRequest | AuthenticationResponse

    def __init__(self, key_derivation: KeyDerivation, protocol: int):
        self._key_derivation = key_derivation
        self._protocol = protocol

        self.version = 0
        self.status_code = 0
        self.network_id = NetworkId()
        self.server_random = bytes(16)
        self.client_random = bytes(16)
        self.payload = AuthenticationRequest()

    def _encrypt_aes_gcm(
        self, header: bytes, payload: bytes
    ) -> tuple[bytes, bytes]:
        key = self._key_derivation.derive_authentication_key(self.client_random)

        aes = AES.new(key, AES.MODE_GCM, nonce=header[:12])
        aes.update(header)

        return aes.encrypt_and_digest(payload)

    def _decrypt_aes_gcm(
        self, header: bytes, payload: bytes, tag: bytes
    ) -> bytes:
        key = self._key_derivation.derive_authentication_key(self.client_random)

        aes = AES.new(key, AES.MODE_GCM, nonce=header[:12])
        aes.update(header)

        return aes.decrypt_and_verify(payload, tag)
    
    def _expected_format(self) -> int:
        if self._protocol == 1:
            return AUTH_FORMAT_PLAIN
        return AUTH_FORMAT_AES_GCM

    def encode(self) -> bytes:
        payload = self.payload.encode(self.version)
        
        stream = streams.StreamOut(">")
        stream.u24(0x0022AA) # Nintendo
        stream.u16(0x102) # Authentication frame
        stream.pad(1)

        substream = streams.StreamOut(">")
        substream.u8(self.version)
        substream.u8(len(payload) & 0xFF)
        substream.u8(self.status_code)
        substream.u8(isinstance(self.payload, AuthenticationResponse))
        substream.u8(len(payload) >> 8)
        substream.u8(self._expected_format())
        substream.pad(2)
        
        substream.write(self.network_id.encode("<"))
        substream.write(self.server_random)
        substream.write(self.client_random)

        header = substream.get()
        stream.write(header)

        if self._protocol == 3:
            payload, tag = self._encrypt_aes_gcm(header, payload)
            stream.write(tag)

        stream.write(payload)
        return stream.get()
    
    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, ">")
        if stream.u24() != 0x0022AA:
            raise ValueError("Data frame has wrong OUI")
        if stream.u16() != 0x102:
            raise ValueError("Data frame is not an authentication frame")
        stream.pad(1)

        header = stream.peek(0x48)

        self.version = stream.u8()
        size_lo = stream.u8()
        self.status_code = stream.u8()
        is_response = stream.u8()
        size_hi = stream.u8()
        format = stream.u8()
        stream.pad(2)

        if format != self._expected_format():
            raise ValueError("Authentication frame has wrong format for the current protocol")

        self.network_id = NetworkId()
        self.network_id.decode(stream.read(32), "<")

        self.server_random = stream.read(16)
        self.client_random = stream.read(16)

        tag = b""
        if format == AUTH_FORMAT_AES_GCM:
            tag = stream.read(16)

        size = (size_hi << 8) | size_lo
        if stream.available() != size:
            raise ValueError("Authentication frame has wrong size")
        
        if is_response:
            self.payload = AuthenticationResponse()
        else:
            self.payload = AuthenticationRequest()

        data = stream.read(size)
        if format == AUTH_FORMAT_AES_GCM:
            data = self._decrypt_aes_gcm(header, data, tag)
        
        self.payload.decode(data, self.version)


@dataclass
class DisconnectFrame:
    reason: int = 0
    
    def encode(self) -> bytes:
        stream = streams.StreamOut(">")
        stream.u24(0x0022AA) # Nintendo
        stream.u16(0x103) # Disconnect frame
        stream.pad(1)
        
        stream.u8(self.reason)
        stream.pad(31)
        return stream.get()
    
    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, ">")
        if stream.u24() != 0x0022AA:
            raise ValueError("Data frame has wrong OUI")
        if stream.u16() != 0x103:
            raise ValueError("Data frame is not a disconnect frame")
        stream.pad(1)
        
        self.reason = stream.u8()
        stream.pad(31)


@dataclass
class NetworkInfo:
    protocol: int

    address: MACAddress = MACAddress()
    band: int = 0
    channel: int = 0

    local_communication_id: int = 0
    scene_id: int = 0
    ssid: bytes = bytes(16)

    version: int = 0
    server_random: bytes = bytes(16)
    security_mode: int = SECURITY_MODE_PROD

    app_version: int = 0

    accept_policy: int = ACCEPT_ALL
    max_participants: int = 0
    num_participants: int = 0
    participants: list[ParticipantInfo] = field(default_factory=list)
    application_data: bytes = b""

    challenge: int = 0

    nonce: bytes = b""

    def is_same_network(self, other: NetworkInfo) -> bool:
        if self.address != other.address: return False
        if self.band != other.band: return False
        if self.channel != other.channel: return False

        if self.local_communication_id != other.local_communication_id:
            return False
        if self.scene_id != other.scene_id: return False
        if self.ssid != other.ssid: return False

        if self.version != other.version: return False
        if self.server_random != other.server_random: return False
        if self.security_mode != other.security_mode: return False

        return True
    
    def parse_advertisement(self, frame: AdvertisementFrame) -> None:
        self.local_communication_id = frame.network_id.local_communication_id
        self.scene_id = frame.network_id.scene_id
        self.ssid = frame.network_id.ssid

        self.version = frame.version
        self.server_random = frame.payload.server_random
        self.security_mode = frame.payload.security_mode

        self.app_version = frame.payload.app_version

        self.accept_policy = frame.payload.station_accept_policy
        self.max_participants = frame.payload.max_participants
        self.num_participants = frame.payload.num_participants
        self.participants = frame.payload.participants
        self.application_data = frame.payload.application_data
        
        self.challenge = frame.payload.challenge
        self.nonce = frame.nonce
    
    def build_advertisement(
        self, key_derivation: KeyDerivation
    ) -> AdvertisementFrame:
        network_id = NetworkId()
        network_id.local_communication_id = self.local_communication_id
        network_id.scene_id = self.scene_id
        network_id.ssid = self.ssid
        
        info = AdvertisementInfo()
        info.server_random = self.server_random
        info.security_mode = self.security_mode
        info.station_accept_policy = self.accept_policy
        info.app_version = self.app_version

        info.band = self.band
        info.channel = self.channel

        info.max_participants = self.max_participants
        info.num_participants = self.num_participants
        info.participants = self.participants
        info.application_data = self.application_data
        info.challenge = self.challenge
        
        frame = AdvertisementFrame(key_derivation, self.protocol)
        frame.network_id = network_id
        frame.version = self.version

        frame.format = ADVERTISE_FORMAT_PLAIN
        if self.security_mode != SECURITY_MODE_SYSTEM_DEBUG:
            if self.protocol == 1:
                frame.format = ADVERTISE_FORMAT_AES_CTR
            else:
                frame.format = ADVERTISE_FORMAT_AES_GCM

        frame.nonce = self.nonce
        frame.payload = info
        return frame


@dataclass
class ConnectNetworkParam:
    ifname: str = "ldn"
    phyname: str = "phy0"

    network: NetworkInfo = field(default_factory=lambda: NetworkInfo(1))
    password: bytes = b""

    name: bytes = b""
    app_version: int = 0
    platform: int = PLATFORM_NX

    enable_challenge: bool = True
    device_id: int = \
        field(default_factory=lambda: random.randint(0, 0xFFFFFFFFFFFFFFFF))

    client_random: bytes | None = None

    keys: dict[str, bytes] = field(default_factory=dict)
    dev: bool = False

    override_data_key: bytes | None = None
    override_advertise_key: bytes | None = None
    override_challenge_key: bytes | None = None

    def check(self) -> None:
        if self.network.address == MACAddress():
            raise ValueError("network is invalid")

        if self.network.version not in [2, 3, 4]:
            raise ValueError("Network version not supported")
        
        if not self.keys:
            raise ValueError("keys are required")


@dataclass
class CreateNetworkParam:
    ifname: str = "ldn"
    ifname_active: str = "ldn-ack"
    ifname_tap: str = "ldn-tap"
    phyname: str = "phy0"

    local_communication_id: int = 0
    scene_id: int = 0

    max_participants: int = 8
    application_data: bytes = b""
    accept_policy: int = ACCEPT_ALL
    accept_filter: list[MACAddress] = field(default_factory=list)
    security_mode: int = SECURITY_MODE_PROD
    ssid: bytes | None = None

    name: bytes = b""
    app_version: int = 0
    platform: int = PLATFORM_NX

    channel: int | None = None
    server_random: bytes | None = None
    password: bytes = b""

    version: int = 4
    enable_challenge: bool = True
    device_id: int = \
        field(default_factory=lambda: random.randint(0, 0xFFFFFFFFFFFFFFFF))

    protocol: int = 1
    
    keys: dict[str, bytes] = field(default_factory=dict)
    dev: bool = False

    override_data_key: bytes | None = None
    override_advertise_key: bytes | None = None
    override_challenge_key: bytes | None = None

    def check(self):
        if self.max_participants > 8:
            raise ValueError("max_participants is too high")

        if len(self.application_data) > 0x180:
            raise ValueError("application_data is too large")

        if self.ssid is not None and len(self.ssid) != 16:
            raise ValueError("ssid has wrong size")

        if self.channel is not None and not wlan.is_valid_channel(self.channel):
            raise ValueError("channel is invalid")
        
        if self.server_random is not None and len(self.server_random) != 16:
            raise ValueError("server_random has wrong size")
        
        if self.version not in [2, 3, 4]:
            raise ValueError("version is invalid")
        
        if self.protocol not in [1, 3]:
            raise ValueError("protocol is not supported")
        
        if not self.keys:
            raise ValueError("keys are required")


@dataclass
class DisconnectEvent:
    reason: int

@dataclass
class JoinEvent:
    index: int
    participant: ParticipantInfo

@dataclass
class LeaveEvent:
    index: int
    participant: ParticipantInfo

@dataclass
class ApplicationDataChanged:
    old: bytes
    new: bytes

@dataclass
class AcceptPolicyChanged:
    old: int
    new: int


type EventType = DisconnectEvent | JoinEvent | LeaveEvent | \
    ApplicationDataChanged | AcceptPolicyChanged


class Scanner:
    _protocols: dict[int, KeyDerivation]
    _monitor: wlan.Monitor

    def __init__(self, protocols: dict[int, KeyDerivation], monitor: wlan.Monitor):
        self._protocols = protocols

        self._monitor = monitor
        self._monitor.set_filter("ff:ff:ff:ff:ff:ff")
    
    async def receive(self) -> NetworkInfo:
        # Vendor-specific, Nintendo OUI, LDN, Advertisement
        header = bytes([0x7F, 0x00, 0x22, 0xAA, 0x04, 0x00, 0x01, 0x01])
        while True:
            # Receive a single frame
            radiotap = await self._monitor.recv()

            if radiotap.frequency is None:
                logger.warning("Expected frequency attribute in radiotap frame")
                continue
            
            action = wlan.ActionFrame()
            try: action.decode(radiotap.data)
            except Exception:
                continue # Skip invalid frames

            # Check if we received an advertisement frame from LDN
            if not action.action.startswith(header):
                continue
            
            # Decode the frame itself
            for protocol, key_derivation in self._protocols.items():
                frame = AdvertisementFrame(key_derivation, protocol)
                try: frame.decode(action.action)
                except Exception:
                    continue # Skip invalid frames
                
                info = NetworkInfo(protocol)
                info.address = action.source
                info.channel = wlan.map_frequency(radiotap.frequency)
                info.band = ChannelBands[info.channel]
                info.parse_advertisement(frame)
                return info
            
            logger.warning("Failed to parse advertisement frame, ignoring it")

    async def scan(
        self, channels: list[int], dwell_time: float
    ) -> list[NetworkInfo]:
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
                await self._monitor.set_channel(channel)
                await trio.sleep(dwell_time)
        return networks

        
class STANetwork:
    _interface: wlan.Station
    _param: ConnectNetworkParam
    _key_derivation: KeyDerivation

    _network: NetworkInfo
    _keys: dict[str, bytes]

    _events: queue.Queue[EventType]
    _advertisements: queue.Queue[NetworkInfo]

    _network_id: int
    _participant_id: int

    def __init__(self,
        interface: wlan.Station, param: ConnectNetworkParam,
        key_derivation: KeyDerivation, 
    ):
        self._interface = interface
        self._param = param
        self._key_derivation = key_derivation

        self._network = param.network
        self._keys = param.keys
        
        self._events = queue.create()
        self._advertisements = queue.create()
        
        self._network_id = 0
        self._participant_id = 0
    
    def _check_authentication_response(
        self, address: MACAddress, data: bytes
    ) -> bool:
        if address != self._network.address: return False
        
        frame = AuthenticationFrame(
            self._key_derivation, self._network.protocol
        )
        try:
            frame.decode(data)
        except Exception:
            logger.warning("Failed to parse authentication response")
            return False
        
        if not isinstance(frame.payload, AuthenticationResponse): return False
        
        if frame.network_id.local_communication_id != \
            self._network.local_communication_id: return False
        if frame.network_id.scene_id != self._network.scene_id: return False
        if frame.network_id.ssid != self._network.ssid: return False
        
        if frame.server_random != self._network.server_random: return False
        if frame.client_random != self._param.client_random: return False
        
        if frame.status_code != 0:
            raise AuthenticationError(frame.status_code)
        
        return True
    
    def info(self) -> NetworkInfo:
        return self._network
    
    def participant(self) -> ParticipantInfo:
        return self._network.participants[self._participant_id]
    
    def broadcast_address(self) -> str:
        return f"169.254.{self._network_id}.255"
    
    async def next_event(self) -> EventType:
        return await self._events.get()
    
    @contextlib.asynccontextmanager
    async def start(self) -> AsyncGenerator[None]:
        await self._authenticate()
        async with util.background_task(self._process_events):
            await self._initialize_network()
            async with util.background_task(self._monitor_network):
                yield
    
    async def _process_events(self) -> None:
        while True:
            event = await self._interface.next_event()

            if isinstance(event, wlan.ActionFrameEvent):
                if event.frame.source != self._network.address:
                    continue # Only process frames from the host
                
                frame = AdvertisementFrame(
                    self._key_derivation, self._network.protocol
                )
                try: frame.decode(event.frame.action)
                except Exception:
                    continue # Skip invalid frames
                
                info = NetworkInfo(self._network.protocol)
                info.address = event.frame.source
                info.channel = wlan.map_frequency(event.frequency)
                info.band = ChannelBands[info.channel]
                info.parse_advertisement(frame)

                if not self._network.is_same_network(info):
                    raise ConnectionError(
                        "Received incompatible advertisement frame from host"
                    )
                
                await self._advertisements.put(info)
            
            elif isinstance(event, wlan.CustomFrameEvent):
                disconnect_frame = DisconnectFrame()
                disconnect_frame.decode(event.data)
                await self._events.put(DisconnectEvent(disconnect_frame.reason))
            
            elif isinstance(event, wlan.DisassociationEvent):
                disconnection = DisconnectEvent(DISCONNECT_CONNECTION_LOST)
                await self._events.put(disconnection)
    
    async def _authenticate(self) -> None:
        assert self._param.client_random is not None
        
        request = AuthenticationRequest()
        request.username = self._param.name
        request.app_version = self._param.app_version
        request.platform = self._param.platform
        
        if self._param.enable_challenge:
            challenge = ChallengeRequest()
            challenge.flags = 0
            challenge.token = self._network.challenge
            challenge.nonce = random.randint(0, 0xFFFFFFFFFFFFFFFF)
            challenge.device_id = self._param.device_id
            request.challenge = challenge.encode(
                self._key_derivation.challenge_key(self._param.dev)
            )
        
        network_id = NetworkId()
        network_id.local_communication_id = self._network.local_communication_id
        network_id.scene_id = self._network.scene_id
        network_id.ssid = self._network.ssid
        
        frame = AuthenticationFrame(
            self._key_derivation, self._network.protocol
        )
        frame.version = self._network.version
        frame.status_code = 0
        frame.network_id = network_id
        frame.server_random = self._network.server_random
        frame.client_random = self._param.client_random
        frame.payload = request
        
        # Attempt authentication up to three times
        for i in range(3):
            await self._interface.send_custom_frame(
                self._network.address, frame.encode()
            )
            
            # Resend the authentication request if we do not
            # receive a response after 700 milliseconds
            with trio.move_on_after(.7):
                while True:
                    event = await self._interface.next_event()
                    if isinstance(event, wlan.CustomFrameEvent):
                        if self._check_authentication_response(
                            event.address, event.data
                        ):
                            return
                    elif isinstance(event, wlan.DisassociationEvent):
                        raise ConnectionError("Station was disassociated")
        raise ConnectionError("Authentication timeout (password may be wrong)")
    
    async def _wait_for_network(self) -> tuple[NetworkInfo, int]:
        while True:
            network = await self._advertisements.get()
            for index, participant in enumerate(network.participants):
                if participant.mac_address == self._interface.address():
                    return network, index
    
    async def _initialize_network(self) -> None:
        await self._interface.set_authorized()
        
        # Wait until the host has updated the advertisement frame
        network = None
        with trio.move_on_after(1):
            network, index = await self._wait_for_network()
        
        if network is None:
            raise ConnectionError(
                "Failed to obtain IP address after joining network (timeout)"
            )
        
        # Initialize local state
        self._network = network
        self._network_id = int(network.participants[0].ip_address.split(".")[2])
        self._participant_id = index
        
        # Initialize interface address
        local_address = network.participants[index].ip_address
        broadcast_address = f"169.254.{self._network_id}.255"
        await self._interface.add_address(local_address, broadcast_address)
        
        # Create a static neighbor entry for each participant
        for participant in network.participants:
            if participant.connected:
                await self._interface.add_neighbor(
                    participant.ip_address, participant.mac_address
                )
    
    async def _monitor_network(self) -> None:
        # Monitors advertisement frames to get
        # notified when the network changes
        while True:
            network = await self._advertisements.get()
            
            # Check if the accept policy has changed
            if network.accept_policy != self._network.accept_policy:
                accept_policy_event = AcceptPolicyChanged(
                    self._network.accept_policy, network.accept_policy
                )
                await self._events.put(accept_policy_event)
            
            # Check if the application data has changed
            if network.application_data != self._network.application_data:
                app_data_event = ApplicationDataChanged(
                    self._network.application_data, network.application_data
                )
                await self._events.put(app_data_event)
            
            # Remove participants that are gone
            for i in range(8):
                old = self._network.participants[i]
                new = network.participants[i]
                if old.connected and old.mac_address != new.mac_address:
                    await self._interface.remove_neighbor(
                        old.ip_address, old.mac_address
                    )
                    await self._events.put(LeaveEvent(i, old))
            
            # Register new participants
            for i in range(8):
                old = self._network.participants[i]
                new = network.participants[i]
                if new.connected and old.mac_address != new.mac_address:
                    await self._interface.add_neighbor(
                        new.ip_address, new.mac_address
                    )
                    await self._events.put(JoinEvent(i, new))
            
            # Update local state
            self._network = network


class APNetwork:
    _interface: wlan.MonitorAP
    _tap: wlan.Tap

    _param: CreateNetworkParam
    _key_derivation: KeyDerivation

    _accept_filter: list[MACAddress]
    _enable_challenge: bool
    _device_id: int
    _platform: int

    _advert_nonce: int
    _network_id: int

    _network: NetworkInfo
    _peers: list[MACAddress]

    _events: queue.Queue[EventType]

    def __init__(
        self, access_point: wlan.MonitorAP, tap: wlan.Tap,
        param: CreateNetworkParam, key_derivation: KeyDerivation
    ):
        assert param.channel is not None
        assert param.ssid is not None
        assert param.server_random is not None

        self._interface = access_point
        self._tap = tap

        self._param = param
        self._key_derivation = key_derivation
        
        self._accept_filter = param.accept_filter
        self._enable_challenge = param.enable_challenge
        self._device_id = param.device_id
        self._platform = param.platform
        
        self._advert_nonce = random.randint(0, 0xFFFFFFFF)
        self._network_id = random.randint(1, 127)
        
        participant = ParticipantInfo()
        participant.ip_address = f"169.254.{self._network_id}.1"
        participant.mac_address = access_point.address()
        participant.connected = True
        participant.name = param.name
        participant.app_version = param.app_version
        participant.platform = param.platform
        
        participants = [participant]
        for i in range(7):
            participants.append(ParticipantInfo())
        
        self._network = NetworkInfo(param.protocol)
        self._network.address = access_point.address()
        self._network.channel = param.channel
        self._network.band = ChannelBands[param.channel]
        self._network.local_communication_id = param.local_communication_id
        self._network.scene_id = param.scene_id
        self._network.ssid = param.ssid
        self._network.version = param.version
        self._network.server_random = param.server_random
        self._network.security_mode = param.security_mode
        self._network.accept_policy = param.accept_policy
        self._network.max_participants = param.max_participants
        self._network.num_participants = 1
        self._network.participants = participants
        self._network.application_data = param.application_data
        self._network.app_version = param.app_version
        self._network.challenge = 0
        if param.enable_challenge:
            self._network.challenge = random.randint(0, 0xFFFFFFFFFFFFFFFF)
        self._network.nonce = struct.pack(">I", self._advert_nonce)
        self._network.protocol = param.protocol

        self._peers = []

        self._events = queue.create()
    
    def info(self) -> NetworkInfo:
        return self._network
    
    def participant(self) -> ParticipantInfo:
        return self._network.participants[0]
    
    def broadcast_address(self) -> str:
        return f"169.254.{self._network_id}.255"
    
    def set_application_data(self, data: bytes) -> None:
        self._network.application_data = data
        self._update_nonce()
    
    def set_accept_policy(self, policy: int) -> None:
        self._network.accept_policy = policy
        self._update_nonce()
    
    def set_accept_filter(self, filter: list[MACAddress]) -> None:
        self._accept_filter = filter
        
    async def kick(self, index: int) -> None:
        participant = self._network.participants[index]
        if participant.connected:
            frame = DisconnectFrame()
            frame.reason = DISCONNECT_STATION_REJECTED_BY_HOST
            await self._send_control_frame(
                participant.mac_address, frame.encode()
            )
            await self._interface.remove_station(participant.mac_address)
            await self._process_disassociation(participant.mac_address)
    
    async def next_event(self) -> EventType:
        return await self._events.get()
    
    @contextlib.asynccontextmanager
    async def start(self) -> AsyncGenerator[None]:
        await self._initialize_network()
        async with util.create_nursery() as nursery:
            nursery.start_soon(self._process_events)
            nursery.start_soon(self._send_advertisements)
            nursery.start_soon(self._receive_data_frames)
            nursery.start_soon(self._transmit_data_frames)
            yield
            await self._destroy_network()
    
    def _make_authentication_response(
        self, status: int, version: int, client_random: bytes,
        challenge: bytes = b""
    ) -> AuthenticationFrame:
        network_id = NetworkId()
        network_id.local_communication_id = self._network.local_communication_id
        network_id.scene_id = self._network.scene_id
        network_id.ssid = self._network.ssid
        
        response = AuthenticationResponse()
        response.platform = self._platform
        response.challenge = challenge
        
        frame = AuthenticationFrame(self._key_derivation, self._param.protocol)
        frame.version = version
        frame.status_code = status
        frame.network_id = network_id
        frame.server_random = self._network.server_random
        frame.client_random = client_random
        frame.payload = response
        return frame
    
    def _check_accept_policy(self, address: MACAddress) -> bool:
        if self._network.accept_policy == ACCEPT_ALL: return True
        if self._network.accept_policy == ACCEPT_NONE: return False
        if self._network.accept_policy == ACCEPT_BLACKLIST:
            return address not in self._accept_filter
        if self._network.accept_policy == ACCEPT_WHITELIST:
            return address in self._accept_filter
        return False
    
    def _check_authentication_request(
        self, address: MACAddress, frame: AuthenticationFrame
    ) -> int:
        if frame.version not in [2, 3, 4]: return AUTH_INVALID_VERSION
        
        if frame.status_code != 0: return AUTH_MALFORMED_REQUEST
        if frame.network_id.local_communication_id != \
            self._network.local_communication_id: return AUTH_MALFORMED_REQUEST
        if frame.network_id.scene_id != self._network.scene_id:
            return AUTH_MALFORMED_REQUEST
        if frame.network_id.ssid != self._network.ssid:
            return AUTH_MALFORMED_REQUEST
        if frame.server_random != self._network.server_random:
            return AUTH_MALFORMED_REQUEST

        if not isinstance(frame.payload, AuthenticationRequest):
            return AUTH_MALFORMED_REQUEST
        
        if not self._check_accept_policy(address):
            return AUTH_DENIED_BY_POLICY
        
        return AUTH_SUCCESS
    
    def _process_authentication_challenge(
        self, challenge: bytes
    ) -> bytes | None:
        if not self._enable_challenge: return b""

        challenge_key = self._key_derivation.challenge_key(self._param.dev)
        
        request = ChallengeRequest()
        try:
            request.decode(challenge, challenge_key)
        except Exception:
            logger.warning("Failed to parse authentication challenge")
            return None
        
        if request.token != self._network.challenge:
            logger.warning("Received authentication request with wrong token")
            return None
        
        response = ChallengeResponse()
        response.flags = 2
        response.nonce = request.nonce
        response.device_id = request.device_id
        response.device_id_host = self._device_id
        response.unk = request.unk
        return response.encode(challenge_key)
    
    def _update_nonce(self) -> None:
        self._advert_nonce = (self._advert_nonce + 1) & 0xFFFFFFFF
        self._network.nonce = struct.pack(">I", self._advert_nonce)
    
    async def _process_events(self) -> None:
        while True:
            event = await self._interface.next_event()
            if isinstance(event, wlan.DisassociationEvent):
                await self._process_disassociation(event.address)

    async def _process_control_frame(self, frame: wlan.EthernetFrame) -> None:
        response = await self._process_authentication_event(frame)
        await self._send_control_frame(frame.source, response.encode())
    
    async def _process_authentication_event(
        self, ethernet: wlan.EthernetFrame
    ) -> AuthenticationFrame:
        frame = AuthenticationFrame(self._key_derivation, self._param.protocol)
        try:
            frame.decode(ethernet.payload)
        except Exception:
            logger.warning("Failed to parse authentication request")
            return self._make_authentication_response(
                AUTH_MALFORMED_REQUEST, self._network.version, bytes(16)
            )
        
        error = self._check_authentication_request(ethernet.source, frame)
        if error != AUTH_SUCCESS:
            return self._make_authentication_response(
                error, self._network.version, frame.client_random
            )
        
        assert isinstance(frame.payload, AuthenticationRequest)
        
        challenge = self._process_authentication_challenge(
            frame.payload.challenge
        )
        if challenge is None:
            return self._make_authentication_response(
                AUTH_CHALLENGE_FAILURE, self._network.version,
                frame.client_random
            )
        
        await self._register_participant(
            ethernet.source, frame.payload.username, frame.payload.app_version,
            frame.payload.platform
        )
        
        return self._make_authentication_response(
            AUTH_SUCCESS, self._network.version, frame.client_random, challenge
        )
    
    async def _register_participant(
        self, address: MACAddress, name: bytes, app_version: int, platform: int
    ) -> None:
        # Allocate an ip address
        for index in range(8):
            if not self._network.participants[index].connected:
                break
        
        self._peers.append(address)
        
        participant = ParticipantInfo()
        participant.ip_address = f"169.254.{self._network_id}.{index + 1}"
        participant.mac_address = address
        participant.connected = True
        participant.name = name
        participant.app_version = app_version
        participant.platform = platform
        
        self._network.participants[index] = participant
        self._network.num_participants += 1
        
        self._update_nonce()
        
        await self._tap.add_neighbor(
            participant.ip_address, participant.mac_address
        )
        
        await self._events.put(JoinEvent(index, participant))
    
    async def _process_disassociation(self, address: MACAddress) -> None:
        for index, participant in enumerate(self._network.participants):
            if participant.connected and participant.mac_address == address:
                break
        else:
            return
        
        self._peers.remove(address)
        
        participant.connected = False
        self._network.num_participants -= 1

        self._update_nonce()
        
        await self._tap.remove_neighbor(
            participant.ip_address, participant.mac_address
        )
        
        await self._events.put(LeaveEvent(index, participant))
    
    async def _initialize_network(self) -> None:
        host = self._network.participants[0]

        broadcast_addr = f"169.254.{self._network_id}.255"
        await self._tap.add_address(host.ip_address, broadcast_addr)
    
    async def _destroy_network(self) -> None:
        for participant in self._network.participants:
            if participant.connected:
                frame = DisconnectFrame()
                frame.reason = DISCONNECT_NETWORK_DESTROYED
                await self._send_control_frame(
                    participant.mac_address, frame.encode()
                )
    
    async def _send_advertisements(self) -> None:
        while True:
            await self._send_advertisement()
            await trio.sleep(.1)
    
    async def _send_advertisement(self) -> None:
        frame = self._network.build_advertisement(self._key_derivation)
        
        action = wlan.ActionFrame()
        action.source = self._interface.address()
        action.action = frame.encode()

        await self._interface.send_frame(action)

    async def _send_control_frame(
        self, target: wlan.MACAddress, data: bytes
    ) -> None:
        frame = wlan.EthernetFrame()
        frame.target = target
        frame.source = self._interface.address()
        frame.protocol = wlan.ETH_P_OUI
        frame.payload = data
        await self._interface.send_data(frame)
    
    async def _receive_data_frames(self) -> None:
        while True:
            frame = await self._interface.receive_data()
            if frame.protocol == wlan.ETH_P_OUI:
                await self._process_control_frame(frame)
            else:
                await self._tap.write(frame.encode())
    
    async def _transmit_data_frames(self) -> None:
        while True:
            data = await self._tap.read()

            ethernet = wlan.EthernetFrame()
            ethernet.decode(data)

            await self._interface.send_data(ethernet)


async def scan(
    keys: dict[str, bytes], ifname: str = "ldn", phyname: str = "phy0",
    channels: list[int] = [1, 6, 11], dwell_time: float = .110,
    protocols: list[int] = [1, 3]
) -> list[NetworkInfo]:
    """Scans for nearbly LDN networks."""

    if not channels: return []

    # Check if all channels are valid
    for channel in channels:
        if not wlan.is_valid_channel(channel):
            raise ValueError(f"Invalid channel: {channel}")
    
    for protocol in protocols:
        if protocol not in [1, 3]:
            raise ValueError(f"Invalid protocol: {protocol}")
    
    key_derivations = {
        protocol: KeyDerivation(keys, protocol) for protocol in protocols
    }

    async with wlan.create_factory() as factory:
        async with factory.create_monitor(phyname, ifname) as monitor:
            scanner = Scanner(key_derivations, monitor)
            return await scanner.scan(channels, dwell_time)


@contextlib.asynccontextmanager
async def connect(param: ConnectNetworkParam) -> AsyncGenerator[STANetwork]:
    """Joins a nearby LDN network."""

    param = copy.copy(param)
    if param.client_random is None:
        param.client_random = secrets.token_bytes(16)
    param.check()
    
    network = param.network

    key_derivation = KeyDerivation(
        param.keys, network.protocol,
        override_advertise_key=param.override_advertise_key,
        override_data_key=param.override_data_key,
        override_challenge_key=param.override_challenge_key
    )
    
    wlan_key = None
    if network.security_mode == SECURITY_MODE_PROD:
        wlan_key = key_derivation.derive_data_key(
            network.server_random, param.password
        )
    
    async with wlan.create_factory() as factory:
        async with factory.connect_network(
            param.phyname, param.ifname, network.ssid.hex(), network.channel,
            wlan_key
        ) as interface:
            sta = STANetwork(interface, param, key_derivation)
            async with sta.start():
                yield sta


@contextlib.asynccontextmanager
async def create_network(param: CreateNetworkParam) -> AsyncGenerator[APNetwork]:
    """Starts hosting an LDN network."""

    param = copy.copy(param)
    if param.ssid is None: param.ssid = secrets.token_bytes(16)
    if param.channel is None: param.channel = random.choice([1, 6, 11])
    if param.server_random is None:
        param.server_random = secrets.token_bytes(16)
    param.check()

    key_derivation = KeyDerivation(
        param.keys, param.protocol,
        override_advertise_key=param.override_advertise_key,
        override_data_key=param.override_data_key,
        override_challenge_key=param.override_challenge_key
    )

    wlan_key = None
    if param.security_mode == SECURITY_MODE_PROD:
        wlan_key = key_derivation.derive_data_key(
            param.server_random, param.password
        )
    
    async with wlan.create_factory() as factory:
        async with factory.create_monitor_ap(
            param.phyname, param.ifname, param.ifname_active, param.ssid.hex(),
            param.channel, wlan_key, param.max_participants
        ) as access_point:
            address = access_point.address()
            async with factory.create_tap(param.ifname_tap, address) as tap:
                network = APNetwork(access_point, tap, param, key_derivation)
                async with network.start():
                    yield network
