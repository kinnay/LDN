
# Module: <code>ldn</code>
Implements the local wireless protocol used by the Nintendo Switch.

<code>**class** [MACAddress](#macaddress)</code><br>
<span class="docs">Class that represents a MAC address.</span>

<code>**class** [NetworkInfo](#networkinfo)</code><br>
<span class="docs">Holds information about a LDN network.</span>

<code>**class** [ParticipantInfo](#participantinfo)</code><br>
<span class="docs">Holds information about a network participant.</span>

<code>**async def scan**(ifname: str = "ldn", phyname: str = "phy0", channels: list[int] = [1, 6, 11], dwell_time: float=.110) -> list[[NetworkInfo](#networkinfo)]</code><br>
<span class="docs">Searches for nearby LDN networks on the given WLAN channels. To perform the scanning, this function creates a new interface on the given wiphy. The given interface name must not already be in use.</span>

## Global Constants
<span class="docs">
`ACCEPT_ALL = 0`<br>
`ACCEPT_NONE = 1`<br>
`ACCEPT_BLACKLIST = 2`<br>
`ACCEPT_WHITELIST = 3`
</span>

## MACAddress
<code>**def \_\_init__**(address: str | bytes | int = None)</code><br>
<span class="docs">Creates a new MAC address. If an address is given, the MAC address is parsed from the given string, bytes or integer object. Examples:<br>`MACAddress() -> 00:00:00:00:00:00`<br>`MACAddress("12:34:56:78:9a:bc") -> 12:34:56:78:9a:bc`<br>`MACAddress(b"\x12\x34\x56\x78\x9a\xbc") -> 12:34:56:78:9a:bc`<br>`MACAddress(0x123456789abc) -> 12:34:56:78:9a:bc`</span>

<code>**def \_\_eq__**(other: [MACAddress](#macaddress)) -> bool</code><br>
<span class="docs">Checks if two MAC addresses are equal.</span>

<code>**def \_\_hash__**() -> int</code><br>
<span class="docs">Returns a hash so that the MAC address can be used in sets and as dictionary keys.</span>

<code>**def \_\_str__**() -> str</code><br>
<span class="docs">Returns a string representation of the MAC address: `12:34:56:78:9a:bc`.</span>

<code>**def \_\_repr__**() -> str</code><br>
<span class="docs">Returns a different string representation of the MAC address: `MACAddress('12:34:56:78:9a:bc')`.</span>

## NetworkInfo
`local_communication_id: int`<br>
<span class="docs">This is usually the title id of the game.</span><br>
`game_mode: int`<br>
<span class="docs">Game mode (defined by game).</span><br>

`accept_policy: int`<br>
<span class="docs">Defines which stations are accepted by the host. One of the [`ACCEPT_`](#global-constants) constants.</span><br>
`max_participants: int`<br>
<span class="docs">Maximum number of participants.</span><br>
<code>participants: list[[ParticipantInfo](#participantinfo)]</code><br>
<span class="docs">Current network participants.</span><br>
`application_data: bytes`<br>
<span class="docs">Additional information provided by game.</span><br>

<code>address: [MACAddress](#macaddress)</code><br>
<span class="docs">The MAC address of the network host.</span><br>
`channel: int`<br>
<span class="docs">The WLAN channel of the network.</span><br>
`ssid: bytes`<br>
<span class="docs">The SSID of the network (16 random bytes).</span><br>

`version: int`<br>
<span class="docs">LDN version used by the host.</span><br>
`key: bytes`<br>
<span class="docs">Network key. This is used to derive encryption keys.</span><br>
`security_level: int`<br>
<span class="docs">The security level of the network.</span><br>

## ParticipantInfo
`ip_address: str`<br>
<code>mac_address: [MACAddress](#macaddress)</code><br>
`connected: bool`<br>
`name: str`<br>
`app_version: int`
