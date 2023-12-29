
# Module: <code>ldn</code>
Implements the local wireless protocol used by the Nintendo Switch.

<code>**class** [MACAddress](#macaddress)</code><br>
<span class="docs">Class that represents a MAC address.</span>

<code>**class** [NetworkInfo](#networkinfo)</code><br>
<span class="docs">Holds information about a LDN network.</span>

<code>**class** [ParticipantInfo](#participantinfo)</code><br>
<span class="docs">Holds information about a network participant.</span>

<code>**class** [ConnectNetworkParam](#connectnetworkparam)</code><br>
<span class="docs">Contains various parameters for joining a network.</span>

<code>**class** [CreateNetworkParam](#createnetworkparam)</code><br>
<span class="docs">Contains various parameters for network creation.</span>

<code>**class** [STANetwork](#stanetwork)</code><br>
<span class="docs">Represents an active LDN network for a station.</span>

<code>**class** [APNetwork](#apnetwork)</code><br>
<span class="docs">Represents an active LDN network for an access point.</span>

<code>**async def scan**(ifname: str = "ldn", phyname: str = "phy0", channels: list[int] = [1, 6, 11], dwell_time: float=.110) -> list[[NetworkInfo](#networkinfo)]</code><br>
<span class="docs">Searches for nearby LDN networks on the given WLAN channels. To perform the scanning, this function creates a new interface on the given wiphy. The given interface name must not already be in use.</span>

<code>**async with connect**(param: [ConnectNetworkParam](#connectnetworkparam)) -> [STANetwork](#stanetwork)</code><br>
<span class="docs">Joins an active LDN network. The station is disconnected automatically at the end of the `async with` block.</span>

<code>**async with create_network**(param: [CreateNetworkParam](#createnetworkparam)) -> [APNetwork](#apnetwork)</code><br>
<span class="docs">Creates a new LDN network. The network is destroyed automatically at the end of the `async with` block.</span>

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
<span class="docs">Game mode (defined by game).</span>

`accept_policy: int`<br>
<span class="docs">Defines which stations are accepted by the host. One of the [`ACCEPT_`](#global-constants) constants.</span><br>
`max_participants: int`<br>
<span class="docs">Maximum number of participants (up to 8).</span><br>
`num_participants: int`<br>
<span class="docs">Current number of connected participants.</span><br>
<code>participants: list[[ParticipantInfo](#participantinfo)]</code><br>
<span class="docs">Current network participants. This list always contains exactly 8 entries.</span><br>
`application_data: bytes`<br>
<span class="docs">Additional information provided by game.</span>

<code>address: [MACAddress](#macaddress)</code><br>
<span class="docs">The MAC address of the network host.</span><br>
`channel: int`<br>
<span class="docs">The WLAN channel of the network.</span><br>
`ssid: bytes`<br>
<span class="docs">The SSID of the network (16 random bytes).</span>

`version: int`<br>
<span class="docs">LDN version used by the host.</span><br>
`key: bytes`<br>
<span class="docs">Network key. This is used to generate encryption keys.</span><br>
`security_level: int`<br>
<span class="docs">The security level of the network.</span>

## ParticipantInfo
`connected: bool`<br>
<span class="docs">Indicates whether this entry is valid.</span><br>
`ip_address: str`<br>
<span class="docs">The IP address of the participant (169.254.X.Y).</span><br>
<code>mac_address: [MACAddress](#macaddress)</code><br>
<span class="docs">The MAC address of the participant.</span><br>
`name: str`<br>
<span class="docs">The nickname of the participant.</span><br>
`app_version: int`<br>
<span class="docs">The application communication version of the participant.</span>

## ConnectNetworkParam
<code>**def \_\_init__**()</code><br>
<span class="docs">Creates a new instance with the default values. Parameters without default value must always be filled in manually.</span>

`ifname: str = "ldn"`<br>
<span class="docs">The interface name for the station. The interface names must not already be in use.</span><br>
`phyname: str = "phy0"`<br>
<span class="docs">The name of the wiphy on which the station interface is created.</span><br>

<code>network: [NetworkInfo](#networkinfo)</code><br>
<span class="docs">The network information obtained during scanning.</span><br>
`password: str = ""`</code><br>
<span class="docs">Password. This is used to generate encryption keys. Authentication fails if the password is wrong.</span>

`name: str`<br>
<span class="docs">Your nickname (up to 32 bytes)</span><br>
`app_version: int`<br>
<span class="docs">Your application communication version.</span>

`enable_challenge: bool = True`<br>
<span class="docs">Specifies whether the DRM challenge is enabled. This is always enabled for games, but not for system titles.</span><br>
`device_id: int = random.randint(0, 0xFFFFFFFFFFFFFFFF)`<br>
<span class="docs">The device id for the DRM challenge.</span>

## CreateNetworkParam
<code>**def \_\_init__**()</code><br>
<span class="docs">Creates a new instance with the default values. Parameters without default value must always be filled in manually.</span>

`ifname: str = "ldn"`<br>
<span class="docs">The interface name for the access point. The interface names must not already be in use.</span><br>
`ifname_monitor: str = "ldn-mon"`<br>
<span class="docs">The interface name for the monitor. The interface names must not already be in use.</span><br>
`phyname: str = "phy0"`<br>
<span class="docs">The name of the wiphy on which the access point interface are created.</span>
`phyname_monitor: str = "phy0"`<br>
<span class="docs">The name of the wiphy on which the monitor interface is created.</span>

`local_communication_id: int`<br>
<span class="docs">This is usually the title id.</span><br>
`game_mode: int`<br>
<span class="docs">The game mode.</span>

`max_participants: int = 8`<br>
<span class="docs">The maximum number of participants. Cannot be higher than 8.</span><br>
`application_data: bytes = b""`<br>
<span class="docs">Game-specific data. Can be updated at any time after network creation.</span><br>
`accept_policy: int = ACCEPT_ALL`<br>
<span class="docs">Specifies which stations are allowed to join the network. Must be one of the [`ACCEPT_`](#global-constants) constants.</span><br>
<code>accept_filter: list[[MACAddress](#macaddress)] = []</code><br>
<span class="docs">This list contains a blacklist or whitelist, depending on the accept policy.</span><br>
`security_level: int = 1`<br>
<span class="docs">The security level of the network. Always `1` in practice.</span><br>
`ssid: bytes = None`<br>
<span class="docs">Must contain exactly 16 bytes. If `None`, a random SSID is generated during network creation.</span>

`name: str`<br>
<span class="docs">Your nickname (up to 32 bytes)</span><br>
`app_version: int`<br>
<span class="docs">Your application communication version.</span>

`channel: int = None`<br>
<span class="docs">The WLAN channel of the network. If `None`, the channel is chosen randomly from `1`, `6` or `11` during network creation.</span><br>
`key: bytes = None`<br>
<span class="docs">Network key (16 bytes). This is used to generate encryption keys. If `None`, a random key is generated during network creation.</span><br>
`password: str = ""`<br>
<span class="docs">Password. This is used to generate encryption keys.</span>

`version: int = 3`<br>
<span class="docs">LDN version (`2` or `3`).</span><br>
`enable_challenge: bool = True`<br>
<span class="docs">Specifies whether the DRM challenge is enabled. This is always enabled for games, but not for system titles.</span><br>
`device_id: int = random.randint(0, 0xFFFFFFFFFFFFFFFF)`<br>
<span class="docs">The device id for the DRM challenge.</span>

## STANetwork
<code>**def info**() -> [NetworkInfo](#networkinfo)</code><br>
<span class="docs">Returns information about the network.</span>

<code>**async def next_event**() -> object</code><br>
<span class="docs">Waits until an event occurs and returns it. Returns [JoinEvent](#Joinevent), [LeaveEvent](#leaveevent), [DisconnectEvent](#disconnected), [ApplicationDataChanged](#applicationdatachanged) or [AcceptPolicyChanged](#acceptpolicychanged).</span>

## APNetwork
<code>**def info**() -> [NetworkInfo](#networkinfo)</code><br>
<span class="docs">Returns information about the network.</span>

<code>**def set_application_data**(data: bytes) -> None</code><br>
<span class="docs">Updates the application data.</span>

<code>**def set_accept_policy**(policy: int) -> None</code><br>
<span class="docs">Updates the station accept policy (one of the [`ACCEPT_`](#global-constants) constants).</span>

<code>**def set_accept_filter**(filter: list[[MACAddress](#macaddress)]) -> None</code><br>
<span class="docs">Updates the accept filter. This is either a blacklist or whitelist, depending on the accept policy.</span>

<code>**async def kick**(index: int) -> None</code><br>
<span class="docs">Kicks a station from the network.</span>

<code>**async def next_event**() -> object</code><br>
<span class="docs">Waits until an event occurs and returns it. Returns either [JoinEvent](#Joinevent) or [LeaveEvent](#leaveevent).</span>

## JoinEvent
Triggered when a new station joins the network.

`index: int`<br>
<code>participant: [ParticipantInfo](#participantinfo)</code>

## LeaveEvent
Triggered when a station leaves the network.

`index: int`<br>
<code>participant: [ParticipantInfo](#participantinfo)</code>

## DisconnectEvent
Triggered when you are disconnected from the network.

`reason: int`

## ApplicationDataChanged
Triggered when the host has changed the application data.

`old: bytes`<br>
`new: bytes`

## AcceptPolicyChanged
Triggered when the host has changed the station accept policy.

`old: int`<br>
`new: int`
