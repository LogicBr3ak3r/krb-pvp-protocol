# Kingdom Rush Battles - Real PvP Protocol Reverse Engineering

**Author:** LogicBr3ak3r
**Contact:** Telegram - [@LogicBr3ak3r](https://t.me/LogicBr3ak3r)

> **Note on Tools & Scripts:** All scripts and automation tools developed during this research - including `auto_farm.py` (the full economy farming bot), the PvP headless client, the savegame editor, and supporting utilities - will be released publicly once these reports gain sufficient attention. Follow the Telegram contact above to stay notified.

Complete documentation of all reverse-engineered components needed to implement a headless
C# client that plays real PvP matches against human opponents via Photon matchmaking.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Photon Connection & Authentication](#2-photon-connection--authentication)
3. [Photon SDK Internals & INIT_BYTES](#3-photon-sdk-internals--init_bytes)
4. [Matchmaking System](#4-matchmaking-system)
5. [Quantum Protocol (Event 100)](#5-quantum-protocol-event-100)
6. [Simulation Commands (Event 101)](#6-simulation-commands-event-101)
7. [Match Lifecycle & Handshake](#7-match-lifecycle--handshake)
8. [RuntimeConfig & FrameSnapshot](#8-runtimeconfig--framesnapshot)
9. [Game AI Engine](#9-game-ai-engine)
10. [Anti-Detection & Stealth](#10-anti-detection--stealth)
11. [String Literal Resolution](#11-string-literal-resolution)
12. [BLOCKER: "Quantum SDK 3" Error](#12-blocker-quantum-sdk-3-error)

---

## 1. Architecture Overview

Kingdom Rush Alliance uses a **Photon Quantum** architecture for PvP:

```
Mobile Client (Unity IL2CPP)
    |
    |-- HTTPS REST API (AWS) -- account, cards, trophies, match results
    |
    |-- Photon Realtime (UDP) -- room matchmaking, event relay
    |       |
    |       +-- Event 100 (reliable) -- Quantum protocol messages (handshake, config)
    |       +-- Event 101 (unreliable) -- Quantum deterministic commands (gameplay)
    |
    +-- Quantum Simulation (deterministic) -- runs identically on both clients
```

**Key identifiers:**
- `AppIdRealtime`: `1b031e9f-aa5e-4cd1-a185-131870e8e4fc`
- `AppVersion`: `1.7.0`
- Server plugin: `QuantumPlugin`
- Transport: UDP
- Checksums: **DISABLED** (server does not validate simulation state)

**Game's class hierarchy (confirmed via IDA):**
- `QuantumLoadBalancingClient` extends `LoadBalancingClient` (adds nickname + best-region PlayerPrefs)
- `Quantum.Services.NetworkClient` extends `LoadBalancingClient` (thin wrapper, just calls base ctor)
- `LoadBalancingPeer` extends `PhotonPeer`
- `EnetPeer` extends `PeerBase` (does NOT override `WriteInitRequest` - confirmed via IDA)

---

## 2. Photon Connection & Authentication

### IDA Source
- Connection flow traced through `Quantum.Services.Network$$Connect`
- Auth mode from `Photon.Realtime.LoadBalancingClient$$OpAuthenticate`

### Authentication Flow

The game does **NOT** use Photon Custom Authentication. It connects anonymously:

```
Client -> NameServer: ConnectUsingSettings (anonymous, AuthMode=Auth)
Client -> MasterServer: auto-redirect
Client -> MasterServer: OpJoinRandomOrCreateRoom (with room properties)
Client -> GameServer: auto-redirect on room join
```

The JWT from the REST API is passed **after** joining the room, via the Quantum protocol
handshake (`SetPlayerData` message, ID 11), not during Photon authentication.

**Critical finding:** Setting `CustomAuthenticationType.Custom` causes
`"Authentication type not supported (none configured)"` error because the Photon app
is not configured for custom auth on the server side.

### Connection Settings

```csharp
AppSettings = {
    AppIdRealtime = "1b031e9f-aa5e-4cd1-a185-131870e8e4fc",
    AppVersion = "1.7.0",
    FixedRegion = "us",       // or best region from FindBestRegion
    UseNameServer = true,
    Protocol = ConnectionProtocol.Udp,
    AuthMode = AuthModeOption.Auth,  // NOT AuthOnce, NOT AuthOnceWss
}
```

---

## 3. Photon SDK Internals & INIT_BYTES

All values in this section are **confirmed via IDA decompilation** of the game's
`libil2cpp.so`.

### Game's Photon SDK

| Property | Value | Source |
|---|---|---|
| DLL name | `Photon3Unity3D.dll` | Il2CppDumper DummyDll |
| SDK version | `4.1.6.25` | `Version.clientVersion` byte array |
| SDK type | Unity SDK | DLL name |

### PhotonPeer Constants & Fields

| Field | Value | IDA RVA / Source |
|---|---|---|
| `DebugBuild` | `True` (const) | dump.cs: `public const bool DebugBuild = True` |
| `ClientSdkId` | `15` (set in ctor) | IDA `PhotonPeer.__ctor @ 0x183C120` line 50 |
| `UseInitV3` | `False` (default) | dump.cs field at offset 0x1E |

### ClientSdkIdShifted Calculation

**IDA: `get_ClientSdkIdShifted @ 0x183A924`:**
```c
return 2 * this->fields.ClientSdkId;
```

Result: `2 * 15 = 30`.

Note: `DebugBuild = True` means no release flag bit is set; the formula simplifies to
`ClientSdkId << 1`, producing `ClientSdkIdShifted = 30`.

### SerializationProtocol Enum (Confirmed via IDA)

```
// TypeDefIndex: 11835
public enum SerializationProtocol {
    GpBinaryV16 = 0,
    GpBinaryV18 = 1
}
```

**Game's LoadBalancingClient constructor** (`IDA @ 0x21B6304`, line 224):
```c
v25->fields._SerializationProtocolType_k__BackingField = 1;  // GpBinaryV18
```

**CONFIRMED: Game uses `GpBinaryV18` (Protocol18), NOT `GpBinaryV16`.**

### Version String Caching Mechanism

**IDA: `get_ClientVersion @ 0x183A934` and `get_Version @ 0x183ACDC`:**

Both methods share the same logic:
1. Check if `PhotonPeer.static_fields->clientVersion` (a cached `string`) is null or empty
2. If so, build string from `Version.clientVersion` byte array using `String.Format("{0}.{1}.{2}.{3}")`
3. Cache result in `PhotonPeer.static_fields->clientVersion`
4. Return cached string

**Critical for spoofing:** The `Version.clientVersion` byte array and the
`PhotonPeer.clientVersion` cached string are SEPARATE fields. After modifying the
byte array, the cached string must be cleared (set to `null`) so it rebuilds on next access.

### INIT_BYTES Format

**IDA: `PeerBase.WriteInitRequest @ 0x297915C`** - confirmed structurally identical
across SDK versions.

**Binary path (to NameServer, when `PhotonToken == null`):**
```
byte[41]:
  [0]  = 0xF3       // magic
  [1]  = 0x00
  [2]  = SerializationProtocol.VersionBytes[0]   // 1
  [3]  = SerializationProtocol.VersionBytes[1]   // 8 (for GpBinaryV18)
  [4]  = ClientSdkIdShifted                      // 30
  [5]  = (clientVersion[0] << 4) | clientVersion[1]  // 0x41 for v4.1.*
         OR'd with 0x80 if IPv6
  [6]  = clientVersion[2]                        // 6 (build)
  [7]  = clientVersion[3]                        // 25 (revision)
  [8]  = 0x00
  [9..40] = AppId string chars (32 bytes, zero-padded)
```

**HTTP path (to Master/Game Server, when `PhotonToken != null`):**
```
Dictionary keys sent as HTTP key-value string:
  "init"          = null
  "app"           = AppId
  "clientversion" = PhotonPeer.ClientVersion  (e.g. "4.1.6.25")
  "protocol"      = SerializationProtocol.ProtocolType  (e.g. "GpBinaryV18")
  "sid"           = ClientSdkIdShifted.ToString()  (e.g. "30")
  + serialized PhotonToken appended as binary
```

String literal keys confirmed via IDA:
- `StringLiteral_14886` = `"init"`
- `StringLiteral_12889` = `"app"` (or `"appId"` - verified as the app key)
- `StringLiteral_13335` = `"clientversion"`
- `StringLiteral_16191` = `"protocol"`
- `StringLiteral_16692` = `"sid"`

### Summary of All INIT_BYTES Parameters

| Parameter | Game Value |
|---|---|
| Magic byte | `0xF3` |
| VersionBytes | `[1, 8]` |
| ClientSdkIdShifted | `30` |
| clientVersion packed | `0x41, 6, 25` |
| clientversion string | `"4.1.6.25"` |
| protocol string | `"GpBinaryV18"` |
| sid string | `"30"` |
| UseInitV3 | `False` |

---

## 4. Matchmaking System

### IDA Sources
| Function | Address | Purpose |
|---|---|---|
| `MatchManager$$StartMatch` | `0x17A90EC` | Entry point, builds MatchRequest |
| `MatchManager$$CreateMatchRequest` | `0x17AAAFC` | Creates request with Type=6, timeout |
| `Matchmaking$$SynchronizeRoom` | `0x1796A1C` | Switch on Type, dispatches to room ops |
| `Matchmaking$$TryJoinOrCreateRandomRoom` | `0x1797FC0` | The actual OpJoinRandomOrCreateRoom call |
| `Matchmaking$$TryJoinRandomRoom` | `0x1797930` | JoinRandom only |
| `Matchmaking$$TryCreateRandomRoom` | `0x1797B00` | CreateRoom only |
| `Matchmaking$$GenerateCustomRoomProperties` | `0x1798A44` | Builds room property hashtable |
| `Matchmaking$$GenerateCustomRoomPropertiesForLobby` | `0x1798EFC` | Keys visible in lobby |
| `Matchmaking$$GenerateExpectedRoomProperties` | `0x17991BC` | Filter for JoinRandom |
| `Matchmaking$$GeneratePlayerProperties` | `0x17984F8` | Player-level properties |
| `MatchmakingConstants$$.cctor` | `0x241F6C0` | Lobby definitions |

### Match Request Types (enum `EMatchRequestType`)

| Value | Type | Method Called |
|---|---|---|
| 1 | JoinRoom | `TryJoinRoom` (private match by code) |
| 2 | CreateRoom | `TryCreateRoom` (private match host) |
| 3 | JoinOrCreateRoom | `TryJoinOrCreateRoom` |
| 4 | JoinRandomRoom | `TryJoinRandomRoom` |
| 5 | CreateRandomRoom | `TryCreateRandomRoom` |
| **6** | **JoinOrCreateRandomRoom** | **`TryJoinOrCreateRandomRoom`** (normal PvP) |

Normal matchmaking uses **Type 6** (`OpJoinRandomOrCreateRoom`) which atomically tries to
join a random matching room, and if none found, creates one in a single round trip.

### Lobby Configuration

```csharp
TypedLobby("BattleLobby", LobbyType.Sql)  // type 2 = SQL lobby
```

IDA: `MatchmakingConstants$$.cctor @ 0x241F6C0`:
- `LobbyBattle` = `new TypedLobby("BattleLobby", 2)` (StringLiteral_2846)
- `LobbyGameEvent` = `new TypedLobby("LobbyGameEvent", 2)` (StringLiteral_7225)

The game uses an **SQL-type lobby** named `"BattleLobby"`, not the default lobby.
This is critical -- rooms created in the default lobby are invisible to real players.

### Custom Room Properties

Set by `GenerateCustomRoomProperties` + `StartMatch`:

| Key | Type | Value | String Literal | BSS Address |
|---|---|---|---|---|
| `"MM1475963"` | bool | `true` | StringLiteral_7302 | 0x3A5A988 |
| `"MinStartPlayers"` | int | `2` | StringLiteral_7583 | 0x3A5ADEC |
| `"ExpectedPlayers"` | int | `2` | StringLiteral_4930 | 0x3A58478 |
| `"ExtraSlots"` | int | `0` | StringLiteral_4968 | 0x3A58510 |
| `"MatchStarted"` | bool | `false` | StringLiteral_7442 | 0x3A5ABB8 |
| `"AutoStart"` | bool | `true` | StringLiteral_2739 | 0x3A5623C |
| `"HasTimeout"` | bool | `true` | StringLiteral_6026 | 0x3A59598 |
| `"Timeout"` | int | `botTimeout * waitMultiplier` | StringLiteral_10935 | 0x3A5E24C |
| `"MatchData"` | byte[] | RuntimeConfig serialized | StringLiteral_7400 | 0x3A5AB10 |
| `"PlayerIgnore_" + userId` | null | Ignore tracking | StringLiteral_8564 | 0x3A5BD40 |
| `"C0"` | string | Arena group ID | StringLiteral_2971 | - |
| `"C1"` | int | Trophies | StringLiteral_2973 | - |
| `"C2"` | float | Avg card level | StringLiteral_2974 | - |
| `"C3"` | string | User ID | StringLiteral_2976 | - |
| `"C4"` | int | Win rate | StringLiteral_2978 | - |
| `"Terrain"` | long | Map asset GUID (optional) | StringLiteral_10108 | - |

**Notes:**
- `"MM1475963"` is the matchmaking class marker. Without it, rooms are invisible to matchmaking.
- `"C0"` through `"C4"` are game-specific matchmaking properties added in `StartMatch`.
- `"MatchData"` contains the serialized `RuntimeConfig` byte array (map, cards, etc.).
- `"PlayerIgnore_" + userId` prevents matching against yourself.

### Lobby-Visible Properties

Set by `GenerateCustomRoomPropertiesForLobby` + additional keys from `StartMatch`:

```
"MM1475963", "ExpectedPlayers", "MatchStarted",
"C0", "C1", "C2", "C3", "C4"
```

Only these keys are visible for SQL filtering in `OpJoinRandomRoom`.

### Expected Room Properties (JoinRandom Filter)

Set by `GenerateExpectedRoomProperties`:

```csharp
{
    "MM1475963" = true,       // must be a Quantum matchmaking room
    "ExpectedPlayers" = 2     // must be a 2-player room
}
```

### SQL Lobby Filter

The game builds a complex SQL filter string from multiple sub-filters joined with ` AND `:

```
UserFilterSql AND ArenaFilterSql AND TrophiesFilterSql AND CardLevelFilterSql AND WinRateFilterSql
```

Built by helper functions:
- `MatchmakingUtils$$GetUserFilterSql` - excludes self: `C3 <> 'userId'`
- `MatchmakingUtils$$GetArenaFilterSql` - matches arena group: `C0 = 'arenaGroupId'`
- `MatchmakingUtils$$GetTrophiesOrMedalsFilterSql` - trophy range filter on `C1`
- `MatchmakingUtils$$GetCardLevelFilterSql` - card level range filter on `C2`
- `MatchmakingUtils$$GetWinRateFilterSql` - win rate range filter on `C4`

The game generates **3 filter strings** with widening ranges (tight, medium, wide),
separated by `";"`, giving the Photon server fallback options for broader matching.

### Player Properties

Set by `GeneratePlayerProperties`:

| Key | Type | Value |
|---|---|---|
| `"IsSpectator"` | bool or null | `true` if spectator, `null` if player |

StringLiteral_6858 = `"IsSpectator"` (BSS 0x3A5A298)

### Room Options

```csharp
RoomOptions = {
    MaxPlayers = 2,            // ExpectedPlayers + ExtraSlots
    IsVisible = true,
    IsOpen = true,
    Plugins = ["QuantumPlugin"],  // StringLiteral_8729 @ 0x3A5BFD8
    CustomRoomProperties = { ... },  // all properties above
    CustomRoomPropertiesForLobby = ["MM1475963", "ExpectedPlayers", "MatchStarted", "C0"-"C4"],
}
```

### MatchRequest Defaults from CreateMatchRequest

```
Type = 6 (JoinOrCreateRandomRoom)
AutoStart = true
IsOpen = true
IsVisible = true
MinStartPlayers = 2
ExpectedPlayers = 2
ExtraSlots = 0
Plugin = "QuantumPlugin"
Timeout = botTimeout * matchmakingWaitTimeMultiplier
Region = null (uses connected region)
TypedLobby = Default (overridden to "BattleLobby" in StartMatch)
```

### Bot Timeout

From `StartMatch`:
```
timeout = MatchmakingSettings.botTimeout * arena.matchmakingWaitTimeMultiplier
```
If `matchmakingWaitTimeMultiplier <= 1`, it defaults to `1`.
The `botTimeout` field comes from `MatchmakingSettings` (configurable server-side, typically 6s).

After the timeout expires without finding a human opponent, the server-side QuantumPlugin
fills the slot with a bot.

---

## 5. Quantum Protocol (Event 100)

### IDA Source
- `Protocol.Serializer.ctor @ 0x1D2CD44` - RegisterPrototype(id, message) calls

### Protocol Message Types

| ID | Name | Direction | Purpose |
|---|---|---|---|
| 1 | `Join` | Client -> Server | Request to join simulation |
| 2 | `Joined` | Server -> Client | Confirmation of join |
| 3 | `SessionConfig` | Bidirectional | Session parameters (request/response) |
| 4 | `RuntimeConfig` | Bidirectional | Game configuration (request/response) |
| 5 | `SimulationStart` | Server -> Client | Simulation begins |
| 6 | `SimulationStop` | Server -> Client | Simulation ends |
| 7 | `ClockCorrect` | Server -> Client | Clock sync |
| 8 | `TickChecksum` | Bidirectional | Frame integrity check |
| 9 | `TickChecksumError` | Server -> Client | Desync detected |
| 10 | `RttUpdate` | Client -> Server | Round-trip time |
| 11 | `SetPlayerData` | Client -> Server | Player identity + JWT |
| 12 | `Disconnect` | Bidirectional | Graceful disconnect |
| 13 | `FrameSnapshot` | Server -> Client | Full game state |
| 14 | `Command` | Client -> Server | Wraps deterministic commands |
| 15 | `TickChecksumErrorFrameDump` | Server -> Client | Debug frame dump on desync |
| 16 | `InputMissing` | Server -> Client | Input not received |
| 17 | `FrameSnapshotRequest` | Client -> Server | Request state snapshot |
| 21 | `StartRequest` | Client -> Server | Ready to start simulation |

### BitStream Serialization Format

All Quantum protocol messages use a **BitStream** serializer (not simple byte arrays).
IDA: `Photon.Deterministic.BitStream` with `WriteByteAt` for bit-level operations.

**Key rules:**
- Strings use a **1-bit null flag**, making subsequent fields non-byte-aligned
- Int32 values are written as 4�-8 bits (byte-aligned within the bit stream)
- Bool values use a **1-bit** write
- Byte arrays use a **1-bit not-null flag** + 16-bit LE length + N bytes
- Int32 arrays use a **1-bit not-null flag** + 16-bit LE length + N�-int32

**Bit ordering:** LSB-first within each byte position.

### Quantum Protocol Version

**Confirmed from game's `quantum.code.dll` version: `2.1.0.0`**

IDA: `GetBackendProtocolVersionString` and `DeterministicProtocolVersions` enum:

| String | Enum Value | Notes |
|---|---|---|
| `"1.2.0.0"` | 0 | |
| `"1.2.1.0"` | 1 | |
| `"1.2.2.0"` | 2 | |
| `"1.2.3.0"` | 3 | |
| `"1.2.3.1"` | 4 | |
| `"2.0.0.0"` | 5 | |
| **`"2.1.0.0"`** | **6** | **Game uses this (Quantum 2)** |
| `"2.2.0.0"` | 7 | Adds `Rejoin` bool field to Join message |

### Key Message Details

**Join (ID 1) - Client -> Server:**

IDA: `Protocol.Join.Serialize @ 0x1D2C958`

Uses BitStream serialization (NOT simple byte array):
```
[1:byte]                        // Message type (prepended separately)
WriteString(clientId)           // 1-bit null + 16-bit len + UTF8 bytes
WriteString(protocolVersion)    // "2.1.0.0" (1-bit null + 16-bit len + UTF8)
WriteInt32(playerSlots)         // 32 bits (usually 1)
WriteInt32(initialTick)         // 32 bits (usually 0)
WriteInt32(playerCount)         // 32 bits (usually 2)
[WriteBool(rejoin)]             // 1 bit, ONLY if versionEnum >= 7
```

**IMPORTANT:** The `clientId` is `LocalPlayerIndex.ToString()` (NOT actor number).
`LocalPlayerIndex = ActorNumber - 1`.

With `ProtocolVersionString = "2.1.0.0"` (enum 6), the `Rejoin` field is NOT written.
With `"2.2.0.0"` (enum 7), the `Rejoin` bool IS written.

**Joined (ID 2) - Server -> Client:**

IDA: `Protocol.Joined.Serialize @ 0x1D2CB10`

```
[2:byte]                        // Message type
ReadInt32(status)               // 32 bits (if versionEnum >= 6)
                                // OR ReadBool (1 bit, if versionEnum < 6)
ReadInt32Array(playerSlots)     // 1-bit not-null + 16-bit len + N�-int32
```

Status values: 1 = confirmed, 2 = reconnect confirmed.

**SessionConfig (ID 3) - Bidirectional:**

IDA: `Protocol.SessionConfig.Serialize @ 0x20F85A8`

```
[3:byte]                        // Message type
ReadBool(requested)             // 1 bit: true = server asks client for config
ReadBool(configIsNull)          // 1 bit
[DeterministicSessionConfig fields if not null]
```

When `requested=true`, the client must respond with its own SessionConfig.

**DeterministicSessionConfig fields** (IDA: `@ 0x20E5940`):
```
Int32 BackgroundThreadPriority
Int32 PlayerCount
Bool  SkipRollbackWhenPossible
Bool  RunInBackgroundThread
Bool  ExposeVerifiedStatusInsideSimulation
Bool  LockstepSimulation
Bool  AggressiveSendMode
Int32 InputDelayMin, InputDelayMax, InputDelayPingStart, UpdateFPS
Int32 ChecksumInterval, RollbackWindow, InputPacking
Int32 InputHardTolerance, InputRedundancy, InputRepeatMaxDistance
Int32 SessionStartTimeout, TimeCorrectionRate, MinTimeCorrectionFrames
Int32 MinOffsetCorrectionDiff, TimeScaleMin, TimeScalePingMin, TimeScalePingMax
Bool  ChecksumCrossPlatformDeterminism
Bool  InputFixedSizeEnabled
Int32 InputFixedSize
```

**RuntimeConfig (ID 4) - Bidirectional:**

IDA: `Protocol.RuntimeConfig.Serialize @ 0x20F8490`

```
[4:byte]                        // Message type
ReadBool(requested)             // 1 bit
ReadByteArray(config)           // 1-bit not-null + 16-bit len + N bytes
```

When `requested=true`, the client must respond with its MatchData (RuntimeConfig bytes).

**Disconnect (ID 12):**

IDA: `Protocol.Disconnect.Serialize @ 0x20F86C0`

```
[12:byte]                       // Message type
ReadString(reason)              // 1-bit null + 16-bit len + UTF8
```

The reason string uses a custom XOR encoding in the BitStream (observed from hex dumps).

**SetPlayerData (ID 11) - Client -> Server:**

IDA: `SetPlayerData.Serialize @ 0x1D2DA94`

```
[11:byte]                       // Message type
WriteInt32(playerIndex)         // 32 bits
WriteByteArray(jwtBytes)        // 1-bit not-null + 16-bit len + N bytes (UTF8 JWT)
```

**StartRequest (ID 21) - Client -> Server:**

```
[21:byte]                       // Message type (no additional fields)
```

### Multi-Message Packing

**CRITICAL:** The server packs MULTIPLE protocol messages into a single Event 100 payload.
IDA: `Protocol.Serializer.ReadNext` / `PackMessages`.

Example from observed traffic: The server sends Joined + SessionConfig(requested) +
RuntimeConfig(requested) as a single 14-byte Event 100 payload. The client must parse
all messages sequentially from the byte stream.

---

## 6. Simulation Commands (Event 101)

### IDA Source
- `DeterministicCommandSetup$$AddCommandFactoriesUser @ 0x2491C28`
- Factory registration order determines command type IDs.

### Command Type IDs

| ID | Command | Fields |
|---|---|---|
| 0 | `PlayerReadyCommand` | (none) |
| 1 | `UseCardCommand` | PlayerRef, CardRef, ... |
| 2 | `UseMercenaryCardCommand` | PlayerRef, MercenaryRef, ... |
| 3 | `UseEmoteCommand` | PlayerRef, EmoteId |
| 4 | `BuyTowerCommand` | EntityRef Holder |
| 5 | `SellTowerCommand` | EntityRef Tower |
| 6 | `UpgradeTowerCommand` | EntityRef Tower |
| 7 | `BuyHolderCommand` | PlayerRef, HolderType |
| 8 | `UnlockTowerSkillCommand` | EntityRef Tower, SkillIndex |
| 9 | `TriggerTowerSkillCommand` | EntityRef Tower, SkillIndex |
| 10 | `DragDraggableCommand` | EntityRef Entity, FPVector2 Target |
| 11 | `SelectWaveModifierCommand` | PlayerRef Player, byte ModifierId |
| 12 | `TapCommand` | FPVector2 Position |
| 13 | `TutorialCommand` | (tutorial-specific) |
| 14 | `TutorialBotAICommand` | (tutorial bot AI) |

### Command Serialization Format

Commands use `BitStream` serialization. Each command starts with:
```
[commandTypeId:ushort] [command-specific fields...]
```

### EntityRef Format

```
[Index:int32] [Version:int32]
```
- `Index` is the entity slot in the ECS
- `Version` is a generation counter for reuse detection

### FPVector2 Format (Fixed Point)

```
[X:int64] [Y:int64]
```
Q48.16 format: `realValue = rawLong / 65536.0`

### PlayerRef Format

```
[PlayerIndex:int32]
```
0-based player index matching Photon actor order.

### Command Wrapping for Event 101

Game commands are wrapped in a `Command` protocol message (ID 14) before being sent:

```
Event 101 payload:
  [14]                    // Protocol.Command type ID
  [currentTick:int32]     // simulation tick number
  [dataLength:int32]      // length of command data
  [commandData:bytes...]  // the actual command (commandTypeId + fields)
```

IDA: `DeterministicNetwork$$SendProtocolMessages` and `Protocol.Command$$Serialize`

---

## 7. Match Lifecycle & Handshake

### Full PvP Match Flow

```
1. ConnectUsingSettings -> NameServer (binary INIT_BYTES)
2. OpAuthenticate on NameServer -> gets PhotonToken
3. Auto-redirect to MasterServer (HTTP INIT_BYTES with token)
4. OpAuthenticate on MasterServer
5. OpJoinRandomOrCreateRoom (BattleLobby, with room properties)
6. Photon matches or creates room
7. Auto-redirect to GameServer (HTTP INIT_BYTES with token)
8. OpAuthenticate on GameServer
9. Both players in room
10. --- Quantum Protocol Handshake (Event 100) ---
11. Client sends: Join (ID 1) - with ProtocolVersionString "2.1.0.0"
12. Server responds with PACKED message containing:
    - Joined (ID 2) - status=1, playerSlots=[0]
    - SessionConfig (ID 3) - requested=true (asks client for config)
    - RuntimeConfig (ID 4) - requested=true (asks client for MatchData)
13. Client sends: SessionConfig response (ID 3, requested=false, with config)
14. Client sends: RuntimeConfig response (ID 4, requested=false, with MatchData)
15. Client sends: StartRequest (ID 21) - ready to begin
16. Server sends: SimulationStart (ID 5) - game begins!
17. --- Gameplay Loop (Event 101) ---
18. Client sends commands (wrapped in Protocol.Command ID 14)
19. Server relays commands to opponent
20. Both clients simulate deterministically
21. --- Match End ---
22. Server sends: SimulationStop (ID 6)
23. Client disconnects
24. Client sends match result to REST API
```

**IMPORTANT:** Steps 12-15 are the critical handshake. The server sends all three
messages (Joined + SessionConfig + RuntimeConfig) packed into a SINGLE Event 100 payload.
The client must parse all three, respond to both config requests, then send StartRequest.

### Timing

- Simulation runs at **60 ticks/second** (16.67ms per tick)
- Match duration: up to **15 waves** (~5-10 minutes)
- `maxTicks` for real PvP: 54,000 (15 minutes at 60 TPS)
- Matchmaking timeout: 90 seconds
- Bot fill timeout: ~6 seconds (from `MatchmakingSettings.botTimeout`)

---

## 8. RuntimeConfig & FrameSnapshot

### RuntimeConfig

IDA: `Quantum.RuntimeConfig$$Serialize @ analyzed`

The RuntimeConfig is sent as a byte array in the `RuntimeConfig` protocol message (ID 4).
It is also embedded in room properties as `"MatchData"`.

**Known fields** (partial, from `RuntimeConfig.Serialize` analysis):
- Seed (int)
- Map Asset GUID (int64)
- SimulationConfig Asset GUID (int64)
- PlayVersusBot flag (bool)
- IsPvpMatch flag (bool)
- Player deck configurations
- Booster settings

**Important:** Map holder EntityRefs (tower placement slots) are NOT in RuntimeConfig.
They are generated during Quantum simulation initialization from the map asset data.

### FrameSnapshot

Server sends `FrameSnapshot` (ID 13) with the full deterministic game state.
Format is Quantum-specific binary serialization. Contains all ECS entity data.

---

## 9. Game AI Engine

### IDA Sources
| Component | Key Functions |
|---|---|
| `UtilityReasoner` | Core AI decision engine |
| `AIBot` | Bot player controller |
| `AIThreatLedger` | Threat tracking per lane/position |
| `AIWaveManager` | Wave timing and difficulty |
| `AIUtilityManagerSystem` | ECS system running AI |
| `AICustomConfig` | Per-difficulty tuning |

### Difficulty Levels (enum `EBotDifficulty`)

| Value | Level |
|---|---|
| 0 | Easy |
| 1 | Normal |
| 2 | Hard |
| 3 | Maximum |

### AI Decision Pipeline

```
1. AIThreatLedger updates threat scores per lane
2. WaveModifierAI selects boosters
3. UtilityReasoner evaluates tower placement scores
4. UtilityReasoner evaluates tower upgrade scores
5. HeroAI repositions hero based on threat
6. SpellAI targets spells at high-threat clusters
7. Highest-scoring action is executed as a Command
```

### Configurable AI Parameters

| Parameter | Description |
|---|---|
| `Difficulty` | EBotDifficulty enum value |
| `UseHeroAI` | Enable/disable hero repositioning |
| `UseSpellAI` | Enable/disable spell targeting |
| `UseModifierAI` | Enable/disable wave modifier selection |
| `eagerness` | How quickly the AI spends gold |
| `cooldowns` | Minimum time between actions |

---

## 10. Anti-Detection & Stealth

### What the Server Can See

1. **Photon room events** - all Event 100/101 messages, timing
2. **REST API calls** - match creation, results, deck, card usage
3. **Telemetry data** - client sends device info, session data
4. **Match timing** - how long between actions, reaction times

### What the Server Cannot Verify

1. **Simulation state** - checksums are **DISABLED**
2. **Client identity** - JWT is passed in protocol, but connection is anonymous
3. **Input source** - no way to distinguish human vs bot input

### Stealth Considerations

- Action timing should mimic human patterns (variable delays)
- Win rate should be realistic (not 100%)
- Trophy progression should be gradual
- Match duration should match typical game length
- Commands should be paced realistically (not instant-optimal)

---

## 11. String Literal Resolution

### Methodology

IL2CPP string literals are stored in `global-metadata.dat` and lazily loaded at runtime.
The IDA binary (`libil2cpp.so`) references them via BSS pointers named `StringLiteral_XXXX`.

**Resolution pipeline:**
1. `ida_name.get_name_ea(0, 'StringLiteral_XXXX')` -> BSS address
2. Cross-reference BSS address with `Il2CppDumper/stringliteral.json`
3. Match by address to get the actual string value

The `stringliteral.json` from Il2CppDumper contains entries like:
```json
{"value": "MM1475963", "address": "0x3A5A988"}
```

**Note:** The metadata file (`global-metadata.dat`, version 31) appears to be
obfuscated/encrypted in this game, so direct parsing fails. The Il2CppDumper output
must be used instead.

### Complete String Literal Table (Matchmaking)

| IDA Name | BSS Address | Value | Context |
|---|---|---|---|
| StringLiteral_7302 | 0x3A5A988 | `"MM1475963"` | Matchmaking class marker |
| StringLiteral_7583 | 0x3A5ADEC | `"MinStartPlayers"` | Room property |
| StringLiteral_4930 | 0x3A58478 | `"ExpectedPlayers"` | Room property + filter |
| StringLiteral_4968 | 0x3A58510 | `"ExtraSlots"` | Room property |
| StringLiteral_7442 | 0x3A5ABB8 | `"MatchStarted"` | Room property + lobby |
| StringLiteral_2739 | 0x3A5623C | `"AutoStart"` | Room property |
| StringLiteral_6026 | 0x3A59598 | `"HasTimeout"` | Room property |
| StringLiteral_10935 | 0x3A5E24C | `"Timeout"` | Room property (int, seconds) |
| StringLiteral_7400 | 0x3A5AB10 | `"MatchData"` | Room property (RuntimeConfig bytes) |
| StringLiteral_8564 | 0x3A5BD40 | `"PlayerIgnore_"` | Player ignore prefix |
| StringLiteral_2971 | - | `"C0"` | Arena group ID |
| StringLiteral_2973 | - | `"C1"` | Trophies |
| StringLiteral_2974 | - | `"C2"` | Avg card level |
| StringLiteral_2976 | - | `"C3"` | User ID |
| StringLiteral_2978 | - | `"C4"` | Win rate |
| StringLiteral_10108 | - | `"Terrain"` | Map terrain asset GUID |
| StringLiteral_6858 | 0x3A5A298 | `"IsSpectator"` | Player property |
| StringLiteral_8729 | 0x3A5BFD8 | `"QuantumPlugin"` | Server plugin name |
| StringLiteral_2846 | - | `"BattleLobby"` | PvP lobby name |
| StringLiteral_7225 | - | `"LobbyGameEvent"` | Event lobby name |
| StringLiteral_171 | - | `" AND "` | SQL filter joiner |
| StringLiteral_1752 | - | `";"` | SQL filter separator (multi-try) |
| StringLiteral_14886 | - | `"init"` | INIT_BYTES HTTP key |
| StringLiteral_12889 | - | `"app"` | INIT_BYTES HTTP key (AppId) |
| StringLiteral_13335 | - | `"clientversion"` | INIT_BYTES HTTP key |
| StringLiteral_16191 | - | `"protocol"` | INIT_BYTES HTTP key |
| StringLiteral_16692 | - | `"sid"` | INIT_BYTES HTTP key |
| StringLiteral_7194 | - | `"Master"` | Default AppId fallback |

---

## 12. BLOCKER: "Quantum SDK 3" Error

### The Problem

After successfully connecting, joining a room, and completing the Quantum protocol
handshake (Join -> Joined -> SessionConfig -> RuntimeConfig -> StartRequest), the
server-side `QuantumPlugin` disconnects the client with:

```
Error #21: Quantum SDK 3 not supported on Quantum 2 AppIds,
check Photon dashboard to set correct version.
```

The AppId (`1b031e9f-aa5e-4cd1-a185-131870e8e4fc`) is configured for **Quantum 2** on
the Photon dashboard. The server detects the client as **Quantum SDK 3** and rejects it.

### Investigation Summary

| Attempt | Details | Result |
|---|---|---|
| Spoof `Version.clientVersion` to `[4,1,6,25]` | Match game's SDK version | Error persists |
| Set `SerializationProtocolType = GpBinaryV16` | Hypothesized game uses V16 | Error persists (**and wrong - game uses V18**) |
| Set `ProtocolVersionString = "2.1.0.0"` | Match game's quantum.code.dll | Error persists |
| Set `ProtocolVersionString = "2.2.0.0"` | Original default | Error persists |
| Clear cached `PhotonPeer.clientVersion` string | Ensure spoof propagates | Error persists |
| Force `UseInitV3 = false` via reflection | Match game's default | Error persists |
| **No spoofing at all** (original SDK) | Test if error message changes | **Same exact error** |

### Key Observation

**The error is identical whether or not any values are spoofed.** This means the server's
"Quantum SDK 3" detection is NOT based on any of these parameters:
- `Version.clientVersion` bytes (INIT_BYTES version)
- `SerializationProtocolType` (GpBinaryV16 vs V18)
- `ProtocolVersionString` in the Join message
- `ClientSdkId` / `ClientSdkIdShifted`
- `UseInitV3` flag

### When the Error Occurs

The error occurs AFTER the full handshake completes:

```
1. NameServer connection      ✓ (binary INIT_BYTES accepted)
2. Master Server connection   ✓ (HTTP INIT_BYTES accepted)
3. Room create/join           ✓ (room created successfully)
4. Game Server connection     ✓ (HTTP INIT_BYTES accepted)
5. Quantum Join sent          ✓ (accepted)
6. Quantum Joined received    ✓ (status=1, confirmed)
7. SessionConfig exchanged    ✓ (request + response)
8. RuntimeConfig exchanged    ✓ (request + response)
9. StartRequest sent          ✓ (sent successfully)
10. Server disconnects        �- "Quantum SDK 3 not supported"
```

The QuantumPlugin processes everything up to StartRequest, then rejects during
simulation initialization.

### Root Cause: Wrong Photon SDK DLL Origin

The detection was caused by using a Photon DLL from a **standard PUN 2 SDK**
instead of the **Quantum 2 SDK**. Despite version spoofing and parameter overrides,
the DLL's internal binary behavior (ENet protocol framing, Init command encoding,
or other low-level transport details) was different enough for the Photon Cloud
infrastructure to classify the client as incompatible with Quantum 2.

The Photon Server's `InitRequest` API exposes `SdkId`, `PlatformId`, `ClientVersion`,
`IsInitV3Used`, and `DecryptedAuthToken` to server-side plugins. The QuantumPlugin
likely reads these (especially data embedded in the auth token by the NameServer)
to determine the client's SDK compatibility.

Key evidence:
- Both the standalone DotNet SDK AND PUN 2's `Photon3Unity3D.dll`
  produced the IDENTICAL error, despite being completely different
  DLL versions. This ruled out version-specific behavior.
- The error persisted regardless of version spoofing, ENet parameter overrides,
  or any other reflection-based modifications. This confirmed the detection is
  at a binary level that cannot be overridden via reflection.

### Solution: Use Quantum 2 SDK DLL

Replacing the Photon DLL with the version from the **Quantum 2.1.5 SDK**
(Build 1144) resolved the issue:

- **DLL version**: 4.1.6.18 (assembly version)
- **SDK build**: Quantum 2.1.5 Stable Build 1144
- **Version spoofed to**: 4.1.6.25 (matching the game's exact version)
- **SentCountAllowance**: Set to 9 via reflection (matching QuantumLoadBalancingClient)

This DLL has the correct internal binary behavior that the Photon Cloud expects
from a Quantum 2 client, including proper SequenceDeltaLimit values (100/75,
changed in v4.1.6.17) and other ENet protocol parameters.

---

## Appendix A: Key IDA Addresses Reference

### Matchmaking

| Address | Function |
|---|---|
| `0x17A90EC` | `MatchManager$$StartMatch` |
| `0x17AAAFC` | `MatchManager$$CreateMatchRequest` |
| `0x1796A1C` | `Matchmaking$$SynchronizeRoom` |
| `0x1797FC0` | `Matchmaking$$TryJoinOrCreateRandomRoom` |
| `0x1797930` | `Matchmaking$$TryJoinRandomRoom` |
| `0x1797B00` | `Matchmaking$$TryCreateRandomRoom` |
| `0x17970C0` | `Matchmaking$$TryCreateRoom` |
| `0x1796D5C` | `Matchmaking$$TryJoinRoom` |
| `0x17974F8` | `Matchmaking$$TryJoinOrCreateRoom` |
| `0x1798A44` | `Matchmaking$$GenerateCustomRoomProperties` |
| `0x1798EFC` | `Matchmaking$$GenerateCustomRoomPropertiesForLobby` |
| `0x17991BC` | `Matchmaking$$GenerateExpectedRoomProperties` |
| `0x17984F8` | `Matchmaking$$GeneratePlayerProperties` |
| `0x1798658` | `Matchmaking$$GenerateExpectedUsers` |
| `0x179936C` | `Matchmaking$$GenerateRoomName` |
| `0x1798A18` | `Matchmaking$$SetNextRoomOperationTime` |
| `0x241F6C0` | `MatchmakingConstants$$.cctor` |
| `0x179617C` | `Matchmaking$$Run` |
| `0x1796758` | `Matchmaking$$Tick` |
| `0x179941C` | `MatchRequest$$IsValid` |
| `0x1799734` | `MatchRequest$$.ctor` |

### Quantum Protocol

| Address | Function |
|---|---|
| `0x1D2CD44` | `Protocol.Serializer.ctor` (message ID registration) |
| `0x1D2C958` | `Protocol.Join.Serialize` |
| `0x1D2CB10` | `Protocol.Joined.Serialize` |
| `0x20F85A8` | `Protocol.SessionConfig.Serialize` |
| `0x20F8490` | `Protocol.RuntimeConfig.Serialize` |
| `0x20F86C0` | `Protocol.Disconnect.Serialize` |
| `0x1D2DA94` | `Protocol.SetPlayerData.Serialize` |
| `0x20E5940` | `DeterministicSessionConfig.Serialize` |
| `0x2491C28` | `DeterministicCommandSetup$$AddCommandFactoriesUser` (command IDs) |
| `0x1D2CD44` | `Photon.Deterministic.Protocol.Serializer.ctor` |

### Photon SDK Internals

| Address | Function |
|---|---|
| `0x183C120` | `PhotonPeer.__ctor` (sets ClientSdkId=15) |
| `0x183A924` | `PhotonPeer.get_ClientSdkIdShifted` (returns 2*ClientSdkId) |
| `0x183A934` | `PhotonPeer.get_ClientVersion` (cached string from byte array) |
| `0x183ACDC` | `PhotonPeer.get_Version` (static, same caching) |
| `0x297915C` | `PeerBase.WriteInitRequest` (binary + HTTP INIT_BYTES) |
| `0x297E94C` | `PeerBase.WriteInitV3` (InitV3 path, not used) |
| `0x21B6304` | `LoadBalancingClient.__ctor` (sets SerializationProtocol=GpBinaryV18) |
| `0x21C5C44` | `LoadBalancingPeer.__ctor(ConnectionProtocol)` |
| `0x21B6F3C` | `LoadBalancingPeer.__ctor(IPhotonPeerListener, ConnectionProtocol)` |
| `0x29CCFEC` | `QuantumLoadBalancingClient.__ctor` |
| `0x29D09DC` | `QuantumLoadBalancingClient.ConnectUsingSettings` |
| `0x179BDDC` | `Quantum.Services.NetworkClient.__ctor` |

### Match State & Room Properties

| Address | Function |
|---|---|
| `0x17AB764` | `MatchManager$$SetGameplayInfoFromRoomProperties` |
| `0x17AFD4C` | `MatchManager$$GetRoomPropertiesForEventMatch` |
| `0x179C088` | `Network$$OnRoomPropertiesUpdate` |

### Photon API

| Address | Function |
|---|---|
| `0x21B9794` | `LoadBalancingClient$$OpJoinRandomRoom` |
| `0x21B9990` | `LoadBalancingClient$$OpJoinRandomOrCreateRoom` |
| `0x21B9B94` | `LoadBalancingClient$$OpCreateRoom` |

---

## Appendix B: Implementation Checklist

### Minimum Viable Real PvP Client

- [x] Anonymous Photon connection (no CustomAuth)
- [x] `"BattleLobby"` SQL lobby with `LobbyType.Sql`
- [x] `OpJoinRandomOrCreateRoom` with correct args
- [x] Room properties: `MM1475963=true`, `ExpectedPlayers=2`, `MatchStarted=false`, etc.
- [x] Lobby-visible properties: `MM1475963`, `ExpectedPlayers`, `MatchStarted`, `C0`-`C4`
- [x] SQL filter: exclude self (`C3 <> userId`), match arena (`C0 = arenaGroup`)
- [x] Plugin: `"QuantumPlugin"`
- [x] Quantum handshake: Join -> handle packed Joined+SessionConfig+RuntimeConfig -> respond -> StartRequest
- [x] BitStream serialization for all Quantum protocol messages
- [x] Command wrapping: Protocol.Command (ID 14) with tick and length prefix
- [x] 15 deterministic command types with correct IDs
- [x] Real-time simulation pacing at 60 TPS
- [x] AI decision engine (UtilityReasoner, Hero, Spell, WaveModifier)
- [x] **FIXED**: Replaced DLL with Quantum 2 SDK version (Build 1144)

### Confirmed Correct

- [x] `SerializationProtocolType = GpBinaryV18` (NOT V16)
- [x] `ClientSdkId = 15` (same as game)
- [x] `DebugBuild = True` (const, same as game)
- [x] `ClientSdkIdShifted = 30` (2 * 15)
- [x] `UseInitV3 = False`
- [x] `ProtocolVersionString = "2.1.0.0"` (enum 6, matches game's quantum.code.dll)
- [x] INIT_BYTES format matches game (both binary and HTTP paths verified via IDA)
- [x] Version string caching cleared after spoof
