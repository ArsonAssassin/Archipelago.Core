# ArchipelagoClient

[← Back to README](../README.md)

`ArchipelagoClient` is the central coordinator. It manages the Archipelago server connection, owns the item and location managers, and integrates the overlay, GPS, and death link services.

## Constructor

```csharp
var client = new ArchipelagoClient(IGameClient gameClient);
```

The constructor sets `PlatformMemory.CurrentProcId` to the game's PID (used for overlay attachment and health polling) and starts the background health-check timer.

## Connection flow

```csharp
// 1. Open the server socket
await client.Connect("archipelago.gg:38281", "My Game Name");

// 2. Authenticate; creates ItemManager, LocationManager, and GameStateManager
await client.Login("PlayerName", password: null);

// 3. Signal that the game is ready to receive items
//    Call this after loading a save or reaching the main gameplay state.
await client.ReceiveReady();

// 4. Start monitoring locations
await client.MonitorLocationsAsync(locations);
```

`Login` fires the `Connected` event after the managers are initialised, so event subscriptions placed in the `Connected` handler are safe.

## Disconnecting

```csharp
client.Disconnect();
```

This cancels location monitors, stops item delivery, tears down the GPS state manager, and disconnects the socket.

`ArchipelagoClient` implements `IDisposable`; wrapping it in a `using` block calls `Disconnect` and saves game state.

## Events

```csharp
// Fired after Login completes and managers are ready
event EventHandler<ConnectionChangedEventArgs> Connected;

// Fired after Disconnect
event EventHandler<ConnectionChangedEventArgs> Disconnected;

// Fired when the game process disappears (triggers Disconnect automatically)
event EventHandler GameDisconnected;

// Fired for every chat/status message received from the server
event EventHandler<MessageReceivedEventArgs> MessageReceived;
```

`ItemReceived` and `LocationCompleted` are on `ItemManager` and `LocationManager` respectively — see [Items](items.md) and [Locations](locations.md).

## Properties

| Property | Type | Description |
|---|---|---|
| `IsConnected` | `bool` | Server socket is open |
| `IsLoggedIn` | `bool` | Logged in as a player |
| `CurrentSession` | `ArchipelagoSession` | Underlying Archipelago.MultiClient.Net session |
| `Options` | `Dictionary<string, object>` | Slot data (`"options"` key) loaded during login |
| `CustomValues` | `Dictionary<string, string>` | Persisted custom key-value store |
| `ItemManager` | `ItemManager` | Available after `Login` |
| `LocationManager` | `LocationManager` | Available after `Login` |
| `GPSHandler` | `GPSHandler` | Assign to enable position tracking |

## Communication

```csharp
// Send a chat message to the room
client.SendMessage("Hello!");

// Mark the goal as completed
client.SendGoalCompletion();

// Send a raw bounce packet
await client.SendBounceMessage(bouncePacket);
```

## Game state persistence

Item progress and custom values are stored server-side via Archipelago's data storage. They are saved automatically on process exit.

```csharp
await client.SaveGameStateAsync();
await client.LoadGameStateAsync();

await client.SaveCustomValuesAsync();
await client.LoadCustomValuesAsync();

await client.SaveGPSAsync();
```

## Per-save-file support

If your game has multiple save slots and you need to track item receipt independently per slot:

```csharp
// Allocate a new save ID (returns the next available byte, starting at 1)
byte saveId = await client.RequestNewSaveId();

// Switch to an existing save ID (resets item receipt for that slot)
bool ok = await client.UpdateSaveId(saveId);
```

## See also

- [Game Client](game-client.md)
- [Items](items.md)
- [Locations](locations.md)
- [Overlay](overlay.md)
- [GPS Handler](gps.md)
- [Death Link](death-link.md)
