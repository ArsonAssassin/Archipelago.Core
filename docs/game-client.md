# Game Client

[← Back to README](../README.md)

The game client represents your connection to the target game process. `ArchipelagoClient` uses it to find the process, set up memory access, and detect when the game is closed.

## GameClient

The built-in `GameClient` class handles the common case of connecting to a named executable.

```csharp
using Archipelago.Core.Helpers;

var gameClient = new GameClient("MyGame.exe");
bool running = gameClient.Connect(); // true if the process is found
```

`ProcId` is resolved dynamically on each access — it always returns the current PID. Partial name matching is supported, so `"MyGame"` will match `"MyGame_v2"`.

### Interface

```csharp
public interface IGameClient
{
    bool   IsConnected  { get; set; }
    bool   Connect();
    int    ProcId       { get; set; }
    string ProcessName  { get; set; }
}
```

## Health polling

`ArchipelagoClient` calls `gameClient.Connect()` every 10 seconds. If it returns `false` the client fires `GameDisconnected` and disconnects from the Archipelago server. See [ArchipelagoClient](archipelago-client.md) for the event.

## Custom game clients

Implement `IGameClient` when you need custom process discovery (for example, picking between multiple running instances, or deriving PID from a helper process):

```csharp
public class MyGameClient : IGameClient
{
    public bool   IsConnected  { get; set; }
    public string ProcessName  { get; set; } = "MyGame";
    public int    ProcId       { get; set; }

    public bool Connect()
    {
        ProcId = FindMyGameProcess();
        IsConnected = ProcId != 0;
        return IsConnected;
    }
}
```

Pass an instance to `ArchipelagoClient`:

```csharp
var client = new ArchipelagoClient(new MyGameClient());
```

## See also

- [ArchipelagoClient](archipelago-client.md)
- [PlatformMemory](platform-memory.md) — process ID utilities
