# GPS Handler

[← Back to README](../README.md)

`GPSHandler` polls the game's position data at a configurable interval and pushes changes to the Archipelago server's data storage via `GPSStateManager`. It fires events when the player moves or changes map.

## Setup

```csharp
using Archipelago.Core.Util.GPS;

// Provide a callback that reads position from game memory each poll cycle
var gps = new GPSHandler(
    updateCallback: () => new PositionData
    {
        X       = Memory.ReadFloat(X_ADDR),
        Y       = Memory.ReadFloat(Y_ADDR),
        Z       = Memory.ReadFloat(Z_ADDR),
        MapId   = Memory.ReadInt(MAP_ID_ADDR),
        MapName = Memory.ReadString(MAP_NAME_ADDR, 32),
        Region  = "Overworld"
    },
    pollingIntervalMs: 500   // default 1000
);

// Assign before or after Login — the GPSStateManager initialised during Login will pick it up
client.GPSHandler = gps;

gps.Start();
```

## Events

```csharp
gps.PositionChanged += (sender, e) =>
{
    Console.WriteLine($"Moved: ({e.OldX}, {e.OldY}, {e.OldZ}) → ({e.NewX}, {e.NewY}, {e.NewZ})");
};

gps.MapChanged += (sender, e) =>
{
    Console.WriteLine($"Map: {e.OldMapName} (id {e.OldMapId}) → {e.NewMapName} (id {e.NewMapId})");
};
```

Events fire only when the respective values actually change between polls.

## Current position

```csharp
PositionData pos = gps.GetCurrentPosition();
Console.WriteLine($"X={pos.X} Y={pos.Y} Z={pos.Z} Map={pos.MapName}");
```

## Polling interval

```csharp
gps.SetInterval(250);  // change to 250 ms while running
```

## Stopping and saving

```csharp
gps.Stop();

// Persist current position to Archipelago data storage
await client.SaveGPSAsync();
```

## GPSHandler API

```csharp
public class GPSHandler
{
    GPSHandler(Func<PositionData> updateCallback, int pollingIntervalMs = 1000)

    void Start()
    void Stop()
    void SetInterval(int pollingIntervalMs)

    PositionData GetCurrentPosition()

    float  X       { get; }
    float  Y       { get; }
    float  Z       { get; }
    int    MapId   { get; }
    string MapName { get; }
    string Region  { get; }

    event EventHandler<PositionChangedEventArgs> PositionChanged
    event EventHandler<MapChangedEventArgs>      MapChanged
}
```

### PositionData

```csharp
public struct PositionData
{
    public float  X, Y, Z;
    public int    MapId;
    public string MapName;
    public string Region;
}
```

## See also

- [ArchipelagoClient](archipelago-client.md) — `GPSHandler` property, `SaveGPSAsync`
