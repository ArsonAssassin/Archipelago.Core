# Archipelago.Core

A C# library for integrating games with the [Archipelago](https://archipelago.gg/) multiworld randomizer. Provides memory read/write, location monitoring, item handling, overlay display, and support for both native process memory and BizHawk via named pipe.

## Installation

```
dotnet add package Archipelago.Core
```

## Quick Start

```csharp
using Archipelago.Core;
using Archipelago.Core.Helpers;
using Archipelago.Core.Models;
using Archipelago.Core.Util;

var gameClient = new GameClient("MyGame.exe");
if (!gameClient.Connect())
    throw new Exception("Game not running");

var client = new ArchipelagoClient(gameClient);

// Wire up events after Login initialises the managers
client.Connected += async (s, e) =>
{
    client.ItemManager.ItemReceived += OnItemReceived;
    client.LocationManager.LocationCompleted += OnLocationCompleted;
    await client.ReceiveReady();
    await client.MonitorLocationsAsync(BuildLocationList());
};

await client.Connect("archipelago.gg:38281", "My Game");
await client.Login("PlayerName");
```

## Documentation

| Topic | Description |
|---|---|
| [Game Client](docs/game-client.md) | Connecting to a game process |
| [ArchipelagoClient](docs/archipelago-client.md) | Server connection, login, events, and state |
| [Items](docs/items.md) | Receiving and handling items |
| [Locations](docs/locations.md) | Defining and monitoring check locations |
| [Memory API](docs/memory.md) | Reading and writing game memory |
| [PlatformMemory](docs/platform-memory.md) | Process management and native memory utilities |
| [Object Mapping](docs/object-mapping.md) | Mapping C# classes to memory structures |
| [BizHawk](docs/bizhawk.md) | Using Archipelago.Core with BizHawk via named pipe |
| [Overlay](docs/overlay.md) | Displaying text over the game window |
| [GPS Handler](docs/gps.md) | Tracking player position and map changes |
| [Death Link](docs/death-link.md) | Synchronising deaths between players |
| [Advanced](docs/advanced.md) | Function hooking, lag simulation |
| [Configuration](docs/configuration.md) | config.ini file support and custom settings |

## License

MIT. See `LICENSE` for details.

## Contributing

Issues and pull requests welcome at <https://github.com/ArsonAssassin/Archipelago.Core>.
