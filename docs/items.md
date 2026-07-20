# Items

[← Back to README](../README.md)

Item receipt is managed by `ItemManager`, which is created during `Login` and accessible at `client.ItemManager`.

## Enabling receipt

By default the client does **not** deliver items until you signal that the game is ready. Call this once the game has loaded a save and is in a state that can accept items:

```csharp
await client.ReceiveReady();
```

You can call `ReceiveReady` again at any time to resume delivery after a pause (for example, after a failed item).

## Handling items

Subscribe to `ItemManager.ItemReceived` before (or immediately after) calling `ReceiveReady`:

```csharp
client.ItemManager.ItemReceived += (sender, e) =>
{
    Console.WriteLine($"Received: {e.Item.Name} (id {e.Item.Id})");
    Console.WriteLine($"From: {e.Player.Name}, location id: {e.LocationId}");

    bool success = GiveItemToPlayer(e.Item.Name);

    // Setting Success = false tells the manager the item could not be applied.
    // Delivery halts and no further items are processed until ReceiveReady() is called again.
    e.Success = success;
};
```

### ItemReceivedEventArgs

| Member | Type | Description |
|---|---|---|
| `Item.Id` | `long` | Archipelago item ID |
| `Item.Name` | `string` | Human-readable item name |
| `Item.flags` | `ItemFlags` | Classification (progression, useful, filler, trap) |
| `LocationId` | `long` | Source location ID |
| `Player` | `PlayerInfo` | The player who sent the item |
| `Success` | `bool` | Set to `false` to pause delivery |

## Pausing and resuming delivery

```csharp
// Pause — items are queued but not delivered
await client.ItemManager.StopReceiving();

// Resume
await client.ReceiveReady();
```

## Force-reload

Re-deliver all items from the beginning. Use this when starting a new save file in a game that shares a slot:

```csharp
await client.ItemManager.ForceReloadAllItems();
await client.ReceiveReady();
```

## See also

- [ArchipelagoClient](archipelago-client.md) — `ReceiveReady`, save IDs
- [Locations](locations.md)
