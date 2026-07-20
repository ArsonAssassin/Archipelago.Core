# Locations

[← Back to README](../README.md)

Location monitoring is handled by `LocationManager`, created during `Login` and accessible at `client.LocationManager`. Workers continuously evaluate each location's check condition against game memory and report completions to the server.

## Defining locations

Locations implement `ILocation`. The concrete `Location` class covers the majority of use cases:

```csharp
using Archipelago.Core.Models;

var locations = new List<ILocation>
{
    // Bit check — location is complete when bit 0 of address 0x200000 is set
    new Location
    {
        Id        = 1001,
        Name      = "First Chest",
        Address   = 0x200000,
        CheckType = LocationCheckType.Bit,
        AddressBit = 0,
        Category  = "Chests"
    },

    // Byte equality — complete when byte at address equals 1
    new Location
    {
        Id          = 1002,
        Name        = "Boss Defeated",
        Address     = 0x200010,
        CheckType   = LocationCheckType.Byte,
        CheckValue  = "1",
        CompareType = LocationCheckCompareType.Match,
        Category    = "Bosses"
    },

    // Integer range — complete when int is between 10 and 15 inclusive
    new Location
    {
        Id              = 1003,
        Name            = "Level Achievement",
        Address         = 0x200020,
        CheckType       = LocationCheckType.Int,
        CompareType     = LocationCheckCompareType.Range,
        RangeStartValue = "10",
        RangeEndValue   = "15",
        Category        = "Achievements"
    }
};
```

### Location fields

| Field | Type | Description |
|---|---|---|
| `Id` | `int` | Archipelago location ID |
| `Name` | `string` | Human-readable name |
| `Category` | `string` | Optional grouping label |
| `Address` | `ulong` | Memory address to read (hex strings accepted in JSON) |
| `AddressBit` | `int` | Bit index (0–7) for `Bit` / `FalseBit` checks |
| `NibblePosition` | `NibblePosition` | `Upper` or `Lower` for `Nibble` checks |
| `CheckType` | `LocationCheckType` | What to read — see table below |
| `CompareType` | `LocationCheckCompareType` | How to compare the read value |
| `CheckValue` | `string` | Expected value (parsed at check time) |
| `RangeStartValue` | `string` | Lower bound for `Range` compares |
| `RangeEndValue` | `string` | Upper bound for `Range` compares |

### CheckType values

| Value | Reads |
|---|---|
| `Bit` | Single bit at `AddressBit` is **set** |
| `FalseBit` | Single bit at `AddressBit` is **not set** |
| `Nibble` | Upper or lower 4-bit nibble |
| `Byte` | 1-byte unsigned integer |
| `Short` / `UShort` | 2-byte signed / unsigned integer |
| `Int` / `UInt` | 4-byte signed / unsigned integer |
| `Long` / `ULong` | 8-byte signed / unsigned integer |
| `AND` | All sub-locations in a `CompositeLocation` must be true |
| `OR` | Any sub-location in a `CompositeLocation` must be true |

### CompareType values

| Value | Condition |
|---|---|
| `Match` | `value == CheckValue` |
| `GreaterThan` | `value > CheckValue` |
| `LessThan` | `value < CheckValue` |
| `Range` | `RangeStartValue <= value <= RangeEndValue` |

## Composite locations

`CompositeLocation` groups multiple conditions with AND / OR logic:

```csharp
var composite = new CompositeLocation
{
    Id        = 2001,
    Name      = "Sword and Shield",
    CheckType = LocationCheckType.AND,
    Category  = "Equipment",
    Conditions = new List<ILocation>
    {
        new Location { Id = 2002, Name = "Has Sword",  Address = 0x300000, CheckType = LocationCheckType.Bit, AddressBit = 0 },
        new Location { Id = 2003, Name = "Has Shield", Address = 0x300000, CheckType = LocationCheckType.Bit, AddressBit = 1 }
    }
};
```

## Starting monitoring

`MonitorLocationsAsync` is a long-running task; it completes only when monitoring is cancelled. Typically you fire-and-forget it or await it on the `Connected` event:

```csharp
client.LocationManager.LocationCompleted += (sender, e) =>
{
    Console.WriteLine($"Checked: {e.Location.Name}");
    client.AddOverlayMessage($"Found: {e.Location.Name}");
};

// Inside the Connected handler (or with _ = to fire-and-forget):
await client.MonitorLocationsAsync(locations);
```

## Gate on a condition

Prevent location checks from being evaluated (and sent) until the game is in the right state:

```csharp
// Locations are only checked while the player is in the overworld
client.LocationManager.EnableLocationsCondition = () => IsInOverworld();
```

## Dynamic management

Add or remove locations while monitoring is running:

```csharp
client.LocationManager.AddLocation(newLocation);
client.LocationManager.RemoveLocation(existingLocation);
```

## Manual send

Manually mark a location as checked without waiting for the monitor to detect it:

```csharp
await client.SendLocationAsync(location);
```

## See also

- [ArchipelagoClient](archipelago-client.md)
- [Items](items.md)
- [Memory API](memory.md)
