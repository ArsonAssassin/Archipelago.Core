# Object Mapping

[← Back to README](../README.md)

`MemoryOffsetAttribute` lets you describe a C# class that maps directly to a contiguous memory layout. `Memory.ReadObject<T>` and `Memory.WriteObject<T>` then handle serialisation automatically.

## Basic usage

```csharp
using Archipelago.Core.Util;

[MemoryOffset(0x100)]   // optional class-level base offset added to the address you pass in
public class PlayerData
{
    [MemoryOffset(0x00)]
    public int Health { get; set; }

    [MemoryOffset(0x04)]
    public int Mana { get; set; }

    [MemoryOffset(0x08, stringLength: 32)]
    public string Name { get; set; }

    [MemoryOffset(0x28, collectionLength: 10)]
    public List<int> Inventory { get; set; }

    [MemoryOffset(0x50, byteArrayLength: 8)]
    public byte[] StatusFlags { get; set; }
}

// Read — effective address = baseAddress + 0x100
PlayerData player = Memory.ReadObject<PlayerData>(baseAddress);

// Write back
Memory.WriteObject(baseAddress, player);
```

## Attribute parameters

```csharp
[MemoryOffset(uint offset,
              int stringLength   = 100,   // max bytes to read for string properties
              int collectionLength = 0,   // element count for List<T> / IList<T> / ICollection<T>
              int bitPosition    = -1,    // reserved
              int byteArrayLength = 0)]   // byte count for byte[] properties
```

| Parameter | Applies to | Description |
|---|---|---|
| `offset` | all | Byte offset from the base address |
| `stringLength` | `string` | Maximum bytes to read |
| `collectionLength` | `List<T>` etc. | Number of elements to read/write |
| `byteArrayLength` | `byte[]` | Number of bytes to read/write |

## Supported property types

| Type | Notes |
|---|---|
| `byte` | |
| `short`, `ushort` | Endianness applied |
| `int`, `uint` | Endianness applied |
| `long`, `ulong` | Endianness applied |
| `float`, `double` | Endianness applied |
| `bool` | Reads/writes bit 0 of the byte at the offset |
| `string` | UTF-8, length controlled by `stringLength` |
| `byte[]` | Length controlled by `byteArrayLength` |
| `enum` | Underlying type is used |
| Nested class | Recursed; the nested class must also have `[MemoryOffset]` properties |
| `List<T>` / `IList<T>` / `ICollection<T>` | Elements read sequentially; `collectionLength` required |

## Nested objects

```csharp
public class Weapon
{
    [MemoryOffset(0x00)]
    public int DamageBase { get; set; }

    [MemoryOffset(0x04)]
    public float AttackSpeed { get; set; }
}

public class Player
{
    [MemoryOffset(0x00)]
    public int Health { get; set; }

    [MemoryOffset(0x10)]
    public Weapon EquippedWeapon { get; set; }  // read from baseAddress + 0x10
}
```

## Endianness

Pass an endianness argument to `ReadObject` / `WriteObject` to swap all multi-byte fields:

```csharp
PlayerData player = Memory.ReadObject<PlayerData>(baseAddress, Endianness.Big);
```

## Marshal structs

For unmanaged structs you already have defined, use `ReadStruct<T>` / `WriteStruct<T>` instead — they use `Marshal.PtrToStructure` directly and do not require `[MemoryOffset]`:

```csharp
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct Vec3
{
    public float X, Y, Z;
}

Vec3 pos = Memory.ReadStruct<Vec3>(address);
Memory.WriteStruct(address, pos);
```

## See also

- [Memory API](memory.md)
