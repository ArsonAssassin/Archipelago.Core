# Memory API

[← Back to README](../README.md)

`Memory` is a static class that routes all reads and writes through an `IMemory` provider. By default this is the native process memory implementation. Call `Memory.Initialize(provider)` to swap to a different backend such as `BizhawkMemory`.

```csharp
using Archipelago.Core.Util;

// Default: reads/writes directly from the game process via ReadProcessMemory/WriteProcessMemory
// No setup required beyond setting PlatformMemory.CurrentProcId (done by ArchipelagoClient).

// BizHawk: swap the provider before using Memory.*
Memory.Initialize(bizhawkMemory);
```

## Read operations

```csharp
byte   Memory.ReadByte   (ulong address)
byte[] Memory.ReadByteArray(ulong address, int length)
bool   Memory.ReadBit    (ulong address, int bitNumber, Endianness endianness = Little)

short  Memory.ReadShort  (ulong address, Endianness endianness = Little)
ushort Memory.ReadUShort (ulong address, Endianness endianness = Little)
int    Memory.ReadInt    (ulong address, Endianness endianness = Little)
uint   Memory.ReadUInt   (ulong address, Endianness endianness = Little)
long   Memory.ReadLong   (ulong address, Endianness endianness = Little)
ulong  Memory.ReadULong  (ulong address, Endianness endianness = Little)
float  Memory.ReadFloat  (ulong address, Endianness endianness = Little)
double Memory.ReadDouble (ulong address, Endianness endianness = Little)

string Memory.ReadString (ulong address, int length,
                          Endianness endianness = Little,
                          Encoding encoding = null)   // defaults to UTF-8

// Generic — supports byte/short/ushort/int/uint/long/ulong/float/double/bool
T Memory.Read<T>(ulong address, Endianness endianness)

// Marshal-based struct reads
T        Memory.ReadStruct<T> (ulong address)
List<T>  Memory.ReadStructs<T>(ulong address, int count)

// Attribute-mapped object reads — see Object Mapping
T Memory.ReadObject<T>(ulong baseAddress, Endianness endianness = Little)
```

## Write operations

```csharp
bool Memory.WriteByte      (ulong address, byte value)
void Memory.WriteByteArray (ulong address, byte[] data, Endianness endianness = Little)
bool Memory.Write          (ulong address, byte[] value)
bool Memory.WriteBit       (ulong address, int bitNumber, bool value,
                            Endianness endianness = Little)

bool Memory.Write (ulong address, short  value, Endianness endianness = Little)
bool Memory.Write (ulong address, ushort value, Endianness endianness = Little)
bool Memory.Write (ulong address, int    value, Endianness endianness = Little)
bool Memory.Write (ulong address, uint   value, Endianness endianness = Little)
bool Memory.Write (ulong address, long   value, Endianness endianness = Little)
bool Memory.Write (ulong address, ulong  value, Endianness endianness = Little)
bool Memory.Write (ulong address, float  value, Endianness endianness = Little)
bool Memory.Write (ulong address, double value, Endianness endianness = Little)

bool Memory.WriteString (ulong address, string value,
                         Endianness endianness = Little,
                         Encoding encoding = null)   // defaults to UTF-8

void Memory.WriteStruct<T> (ulong address, T value)
bool Memory.WriteObject<T> (ulong baseAddress, T obj, Endianness endianness = Little)
```

## Address monitoring

These helpers poll in a background task and fire a callback when a condition is met.

```csharp
// Fire action once criteria(value) returns true
Task Memory.MonitorAddressForAction<T>(
    ulong address, Action action, Func<T, bool> criteria)

// Fire action once the bit at bitNum is set
Task Memory.MonitorAddressBitForAction(ulong address, int bitNum, Action action)

// Fire action when the byte at address transitions readyTriggerVal → triggerActionVal
Task Memory.MonitorAddressByteChangeForAction(
    ulong address, int readyTriggerVal, int triggerActionVal, Action action)
```

Example:

```csharp
// Call LoadLevel() once the "loading done" byte flips from 0 to 1
_ = Memory.MonitorAddressByteChangeForAction(0x300000, readyTriggerVal: 0, triggerActionVal: 1,
        action: LoadLevel);
```

## Pattern scanning

Scan a block of memory for a byte pattern. Use `'?'` in the mask for wildcard bytes.

```csharp
IntPtr result = Memory.FindSignature(
    start:   moduleBase,
    size:    0x200000,
    pattern: new byte[] { 0x48, 0x8B, 0x00, 0xE8 },
    mask:    "xx?x");

if (result != IntPtr.Zero)
    Console.WriteLine($"Found at 0x{result:X}");
```

## Pointer chains

Follow a chain of pointers, reading `length` bytes at each level:

```csharp
// Read 4 bytes at the address stored at ptrAddress, recursing depth times
byte[] data = Memory.ReadFromPointer(ptrAddress, length: 4, depth: 2);
```

## Endianness

All multi-byte reads and writes default to little-endian. Pass `Endianness.Big` for big-endian targets (PS2, Wii, etc.):

```csharp
int hp = Memory.ReadInt(0x200000, Endianness.Big);
Memory.Write(0x200000, hp - 10, Endianness.Big);
```

## Failure logging

Read and write operations through the default `IInvocableMemory` implementations log a warning via Serilog when `ReadProcessMemory` or `WriteProcessMemory` returns `false`. These warnings cover transient failures such as pages that are not yet committed. Access-denied failures are caught earlier at handle-open time — see [Elevation](platform-memory.md#elevation) in PlatformMemory.

## See also

- [Object Mapping](object-mapping.md) — `ReadObject` / `WriteObject`
- [PlatformMemory](platform-memory.md) — process handle, allocation, and elevation utilities
- [BizHawk](bizhawk.md) — swapping the Memory backend
- [Configuration](configuration.md) — config.ini settings
