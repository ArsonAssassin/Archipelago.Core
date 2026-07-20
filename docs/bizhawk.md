# BizHawk Support

[← Back to README](../README.md)

For BizHawk (EmuHawk) targets, memory access goes through a named pipe rather than `ReadProcessMemory`. The `Archipelago.Core.BizhawkConnector` external tool runs inside BizHawk and acts as the pipe server; `BizhawkMemory` is the client-side `IMemory` implementation.

## Setup

### 1. Install the connector tool

Build `Archipelago.Core.BizhawkConnector` (the companion project) and copy the resulting `Archipelago.Core.BizhawkConnector.dll` into BizHawk's `ExternalTools` folder. The PostBuild step does this automatically if `BIZHAWK_DATA_HOME` is set in your environment.

### 2. Load the tool in BizHawk

With a ROM loaded, open **Tools → External Tool → Archipelago BizhawkConnector**. A status message will appear in the BizHawk message bar. The pipe server starts immediately.

### 3. Connect from your game client

```csharp
using Archipelago.Core.Util.BizHawk;

var bizhawkMemory = new BizhawkMemory();

// Connect to the pipe (throws TimeoutException if the tool is not running)
bizhawkMemory.Connect();  // default 5 000 ms timeout

// Discover which memory domains the current ROM exposes
string[] domains = bizhawkMemory.ListDomains();
// e.g. ["MainRAM", "VRAM", "SPU RAM", "Scratchpad", "System Bus"]

// Select the domain you want to address
bizhawkMemory.SetDomain("MainRAM");

// Install as the Memory backend
Memory.Initialize(bizhawkMemory);
```

If you already know the domain name, connect and select in one call:

```csharp
bizhawkMemory.Connect("MainRAM");
```

### 4. Use Memory as normal

After `Memory.Initialize(bizhawkMemory)`, all `Memory.Read*` and `Memory.Write*` calls go through the pipe to BizHawk's memory API.

```csharp
int hp = Memory.ReadInt(0x1F800000);
Memory.Write(0x1F800010, 255);
```

## Switching domains at runtime

```csharp
bizhawkMemory.SetDomain("VRAM");
// Memory operations now target VRAM
bizhawkMemory.SetDomain("MainRAM");
```

## Disconnecting

```csharp
bizhawkMemory.Disconnect();
```

## BizhawkMemory API

```csharp
public class BizhawkMemory : IMemory
{
    bool     IsConnected { get; }

    // Connect pipe only (no domain selected)
    void     Connect(int timeoutMs = 5000)

    // Connect pipe and select a domain in one step
    bool     Connect(string domainName, int timeoutMs = 5000)

    // List available memory domains for the loaded ROM
    string[] ListDomains()

    // Select or change the active memory domain
    bool     SetDomain(string domainName)

    void     Disconnect()

    // IMemory implementation
    byte   ReadByte     (ulong address)
    byte[] ReadByteArray(ulong address, int length)
    bool   WriteByte    (ulong address, byte value)
    void   WriteByteArray(ulong address, byte[] data, Endianness endianness = Little)
}
```

## Notes

- Only one `BizhawkMemory` instance / pipe connection is expected at a time. The internal `BizhawkPipeClient` is a static singleton.
- The `ArchipelagoClient` constructor still sets `PlatformMemory.CurrentProcId` to EmuHawk's PID. This is intentional — it is used for overlay window attachment and health-check polling, not for memory reads.
- The pipe protocol uses binary framing (4-byte length prefix + payload). Addresses are passed as `long` to match BizHawk's `IMemoryApi` parameter type.

## See also

- [Memory API](memory.md)
- [ArchipelagoClient](archipelago-client.md)
