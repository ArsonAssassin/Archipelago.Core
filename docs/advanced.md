# Advanced

[← Back to README](../README.md)

## Function Hooking

`FunctionHook` (Windows only) detours a native function in the game process by writing a trampoline at the target address. It uses `PlatformMemory.ExecuteCommand` internally and requires `AllowUnsafeBlocks`.

```csharp
using Archipelago.Core.Util.Hook;

var hook = new FunctionHook(functionAddress, context =>
{
    // Inspect or modify registers/arguments here
    Console.WriteLine("Function intercepted");
    return true;  // true = also execute the original function
                  // false = skip the original function
});

hook.Install();

// Later:
hook.Uninstall();
```

`functionAddress` is the absolute address of the function to hook (e.g. obtained via `PlatformMemory.GetExportAddress` or pattern scanning with `Memory.FindSignature`).

## Lag Simulator

`LagSimulator` suspends the game process threads to simulate lag. Useful for testing timing-sensitive item and location logic without needing a slow machine.

```csharp
using Archipelago.Core.Util;

// Suspend the game for delayMs milliseconds per cycle
LagSimulator.StartLag(delayMs: 200);

// Stop artificial lag
LagSimulator.StopLag();
```

## IMemory / Custom backends

`Memory.Initialize` accepts any `IMemory` implementation. You can write your own provider — for example, to read from a memory dump file during offline testing:

```csharp
public class DumpMemory : IMemory
{
    private readonly byte[] _dump;
    private readonly ulong _baseAddress;

    public DumpMemory(byte[] dump, ulong baseAddress)
    {
        _dump = dump;
        _baseAddress = baseAddress;
    }

    public byte ReadByte(ulong address)
        => _dump[address - _baseAddress];

    public byte[] ReadByteArray(ulong address, int length)
        => _dump[(int)(address - _baseAddress)..((int)(address - _baseAddress) + length)];

    public bool WriteByte(ulong address, byte value)
    {
        _dump[address - _baseAddress] = value;
        return true;
    }

    public void WriteByteArray(ulong address, byte[] data,
                               Archipelago.Core.Util.Enums.Endianness endianness
                                   = Archipelago.Core.Util.Enums.Endianness.Little)
    {
        var bytes = endianness == Archipelago.Core.Util.Enums.Endianness.Big
            ? data.Reverse().ToArray() : data;
        bytes.CopyTo(_dump, (int)(address - _baseAddress));
    }
}

Memory.Initialize(new DumpMemory(File.ReadAllBytes("memdump.bin"), 0x80000000));
```

## IInvocableMemory

The native platform implementations (`WindowsMemory`, `LinuxMemory`, `MacOSMemory`) implement `IInvocableMemory : IMemory`, which extends the interface with the full Win32-style P/Invoke surface (process handles, virtual memory, module info, remote thread execution). `PlatformMemory.PlatformImpl` exposes this internally.

The default `ReadByte`, `ReadByteArray`, and `WriteByteArray` implementations on `IInvocableMemory` log a warning via Serilog when the underlying platform call returns `false`. This makes transient read/write failures visible in logs without throwing exceptions. Access-denied failures are caught earlier at handle-open time — see [Elevation](platform-memory.md#elevation) in PlatformMemory.

## See also

- [Memory API](memory.md)
- [PlatformMemory](platform-memory.md)
