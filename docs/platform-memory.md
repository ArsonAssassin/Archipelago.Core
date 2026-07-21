# PlatformMemory

[← Back to README](../README.md)

`PlatformMemory` (namespace `Archipelago.Core.Util.PlatformMemory`) exposes the native process-management surface: process discovery, module information, memory protection, allocation, and remote execution. These operations always target the native host process and are independent of the `IMemory` backend used by [Memory](memory.md).

`PlatformMemory` selects a platform-specific implementation at startup (Windows, Linux, macOS).

## Process ID

```csharp
// Set by ArchipelagoClient automatically from the GameClient's ProcId.
// Required before calling any method that touches the process.
PlatformMemory.CurrentProcId = pid;
```

## Process discovery

```csharp
// Exact match, then falls back to partial (case-insensitive) match
int   PlatformMemory.GetProcessID(string name)
int   PlatformMemory.GetProcIdFromExe(string exe)

// All matching PIDs
List<int> PlatformMemory.GetProcessIDs(string name)
List<int> PlatformMemory.GetProcIdsFromExe(string exe)

// Partial-match only
int       PlatformMemory.GetProcFromIdFromPartial(string partialName)
List<int> PlatformMemory.GetProcFromIdsFromPartial(string partialName)
```

### Common emulator shortcuts

```csharp
PlatformMemory.BIZHAWK_PROCESSID   // EmuHawk.exe
PlatformMemory.EPSXE_PROCESSID     // ePSXe
PlatformMemory.PCSX2_PROCESSID     // pcsx2 or pcsx2-qt
PlatformMemory.XENIA_PROCESSID     // Xenia
```

### Emulator EEmem offsets

For PS2 emulators that use a mapped EEmem region:

```csharp
ulong PlatformMemory.GetPCSX2Offset()
ulong PlatformMemory.GetDuckstationOffset()
```

## Process and module info

```csharp
Process    PlatformMemory.GetCurrentProcess()
Process    PlatformMemory.GetProcessById(int id)
ulong      PlatformMemory.GetBaseAddress(string moduleName)
MODULEINFO PlatformMemory.GetModuleInfo(string moduleName)
IntPtr     PlatformMemory.GetModuleBaseAddress(int pid, string moduleName)
IntPtr     PlatformMemory.GetExportAddress(int pid, IntPtr moduleBase, string exportName)
string     PlatformMemory.GetLastErrorMessage()
```

## Handle management

```csharp
IntPtr PlatformMemory.CurrentHandle()  // opens/caches the process handle
void   PlatformMemory.CloseCurrentHandle()
```

## Elevation

When `OpenProcess` fails with `ERROR_ACCESS_DENIED` (e.g. the game is running as administrator but the client is not), `CurrentHandle()` throws `ElevationRequiredException` instead of returning a zero handle.

### Catching elevation failures

```csharp
using Archipelago.Core.Util.PlatformMemory;

try
{
    var handle = PlatformMemory.CurrentHandle();
}
catch (ElevationRequiredException ex)
{
    Console.WriteLine(ex.Message);         // "Access denied opening process 1234. ..."
    Console.WriteLine(ex.TargetProcessId); // 1234
}
```

### ElevationHelper

`ElevationHelper` provides proactive checks and a relaunch helper:

```csharp
using Archipelago.Core.Util.PlatformMemory;

// Check if the current process is running as admin / root
bool isAdmin = ElevationHelper.IsElevated();

// Probe whether a specific process requires elevation to access
bool needsAdmin = ElevationHelper.RequiresElevation(pid);

// Relaunch the current process with a UAC prompt (Windows only)
// Returns false if the user cancels the prompt
bool launched = ElevationHelper.RestartElevated();
```

A typical startup pattern:

```csharp
int pid = PlatformMemory.GetProcessID("MyGame");
if (ElevationHelper.RequiresElevation(pid))
{
    Console.WriteLine("Game requires admin access. Requesting elevation...");
    if (!ElevationHelper.RestartElevated())
        Console.WriteLine("UAC prompt was cancelled.");
}
```

On Linux/macOS, `IsElevated()` checks `geteuid() == 0`. `RestartElevated()` is not supported on non-Windows platforms — instruct users to re-run with `sudo`.

## Memory management

```csharp
// Change page protection on a region
bool PlatformMemory.FreezeAddress  (ulong address, int length)  // → PAGE_READONLY
bool PlatformMemory.UnfreezeAddress(ulong address, int length)  // → PAGE_READWRITE

// Allocate memory in the target process
IntPtr PlatformMemory.Allocate     (uint size, uint flProtect = PAGE_READWRITE)
IntPtr PlatformMemory.AllocateAbove(uint size)   // finds a region below 4 GB
bool   PlatformMemory.FreeMemory   (IntPtr address)
```

### Protection constants

```csharp
PlatformMemory.PAGE_READONLY           // 0x02
PlatformMemory.PAGE_READWRITE          // 0x04
PlatformMemory.PAGE_EXECUTE_READWRITE  // 0x40
```

## Remote execution

Execute a byte array as a native thread in the target process:

```csharp
uint PlatformMemory.ExecuteCommand(byte[] bytes, uint timeoutSeconds = 0xFFFFFFFF)
```

## See also

- [Memory API](memory.md)
- [Configuration](configuration.md) — config.ini settings
- [Advanced](advanced.md) — FunctionHook
