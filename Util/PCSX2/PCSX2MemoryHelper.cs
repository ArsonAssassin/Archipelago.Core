using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.PCSX2
{
    internal class PCSX2MemoryHelper
    {
        private const string PCSX2_MODULE_NAME = "pcsx2-qt";
        private const string EEMEM_EXPORT_NAME = "EEmem";

        public IntPtr FindEEromAddress()
        {
            // Use the PCSX2 process ID with built-in fallback that was already in the code but not previously utilised.
            int pid = PlatformMemory.PlatformMemory.PCSX2_PROCESSID;
            if (pid == 0)
            {
                Log.Logger.Warning("PCSX2 process not found");
                return IntPtr.Zero;
            }
            
            // Preferred Linux Method, try to access shared memory exposed by PCSX2
            // Currently, not supported in main PCSX2 build, so we try our best
            // but fall back happily for older versions of PCSX2
            if (OperatingSystem.IsLinux())
            {
                IntPtr shmBase = PlatformMemory.PlatformMemory.GetNamedMemoryBaseAddress(pid, "pcsx2");
                if (shmBase != IntPtr.Zero)
                {
                    PlatformMemory.PlatformMemory.AttachSharedMemory($"pcsx2_{pid}", (ulong)shmBase);
                    Log.Logger.Debug($"Found shared memory base 0x{shmBase:X}");
                    return shmBase;
                }
                // Log verbose to show the program execution flow without scaring users while we wait for compatibility.
                Log.Logger.Verbose("Couldn't find shm from PCSX2. This is currently expected.");
                // In future when supported by PCSX2 officially,
                // we can let Logger know they are probably using an outdated version 
                // Log.Logger.Debug("Could not find Shared Memory. Are you using an older version of PCSX2?");
            }
            
            // Find the PCSX2 module base address
            IntPtr moduleBase = PlatformMemory.PlatformMemory.GetModuleBaseAddress(pid, PCSX2_MODULE_NAME);
            if (moduleBase == IntPtr.Zero)
            {
                Log.Logger.Warning("Failed to find PCSX2 module");
                return IntPtr.Zero;
            }

            // Find the EEmem export in the module
            IntPtr eememExportAddress = PlatformMemory.PlatformMemory.GetExportAddress(pid, moduleBase, EEMEM_EXPORT_NAME);
            if (eememExportAddress == IntPtr.Zero)
            {
                Log.Logger.Warning("Failed to find EEmem export.");
                if (OperatingSystem.IsLinux())
                {
                    // pcsx2 binary symbols are commonly stripped on Linux, which is apparently unintended behaviour,
                    // but the Flatpak is known to preserve them, so direct the user to try the Flatpak.
                    Log.Logger.Warning("You may have better luck locating EEmem with the Flatpak build.");
                }
                return IntPtr.Zero;
            }

            // Open a handle to the process for reading
            IntPtr processHandle = PlatformMemory.PlatformMemory.PlatformImpl.OpenProcess(
                PlatformMemory.PlatformMemory.PROCESS_VM_READ | PlatformMemory.PlatformMemory.PROCESS_VM_OPERATION,
                false, pid);

            if (processHandle == IntPtr.Zero)
            {
                Log.Logger.Error("Failed to open PCSX2 process");
                return IntPtr.Zero;
            }

            try
            {
                // Read the pointer value at the EEmem export address
                byte[] buffer = new byte[IntPtr.Size];
                if (!PlatformMemory.PlatformMemory.PlatformImpl.ReadProcessMemory(processHandle, (ulong)eememExportAddress,
                    buffer, buffer.Length, out IntPtr bytesRead))
                {
                    Log.Logger.Warning("Failed to read EEmem pointer value");
                    return IntPtr.Zero;
                }

                // Convert buffer to pointer
                IntPtr eememBaseAddress = (IntPtr)BitConverter.ToInt64(buffer, 0);

                Log.Logger.Information($"Found PCSX2 EEmem at 0x{eememBaseAddress:X}");
                return eememBaseAddress;
            }
            finally
            {
                PlatformMemory.PlatformMemory.PlatformImpl.CloseHandle(processHandle);
            }
        }
    }
}

