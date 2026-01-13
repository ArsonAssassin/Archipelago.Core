using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Archipelago.Core.Util.Duckstation
{
    internal class DuckstationMemoryHelper
    {
        private const string DUCKSTATION_MODULE_NAME = "duckstation";
        private const string RAM_EXPORT_NAME = "RAM";

        public IntPtr FindEEromAddress()
        {
            // Get the Duckstation process ID
            int pid = Memory.GetProcessID(DUCKSTATION_MODULE_NAME);
            if (pid == 0)
            {
                Log.Logger.Warning("Duckstation process not found");
                return IntPtr.Zero;
            }

            // Find the Duckstation module base address
            IntPtr moduleBase = Memory.GetModuleBaseAddress(pid, DUCKSTATION_MODULE_NAME);
            if (moduleBase == IntPtr.Zero)
            {
                Log.Logger.Warning("Failed to find Duckstation module");
                return IntPtr.Zero;
            }

            // Find the RAM export in the module
            IntPtr ramExportAddress = Memory.GetExportAddress(pid, moduleBase, RAM_EXPORT_NAME);
            if (ramExportAddress == IntPtr.Zero)
            {
                Log.Logger.Warning("Failed to find RAM export");
                return IntPtr.Zero;
            }

            // Open a handle to the process for reading
            IntPtr processHandle = Memory.PlatformImpl.OpenProcess(
                Memory.PROCESS_VM_READ | Memory.PROCESS_VM_OPERATION,
                false, pid);

            if (processHandle == IntPtr.Zero)
            {
                Log.Logger.Error("Failed to open Duckstation process");
                return IntPtr.Zero;
            }

            try
            {
                // Read the pointer value at the RAM export address
                byte[] buffer = new byte[IntPtr.Size];
                if (!Memory.PlatformImpl.ReadProcessMemory(processHandle, (ulong)ramExportAddress,
                    buffer, buffer.Length, out IntPtr bytesRead))
                {
                    Log.Logger.Warning("Failed to read RAM pointer value");
                    return IntPtr.Zero;
                }

                // Convert buffer to pointer
                IntPtr ramBaseAddress = (IntPtr)BitConverter.ToInt64(buffer, 0);

                Log.Logger.Information($"Found Duckstation RAM at 0x{ramBaseAddress:X}");
                return ramBaseAddress;
            }
            finally
            {
                Memory.PlatformImpl.CloseHandle(processHandle);
            }
        }
    }
}

