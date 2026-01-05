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
            // Get the PCSX2 process ID
            int pid = Memory.GetProcessID(PCSX2_MODULE_NAME);
            if (pid == 0)
            {
                Log.Logger.Warning("PCSX2 process not found");
                return IntPtr.Zero;
            }

            // Find the PCSX2 module base address
            IntPtr moduleBase = Memory.GetModuleBaseAddress(pid, PCSX2_MODULE_NAME);
            if (moduleBase == IntPtr.Zero)
            {
                Log.Logger.Warning("Failed to find PCSX2 module");
                return IntPtr.Zero;
            }

            // Find the EEmem export in the module
            IntPtr eememExportAddress = Memory.GetExportAddress(pid, moduleBase, EEMEM_EXPORT_NAME);
            if (eememExportAddress == IntPtr.Zero)
            {
                Log.Logger.Warning("Failed to find EEmem export");
                return IntPtr.Zero;
            }

            // Open a handle to the process for reading
            IntPtr processHandle = Memory.PlatformImpl.OpenProcess(
                Memory.PROCESS_VM_READ | Memory.PROCESS_VM_OPERATION,
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
                if (!Memory.PlatformImpl.ReadProcessMemory(processHandle, (ulong)eememExportAddress,
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
                Memory.PlatformImpl.CloseHandle(processHandle);
            }
        }
    }
}

