using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Serilog;
using static Archipelago.Core.Util.Enums;

namespace Archipelago.Core.Util.PlatformMemory
{
    public class WindowsMemory : IMemory
    {
        #region Constants
        private const uint FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
        private const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
        private const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RELEASE = 0x00008000;
        #endregion

        [Flags]
        public enum MemoryState : uint
        {
            Free = 0x10000,
            Reserve = 0x2000,
            Commit = 0x1000,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public nint BaseAddress;
            public nint AllocationBase;
            public uint AllocationProtect;
            public nint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct MODULEENTRY32
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public nint modBaseAddr;
            public uint modBaseSize;
            public nint hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }
        #region Native Methods
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "ReadProcessMemory")]
        private static extern bool ReadProcessMemory_Win32(nint processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out nint lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "WriteProcessMemory")]
        private static extern bool WriteProcessMemory_Win32(nint processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out nint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "OpenProcess")]
        private static extern nint OpenProcess_Win32(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualProtectEx")]
        private static extern bool VirtualProtectEx_Win32(nint processH, nint lpAddress, nint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualAllocEx")]
        private static extern nint VirtualAllocEx_Win32(nint hProcess, nint lpAddress, nint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualQueryEx")]
        static extern nint VirtualQueryEx_Win32(nint hProcess, nint lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", EntryPoint = "VirtualFreeEx")]
        private static extern bool VirtualFreeEx_Win32(nint hProcess, nint lpAddress, nint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetLastError")]
        private static extern uint GetLastError_Win32();

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "CloseHandle")]
        private static extern bool CloseHandle_Win32(nint handle);

        [DllImport("kernel32.dll", EntryPoint = "CreateRemoteThread")]
        private static extern nint CreateRemoteThread_Win32(nint hProcess, nint lpThreadAttributes, uint dwStackSize, nint lpStartAddress, nint lpParameter, uint dwCreationFlags, nint lpThreadId);

        [DllImport("kernel32.dll", EntryPoint = "WaitForSingleObject")]
        private static extern uint WaitForSingleObject_Win32(nint hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetModuleHandle")]
        private static extern nint GetModuleHandle_Win32(string lpModuleName);

        [DllImport("psapi.dll", SetLastError = true, EntryPoint = "GetModuleInformation")]
        private static extern bool GetModuleInformation_Win32(nint hProcess, nint hModule, out MODULEINFO lpmodinfo, uint cb);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int FormatMessage(uint dwFlags, nint lpSource, uint dwMessageId, uint dwLanguageId, ref nint lpBuffer, uint nSize, nint Arguments);
	[DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowThreadProcessId(nint hWnd, out int processID);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern nint CreateToolhelp32Snapshot(uint dwFlags, int th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Module32First(nint hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Module32Next(nint hSnapshot, ref MODULEENTRY32 lpme);
        #endregion

        #region Memory Operations
        public bool ReadProcessMemory(nint processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out nint lpNumberOfBytesRead)
        {
            return ReadProcessMemory_Win32(processH, lpBaseAddress, lpBuffer, dwSize, out lpNumberOfBytesRead);
        }

        public bool WriteProcessMemory(nint processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out nint lpNumberOfBytesWritten)
        {
            return WriteProcessMemory_Win32(processH, lpBaseAddress, lpBuffer, dwSize, out lpNumberOfBytesWritten);
        }

        public nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId)
        {
            return OpenProcess_Win32(dwDesiredAccess, bInheritHandle, dwProcessId);
        }

        public bool VirtualProtectEx(nint processH, nint lpAddress, nint dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            return VirtualProtectEx_Win32(processH, lpAddress, dwSize, flNewProtect, out lpflOldProtect);
        }

        public nint VirtualAllocEx(nint hProcess, nint lpAddress, nint dwSize, uint flAllocationType, uint flProtect)
        {
            return VirtualAllocEx_Win32(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
        }

        public nint VirtualQueryEx(nint hProcess, nint lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength)
        {
            nint ptr = VirtualQueryEx_Win32(hProcess, lpAddress, out MEMORY_BASIC_INFORMATION mbi, dwLength);
            lpBuffer = mbi;
            return ptr;
        }

        public nint FindFreeRegionBelow4GB(nint hProcess, uint size)
        {
            const ulong MAX_32BIT = 0x7FFE0000;
            nint lpAddress = (nint)(MAX_32BIT - 0x1000);

            while ((ulong)lpAddress >= 0)
            {
                if (VirtualQueryEx(hProcess, lpAddress, out MEMORY_BASIC_INFORMATION mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0)
                    break;
                if (GetLastError() != 0)
                {
                    Log.Logger.Warning("Could not find suitable Address");
                }
                if ((MemoryState)mbi.State == MemoryState.Free && mbi.RegionSize >= size)
                {
                    return new nint(mbi.BaseAddress);
                }

                // Move to next region
                lpAddress = new nint(mbi.BaseAddress.ToInt32() - 0x10000);
            }

            return nint.Zero; // No suitable region found
        }

        public bool VirtualFreeEx(nint hProcess, nint lpAddress, nint dwSize, uint dwFreeType)
        {
            return VirtualFreeEx_Win32(hProcess, lpAddress, dwSize, dwFreeType);
        }

        public bool CloseHandle(nint handle)
        {
            return CloseHandle_Win32(handle);
        }
        public int GetPID(string procName)
        {
            Process[] Processes = Process.GetProcessesByName(procName);
            if (Processes.Any(x => x.MainWindowHandle > 0))
            {
                nint hWnd = Processes.First(x => x.MainWindowHandle > 0).MainWindowHandle;
                GetWindowThreadProcessId(hWnd, out int PID);
                return PID;
            }
            else
            {
                //application is not running
                return 0;
            }
        }
        public List<int> GetPIDs(string procName)
        {
            Process[] Processes = Process.GetProcessesByName(procName);
            List<int> result = [];
            if (Processes.Any(x => x.MainWindowHandle > 0))
            {
                foreach (var window in Processes.Where(x => x.MainWindowHandle > 0))
                {
                    nint hWnd = window.MainWindowHandle;
                    GetWindowThreadProcessId(hWnd, out int PID);
                    result.Add(PID);
                }
                return result;
            }
            else
            {
                //application is not running
                return [];
            }
        }


        #endregion

        #region Error Handling
        public string GetLastErrorMessage()
        {
            uint errorCode = GetLastError_Win32();
            nint lpMsgBuf = nint.Zero;
            FormatMessage(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nint.Zero,
                errorCode,
                0,
                ref lpMsgBuf,
                0,
                nint.Zero);
            string errorMessage = Marshal.PtrToStringAnsi(lpMsgBuf);
            Marshal.FreeHGlobal(lpMsgBuf);
            return $"Error {errorCode}: {errorMessage}";
        }
        public uint GetLastError()
        {
            return GetLastError_Win32();
        }
        #endregion

        #region Module Information
        public MODULEINFO GetModuleInfo(nint processHandle, string moduleName)
        {
            nint moduleHandle = GetModuleHandle(moduleName);
            GetModuleInformation_Win32(processHandle, moduleHandle, out var moduleInfo, (uint)Marshal.SizeOf(typeof(MODULEINFO)));
            return moduleInfo;
        }

        public nint GetModuleHandle(string moduleName)
        {
            return GetModuleHandle_Win32(moduleName);
        }

        public nint GetModuleBaseAddress(int pid, string moduleName)
        {
            const uint TH32CS_SNAPMODULE = 0x00000008;

            nint snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
            if (snapshot == nint.Zero)
            {
                Log.Logger.Warning($"Failed to create module snapshot for PID {pid}");
                return nint.Zero;
            }

            try
            {
                MODULEENTRY32 moduleEntry = new MODULEENTRY32();
                moduleEntry.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));

                if (Module32First(snapshot, ref moduleEntry))
                {
                    do
                    {
                        if (moduleEntry.szModule.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
                        {
                            return moduleEntry.modBaseAddr;
                        }
                    } while (Module32Next(snapshot, ref moduleEntry));
                }

                Log.Logger.Warning($"Module '{moduleName}' not found in process {pid}");
                return nint.Zero;
            }
            finally
            {
                CloseHandle(snapshot);
            }
        }

        #endregion
        #region export info
        public nint GetExportAddress(int pid, nint moduleBase, string exportName)
        {
            nint processHandle = OpenProcess(0x0010 | 0x0020 | 0x0008, false, pid); // VM_READ | VM_WRITE | VM_OPERATION
            if (processHandle == nint.Zero)
            {
                Log.Logger.Error($"Failed to open process {pid}");
                return nint.Zero;
            }

            try
            {
                // Find export table in PE header
                nint exportTableAddress = FindExportTable(processHandle, moduleBase);
                if (exportTableAddress == nint.Zero)
                {
                    return nint.Zero;
                }

                // Find the specific export by name
                return FindExportByName(processHandle, moduleBase, exportTableAddress, exportName);
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }

        private nint FindExportTable(nint processHandle, nint moduleBaseAddress)
        {
            // Read the DOS header
            byte[] dosHeaderBuffer = new byte[64];
            if (!ReadProcessMemory(processHandle, (ulong)moduleBaseAddress, dosHeaderBuffer, dosHeaderBuffer.Length, out nint bytesRead))
            {
                Log.Logger.Warning("Failed to read DOS header");
                return nint.Zero;
            }

            // Check for MZ signature
            if (dosHeaderBuffer[0] != 'M' || dosHeaderBuffer[1] != 'Z')
            {
                Log.Logger.Warning("Invalid DOS header signature");
                return nint.Zero;
            }

            // Get e_lfanew field to find the PE header
            int e_lfanew = BitConverter.ToInt32(dosHeaderBuffer, 0x3C);

            // Read the NT header signature
            byte[] ntSignatureBuffer = new byte[4];
            if (!ReadProcessMemory(processHandle, (ulong)moduleBaseAddress + (ulong)e_lfanew, ntSignatureBuffer, ntSignatureBuffer.Length, out bytesRead))
            {
                Log.Logger.Warning("Failed to read NT signature");
                return nint.Zero;
            }

            // Check for PE signature
            if (ntSignatureBuffer[0] != 'P' || ntSignatureBuffer[1] != 'E' || ntSignatureBuffer[2] != 0 || ntSignatureBuffer[3] != 0)
            {
                Log.Logger.Warning("Invalid PE signature");
                return nint.Zero;
            }

            // Read the File Header to determine architecture
            byte[] machineBuffer = new byte[2];
            if (!ReadProcessMemory(processHandle, (ulong)moduleBaseAddress + (ulong)e_lfanew + 4, machineBuffer, machineBuffer.Length, out bytesRead))
            {
                Log.Logger.Warning("Failed to read machine type");
                return nint.Zero;
            }

            bool is32Bit = (BitConverter.ToUInt16(machineBuffer, 0) & 0x0100) != 0;
            int optionalHeaderOffset = e_lfanew + 4 + 20; // 4 for PE signature, 20 for File Header
            int dataDirectoryOffset = is32Bit ? optionalHeaderOffset + 96 : optionalHeaderOffset + 112;

            // Read the Export Directory RVA
            byte[] exportDirectoryBuffer = new byte[8];
            if (!ReadProcessMemory(processHandle, (ulong)moduleBaseAddress + (ulong)dataDirectoryOffset, exportDirectoryBuffer, exportDirectoryBuffer.Length, out bytesRead))
            {
                Log.Logger.Warning("Failed to read export directory");
                return nint.Zero;
            }

            uint exportDirectoryRVA = BitConverter.ToUInt32(exportDirectoryBuffer, 0);
            if (exportDirectoryRVA == 0)
            {
                Log.Logger.Warning("Module has no export directory");
                return nint.Zero;
            }

            return (nint)((ulong)moduleBaseAddress + exportDirectoryRVA);
        }

        private nint FindExportByName(nint processHandle, nint moduleBaseAddress, nint exportTableAddress, string exportName)
        {
            // Read the export directory structure
            byte[] exportDirectoryBuffer = new byte[40]; // Size of IMAGE_EXPORT_DIRECTORY
            if (!ReadProcessMemory(processHandle, (ulong)exportTableAddress, exportDirectoryBuffer, exportDirectoryBuffer.Length, out nint bytesRead))
            {
                Log.Logger.Warning("Failed to read export directory");
                return nint.Zero;
            }

            // Extract fields from IMAGE_EXPORT_DIRECTORY
            uint numberOfNames = BitConverter.ToUInt32(exportDirectoryBuffer, 24);
            uint addressOfFunctions = BitConverter.ToUInt32(exportDirectoryBuffer, 28);
            uint addressOfNames = BitConverter.ToUInt32(exportDirectoryBuffer, 32);
            uint addressOfNameOrdinals = BitConverter.ToUInt32(exportDirectoryBuffer, 36);

            // Read the names RVA array
            byte[] namesBuffer = new byte[numberOfNames * 4];
            if (!ReadProcessMemory(processHandle, (ulong)moduleBaseAddress + addressOfNames, namesBuffer, namesBuffer.Length, out bytesRead))
            {
                Log.Logger.Warning("Failed to read export names");
                return nint.Zero;
            }

            // Read the ordinals array
            byte[] ordinalsBuffer = new byte[numberOfNames * 2];
            if (!ReadProcessMemory(processHandle, (ulong)moduleBaseAddress + addressOfNameOrdinals, ordinalsBuffer, ordinalsBuffer.Length, out bytesRead))
            {
                Log.Logger.Warning("Failed to read export ordinals");
                return nint.Zero;
            }

            // Read the functions RVA array
            byte[] functionsBuffer = new byte[numberOfNames * 4];
            if (!ReadProcessMemory(processHandle, (ulong)moduleBaseAddress + addressOfFunctions, functionsBuffer, functionsBuffer.Length, out bytesRead))
            {
                Log.Logger.Warning("Failed to read export functions");
                return nint.Zero;
            }

            // Search for the export by name
            for (uint i = 0; i < numberOfNames; i++)
            {
                uint nameRVA = BitConverter.ToUInt32(namesBuffer, (int)(i * 4));

                // Read the export name string
                byte[] nameBuffer = new byte[256];
                if (!ReadProcessMemory(processHandle, (ulong)moduleBaseAddress + nameRVA, nameBuffer, nameBuffer.Length, out bytesRead))
                {
                    continue;
                }

                // Convert to null-terminated string
                string currentExportName = System.Text.Encoding.ASCII.GetString(nameBuffer);
                int nullTerminator = currentExportName.IndexOf('\0');
                if (nullTerminator != -1)
                {
                    currentExportName = currentExportName.Substring(0, nullTerminator);
                }

                if (currentExportName == exportName)
                {
                    // Get the ordinal for this name
                    ushort ordinal = BitConverter.ToUInt16(ordinalsBuffer, (int)(i * 2));

                    // Get the function RVA for this ordinal
                    uint functionRVA = BitConverter.ToUInt32(functionsBuffer, ordinal * 4);

                    // Return the actual address
                    return (nint)((ulong)moduleBaseAddress + functionRVA);
                }
            }

            Log.Logger.Warning($"Export '{exportName}' not found");
            return nint.Zero;
        }
        #endregion
        #region Remote Execution
        public uint Execute(nint processHandle, nint address, uint timeoutSeconds = 0xFFFFFFFF)
        {
            nint thread = CreateRemoteThread_Win32(processHandle, nint.Zero, 0, address, nint.Zero, 0, nint.Zero);
            if (thread == nint.Zero)
            {
                Log.Logger.Error($"Failed to create remote thread: {GetLastErrorMessage()}");
                return 0;
            }

            uint result = WaitForSingleObject_Win32(thread, timeoutSeconds);
            if (result == 0xffffffff) // WAIT_FAILED
            {
                Log.Logger.Error($"Failed to execute remote thread: {GetLastErrorMessage()}");
            }
            if (!CloseHandle(thread)) // close failed
            {
                Log.Logger.Warning($"Failed to close handle after execute: {GetLastErrorMessage()}");
            }
            return result;
        }

        public uint ExecuteCommand(nint processHandle, byte[] bytes, uint timeoutSeconds = 0xFFFFFFFF)
        {
            nint address = VirtualAllocEx(processHandle, nint.Zero, bytes.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (address == nint.Zero)
            {
                Log.Logger.Error($"Failed to allocate memory: {GetLastErrorMessage()}");
                return 0;
            }

            try
            {
                if (!WriteProcessMemory(processHandle, (ulong)address, bytes, bytes.Length, out nint bytesWritten))
                {
                    Log.Logger.Error($"Failed to write bytes to memory: {GetLastErrorMessage()}");
                    if (!VirtualFreeEx(processHandle, address, nint.Zero, MEM_RELEASE))
                    {
                        Log.Logger.Warning($"Failed to free bytes in memory: 1_{GetLastErrorMessage()}");
                    }
                    return 0;
                }

                uint result = Execute(processHandle, address, timeoutSeconds);
                if (!VirtualFreeEx(processHandle, address, nint.Zero, MEM_RELEASE))
                {
                    Log.Logger.Warning($"Failed to free bytes in memory: 2_{GetLastErrorMessage()}");
                }
                return result;
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Error executing command: {ex.Message}");
                if (!VirtualFreeEx(processHandle, address, nint.Zero, MEM_RELEASE))
                {
                    Log.Logger.Warning($"Failed to free bytes in memory: 3_{GetLastErrorMessage()}");
                }
                return 0;
            }
        }
        #endregion
    }
}
