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
