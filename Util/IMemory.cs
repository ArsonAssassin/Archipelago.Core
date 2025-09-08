using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Archipelago.Core.Util.Enums;

namespace Archipelago.Core.Util
{
    public interface IMemory
    {
        bool ReadProcessMemory(IntPtr processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        bool WriteProcessMemory(IntPtr processH, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);
        IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        bool VirtualProtectEx(IntPtr processH, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);
        bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint dwFreeType);
        uint GetLastError();
        bool CloseHandle(IntPtr handle);
	int GetPID(string procName);
        IntPtr GetModuleHandle(string moduleName);
        string GetLastErrorMessage();
        uint Execute(nint v, nint address, uint timeoutSeconds);
        uint ExecuteCommand(nint v, byte[] bytes, uint timeoutSeconds);
        MODULEINFO GetModuleInfo(IntPtr processHandle, string moduleName);
        IntPtr FindFreeRegionBelow4GB(IntPtr processHandle, uint size);
    }
}
